/*
 * main.go - or-ctl-filter
 * Copyright (C) 2014  Yawning Angel
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

// or-ctl-filter is a Tor Control Port filter in the spirit of
// "control-port-filter" by the Whonix developers.  It is more limited as the
// only use case considered is "I want to run Tor Browser on my desktop with a
// system tor service and have 'about:tor' and 'New Identity' work while
// disallowing scary control port commands".  But on a positive note, it's not
// a collection of bash and doesn't call netcat.
package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
)

const (
	defaultLogFile = "or-ctl-filter.log"

	controlSocketFile = "/var/run/tor/control"
	torControlAddr    = "127.0.0.1:9151" // Match ControlPort in torrc-defaults.

	cmdProtocolInfo  = "PROTOCOLINFO"
	cmdAuthenticate  = "AUTHENTICATE"
	cmdAuthChallenge = "AUTHCHALLENGE"
	cmdGetInfo       = "GETINFO"
	cmdSignal        = "SIGNAL"

	argSignalNewnym = "NEWNYM"
	argGetinfoSocks = "net/listeners/socks"
	argServerHash   = "SERVERHASH="
	argServerNonce  = "SERVERNONCE="

	respProtocolInfoAuth       = "250-AUTH"
	respProtocolInfoMethods    = "METHODS="
	respProtocolInfoCookieFile = "COOKIEFILE="

	respAuthChallenge = "250 AUTHCHALLENGE "

	authMethodNull       = "NULL"
	authMethodCookie     = "COOKIE"
	authMethodSafeCookie = "SAFECOOKIE"

	authNonceLength   = 32
	authServerHashKey = "Tor safe cookie authentication server-to-controller hash"
	authClientHashKey = "Tor safe cookie authentication controller-to-server hash"

	errAuthenticationRequired = "514 Authentication required\n"
	errUnrecognizedCommand    = "510 Unrecognized command\n"
)

var filteredControlAddr *net.UnixAddr
var enableLogging bool
var logFile string

func readAuthCookie(path string) ([]byte, error) {
	// Read the cookie auth file.
	cookie, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading cookie auth file: %s", err)
	}
	return cookie, nil
}

func authSafeCookie(conn net.Conn, connReader *bufio.Reader, cookie []byte) ([]byte, error) {
	clientNonce := make([]byte, authNonceLength)
	if _, err := rand.Read(clientNonce); err != nil {
		return nil, fmt.Errorf("generating AUTHCHALLENGE nonce: %s", err)
	}
	clientNonceStr := hex.EncodeToString(clientNonce)

	// Send and process the AUTHCHALLENGE.
	authChallengeReq := []byte(fmt.Sprintf("%s %s %s\n", cmdAuthChallenge, authMethodSafeCookie, clientNonceStr))
	if _, err := conn.Write(authChallengeReq); err != nil {
		return nil, fmt.Errorf("writing AUTHCHALLENGE request: %s", err)
	}
	line, err := connReader.ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("reading AUTHCHALLENGE response: %s", err)
	}
	lineStr := strings.TrimSpace(string(line))
	respStr := strings.TrimPrefix(lineStr, respAuthChallenge)
	if respStr == lineStr {
		return nil, fmt.Errorf("parsing AUTHCHALLENGE response")
	}
	splitResp := strings.SplitN(respStr, " ", 2)
	if len(splitResp) != 2 {
		return nil, fmt.Errorf("parsing AUTHCHALLENGE response")
	}
	hashStr := strings.TrimPrefix(splitResp[0], argServerHash)
	serverHash, err := hex.DecodeString(hashStr)
	if err != nil {
		return nil, fmt.Errorf("decoding AUTHCHALLENGE ServerHash: %s", err)
	}
	serverNonceStr := strings.TrimPrefix(splitResp[1], argServerNonce)
	serverNonce, err := hex.DecodeString(serverNonceStr)
	if err != nil {
		return nil, fmt.Errorf("decoding AUTHCHALLENGE ServerNonce: %s", err)
	}

	// Validate the ServerHash.
	m := hmac.New(sha256.New, []byte(authServerHashKey))
	m.Write([]byte(cookie))
	m.Write([]byte(clientNonce))
	m.Write([]byte(serverNonce))
	dervServerHash := m.Sum(nil)
	if !hmac.Equal(serverHash, dervServerHash) {
		return nil, fmt.Errorf("AUTHCHALLENGE ServerHash is invalid")
	}

	// Calculate the ClientHash.
	m = hmac.New(sha256.New, []byte(authClientHashKey))
	m.Write([]byte(cookie))
	m.Write([]byte(clientNonce))
	m.Write([]byte(serverNonce))

	return m.Sum(nil), nil
}

func authenticate(torConn net.Conn, torConnReader *bufio.Reader, appConn net.Conn, appConnReader *bufio.Reader) error {
	var canNull, canCookie, canSafeCookie bool
	var cookiePath string

	// Figure out the best auth method, and where the cookie is if any.
	protocolInfoReq := []byte(fmt.Sprintf("%s\n", cmdProtocolInfo))
	if _, err := torConn.Write(protocolInfoReq); err != nil {
		return fmt.Errorf("writing PROTOCOLINFO request: %s", err)
	}
	for {
		line, err := torConnReader.ReadBytes('\n')
		if err != nil {
			return fmt.Errorf("reading PROTOCOLINFO response: %s", err)
		}
		lineStr := strings.TrimSpace(string(line))
		if !strings.HasPrefix(lineStr, "250") {
			return fmt.Errorf("parsing PROTOCOLINFO response")
		} else if lineStr == "250 OK" {
			break
		}
		splitResp := strings.SplitN(lineStr, " ", 3)
		if splitResp[0] == respProtocolInfoAuth {
			if len(splitResp) == 1 {
				continue
			}

			methodsStr := strings.TrimPrefix(splitResp[1], respProtocolInfoMethods)
			if methodsStr == splitResp[1] {
				continue
			}
			methods := strings.Split(methodsStr, ",")
			for _, method := range methods {
				switch method {
				case authMethodNull:
					canNull = true
				case authMethodCookie:
					canCookie = true
				case authMethodSafeCookie:
					canSafeCookie = true
				}
			}
			if (canCookie || canSafeCookie) && len(splitResp) == 3 {
				cookiePathStr := strings.TrimPrefix(splitResp[2], respProtocolInfoCookieFile)
				if cookiePathStr == splitResp[2] {
					continue
				}
				cookiePath, err = strconv.Unquote(cookiePathStr)
				if err != nil {
					continue
				}
			}
		}
	}

	// Authenticate using the best possible authentication method.
	var authReq []byte
	if canNull {
		authReq = []byte(fmt.Sprintf("%s\n", cmdAuthenticate))
	} else if (canCookie || canSafeCookie) && (cookiePath != "") {
		// Read the auth cookie.
		cookie, err := readAuthCookie(cookiePath)
		if err != nil {
			return err
		}
		if canSafeCookie {
			cookie, err = authSafeCookie(torConn, torConnReader, cookie)
			if err != nil {
				return err
			}
		}
		cookieStr := hex.EncodeToString(cookie)
		authReq = []byte(fmt.Sprintf("%s %s\n", cmdAuthenticate, cookieStr))
	} else {
		return fmt.Errorf("no supported authentication methods")
	}
	if _, err := torConn.Write(authReq); err != nil {
		return fmt.Errorf("writing AUTHENTICATE request: %s", err)
	}
	authResp, err := torConnReader.ReadBytes('\n')
	if err != nil {
		return fmt.Errorf("reading AUTHENTICATE response: %s", err)
	}

	// "Authenticate" the application.
	authReq, err = appConnReader.ReadBytes('\n')
	if err != nil {
		return fmt.Errorf("reading app AUTHENTICATE request:%s", err)
	}
	splitReq := strings.SplitN(string(authReq), " ", 2)
	if strings.ToUpper(splitReq[0]) != cmdAuthenticate { // TODO: PROTOCOLINFO/AUTHCHALLENGE/QUIT?
		appConn.Write([]byte(errAuthenticationRequired))
		return fmt.Errorf("invalid app command: '%s'", splitReq[0])
	}
	if _, err = appConn.Write(authResp); err != nil {
		return fmt.Errorf("writing app AUTHENTICATE response: %s", err)
	}
	return nil
}

func syncedWrite(l *sync.Mutex, conn net.Conn, buf []byte) (int, error) {
	l.Lock()
	defer l.Unlock()
	return conn.Write(buf)
}

func validateCmdSignal(splitReq []string) bool {
	if len(splitReq) != 2 {
		log.Printf("A->T: Filtering SIGNAL with invalid args\n")
		return false
	}
	if splitReq[1] != argSignalNewnym {
		log.Printf("A->T: Filtering SIGNAL: [%s]\n", splitReq[1])
		return false
	}
	return true
}

func validateCmdGetinfo(splitReq []string) bool {
	if len(splitReq) != 2 {
		log.Printf("A->T: Filtering GETINFO with unexpected args\n")
		return false
	}
	if splitReq[1] != argGetinfoSocks {
		log.Printf("A->T: Filtering GETINFO: [%s]\n", splitReq[1])
		return false
	}
	return true
}

func filterConnection(appConn net.Conn) {
	defer appConn.Close()

	clientAddr := appConn.RemoteAddr()
	log.Printf("New app connection from: %s\n", clientAddr)

	torConn, err := net.DialUnix("unix", nil, filteredControlAddr)
	if err != nil {
		log.Printf("Failed to connect to the tor control port: %s\n", err)
		return
	}
	defer torConn.Close()

	// Authenticate with the real control port, and wait for the application to
	// authenticate.
	torConnReader := bufio.NewReader(torConn)
	appConnReader := bufio.NewReader(appConn)
	if err = authenticate(torConn, torConnReader, appConn, appConnReader); err != nil {
		log.Printf("Failed to authenticate: %s\n", err)
		return
	}

	// Start filtering commands as appropriate.
	errChan := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)

	var appConnLock sync.Mutex
	writeAppConn := func(b []byte) (int, error) {
		appConnLock.Lock()
		defer appConnLock.Unlock()
		return appConn.Write(b)
	}

	// Just proxy tor to application chatter.
	go func() {
		defer wg.Done()
		defer appConn.Close()
		defer torConn.Close()

		for {
			line, err := torConnReader.ReadBytes('\n')
			if err != nil {
				errChan <- err
				break
			}
			lineStr := strings.TrimSpace(string(line))
			log.Printf("A<-T: [%s]\n", lineStr)

			if _, err = writeAppConn(line); err != nil {
				errChan <- err
				break
			}
		}
	}()

	// Filter and selectively proxy or deny application to tor chatter.
	go func() {
		defer wg.Done()
		defer torConn.Close()
		defer appConn.Close()

		for {
			line, err := appConnReader.ReadBytes('\n')
			if err != nil {
				errChan <- err
				break
			}
			lineStr := strings.TrimSpace(string(line))
			log.Printf("A->T: [%s]\n", lineStr)

			// Filter out commands that aren't "required" for Tor Browser to
			// work with SKIP_LAUNCH etc set.
			allow := false // Default deny, yo.
			splitReq := strings.SplitN(lineStr, " ", 2)
			cmd := strings.ToUpper(splitReq[0])
			switch cmd {
			case cmdGetInfo:
				allow = validateCmdGetinfo(splitReq)
			case cmdSignal:
				allow = validateCmdSignal(splitReq)
			default:
				log.Printf("A->T: Filtering command: [%s]\n", cmd)
			}

			if allow {
				if _, err = torConn.Write(line); err != nil {
					errChan <- err
					break
				}
			} else {
				if _, err = writeAppConn([]byte(errUnrecognizedCommand)); err != nil {
					errChan <- err
					break
				}
			}
		}
	}()

	wg.Wait()
	if len(errChan) > 0 {
		err = <-errChan
		log.Printf("Closed client connection from: %s: %s\n", clientAddr, err)
	} else {
		log.Printf("Closed client connection from: %s\n", clientAddr)
	}
}

func main() {
	var err error

	flag.BoolVar(&enableLogging, "enable-logging", false, "enable logging")
	flag.StringVar(&logFile, "log-file", defaultLogFile, "log file")
	flag.Parse()

	// Deal with logging.
	if !enableLogging {
		log.SetOutput(ioutil.Discard)
	} else if logFile != "" {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			log.Fatalf("Failed to create log file: %s\n", err)
		}
		log.SetOutput(f)
	}

	filteredControlAddr, err = net.ResolveUnixAddr("unix", controlSocketFile)
	if err != nil {
		log.Fatalf("Failed to resolve the control port: %s\n", err)
	}

	// Initialize the listener
	ln, err := net.Listen("tcp", torControlAddr)
	if err != nil {
		log.Fatalf("Failed to listen on the filter port: %s\n", err)
	}
	defer ln.Close()

	// Listen for incoming connections, and dispatch workers.
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Failed to Accept(): %s\n", err)
			continue
		}
		go filterConnection(conn)
	}
}
