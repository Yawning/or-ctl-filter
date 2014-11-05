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
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"
	"sync"
)

const (
	defaultLogFile = "or-ctl-filter.log"

	cookieAuthFile    = "/var/run/tor/control_auth_cookie"
	controlSocketFile = "/var/run/tor/control"
	torControlAddr    = "127.0.0.1:9151" // Match ControlPort in torrc-defaults.

	cmdAuthenticate = "AUTHENTICATE"
	cmdGetInfo      = "GETINFO"
	cmdSignal       = "SIGNAL"

	argSignalNewnym = "NEWNYM"
	argGetinfoSocks = "net/listeners/socks"

	errAuthenticationRequired = "514 Authentication required\n"
	errUnrecognizedCommand    = "510 Unrecognized command\n"
)

var filteredControlAddr *net.UnixAddr
var cookieString string
var enableLogging bool
var logFile string

func authenticate(torConn net.Conn, torConnReader *bufio.Reader, appConn net.Conn, appConnReader *bufio.Reader) error {
	// Authenticate with the real (tor) control port.
	authReq := []byte(fmt.Sprintf("%s %s\n", cmdAuthenticate, cookieString))
	if _, err := torConn.Write(authReq); err != nil {
		return fmt.Errorf("writing tor authentication request:%s\n", err)
	}
	authResp, err := torConnReader.ReadBytes('\n')
	if err != nil {
		return fmt.Errorf("reading tor authentication response:%s\n", err)
	}

	// "Authenticate" the application.
	authReq, err = appConnReader.ReadBytes('\n')
	if err != nil {
		return fmt.Errorf("reading app authentication request:%s\n", err)
	}
	splitReq := strings.SplitN(string(authReq), " ", 2)
	if strings.ToUpper(splitReq[0]) != cmdAuthenticate {
		// Note: Technically "QUIT" is ok here, but whatever.
		appConn.Write([]byte(errAuthenticationRequired))
		return fmt.Errorf("invalid app command: '%s'", splitReq[0])
	}
	if _, err = appConn.Write(authResp); err != nil {
		return fmt.Errorf("writing app authentication response:%s\n", err)
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
	} else {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			log.Fatalf("Failed to create log file: %s\n", err)
		}
		log.SetOutput(f)
	}

	// Read the cookie auth file.
	cookie, err := ioutil.ReadFile(cookieAuthFile)
	if err != nil {
		log.Fatalf("Failed to read cookie auth file: %s\n", err)
	}
	cookieString = hex.EncodeToString(cookie)

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
