/*
 * main.go - or-ctl-filter
 *
 * To the extent possible under law, Yawning Angel has waived all copyright and
 * related or neighboring rights to or-ctl-filter, using the creative commons
 * "cc0" public domain dedication. See LICENSE or
 * <http://creativecommons.org/publicdomain/zero/1.0/> for full details.
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
	"bytes"
	"flag"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/yawning/bulb"
)

const (
	defaultLogFile = "or-ctl-filter.log"

	controlSocketFile = "/var/run/tor/control"
	torControlAddr    = "127.0.0.1:9151" // Match ControlPort in torrc-defaults.

	cmdGetInfo = "GETINFO"
	cmdSignal  = "SIGNAL"

	errUnrecognizedCommand = "510 Unrecognized command\n"
)

func validateCmdSignal(splitReq []string) bool {
	const argSignalNewnym = "NEWNYM"
	if len(splitReq) != 2 {
		log.Printf("Filtering SIGNAL with invalid args\n")
		return false
	}
	if splitReq[1] != argSignalNewnym {
		log.Printf("Filtering SIGNAL: [%s]\n", splitReq[1])
		return false
	}
	return true
}

func validateCmdGetinfo(splitReq []string) bool {
	const argGetinfoSocks = "net/listeners/socks"
	if len(splitReq) != 2 {
		log.Printf("Filtering GETINFO with unexpected args\n")
		return false
	}
	if splitReq[1] != argGetinfoSocks {
		log.Printf("Filtering GETINFO: [%s]\n", splitReq[1])
		return false
	}
	return true
}

func filterConnection(appConn net.Conn) {
	defer appConn.Close()

	appConnReader := bufio.NewReader(appConn)
	clientAddr := appConn.RemoteAddr()
	log.Printf("New app connection from: %s\n", clientAddr)

	torConn, err := bulb.Dial("unix", controlSocketFile)
	if err != nil {
		log.Printf("Failed to connect to the tor control port: %s\n", err)
		return
	}
	defer torConn.Close()

	// Authenticate with the real tor connection.
	if err = torConn.Authenticate(""); err != nil {
		log.Printf("Failed to connect to the tor control port: %s\n", err)
		return
	}

	// Get a valid PROTOCOLINFO command so we can lie about the version.
	pi, err := torConn.ProtocolInfo()
	if err != nil {
		log.Printf("Failed to query protocol info: %s\n", err)
		return
	}

	const (
		proxyToClientPreAuth = iota
		proxyToClient
		serverToClient
	)
	var appConnLock sync.Mutex
	writeAppConn := func(direction int, b []byte) (int, error) {
		var prefix string
		switch direction {
		case proxyToClientPreAuth:
			prefix = "P->C [PreAuth]:"
		case proxyToClient:
			prefix = "P->C:"
		case serverToClient:
			prefix = "S->C:"
		}
		appConnLock.Lock()
		defer appConnLock.Unlock()
		log.Printf("%s %s", prefix, bytes.TrimSpace(b))
		return appConn.Write(b)
	}

	// Ok.  It looks like we can talk to the real control port.
	// At this point the application has yet to authenticate so it
	// can either "PROTOCOLINFO"/"QUIT" or attempt to authenticate via
	// "AUTHCHALLENGE"/"AUTHENTICATE".
preauthLoop:
	for {
		// Fake results entirely till the client authenticates.
		const (
			cmdProtocolInfo  = "PROTOCOLINFO"
			cmdAuthenticate  = "AUTHENTICATE"
			cmdAuthChallenge = "AUTHCHALLENGE"
			cmdQuit          = "QUIT"

			responseOk                = "250 OK\r\n"
			errAuthenticationRequired = "514 Authentication required\r\n"
		)

		appReq, err := appConnReader.ReadBytes('\n')
		if err != nil {
			log.Printf("[PreAuth]: Failed reading client request: %s", err)
			return
		}
		log.Printf("C [PreAuth]: %s", bytes.TrimSpace(appReq))

		splitReq := strings.SplitN(string(appReq), " ", 2)
		switch strings.ToUpper(strings.TrimSpace(splitReq[0])) {
		case cmdProtocolInfo:
			respStr := "250-PROTOCOLINFO 1\r\n250-AUTH METHODS=NULL,HASHEDPASSWORD\r\n250-VERSION Tor=\"" + pi.TorVersion + "\"\r\n" + responseOk
			writeAppConn(proxyToClientPreAuth, []byte(respStr))
		case cmdAuthenticate:
			writeAppConn(proxyToClientPreAuth, []byte(responseOk))
			break preauthLoop
		case cmdAuthChallenge:
			// WTF?  We should never see this since PROTOCOLINFO lies about the
			// supported authentication types.
			log.Printf("[PreAuth]: Client sent AUTHCHALLENGE, when not supported")
			writeAppConn(proxyToClientPreAuth, []byte(errUnrecognizedCommand))
			return
		case cmdQuit:
			log.Printf("[PreAuth]: Client requested connection close")
			return
		default:
			log.Printf("[PreAuth]: Invalid app command: '%s'", splitReq[0])
			writeAppConn(proxyToClientPreAuth, []byte(errAuthenticationRequired))
			return
		}
	}

	// Initialize the filtering/proxy handlers.
	//  * Tor->Client chatter: Direct.
	//  * Client->Tor chatter: Intercepted.
	torConnReader := bufio.NewReader(torConn)
	errChan := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)

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
			if _, err = writeAppConn(serverToClient, line); err != nil {
				errChan <- err
				break
			}
		}
	}()

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
			log.Printf("C: %s", lineStr)

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
				log.Printf("Filtering command: [%s]\n", cmd)
			}

			if allow {
				if _, err = torConn.Write(line); err != nil {
					errChan <- err
					break
				}
			} else {
				if _, err = writeAppConn(proxyToClient, []byte(errUnrecognizedCommand)); err != nil {
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
	enableLogging := flag.Bool("enable-logging", false, "enable logging")
	logFile := flag.String("log-file", defaultLogFile, "log file")
	flag.Parse()

	// Deal with logging.
	if !*enableLogging {
		log.SetOutput(ioutil.Discard)
	} else if *logFile != "" {
		f, err := os.OpenFile(*logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			log.Fatalf("Failed to create log file: %s\n", err)
		}
		log.SetOutput(f)
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
