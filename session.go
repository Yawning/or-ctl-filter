/*
 * session.go - or-ctl-filter session instance.
 *
 * To the extent possible under law, Yawning Angel has waived all copyright and
 * related or neighboring rights to or-ctl-filter, using the creative commons
 * "cc0" public domain dedication. See LICENSE or
 * <http://creativecommons.org/publicdomain/zero/1.0/> for full details.
 */

package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"

	"github.com/yawning/bulb"
)

const (
	controlSocketFile = "/var/run/tor/control"

	cmdProtocolInfo  = "PROTOCOLINFO"
	cmdAuthenticate  = "AUTHENTICATE"
	cmdAuthChallenge = "AUTHCHALLENGE"
	cmdQuit          = "QUIT"
	cmdGetInfo       = "GETINFO"
	cmdSignal        = "SIGNAL"

	responseOk = "250 OK\r\n"

	errAuthenticationRequired = "514 Authentication required\r\n"
	errUnrecognizedCommand    = "510 Unrecognized command\r\n"
)

type session struct {
	appConn          net.Conn
	appConnReader    *bufio.Reader
	appConnWriteLock sync.Mutex

	torConn   *bulb.Conn
	protoInfo *bulb.ProtocolInfo

	isPreAuth bool

	sync.WaitGroup
	errChan chan error
}

func (s *session) FilterSession() {
	defer s.appConn.Close()

	clientAddr := s.appConn.RemoteAddr()
	log.Printf("New app connection from: %s\n", clientAddr)

	// Connect to the real control port.
	// TODO: Allow specifying the address as an argument.
	var err error
	if s.torConn, err = bulb.Dial("unix", controlSocketFile); err != nil {
		log.Printf("Failed to connect to the tor control port: %s\n", err)
		return
	}
	defer s.torConn.Close()

	// Get a valid PROTOCOLINFO command so we can lie about the version.
	if s.protoInfo, err = s.torConn.ProtocolInfo(); err != nil {
		log.Printf("Failed to query protocol info: %s\n", err)
		return
	}

	// Authenticate with the real tor connection.
	// TODO: Allow specifying a password.
	if err = s.torConn.Authenticate(""); err != nil {
		log.Printf("Failed to connect to the tor control port: %s\n", err)
		return
	}

	// Handle all of the allowed commands till the client authenticates.
	if err = s.processPreAuth(); err != nil {
		log.Printf("[PreAuth]: %s", err)
		return
	}

	s.Add(2)
	go s.proxyTorToApp()
	go s.proxyAndFilerApp()

	// Wait till all sessions are finished, log and return.
	s.Wait()
	if len(s.errChan) > 0 {
		err = <-s.errChan
		log.Printf("Closed client connection from: %s: %s\n", clientAddr, err)
	} else {
		log.Printf("Closed client connection from: %s\n", clientAddr)
	}
}

func (s *session) processPreAuth() error {
	// Ok, we have a valid upstream control port connection.  Process
	// all of the commands a client can issue before authentication.

	sentProtocolInfo := false
	for {
		cmd, splitCmd, _, err := s.appConnReadLine()
		if err != nil {
			log.Printf("[PreAuth]: Failed reading client request: %s", err)
			return err
		}

		switch cmd {
		case cmdProtocolInfo:
			if sentProtocolInfo {
				s.sendErrAuthenticationRequired()
				return errors.New("Client already sent PROTOCOLINFO already")
			}
			sentProtocolInfo = true
			if err = s.onCmdProtocolInfo(splitCmd); err != nil {
				return err
			}
		case cmdAuthenticate:
			_, err = s.appConnWrite(false, []byte(responseOk))
			s.isPreAuth = false
			return err
		case cmdAuthChallenge:
			// WTF?  We should never see this since PROTOCOLINFO lies about the
			// supported authentication types.
			s.sendErrUnrecognizedCommand()
			return errors.New("Client sent AUTHCHALLENGE, when not supported")
		case cmdQuit:
			return errors.New("Client requested connection close")
		default:
			s.sendErrAuthenticationRequired()
			return fmt.Errorf("Invalid app command: '%s'", cmd)
		}
	}
}

func (s *session) proxyTorToApp() {
	defer s.Done()
	defer s.appConn.Close()
	defer s.torConn.Close()

	rd := bufio.NewReader(s.torConn)
	for {
		line, err := rd.ReadBytes('\n')
		if err != nil {
			s.errChan <- err
			break
		}
		if _, err = s.appConnWrite(true, line); err != nil {
			s.errChan <- err
			break
		}
	}
}

func (s *session) proxyAndFilerApp() {
	defer s.Done()
	defer s.appConn.Close()
	defer s.torConn.Close()

	for {
		cmd, splitCmd, raw, err := s.appConnReadLine()
		if err != nil {
			s.errChan <- err
			break
		}

		switch cmd {
		case cmdProtocolInfo:
			err = s.onCmdProtocolInfo(splitCmd)
		case cmdGetInfo:
			err = s.onCmdGetInfo(splitCmd, raw)
		case cmdSignal:
			err = s.onCmdSignal(splitCmd, raw)
		default:
			log.Printf("Filtering command: [%s]\n", cmd)
			err = s.sendErrUnrecognizedCommand()
		}
		if err != nil {
			s.errChan <- err
			break
		}
	}
}

func (s *session) sendErrAuthenticationRequired() error {
	_, err := s.appConnWrite(false, []byte(errAuthenticationRequired))
	return err
}

func (s *session) sendErrUnrecognizedCommand() error {
	_, err := s.appConnWrite(false, []byte(errUnrecognizedCommand))
	return err
}

func (s *session) sendErrUnexpectedArgCount(cmd string, expected, actual int) error {
	if expected > actual {
		respStr := "512 Too many arguments to " + cmd + "\r\n"
		_, err := s.appConnWrite(false, []byte(respStr))
		return err
	} else {
		respStr := "512 Missing argument to " + cmd + "\r\n"
		_, err := s.appConnWrite(false, []byte(respStr))
		return err
	}
}

func (s *session) onCmdProtocolInfo(splitCmd []string) error {
	// XXX: Do something with splitCmd like validate args.
	respStr := "250-PROTOCOLINFO 1\r\n250-AUTH METHODS=NULL,HASHEDPASSWORD\r\n250-VERSION Tor=\"" + s.protoInfo.TorVersion + "\"\r\n" + responseOk
	_, err := s.appConnWrite(false, []byte(respStr))
	return err
}

func (s *session) onCmdGetInfo(splitCmd []string, raw []byte) error {
	const argGetInfoSocks = "net/listeners/socks"
	if len(splitCmd) != 2 {
		return s.sendErrUnexpectedArgCount(cmdGetInfo, 2, len(splitCmd))
	} else if splitCmd[1] != argGetInfoSocks {
		log.Printf("Filtering GETINFO: [%s]\n", splitCmd[1])
		respStr := "552 Unrecognized key \"" + splitCmd[1] + "\"\r\n"
		_, err := s.appConnWrite(false, []byte(respStr))
		return err
	} else {
		_, err := s.torConn.Write(raw)
		return err
	}
}

func (s *session) onCmdSignal(splitCmd []string, raw []byte) error {
	const argSignalNewnym = "NEWNYM"
	if len(splitCmd) != 2 {
		return s.sendErrUnexpectedArgCount(cmdSignal, 2, len(splitCmd))
	} else if splitCmd[1] != argSignalNewnym {
		log.Printf("Filtering SIGNAL: [%s]\n", splitCmd[1])
		respStr := "552 Unrecognized signal code \"" + splitCmd[1] + "\"\r\n"
		_, err := s.appConnWrite(false, []byte(respStr))
		return err
	} else {
		_, err := s.torConn.Write(raw)
		return err
	}
}

func (s *session) appConnWrite(fromServer bool, b []byte) (int, error) {
	var prefix string
	if fromServer {
		prefix = "S->C:"
	} else if s.isPreAuth {
		prefix = "P->C [PreAuth]:"
	} else {
		prefix = "P->C:"
	}

	s.appConnWriteLock.Lock()
	defer s.appConnWriteLock.Unlock()
	log.Printf("%s %s", prefix, bytes.TrimSpace(b))
	return s.appConn.Write(b)
}

func (s *session) appConnReadLine() (cmd string, splitCmd []string, rawLine []byte, err error) {
	if rawLine, err = s.appConnReader.ReadBytes('\n'); err != nil {
		return
	}

	var prefix string
	if s.isPreAuth {
		prefix = "C [PreAuth]:"
	} else {
		prefix = "C:"
	}
	trimmedLine := bytes.TrimSpace(rawLine)
	log.Printf("%s %s", prefix, trimmedLine)

	splitCmd = strings.Split(string(trimmedLine), " ")
	cmd = strings.ToUpper(strings.TrimSpace(splitCmd[0]))
	return
}

func newSession(appConn net.Conn) *session {
	s := new(session)
	s.appConn = appConn
	s.appConnReader = bufio.NewReader(s.appConn)
	s.errChan = make(chan error, 2)
	s.isPreAuth = true
	return s
}
