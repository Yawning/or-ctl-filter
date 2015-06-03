/*
 * session.go - or-ctl-filter Tor control port interface.
 *
 * To the extent possible under law, Yawning Angel has waived all copyright and
 * related or neighboring rights to or-ctl-filter, using the creative commons
 * "cc0" public domain dedication. See LICENSE or
 * <http://creativecommons.org/publicdomain/zero/1.0/> for full details.
 */

// Package tor implements the Tor control port session/interface.
package tor

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/yawning/or-ctl-filter/config"
)

const (
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
	cfg *config.Config

	appConn          net.Conn
	appConnReader    *bufio.Reader
	appConnWriteLock sync.Mutex

	backend   sessionBackend
	isPreAuth bool

	sync.WaitGroup
	errChan chan error
}

type sessionBackend interface {
	Init() error
	Term()

	TorVersion() string

	OnNewnym([]byte) error

	RelayTorToApp()
}

// InitCtlListener initializes the control port listener.
func InitCtlListener(cfg *config.Config, wg *sync.WaitGroup) {
	ln, err := net.Listen(cfg.FilteredNetAddr())
	if err != nil {
		log.Fatalf("ERR/tor: Failed to listen on the control address: %v", err)
	}

	wg.Add(1)
	go filterAcceptLoop(cfg, ln, wg)
}

func filterAcceptLoop(cfg *config.Config, ln net.Listener, wg *sync.WaitGroup) error {
	defer wg.Done()
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if e, ok := err.(net.Error); ok && !e.Temporary() {
				log.Printf("ERR/tor: Failed to Accept(): %v", err)
				return err
			}
		}

		// Create the appropriate session instance.
		s := newSession(cfg, conn)
		go s.sessionWorker()
	}
}

func newSession(cfg *config.Config, conn net.Conn) *session {
	s := &session{
		cfg:           cfg,
		appConn:       conn,
		appConnReader: bufio.NewReader(conn),
		isPreAuth:     true,
		errChan:       make(chan error, 2),
	}
	return s
}

func (s *session) sessionWorker() {
	defer s.appConn.Close()

	clientAddr := s.appConn.RemoteAddr()
	log.Printf("INFO/tor: New ctrl connection from: %s", clientAddr)

	// Initialize the appropriate backend.
	if s.cfg.Tor.Enable {
		s.backend = newTorBackend(s)
	} else {
		s.backend = newStubBackend(s)
	}

	if err := s.backend.Init(); err != nil {
		log.Printf("ERR/tor: Failed to initialize backend: %v", err)
		return
	}
	defer s.backend.Term()

	// Handle all of the allowed commands till the client authenticates.
	if err := s.processPreAuth(); err != nil {
		log.Printf("ERR/tor: [PreAuth]: %s", err)
		return
	}

	s.Add(2)
	go s.backend.RelayTorToApp()
	go s.proxyAndFilerApp()

	// Wait till all sessions are finished, log and return.
	s.Wait()
	if len(s.errChan) > 0 {
		err := <-s.errChan
		log.Printf("INFO/tor: Closed client connection from: %s: %v", clientAddr, err)
	} else {
		log.Printf("INFO/tor: Closed client connection from: %v", clientAddr)
	}
}

func (s *session) processPreAuth() error {
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
	return nil
}

func (s *session) proxyAndFilerApp() {
	defer s.Done()
	defer s.appConn.Close()
	defer s.backend.Term()

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
			log.Printf("Filtering command: [%s]", cmd)
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
	var err error
	var respStr string
	if expected > actual {
		respStr = "512 Too many arguments to " + cmd + "\r\n"
	} else {
		respStr = "512 Missing argument to " + cmd + "\r\n"
	}
	_, err = s.appConnWrite(false, []byte(respStr))
	return err
}

func (s *session) onCmdProtocolInfo(splitCmd []string) error {
	for i := 1; i < len(splitCmd); i++ {
		v := splitCmd[i]
		if _, err := strconv.ParseInt(v, 10, 32); err != nil {
			log.Printf("PROTOCOLINFO received with invalid arg")
			respStr := "513 No such version \"" + v + "\"\r\n"
			_, err := s.appConnWrite(false, []byte(respStr))
			return err
		}
	}
	torVersion := s.backend.TorVersion()
	respStr := "250-PROTOCOLINFO 1\r\n250-AUTH METHODS=NULL,HASHEDPASSWORD\r\n250-VERSION Tor=\"" + torVersion + "\"\r\n" + responseOk
	_, err := s.appConnWrite(false, []byte(respStr))
	return err
}

func (s *session) onCmdGetInfo(splitCmd []string, raw []byte) error {
	const argGetInfoSocks = "net/listeners/socks"
	if len(splitCmd) != 2 {
		return s.sendErrUnexpectedArgCount(cmdGetInfo, 2, len(splitCmd))
	} else if splitCmd[1] != argGetInfoSocks {
		log.Printf("Filtering GETINFO: [%s]", splitCmd[1])
		respStr := "552 Unrecognized key \"" + splitCmd[1] + "\"\r\n"
		_, err := s.appConnWrite(false, []byte(respStr))
		return err
	} else {
		log.Printf("Spoofing GETINFO: [%s]", splitCmd[1])
		_, socksAddr := s.cfg.SOCKSNetAddr()
		respStr := "250-" + argGetInfoSocks + "=\"" + socksAddr + "\"\r\n" + responseOk
		_, err := s.appConnWrite(false, []byte(respStr))
		return err
	}
}

func (s *session) onCmdSignal(splitCmd []string, raw []byte) error {
	const argSignalNewnym = "NEWNYM"
	if len(splitCmd) != 2 {
		return s.sendErrUnexpectedArgCount(cmdSignal, 2, len(splitCmd))
	} else if splitCmd[1] != argSignalNewnym {
		log.Printf("Filtering SIGNAL: [%s]", splitCmd[1])
		respStr := "552 Unrecognized signal code \"" + splitCmd[1] + "\"\r\n"
		_, err := s.appConnWrite(false, []byte(respStr))
		return err
	} else {
		return s.backend.OnNewnym(raw)
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
	log.Printf("DEBUG/tor: %s %s", prefix, bytes.TrimSpace(b))
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
	log.Printf("DEBUG/tor: %s %s", prefix, trimmedLine)

	splitCmd = strings.Split(string(trimmedLine), " ")
	cmd = strings.ToUpper(strings.TrimSpace(splitCmd[0]))
	return
}
