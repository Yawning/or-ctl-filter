/*
 * socks.go - or-ctl-filter SOCKS shim
 *
 * To the extent possible under law, Yawning Angel has waived all copyright and
 * related or neighboring rights to or-ctl-filter, using the creative commons
 * "cc0" public domain dedication. See LICENSE or
 * <http://creativecommons.org/publicdomain/zero/1.0/> for full details.
 */

// Package proxy implements the upstream selection/dispatch logic for
// or-ctl-filter.
package proxy

import (
	"bytes"
	"errors"
	"io"
	"log"
	"net"
	"net/url"
	"strings"
	"sync"

	"github.com/yawning/or-ctl-filter/config"
	"github.com/yawning/or-ctl-filter/http"
	"github.com/yawning/or-ctl-filter/socks5"
)

var (
	errInvalidUpstream  = errors.New("invalid upstream")
	errInvalidIsolation = errors.New("invalid SOCKS port isolation")
	errDstForbidden     = errors.New("destination forbidden by configuration")
	errRewriteFailed    = errors.New("failed to rewrite HTTP request")
)

type upstreamType byte

const (
	upstreamTor = iota
	upstreamI2P
	upstreamI2PConsole
	upstreamI2PLocal
	upstreamInternet
)

type session struct {
	cfg *config.Config

	clientConn   net.Conn
	upstreamConn net.Conn

	req     *socks5.Request
	bndAddr *socks5.Address
	optData []byte
}

// InitSocksListener initializes the redispatching SOCKS 5 server and starts
// accepting connections.
func InitSocksListener(cfg *config.Config, wg *sync.WaitGroup) {
	ln, err := net.Listen(cfg.SOCKSNetAddr())
	if err != nil {
		log.Fatalf("ERR/socks: Failed to listen on the socks address: %v", err)
	}

	wg.Add(1)
	go socksAcceptLoop(cfg, ln, wg)
}

func socksAcceptLoop(cfg *config.Config, ln net.Listener, wg *sync.WaitGroup) error {
	defer wg.Done()
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if e, ok := err.(net.Error); ok && !e.Temporary() {
				log.Printf("ERR/socks: Failed to Accept(): %v", err)
				return err
			}
			continue
		}
		s := &session{cfg: cfg, clientConn: conn}
		go s.sessionWorker()
	}
}

func (s *session) sessionWorker() {
	defer s.clientConn.Close()

	clientAddr := s.clientConn.RemoteAddr()
	log.Printf("INFO/socks: New connection from: %v", clientAddr)

	// Do the SOCKS handshake with the client, and read the command.
	var err error
	if s.req, err = socks5.Handshake(s.clientConn); err != nil {
		log.Printf("ERR/socks: Failed SOCKS5 handshake: %v", err)
		return
	}

	switch s.req.Cmd {
	case socks5.CommandTorResolve, socks5.CommandTorResolvePTR:
		if !s.cfg.Tor.Enable {
			if s.cfg.UnsafeAllowDirect {
				if s.req.Cmd == socks5.CommandTorResolve {
					log.Printf("INFO/socks: Dispatching clearnet address: '%s' (Direct, DNS)", s.req.Addr.String())
					err = s.resolveDirect()
				} else {
					log.Printf("INFO/socks: Dispatching clearnet address: '%s' (Direct, DNS PTR)", s.req.Addr.String())
					err = s.resolvePTRDirect()
				}
			} else {
				// TODO: Figure out what to do with I2P.  (Use the torsocks trick?)
				log.Printf("ERR/socks: Rejecting RESOLVE/RESOLVE_PTR request (Tor not enabled)")
				s.req.Reply(socks5.ReplyCommandNotSupported)
				return
			}
		} else {
			// Redispatch the RESOLVE/RESOLVE_PTR request via tor.
			log.Printf("INFO/socks: Dispatching clearnet address: '%s' (Tor, DNS)", s.req.Addr.String())
			if err = s.dispatchTorSOCKS(); err != nil {
				return
			}
		}
		s.req.ReplyAddr(socks5.ReplySucceeded, s.bndAddr)
		return
	case socks5.CommandConnect:
	default:
		// Should *NEVER* happen, validated as part of handshake.
		log.Printf("BUG/socks: Unsupported SOCKS command: 0x%02x", s.req.Cmd)
		s.req.Reply(socks5.ReplyCommandNotSupported)
		return
	}

	if err = s.pickUpstreamAndDispatch(); err != nil {
		return
	}
	s.req.Reply(socks5.ReplySucceeded)
	defer s.upstreamConn.Close()

	if s.optData != nil {
		if _, err = s.upstreamConn.Write(s.optData); err != nil {
			log.Printf("ERR/socks: Failed writing OptData: %v", err)
			return
		}
		s.optData = nil
	}

	// A upstream connection has been established, push data back and forth
	// till the session is done.
	var wg sync.WaitGroup
	wg.Add(2)

	copyLoop := func(dst, src net.Conn) {
		defer wg.Done()
		defer dst.Close()

		io.Copy(dst, src)
	}
	go copyLoop(s.upstreamConn, s.clientConn)
	go copyLoop(s.clientConn, s.upstreamConn)

	wg.Wait()
	log.Printf("INFO/socks: Closed SOCKS connection from: %v", clientAddr)
}

func (s *session) pickUpstreamAndDispatch() error {
	const (
		suffixOnion = ".onion"
		suffixI2P   = ".i2p"

		httpPort = "80"
	)

	// First, determine the upstream connection type for a given request.
	targetStr := s.req.Addr.String()
	host, port := s.req.Addr.HostPort()
	var upstream upstreamType
	if strings.HasSuffix(host, suffixOnion) {
		// Tor .onion address.
		upstream = upstreamTor
	} else if strings.HasSuffix(host, suffixI2P) {
		// I2P address.
		upstream = upstreamI2P
	} else if s.cfg.I2P.IsManagementAddr(targetStr) {
		// I2P management web console.
		upstream = upstreamI2PConsole
	} else if s.cfg.I2P.IsLocalAddr(targetStr) {
		// I2P local web server.
		upstream = upstreamI2PLocal
	} else {
		// Clearnet/IP address/etc.
		// TODO: Check for I2P RESOLVE address range, and rewrite.
		upstream = upstreamInternet
	}

	// Check the isolation settings:
	if upstream == upstreamI2PConsole || upstream == upstreamI2PLocal {
		// I2P router services hosted on localhost MUST be protected
		// from everyone so require Tor Browser style IsolateSOCKSAuth
		// to be set.
		if s.req.Auth.Uname == nil || s.req.Auth.Passwd == nil {
			log.Printf("ERR/socks: Rejecting I2P management/local server access, no isolation")
			s.req.Reply(socks5.ReplyConnectionNotAllowed)
			return errDstForbidden
		}

		if upstream == upstreamI2PConsole && !s.cfg.I2P.IsManagementHost(string(s.req.Auth.Uname)) {
			log.Printf("ERR/socks: Rejecting I2P management access, invalid isolation")
			s.req.Reply(socks5.ReplyConnectionNotAllowed)
			return errDstForbidden
		} else if upstream == upstreamI2PLocal && !s.cfg.I2P.IsLocalHost(string(s.req.Auth.Uname)) {
			log.Printf("ERR/socks: Rejecting I2P local server access, invalid isolation")
			s.req.Reply(socks5.ReplyConnectionNotAllowed)
			return errDstForbidden
		}

		// At this point the management console request at least has the SOCKS
		// username set to the host component of the management interface
		// address.  There's not more that can be done without hacking up
		// Tor Browser I think. :(
	} else if s.req.Auth.Uname != nil && s.req.Auth.Passwd != nil {
		// Detect clearly bogus isolation, and fixup the upstream type to
		// attempt to avoid giving information that the other protocol was
		// considered.
		switch upstream {
		case upstreamI2P:
			// I2P destination with Tor HS isolation.
			if strings.HasSuffix(string(s.req.Auth.Uname), suffixOnion) {
				log.Printf("WARN/socks: Tor HS isolation for I2P destination, forcing Tor dispatch")
				upstream = upstreamTor
			}
		case upstreamTor:
			// Tor HS destination with I2P isolation.
			if strings.HasSuffix(string(s.req.Auth.Uname), suffixI2P) {
				log.Printf("WARN/socks: I2P isolation for Tor HS destination, forcing I2P dispatch")
				upstream = upstreamI2P
			}
		}

		// In theory I could/should validate more constraints here but in
		// practice per the Tor Browser developers, "--unknown--" still
		// gets set for things that aren't trusted browser code (Bugs:
		// #13670, #15555, #15569, #15599 and possibly others), which
		// limits what I can do.
	}

	// Handle all the special upstream types (Tor HS/I2P) first.
	switch upstream {
	case upstreamTor:
		if !s.cfg.Tor.Enable {
			log.Printf("ERR/socks: Rejecting Tor HS address: '%s' (Tor not enabled)", targetStr)
			s.req.Reply(socks5.ReplyNetworkUnreachable)
			return errInvalidUpstream
		}
		log.Printf("INFO/socks: Dispatching Tor HS address: '%s'", targetStr)
		return s.dispatchTorSOCKS()
	case upstreamI2P, upstreamI2PConsole, upstreamI2PLocal:
		if !s.cfg.I2P.Enable {
			log.Printf("ERR/socks: Rejecting I2P address: '%s' (I2P not enabled)", targetStr)
			s.req.Reply(socks5.ReplyNetworkUnreachable)
			return errInvalidUpstream
		}
		if upstream == upstreamI2PConsole {
			if !s.cfg.I2P.EnableManagement {
				log.Printf("ERR/socks: Rejecting I2P address: '%s' (I2P management access not enabled)", targetStr)
				s.req.Reply(socks5.ReplyConnectionNotAllowed)
				return errDstForbidden
			}
			log.Printf("INFO/socks: Dispatching I2P address: '%s' (Direct)", targetStr)
			return s.dispatchDirect()
		} else if upstream == upstreamI2PLocal {
			if !s.cfg.I2P.EnableLocal {
				log.Printf("ERR/socks: Rejecting I2P address: '%s' (I2P local server access not enabled)", targetStr)
				s.req.Reply(socks5.ReplyConnectionNotAllowed)
				return errDstForbidden
			}
			log.Printf("INFO/socks: Dispatching I2P address: '%s' (Direct)", targetStr)
			return s.dispatchDirect()
		} else if port == httpPort {
			log.Printf("INFO/socks: Dispatching I2P address: '%s' (HTTP)", targetStr)
			return s.dispatchI2PHTTP()
		}

		// Welp.  It's not going to port 80, so fall back to the HTTPS CONNECT
		// proxy.  Per the I2P developers the HTTP proxy will do HTTPS, but I
		// want this to also do things like SSH, and a SOCKS proxy isn't
		// configured by default.
		log.Printf("INFO/socks: Dispatching I2P address: '%s' (HTTPS CONNECT)", targetStr)
		return s.dispatchI2PHTTPS()
	}

	// Clearnet destinations.
	if s.cfg.Tor.Enable {
		log.Printf("INFO/socks: Dispatching clearnet address: '%s' (Tor)", targetStr)
		return s.dispatchTorSOCKS()
	} else if s.cfg.UnsafeAllowDirect {
		log.Printf("INFO/socks: Dispatching clearnet address: '%s' (Direct)", targetStr)
		return s.dispatchDirect()
	}

	log.Printf("ERR/socks: Unable to dispatch addres: '%s' (No suitable upstream)", targetStr)
	s.req.Reply(socks5.ReplyConnectionNotAllowed)
	return errInvalidUpstream
}

func (s *session) resolveDirect() error {
	hostStr, portStr := s.req.Addr.HostPort()
	hosts, err := net.LookupHost(hostStr)
	if err != nil {
		s.req.Reply(socks5.ErrorToReplyCode(err))
		return err
	} else if len(hosts) == 0 {
		s.req.Reply(socks5.ReplyGeneralFailure)
		return errors.New("no results found (NXDOMAIN?)")
	}

	// torsocks (at least 2.1.0) totally flips out if a non-IPv4 address is
	// returned, so return the first IPv4 address.
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip == nil {
			continue
		} else if v4 := ip.To4(); v4 == nil {
			continue
		}

		var resAddr socks5.Address
		if err = resAddr.FromString(net.JoinHostPort(h, portStr)); err != nil {
			s.req.Reply(socks5.ReplyGeneralFailure)
			return err
		}
		s.bndAddr = &resAddr
		return nil
	}

	// No IPv4 addresses found.
	s.req.Reply(socks5.ReplyGeneralFailure)
	return errors.New("no IPv4 results found")
}

func (s *session) resolvePTRDirect() error {
	hostStr, portStr := s.req.Addr.HostPort()
	hosts, err := net.LookupAddr(hostStr)
	if err != nil {
		s.req.Reply(socks5.ErrorToReplyCode(err))
		return err
	} else if len(hosts) == 0 {
		s.req.Reply(socks5.ReplyGeneralFailure)
		return errors.New("no results found")
	}

	var resAddr socks5.Address
	if err = resAddr.FromString(net.JoinHostPort(hosts[0], portStr)); err != nil {
		s.req.Reply(socks5.ReplyGeneralFailure)
		return err
	}
	s.bndAddr = &resAddr
	return nil
}

func (s *session) dispatchDirect() (err error) {
	s.upstreamConn, err = net.Dial("tcp", s.req.Addr.String())
	if err != nil {
		s.req.Reply(socks5.ErrorToReplyCode(err))
	}
	return
}

func (s *session) dispatchTorSOCKS() (err error) {
	pNet, pAddr := s.cfg.Tor.SOCKSNetAddr()
	s.upstreamConn, s.bndAddr, err = socks5.Redispatch(pNet, pAddr, s.req)
	if err != nil {
		s.req.Reply(socks5.ErrorToReplyCode(err))
	}
	return
}

func (s *session) dispatchI2PHTTP() (err error) {
	pNet, pAddr := s.cfg.I2P.HTTPNetAddr()
	s.upstreamConn, err = net.Dial(pNet, pAddr)
	if err != nil {
		s.req.Reply(socks5.ErrorToReplyCode(err))
		return
	}

	// Ok, so I2P's HTTP Proxy expects the first line to have the full URL.
	// This isn't ideal because Tor Browser doesn't send things like that
	// when proxying over SOCKS (the default).
	//
	// I2P doesn't need to depend on the GET line for this information,
	// since a perfectly valid Host header will always be present with
	// anything modern as well, but so it goes.
	//
	// Read in the first line and rewrite it be in the format that the proxy
	// expects.

	return s.rewriteHTTPRequest()
}

func (s *session) dispatchI2PHTTPS() (err error) {
	pNet, pAddr := s.cfg.I2P.HTTPSNetAddr()
	s.upstreamConn, err = http.Dial(pNet, pAddr, s.req.Addr.String())
	if err != nil {
		s.req.Reply(socks5.ErrorToReplyCode(err))
	}
	return
}

func (s *session) rewriteHTTPRequest() error {
	const (
		schemeHTTP = "http"
		prefixHTTP = "HTTP/"

		// In theory modern browsers support much much more, but a lot
		// of the server code will not.  Anything over 2000 bytes here
		// or so is frowned upon because of stupid legacy Microsoft
		// limitations.
		maxRequestLen = 8192
	)

	var lineBuf []byte
rewriteLoop:
	for {
		if idx := bytes.IndexAny(lineBuf, "\n"); idx != -1 {
			l := bytes.TrimRight(lineBuf[:idx], "\r\n")
			splitLine := strings.Split(string(l), " ")
			if len(splitLine) != 3 {
				log.Printf("ERR/socks: HTTP request didn't split right")
				break rewriteLoop
			}

			if !strings.HasPrefix(splitLine[2], prefixHTTP) {
				log.Printf("ERR/socks: HTTP request doesn't appear to be HTTP")
				break rewriteLoop
			}

			uri, err := url.Parse(string(splitLine[1]))
			if err != nil {
				log.Printf("ERR/socks: HTTP request URI invalid: %v", err)
				break rewriteLoop
			}

			if uri.Scheme == "" {
				uri.Scheme = schemeHTTP
			}
			if uri.Host == "" {
				uri.Host = s.req.Addr.String()
			}

			var newLine []byte
			newLine = append(newLine, splitLine[0]...)
			newLine = append(newLine, ' ')
			newLine = append(newLine, uri.String()...)
			newLine = append(newLine, ' ')
			newLine = append(newLine, splitLine[2]...)
			newLine = append(newLine, '\r')
			newLine = append(newLine, '\n')
			s.optData = append(newLine, lineBuf[idx:]...)

			return nil
		}

		if len(lineBuf) > maxRequestLen {
			log.Printf("ERR/socks: HTTP request greater than max len durring rewrite")
			break rewriteLoop
		}

		var tmp [1]byte
		if _, err := s.clientConn.Read(tmp[:]); err != nil {
			return err
		}
		lineBuf = append(lineBuf, tmp[0])
	}
	return errRewriteFailed
}
