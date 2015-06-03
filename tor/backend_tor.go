/*
 * backend_tor.go - Filtered Tor control port backend.
 *
 * To the extent possible under law, Yawning Angel has waived all copyright and
 * related or neighboring rights to or-ctl-filter, using the creative commons
 * "cc0" public domain dedication. See LICENSE or
 * <http://creativecommons.org/publicdomain/zero/1.0/> for full details.
 */

package tor

import (
	"bufio"
	"log"

	"github.com/yawning/bulb"
)

type torBackend struct {
	s *session

	torConn   *bulb.Conn
	protoInfo *bulb.ProtocolInfo
}

func (b *torBackend) Init() (err error) {
	// Connect to the real control port.
	if b.torConn, err = bulb.Dial(b.s.cfg.Tor.ControlNetAddr()); err != nil {
		log.Printf("ERR/tor: Failed to connect to tor control port: %v", err)
		return
	}

	// Issue a PROTOCOLINFO, so we can send a realistic response.
	if b.protoInfo, err = b.torConn.ProtocolInfo(); err != nil {
		log.Printf("ERR/tor: Failed to issue PROTOCOLINFO: %v", err)
		b.torConn.Close()
		return
	}

	// Authenticate with the real tor control port.
	// XXX: Pull password out of `b.s.cfg`.
	if err = b.torConn.Authenticate(""); err != nil {
		log.Printf("ERR/tor: Failed to authenticate: %v", err)
		b.torConn.Close()
		return
	}

	return
}

func (b *torBackend) Term() {
	if b.torConn != nil {
		b.torConn.Close()
	}
}

func (b *torBackend) TorVersion() string {
	return b.protoInfo.TorVersion
}

func (b *torBackend) OnNewnym(raw []byte) error {
	_, err := b.torConn.Write(raw)
	return err
}

func (b *torBackend) RelayTorToApp() {
	defer b.Term()
	defer b.s.Done()
	defer b.s.appConn.Close()

	rd := bufio.NewReader(b.torConn)
	for {
		line, err := rd.ReadBytes('\n')
		if err != nil {
			b.s.errChan <- err
			break
		}
		if _, err = b.s.appConnWrite(true, line); err != nil {
			b.s.errChan <- err
			break
		}
	}
}

func newTorBackend(session *session) sessionBackend {
	return &torBackend{s: session}
}
