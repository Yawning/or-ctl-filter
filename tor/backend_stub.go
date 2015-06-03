/*
 * backend_stub.go - Fake Tor control port backend.
 *
 * To the extent possible under law, Yawning Angel has waived all copyright and
 * related or neighboring rights to or-ctl-filter, using the creative commons
 * "cc0" public domain dedication. See LICENSE or
 * <http://creativecommons.org/publicdomain/zero/1.0/> for full details.
 */

package tor

type stubBackend struct {
	s *session
}

func (b *stubBackend) Init() error {
	// Nothing to initialize.
	return nil
}

func (b *stubBackend) Term() {
	// Nothing to cleanup.
}

func (b *stubBackend) TorVersion() string {
	return "0.2.7.1-alpha"
}

func (b *stubBackend) OnNewnym(raw []byte) error {
	// Pretend everything went ok, so that Tor Browser at least clears state.
	_, err := b.s.appConnWrite(false, []byte(responseOk))
	return err
}

func (b *stubBackend) RelayTorToApp() {
	b.s.Done()
}

func newStubBackend(session *session) sessionBackend {
	return &stubBackend{s: session}
}
