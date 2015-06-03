/*
 * https_connect.go - HTTPS CONNECT proxy client
 *
 * To the extent possible under law, Yawning Angel has waived all copyright and
 * related or neighboring rights to or-ctl-filter, using the creative commons
 * "cc0" public domain dedication. See LICENSE or
 * <http://creativecommons.org/publicdomain/zero/1.0/> for full details.
 */

// Package http implements a HTTPS CONNECT proxy client.
//
// Notes:
//  * A lot of the code is shamelessly stolen from obfs4proxy.
package http

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

// Dial dials the requested destination via the provided HTTP CONNECT proxy.
func Dial(proxyNet, proxyAddr, targetAddr string) (net.Conn, error) {
	c, err := net.Dial(proxyNet, proxyAddr)
	if err != nil {
		return nil, err
	}

	conn := new(httpConn)
	conn.httpConn = httputil.NewClientConn(c, nil)
	conn.remoteAddr = nil // XXX: remove this and just make it return an error.

	// HACK HACK HACK HACK.  http.ReadRequest also does this.
	reqURL, err := url.Parse("http://" + targetAddr)
	if err != nil {
		conn.httpConn.Close()
		return nil, err
	}
	reqURL.Scheme = ""

	hReq, err := http.NewRequest("CONNECT", reqURL.String(), nil)
	if err != nil {
		conn.httpConn.Close()
		return nil, err
	}
	hReq.Close = false
	hReq.Header.Set("User-Agent", "")

	resp, err := conn.httpConn.Do(hReq)
	if err != nil && err != httputil.ErrPersistEOF {
		conn.httpConn.Close()
		return nil, err
	}
	if resp.StatusCode != 200 {
		conn.httpConn.Close()
		return nil, fmt.Errorf("proxy error: %s", resp.Status)
	}

	conn.hijackedConn, conn.staleReader = conn.httpConn.Hijack()
	return conn, nil
}

type httpConn struct {
	remoteAddr   *net.TCPAddr
	httpConn     *httputil.ClientConn
	hijackedConn net.Conn
	staleReader  *bufio.Reader
}

func (c *httpConn) Read(b []byte) (int, error) {
	if c.staleReader != nil {
		if c.staleReader.Buffered() > 0 {
			return c.staleReader.Read(b)
		}
		c.staleReader = nil
	}
	return c.hijackedConn.Read(b)
}

func (c *httpConn) Write(b []byte) (int, error) {
	return c.hijackedConn.Write(b)
}

func (c *httpConn) Close() error {
	return c.hijackedConn.Close()
}

func (c *httpConn) LocalAddr() net.Addr {
	return c.hijackedConn.LocalAddr()
}

func (c *httpConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *httpConn) SetDeadline(t time.Time) error {
	return c.hijackedConn.SetDeadline(t)
}

func (c *httpConn) SetReadDeadline(t time.Time) error {
	return c.hijackedConn.SetReadDeadline(t)
}

func (c *httpConn) SetWriteDeadline(t time.Time) error {
	return c.hijackedConn.SetWriteDeadline(t)
}
