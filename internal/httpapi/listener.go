package httpapi

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const tlsHandshakeRecord = 0x16

// SplitTLS serves HTTPS and plain HTTP on one port. It returns TLS
// connections as *tls.Conn, which http.Server handles as HTTPS (with HTTP/2
// when cfg offers "h2"), and every other connection as is, for the handler
// to redirect (see Options.RequireTLS). A connection that sends nothing
// within timeout is closed.
func SplitTLS(ln net.Listener, cfg *tls.Config, timeout time.Duration) net.Listener {
	s := &splitListener{Listener: ln, cfg: cfg, timeout: timeout, conns: make(chan net.Conn), done: make(chan struct{})}
	go s.acceptLoop()
	return s
}

type splitListener struct {
	net.Listener
	cfg     *tls.Config
	timeout time.Duration
	conns   chan net.Conn
	done    chan struct{}
	once    sync.Once
	err     error
}

func (s *splitListener) Accept() (net.Conn, error) {
	select {
	case c := <-s.conns:
		return c, nil
	case <-s.done:
		return nil, s.err
	}
}

func (s *splitListener) Close() error {
	s.stop(net.ErrClosed)
	return s.Listener.Close()
}

func (s *splitListener) stop(err error) {
	s.once.Do(func() {
		s.err = err
		close(s.done)
	})
}

func (s *splitListener) acceptLoop() {
	var delay time.Duration
	for {
		c, err := s.Listener.Accept()
		if err != nil {
			if isTemporary(err) {
				delay = min(max(2*delay, 5*time.Millisecond), time.Second)
				select {
				case <-time.After(delay):
					continue
				case <-s.done:
					return
				}
			}
			s.stop(err)
			return
		}
		delay = 0
		// Sniffed concurrently, so a client that sends nothing cannot hold up
		// the others.
		go s.sniff(c)
	}
}

func isTemporary(err error) bool {
	var t interface{ Temporary() bool }
	return errors.As(err, &t) && t.Temporary()
}

func (s *splitListener) sniff(c net.Conn) {
	var first [1]byte
	if s.timeout > 0 {
		c.SetReadDeadline(time.Now().Add(s.timeout))
	}
	if _, err := io.ReadFull(c, first[:]); err != nil {
		c.Close()
		return
	}
	c.SetReadDeadline(time.Time{})

	var out net.Conn = &prefixConn{Conn: c, prefix: first[:]}
	if first[0] == tlsHandshakeRecord {
		out = tls.Server(out, s.cfg)
	}
	select {
	case s.conns <- out:
	case <-s.done:
		c.Close()
	}
}

type prefixConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

// CloseWrite lets net/http finish a plain response before closing, so the
// client reads it instead of a reset.
func (c *prefixConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
