package proxy

import (
	"bufio"
	"io"
	"net"
	"sync"
	"time"
)

// bufConn reads through the bufio.Reader left over from hijacking, so bytes
// the client sent right after CONNECT (often the TLS ClientHello) aren't lost.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (c *bufConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

// tunnel copies bytes both ways until both directions finish, or one finishes
// and the other stays idle for a while.
func tunnel(a, b net.Conn) {
	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		} else {
			dst.Close()
		}
		done <- struct{}{}
	}
	go pipe(a, b)
	go pipe(b, a)
	<-done
	select {
	case <-done:
	case <-time.After(time.Minute):
	}
	a.Close()
	b.Close()
}

// oneConnListener hands a single connection to an http.Server and then
// blocks until that connection is closed, so Serve returns when it's done.
type oneConnListener struct {
	conn   net.Conn
	done   chan struct{}
	mu     sync.Mutex
	served bool
}

func newOneConnListener(c net.Conn) *oneConnListener {
	return &oneConnListener{conn: c, done: make(chan struct{})}
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if !l.served {
		l.served = true
		l.mu.Unlock()
		return &notifyConn{Conn: l.conn, done: l.done}, nil
	}
	l.mu.Unlock()
	<-l.done
	return nil, net.ErrClosed
}

func (l *oneConnListener) Close() error   { return nil }
func (l *oneConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

type notifyConn struct {
	net.Conn
	done chan struct{}
	once sync.Once
}

func (c *notifyConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.done) })
	return err
}
