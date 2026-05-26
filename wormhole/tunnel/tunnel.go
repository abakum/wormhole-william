package tunnel

import (
	"context"
	"io"
	"net"
	"sync"
)

type Tunnel struct {
	session *Session
	ready   chan struct{}
}

func NewTunnel(session *Session) *Tunnel {
	t := &Tunnel{
		session: session,
		ready:   make(chan struct{}),
	}
	close(t.ready)
	return t
}

func (t *Tunnel) Ready() <-chan struct{} {
	return t.ready
}

func (t *Tunnel) Dial(ctx context.Context, remoteAddr string) (net.Conn, error) {
	return t.session.Dial(ctx, remoteAddr)
}

func (t *Tunnel) Listen() (net.Listener, error) {
	return t.session.Listen(), nil
}

func (t *Tunnel) Forward(ctx context.Context, localAddr, remoteAddr string) error {
	ln, err := net.Listen("tcp", localAddr)
	if err != nil {
		return err
	}
	defer ln.Close()

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go func(localConn net.Conn) {
			defer localConn.Close()
			tunnelConn, err := t.Dial(ctx, remoteAddr)
			if err != nil {
				return
			}
			defer tunnelConn.Close()
			Proxy(localConn, tunnelConn)
		}(conn)
	}
}

func (t *Tunnel) Serve(ctx context.Context, localAddr string) error {
	ln := t.session.Listen()
	defer ln.Close()

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		tunnelConn, err := ln.Accept()
		if err != nil {
			return err
		}
		go func(tc net.Conn) {
			defer tc.Close()
			localConn, err := net.Dial("tcp", localAddr)
			if err != nil {
				return
			}
			defer localConn.Close()
			Proxy(localConn, tc)
		}(tunnelConn)
	}
}

func (t *Tunnel) Close() error {
	return t.session.Close()
}

func Proxy(a, b net.Conn) {
	var once sync.Once
	done := make(chan struct{})

	go func() {
		io.Copy(a, b)
		once.Do(func() { close(done) })
	}()

	go func() {
		io.Copy(b, a)
		once.Do(func() { close(done) })
	}()

	<-done
	a.Close()
	b.Close()
}
