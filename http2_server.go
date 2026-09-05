package mitmproxy

import (
	"context"
	"errors"
	"net"
	"sync"

	http "github.com/josexy/xhttp"
)

// singleConnListener lets xhttp serve an already accepted connection. Its
// accept loop is released when that connection reaches a terminal state.
type singleConnListener struct {
	mu     sync.Mutex
	conn   net.Conn
	addr   net.Addr
	closed chan struct{}
	once   sync.Once
}

func newSingleConnListener(conn net.Conn) *singleConnListener {
	return &singleConnListener{
		conn:   conn,
		addr:   conn.LocalAddr(),
		closed: make(chan struct{}),
	}
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if l.conn != nil {
		conn := l.conn
		l.conn = nil
		l.mu.Unlock()
		return conn, nil
	}
	l.mu.Unlock()

	<-l.closed
	return nil, net.ErrClosed
}

func (l *singleConnListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *singleConnListener) Addr() net.Addr { return l.addr }

func serveHTTP2Conn(ctx context.Context, conn net.Conn, handler http.Handler, cfg *runtimeConfig, tlsMode bool) error {
	protocols := &http.Protocols{}
	if tlsMode {
		protocols.SetHTTP2(true)
	} else {
		protocols.SetUnencryptedHTTP2(true)
	}

	listener := newSingleConnListener(conn)
	terminal := make(chan struct{})
	var terminalOnce sync.Once
	server := &http.Server{
		Handler:   handler,
		Protocols: protocols,
		BaseContext: func(net.Listener) context.Context {
			return ctx
		},
		ConnState: func(_ net.Conn, state http.ConnState) {
			if state == http.StateClosed || state == http.StateHijacked {
				terminalOnce.Do(func() { close(terminal) })
				_ = listener.Close()
			}
		},
	}
	if cfg != nil {
		server.IdleTimeout = cfg.state.idleConnTimeout
	}

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
			_ = listener.Close()
		case <-terminal:
		case <-stop:
		}
	}()

	err := server.Serve(listener)
	if errors.Is(err, net.ErrClosed) || errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
