package mitmproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/josexy/mitmproxy-go/metadata"
)

type singleConnTransport struct {
	hostport     string
	dialFn       func(ctx context.Context, network, addr string) (net.Conn, error)
	idleTimeout  time.Duration
	disableHTTP2 bool

	mu         sync.Mutex
	clientConn *http.ClientConn
	closed     bool
}

func newTransport(
	hostport string,
	dialFn func(ctx context.Context, network, addr string) (net.Conn, error),
	idleConnTimeout time.Duration,
	disableHTTP2 bool,
) *singleConnTransport {
	return &singleConnTransport{
		hostport:     hostport,
		dialFn:       dialFn,
		idleTimeout:  idleConnTimeout,
		disableHTTP2: disableHTTP2,
	}
}

func (t *singleConnTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clientConn, reused, err := t.getClientConn(req.Context(), req)
	if err != nil {
		return nil, err
	}
	if md, ok := metadata.FromContext(req.Context()); ok {
		md.SetConnectionReused(reused)
	}
	resp, err := clientConn.RoundTrip(req)
	if err != nil {
		_ = t.Close()
	}
	return resp, err
}

func (t *singleConnTransport) Close() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	clientConn := t.clientConn
	t.clientConn = nil
	t.mu.Unlock()

	if clientConn != nil {
		return clientConn.Close()
	}
	return nil
}

func (t *singleConnTransport) getClientConn(ctx context.Context, req *http.Request) (*http.ClientConn, bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil, false, net.ErrClosed
	}
	if t.clientConn != nil {
		return t.clientConn, true, nil
	}

	scheme := req.URL.Scheme
	if scheme == "" {
		return nil, false, errors.New("request URL scheme is empty")
	}
	if scheme != "http" && scheme != "https" {
		return nil, false, fmt.Errorf("unsupported request URL scheme %q", scheme)
	}

	baseTransport := &http.Transport{
		DialContext:        t.dialFn,
		DialTLSContext:     t.dialFn,
		DisableCompression: true,
		IdleConnTimeout:    t.idleTimeout,
		Protocols:          protocolsForRequest(scheme, req.ProtoMajor, t.disableHTTP2),
	}
	clientConn, err := baseTransport.NewClientConn(ctx, scheme, t.hostport)
	if err != nil {
		return nil, false, err
	}
	t.clientConn = clientConn
	return clientConn, false, nil
}

func protocolsForRequest(scheme string, protoMajor int, disableHTTP2 bool) *http.Protocols {
	protos := &http.Protocols{}
	switch {
	case scheme == "http" && protoMajor == 2 && !disableHTTP2:
		protos.SetUnencryptedHTTP2(true)
	case scheme == "https":
		protos.SetHTTP1(true)
		if !disableHTTP2 {
			protos.SetHTTP2(true)
		}
	default:
		protos.SetHTTP1(true)
	}
	return protos
}
