package mitmproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/textproto"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

type singleConnTransport struct {
	hostport     string
	dialFn       func(ctx context.Context, network, addr string) (net.Conn, error)
	idleTimeout  time.Duration
	disableHTTP2 bool

	mu         sync.Mutex
	clientConn *http.ClientConn
	retired    []*http.ClientConn
	upstream   string
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
	for attempt := 0; ; attempt++ {
		clientConn, err := t.getClientConn(req.Context(), req)
		if err != nil {
			return nil, err
		}
		resp, err := clientConn.RoundTrip(req)
		if err == nil {
			return resp, nil
		}
		discard := shouldDiscardClientConnAfterRoundTripError(req.Context(), clientConn, err)
		if discard {
			t.discardClientConn(clientConn, shouldCloseDiscardedClientConn(clientConn, err))
		}
		if attempt == 0 && discard {
			nextReq, ok := replayableRequest(req)
			if ok {
				req = nextReq
				continue
			}
		}
		return nil, err
	}
}

func shouldDiscardClientConnAfterRoundTripError(ctx context.Context, clientConn *http.ClientConn, err error) bool {
	if err == nil {
		return false
	}
	if clientConn.Err() != nil {
		return true
	}
	if isRequestCanceledRoundTripError(ctx, err) {
		return false
	}
	return isClientConnUnusableRoundTripError(err)
}

func replayableRequest(req *http.Request) (*http.Request, bool) {
	if !isReplayableRequest(req) {
		return nil, false
	}
	if req.Body == nil || req.Body == http.NoBody {
		return req, true
	}
	if req.GetBody == nil {
		return nil, false
	}
	next := req.Clone(req.Context())
	body, err := req.GetBody()
	if err != nil {
		return nil, false
	}
	next.Body = body
	return next, true
}

func isReplayableRequest(req *http.Request) bool {
	if req == nil {
		return false
	}
	switch req.Method {
	case "", http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	}
	return headerHasKey(req.Header, "Idempotency-Key") || headerHasKey(req.Header, "X-Idempotency-Key")
}

func headerHasKey(header http.Header, key string) bool {
	if header == nil {
		return false
	}
	canonical := textproto.CanonicalMIMEHeaderKey(key)
	if _, ok := header[canonical]; ok {
		return true
	}
	for k := range header {
		if strings.EqualFold(k, key) {
			return true
		}
	}
	return false
}

func isRequestCanceledRoundTripError(ctx context.Context, err error) bool {
	if ctx != nil && ctx.Err() != nil {
		return true
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "request canceled") ||
		strings.Contains(msg, "context canceled") ||
		strings.Contains(msg, "context deadline exceeded")
}

func isClientConnUnusableRoundTripError(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "client conn not usable") ||
		strings.Contains(msg, "client conn is closed") ||
		strings.Contains(msg, "use of closed network connection") ||
		strings.Contains(msg, "server's graceful shutdown goaway")
}

func shouldCloseDiscardedClientConn(clientConn *http.ClientConn, err error) bool {
	if clientConn.Err() != nil {
		return true
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "client conn is closed") ||
		strings.Contains(msg, "use of closed network connection") {
		return true
	}
	return clientConn.InFlight() == 0
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
	retired := t.retired
	t.retired = nil
	t.mu.Unlock()

	if clientConn != nil {
		_ = clientConn.Close()
	}
	for _, conn := range retired {
		_ = conn.Close()
	}
	return nil
}

func (t *singleConnTransport) setNegotiatedProtocol(proto string) {
	t.mu.Lock()
	t.upstream = proto
	t.mu.Unlock()
}

func (t *singleConnTransport) discardClientConn(clientConn *http.ClientConn, closeConn bool) {
	t.mu.Lock()
	if t.clientConn != clientConn {
		t.mu.Unlock()
		return
	}
	t.clientConn = nil
	if !closeConn {
		t.retired = append(t.retired, clientConn)
	}
	t.mu.Unlock()

	if closeConn {
		_ = clientConn.Close()
	} else {
		t.watchRetiredClientConn(clientConn)
	}
}

func (t *singleConnTransport) watchRetiredClientConn(clientConn *http.ClientConn) {
	clientConn.SetStateHook(func(cc *http.ClientConn) {
		if cc.Err() != nil || cc.InFlight() == 0 {
			t.closeRetiredClientConn(cc)
		}
	})
	if clientConn.Err() != nil || clientConn.InFlight() == 0 {
		t.closeRetiredClientConn(clientConn)
	}
}

func (t *singleConnTransport) closeRetiredClientConn(clientConn *http.ClientConn) {
	t.mu.Lock()
	idx := -1
	for i, retired := range t.retired {
		if retired == clientConn {
			idx = i
			break
		}
	}
	if idx < 0 {
		t.mu.Unlock()
		return
	}
	t.retired = append(t.retired[:idx], t.retired[idx+1:]...)
	t.mu.Unlock()

	clientConn.SetStateHook(nil)
	_ = clientConn.Close()
}

func (t *singleConnTransport) getClientConn(ctx context.Context, req *http.Request) (*http.ClientConn, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil, net.ErrClosed
	}
	if t.clientConn != nil {
		return t.clientConn, nil
	}

	scheme := req.URL.Scheme
	if scheme == "" {
		return nil, errors.New("request URL scheme is empty")
	}
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("unsupported request URL scheme %q", scheme)
	}

	connScheme, protos := clientConnSchemeAndProtocols(scheme, req.ProtoMajor, t.disableHTTP2, t.upstream)
	baseTransport := &http.Transport{
		DialContext:        t.dialFn,
		DialTLSContext:     t.dialFn,
		DisableCompression: true,
		IdleConnTimeout:    t.idleTimeout,
		Protocols:          protos,
	}
	clientConn, err := baseTransport.NewClientConn(ctx, connScheme, t.hostport)
	if err != nil {
		return nil, err
	}
	t.clientConn = clientConn
	return clientConn, nil
}

func clientConnSchemeAndProtocols(scheme string, protoMajor int, disableHTTP2 bool, negotiatedProtocol string) (string, *http.Protocols) {
	if scheme == "https" {
		switch negotiatedProtocol {
		case http2.NextProtoTLS:
			if !disableHTTP2 {
				return "http", protocolsForExistingHTTP2Conn()
			}
		case "http/1.1":
			return "http", protocolsForHTTP1()
		}
	}
	return scheme, protocolsForRequest(scheme, protoMajor, disableHTTP2)
}

func protocolsForRequest(scheme string, protoMajor int, disableHTTP2 bool) *http.Protocols {
	switch {
	case scheme == "http" && protoMajor == 2 && !disableHTTP2:
		return protocolsForExistingHTTP2Conn()
	case scheme == "https":
		protos := protocolsForHTTP1()
		if !disableHTTP2 {
			protos.SetHTTP2(true)
		}
		return protos
	default:
		return protocolsForHTTP1()
	}
}

func protocolsForHTTP1() *http.Protocols {
	protos := &http.Protocols{}
	protos.SetHTTP1(true)
	return protos
}

func protocolsForExistingHTTP2Conn() *http.Protocols {
	protos := &http.Protocols{}
	protos.SetUnencryptedHTTP2(true)
	return protos
}
