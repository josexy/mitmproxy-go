package mitmproxy

import (
	"bytes"
	"context"
	"crypto/x509/pkix"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/josexy/mitmproxy-go/internal/cert"
	"github.com/josexy/mitmproxy-go/metadata"
)

type flushingResponseWriter struct {
	header  http.Header
	body    bytes.Buffer
	flushes int
}

func (w *flushingResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *flushingResponseWriter) Write(data []byte) (int, error) { return w.body.Write(data) }
func (w *flushingResponseWriter) WriteHeader(int)                {}
func (w *flushingResponseWriter) Flush()                         { w.flushes++ }

func TestForwardStreamBodyFlushPolicy(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 96*1024)
	handler := &mitmProxyHandler{}

	fixed := &flushingResponseWriter{}
	if err := handler.forwardStreamBody(fixed, bytes.NewReader(payload), false); err != nil {
		t.Fatal(err)
	}
	if fixed.flushes != 0 || !bytes.Equal(fixed.body.Bytes(), payload) {
		t.Fatalf("fixed response flushes = %d, bytes = %d", fixed.flushes, fixed.body.Len())
	}

	streaming := &flushingResponseWriter{}
	if err := handler.forwardStreamBody(streaming, bytes.NewReader(payload), true); err != nil {
		t.Fatal(err)
	}
	if streaming.flushes == 0 {
		t.Fatal("streaming response was not flushed")
	}
}

func TestHTTP2HandlerRejectsChangedAuthority(t *testing.T) {
	cfg := testRuntimeConfig(t)
	ctx := newHTTP2HandlerTestContext(cfg, "allowed.example:443", nil)
	handler := (&mitmProxyHandler{}).serveHTTP2Handler(ctx)
	req := httptest.NewRequest(http.MethodGet, "https://blocked.example/resource", nil)
	req.Host = "blocked.example"
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusMisdirectedRequest {
		t.Fatalf("status = %d; want %d", recorder.Code, http.StatusMisdirectedRequest)
	}
}

func TestHTTP2HandlerRejectsAuthorityWithImplicitDifferentPort(t *testing.T) {
	cfg := testRuntimeConfig(t)
	ctx := newHTTP2HandlerTestContext(cfg, "allowed.example:8443", nil)
	handler := (&mitmProxyHandler{}).serveHTTP2Handler(ctx)
	req := httptest.NewRequest(http.MethodGet, "https://allowed.example/resource", nil)
	req.Host = "allowed.example"
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusMisdirectedRequest {
		t.Fatalf("status = %d; want %d", recorder.Code, http.StatusMisdirectedRequest)
	}
}

func TestRequestMatchesHostportUsesWSSDefaultPort(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://allowed.example/socket", nil)
	req.Host = "allowed.example"
	req.TLS = nil
	req.URL.Scheme = "wss"
	if !requestMatchesHostport(req, "allowed.example:443") {
		t.Fatal("WSS authority without an explicit port did not match port 443")
	}
}

func TestParseHostPortRejectsMalformedTargets(t *testing.T) {
	tests := []*http.Request{
		{Method: http.MethodConnect, RequestURI: "example.test"},
		{Method: http.MethodConnect, RequestURI: "["},
		{Method: http.MethodConnect, RequestURI: "example.test:70000"},
		{Method: http.MethodGet, Host: "::1"},
	}
	for _, req := range tests {
		if got, err := ParseHostPort(req); err == nil {
			t.Fatalf("ParseHostPort(%q) = %q; want error", req.RequestURI+req.Host, got)
		}
	}
	if got, err := ParseHostPort(&http.Request{Method: http.MethodGet, Host: "[::1]"}); err != nil || got != "[::1]:80" {
		t.Fatalf("IPv6 host = %q, %v; want [::1]:80", got, err)
	}
}

func TestPassthroughTunnelRequiresInitialActivity(t *testing.T) {
	client, local := net.Pipe()
	remote, upstream := net.Pipe()
	defer client.Close()
	defer upstream.Close()
	ctx := AppendToRequestContext(context.Background(), ReqContext{})
	done := make(chan error, 1)
	go func() {
		done <- (&mitmProxyHandler{}).passthroughTunnel(ctx, local, remote, 30*time.Millisecond)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("inactive passthrough tunnel did not time out")
	}
}

func TestWebsocketInterceptorReturnCancelsRelayContext(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	returned := make(chan struct{})
	startWebsocketInterceptor(ctx, cancel, func(context.Context, *http.Request, *http.Response, WebsocketFramesWatcher) {
		close(returned)
	}, nil, nil, &wsFramesWatcherImpl{framesCh: make(chan WsFrame)})

	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("interceptor did not run")
	}
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("interceptor return did not cancel relay context")
	}
	if !errors.Is(context.Cause(ctx), io.EOF) {
		t.Fatalf("cause = %v; want io.EOF", context.Cause(ctx))
	}
}

func TestHTTPKeepAliveWithoutIdleTimeoutIsNotLimitedByHandshakeTimeout(t *testing.T) {
	cfg := testRuntimeConfig(t)
	cfg.state.disableHTTP2 = true
	cfg.state.handshakeTimeout = 20 * time.Millisecond
	cfg.state.idleConnTimeout = 0
	ctx := AppendToRequestContext(context.Background(), ReqContext{Hostport: "example.test:80"})
	ctx = context.WithValue(ctx, connContextKey, &biConnContext{config: cfg})
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	type result struct {
		ctx context.Context
		err error
	}
	resultCh := make(chan result, 1)
	go func() {
		nextCtx, _, _, err := (&mitmProxyHandler{}).distinguishHTTPRequest(ctx, newFakeHttpResponseWriter(server), nil, false, false)
		resultCh <- result{ctx: nextCtx, err: err}
	}()

	time.Sleep(50 * time.Millisecond)
	if _, err := io.WriteString(client, "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-resultCh:
		if got.err != nil {
			t.Fatalf("read failed after handshake timeout: %v", got.err)
		}
		reqCtx, ok := FromRequestContext(got.ctx)
		if !ok || reqCtx.Request == nil {
			t.Fatal("request context was not populated")
		}
	case <-time.After(time.Second):
		t.Fatal("keep-alive request was not read")
	}
}

func TestPassthroughTunnelClearsDeadlineAfterActivity(t *testing.T) {
	client, local := net.Pipe()
	remote, upstream := net.Pipe()
	defer client.Close()
	defer upstream.Close()
	ctx := AppendToRequestContext(context.Background(), ReqContext{})
	done := make(chan error, 1)
	go func() {
		done <- (&mitmProxyHandler{}).passthroughTunnel(ctx, local, remote, 30*time.Millisecond)
	}()

	go func() { _, _ = client.Write([]byte("ping")) }()
	request := make([]byte, 4)
	if _, err := io.ReadFull(upstream, request); err != nil || string(request) != "ping" {
		t.Fatalf("upstream read = %q, %v", request, err)
	}
	time.Sleep(50 * time.Millisecond)
	go func() { _, _ = upstream.Write([]byte("pong")) }()
	response := make([]byte, 4)
	if _, err := io.ReadFull(client, response); err != nil || string(response) != "pong" {
		t.Fatalf("client read = %q, %v", response, err)
	}
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("passthrough tunnel did not close")
	}
}

func TestHTTP2HandlerReturnsBadGatewayOnRoundTripFailure(t *testing.T) {
	cfg := testRuntimeConfig(t)
	transport := newTransport("allowed.example:443", func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("dial failed")
	}, time.Second, false)
	ctx := newHTTP2HandlerTestContext(cfg, "allowed.example:443", transport)
	handler := (&mitmProxyHandler{}).serveHTTP2Handler(ctx)
	req := httptest.NewRequest(http.MethodGet, "https://allowed.example/resource", nil)
	req.Host = "allowed.example"
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("status = %d; want %d", recorder.Code, http.StatusBadGateway)
	}
}

func testRuntimeConfig(t *testing.T) *runtimeConfig {
	t.Helper()
	cfg, err := buildRuntimeConfig(newRuntimeConfigStateFromOptions(newOptions()))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func newHTTP2HandlerTestContext(cfg *runtimeConfig, hostport string, transport *singleConnTransport) context.Context {
	ctx := AppendToRequestContext(context.Background(), ReqContext{Hostport: hostport})
	ctx = metadata.AppendToContext(ctx, metadata.NewMD())
	return context.WithValue(ctx, connContextKey, &biConnContext{
		config:    cfg,
		transport: transport,
	})
}

func TestDialTCPWithMetadataRefreshesCurrentAndBaseRemoteMetadata(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	acceptedCh := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			acceptedCh <- conn
		}
	}()

	baseMD := metadata.NewMD()
	streamMD := metadata.NewMD()
	connCtx := &biConnContext{
		config: &runtimeConfig{
			proxyDialer: NewProxyDialer(nil, &net.Dialer{Timeout: time.Second}),
		},
		baseMetadata: baseMD,
	}

	ctx := metadata.AppendToContext(context.Background(), streamMD)
	conn, err := connCtx.dialTCPWithMetadata(ctx, ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	select {
	case accepted := <-acceptedCh:
		defer accepted.Close()
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for accepted connection")
	}

	wantAddr := metadata.ConnectionAddrInfo{
		SourceAddr:      getLocalAddrPortFromConn(conn),
		DestinationAddr: getRemoteAddrPortFromConn(conn),
	}
	assertRemoteMetadataRefreshed(t, "stream", streamMD.MD(), wantAddr)
	assertRemoteMetadataRefreshed(t, "base", baseMD.MD(), wantAddr)
}

func assertRemoteMetadataRefreshed(t *testing.T, name string, md metadata.MD, wantAddr metadata.ConnectionAddrInfo) {
	t.Helper()
	if md.RemoteConnectionEstablishedTs.IsZero() {
		t.Fatalf("%s remote connection established timestamp was not set", name)
	}
	if md.SocketConnectStartTs.IsZero() || md.SocketConnectCompletedTs.IsZero() {
		t.Fatalf("%s socket timing was not set: %#v", name, md)
	}
	if md.RemoteAddrInfo != wantAddr {
		t.Fatalf("%s remote addr = %#v, want %#v", name, md.RemoteAddrInfo, wantAddr)
	}
}

func TestCleanupClosesActiveClientConnections(t *testing.T) {
	caCertPath, caKeyPath := writeTestCA(t)
	upstreamStarted := make(chan struct{})
	upstreamRelease := make(chan struct{})
	var upstreamRequests atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if upstreamRequests.Add(1) == 1 {
			close(upstreamStarted)
		}
		<-upstreamRelease
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	defer close(upstreamRelease)

	handler, err := NewMitmProxyHandler(
		WithCACertPath(caCertPath),
		WithCAKeyPath(caKeyPath),
	)
	if err != nil {
		t.Fatal(err)
	}

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodGet, upstream.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()

	serveDone := make(chan error, 1)
	go func() {
		serveDone <- handler.Serve(AppendToRequestContext(context.Background(), ReqContext{
			Hostport: targetURL.Host,
			Request:  req,
		}), proxyConn)
	}()

	select {
	case <-upstreamStarted:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for upstream request")
	}

	handler.Cleanup()

	if err := clientConn.SetReadDeadline(time.Now().Add(time.Second)); err == nil {
		if _, err := clientConn.Read(make([]byte, 1)); err == nil {
			t.Fatal("client connection remained open after Cleanup")
		}
	}

	select {
	case <-serveDone:
	case <-time.After(time.Second):
		t.Fatal("Serve did not exit after Cleanup")
	}
	if got := upstreamRequests.Load(); got != 1 {
		t.Fatalf("upstream request count = %d, want 1; cleanup should not retry", got)
	}
}

func writeTestCA(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	tmpDir := t.TempDir()
	ca, err := cert.NewCaBuilder().
		Subject(pkix.Name{CommonName: "example.ca.test"}).
		ValidateDays(1).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	keyPem, certPem := ca.Pem()
	certPath = filepath.Join(tmpDir, "ca.crt")
	keyPath = filepath.Join(tmpDir, "ca.key")
	if err := os.WriteFile(certPath, certPem, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPem, 0644); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}
