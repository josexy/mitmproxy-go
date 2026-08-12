package mitmproxy

import (
	"bytes"
	"context"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"github.com/josexy/xhttp"
	"github.com/josexy/xhttp/httptest"
	"io"
	"net"
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

func TestBiConnContextTransportSwap(t *testing.T) {
	connCtx := &biConnContext{}
	first := &singleConnTransport{hostport: "first.test:443"}
	second := &singleConnTransport{hostport: "second.test:443"}

	if previous := connCtx.setTransport(first); previous != nil {
		t.Fatalf("initial previous transport = %p, want nil", previous)
	}
	if current := connCtx.currentTransport(); current != first {
		t.Fatalf("current transport = %p, want %p", current, first)
	}
	if previous := connCtx.setTransport(second); previous != first {
		t.Fatalf("replaced transport = %p, want %p", previous, first)
	}
	if previous := connCtx.setTransport(nil); previous != second {
		t.Fatalf("cleared transport = %p, want %p", previous, second)
	}
	if current := connCtx.currentTransport(); current != nil {
		t.Fatalf("transport after clear = %p, want nil", current)
	}
}

type immediateReadErrorConn struct {
	err error
}

func (c *immediateReadErrorConn) Read([]byte) (int, error)         { return 0, c.err }
func (c *immediateReadErrorConn) Write(data []byte) (int, error)   { return len(data), nil }
func (c *immediateReadErrorConn) Close() error                     { return nil }
func (c *immediateReadErrorConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *immediateReadErrorConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *immediateReadErrorConn) SetDeadline(time.Time) error      { return nil }
func (c *immediateReadErrorConn) SetReadDeadline(time.Time) error  { return nil }
func (c *immediateReadErrorConn) SetWriteDeadline(time.Time) error { return nil }

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

func TestRawTCPTunnelSourceForRequest(t *testing.T) {
	tests := []struct {
		name string
		req  ReqContext
		want RawTCPTunnelSource
	}{
		{name: "direct", want: RawTCPTunnelSourceDirect},
		{name: "http connect", req: ReqContext{HttpConnectMethod: true}, want: RawTCPTunnelSourceHTTPConnect},
		{name: "socks5", req: ReqContext{Socks5Connect: true}, want: RawTCPTunnelSourceSOCKS5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := rawTCPTunnelSourceForRequest(tt.req); got != tt.want {
				t.Fatalf("source = %v; want %v", got, tt.want)
			}
		})
	}
}

func TestSnapshotRawTCPConnectRequestIsBodylessAndIsolated(t *testing.T) {
	originalBody := io.NopCloser(bytes.NewBufferString("tunnel payload"))
	original := &http.Request{
		Method:     http.MethodConnect,
		URL:        &url.URL{Host: "example.test:443"},
		RequestURI: "example.test:443",
		Host:       "example.test:443",
		Header:     http.Header{"X-Test": {"original"}},
		Body:       originalBody,
		GetBody: func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(nil)), nil
		},
		Cancel: make(chan struct{}),
	}

	snapshot := snapshotRawTCPConnectRequest(original)
	if snapshot == original || snapshot.Method != original.Method || snapshot.RequestURI != original.RequestURI ||
		snapshot.Host != original.Host || snapshot.Header.Get("X-Test") != "original" {
		t.Fatalf("CONNECT request snapshot = %#v; want isolated copy of %#v", snapshot, original)
	}
	if snapshot.Body != http.NoBody || snapshot.GetBody != nil || snapshot.Cancel != nil {
		t.Fatalf("snapshot body handles = Body:%#v GetBody-nil:%t Cancel-nil:%t; want NoBody, true, true", snapshot.Body, snapshot.GetBody == nil, snapshot.Cancel == nil)
	}

	snapshot.Header.Set("X-Test", "changed")
	snapshot.URL.Host = "changed.example:1"
	if original.Header.Get("X-Test") != "original" || original.URL.Host != "example.test:443" || original.Body != originalBody {
		t.Fatalf("snapshot mutation changed original request: %#v", original)
	}
}

func TestServeReportsDirectRawTCPTunnelOnce(t *testing.T) {
	echo := startEchoServer(t)
	certPath, keyPath := writeTestCA(t)
	events := make(chan RawTCPTunnelEvent, 2)
	eventMetadata := make(chan metadata.MD, 1)
	handler, err := NewMitmProxyHandler(
		WithCACertPath(certPath),
		WithCAKeyPath(keyPath),
		WithDisableProxy(),
		WithRawTCPInterceptor(func(ctx context.Context, event RawTCPTunnelEvent) {
			if md, ok := metadata.FromContext(ctx); ok {
				eventMetadata <- md.MD()
			} else {
				eventMetadata <- metadata.MD{}
			}
			events <- event
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Cleanup()

	client, proxy := net.Pipe()
	defer client.Close()
	if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- handler.Serve(AppendToRequestContext(context.Background(), ReqContext{Hostport: echo}), proxy)
	}()

	payload := []byte{0xef, 0x00, 0x01, 0xff, 'r', 'a', 'w'}
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	echoed := make([]byte, len(payload))
	if _, err := io.ReadFull(client, echoed); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(echoed, payload) {
		t.Fatalf("direct raw echo = %x; want %x", echoed, payload)
	}
	_ = client.Close()

	var event RawTCPTunnelEvent
	select {
	case event = <-events:
	case <-time.After(time.Second):
		t.Fatal("raw TCP callback was not invoked")
	}
	if event.Hostport != echo || event.Source != RawTCPTunnelSourceDirect || event.TLS || event.Request != nil {
		t.Fatalf("direct raw TCP event = %#v; want host=%q, direct source, plaintext, nil request", event, echo)
	}
	md := <-eventMetadata
	if md.RequestHostport != echo || md.RemoteAddrInfo.DestinationAddr.String() != echo {
		t.Fatalf("raw TCP metadata = %#v; want target %q", md, echo)
	}
	select {
	case serveErr := <-serveDone:
		_ = serveErr
	case <-time.After(time.Second):
		t.Fatal("Serve did not return after direct raw tunnel closed")
	}
	select {
	case duplicate := <-events:
		t.Fatalf("raw TCP callback invoked more than once: %#v", duplicate)
	default:
	}
}

func TestRawTCPInterceptorNotCalledWhenProtocolDetectionFails(t *testing.T) {
	echo := startEchoServer(t)
	certPath, keyPath := writeTestCA(t)

	for _, tt := range []struct {
		name        string
		closeClient bool
	}{
		{name: "timeout"},
		{name: "EOF", closeClient: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var rawEvents atomic.Int32
			handler, err := NewMitmProxyHandler(
				WithCACertPath(certPath),
				WithCAKeyPath(keyPath),
				WithDisableProxy(),
				WithHandshakeTimeout(50*time.Millisecond),
				WithRawTCPInterceptor(func(context.Context, RawTCPTunnelEvent) { rawEvents.Add(1) }),
			)
			if err != nil {
				t.Fatal(err)
			}
			defer handler.Cleanup()

			client, proxy := net.Pipe()
			serveDone := make(chan error, 1)
			go func() {
				serveDone <- handler.Serve(AppendToRequestContext(context.Background(), ReqContext{Hostport: echo}), proxy)
			}()
			if tt.closeClient {
				_ = client.Close()
			} else {
				defer client.Close()
			}

			select {
			case serveErr := <-serveDone:
				if serveErr == nil {
					t.Fatal("Serve succeeded without enough data to classify the tunnel protocol")
				}
			case <-time.After(time.Second):
				t.Fatal("Serve did not return after protocol detection failure")
			}
			if got := rawEvents.Load(); got != 0 {
				t.Fatalf("raw TCP interceptor called %d times after protocol detection failure", got)
			}
		})
	}
}

func TestRelayRawTCPTunnelCallbackIsSynchronousAndRunsOnce(t *testing.T) {
	client, local := net.Pipe()
	remote, upstream := net.Pipe()
	defer client.Close()
	defer upstream.Close()

	events := make(chan RawTCPTunnelEvent, 2)
	releaseCallback := make(chan struct{})
	cfg := testRuntimeConfig(t)
	cfg.state.rawTCPInt = func(_ context.Context, event RawTCPTunnelEvent) {
		events <- event
		<-releaseCallback
	}
	handler := &mitmProxyHandler{}
	connectSnapshot := &http.Request{
		Method:     http.MethodConnect,
		RequestURI: "example.test:443",
		Host:       "example.test:443",
		Header:     make(http.Header),
		Body:       http.NoBody,
	}
	ctx := AppendToRequestContext(context.Background(), ReqContext{
		Hostport:          "example.test:443",
		HttpConnectMethod: true,
	})
	ctx = context.WithValue(ctx, rawTCPConnectRequestContextKey, connectSnapshot)
	ctx = metadata.AppendToContext(ctx, metadata.NewMD())
	ctx = context.WithValue(ctx, connContextKey, &biConnContext{config: cfg})
	done := make(chan error, 1)
	go func() { done <- handler.relayRawTCPTunnel(ctx, local, remote, false) }()

	var event RawTCPTunnelEvent
	select {
	case event = <-events:
	case <-time.After(time.Second):
		t.Fatal("raw TCP callback was not invoked")
	}
	if event.Hostport != "example.test:443" ||
		event.Source != RawTCPTunnelSourceHTTPConnect || event.TLS || event.Request != connectSnapshot {
		t.Fatalf("raw TCP event = %#v; want CONNECT plaintext tunnel metadata and request snapshot", event)
	}

	writeDone := make(chan error, 1)
	go func() {
		_, err := client.Write([]byte("ping"))
		writeDone <- err
	}()
	select {
	case err := <-writeDone:
		close(releaseCallback)
		t.Fatalf("client write completed before raw TCP callback returned: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(releaseCallback)
	payload := make([]byte, 4)
	if _, err := io.ReadFull(upstream, payload); err != nil || string(payload) != "ping" {
		t.Fatalf("upstream payload = %q, %v; want ping", payload, err)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("client write: %v", err)
	}
	_ = client.Close()

	select {
	case err := <-done:
		_ = err
	case <-time.After(time.Second):
		t.Fatal("relay did not return after the client closed")
	}
	select {
	case duplicate := <-events:
		t.Fatalf("raw TCP callback invoked more than once: %#v", duplicate)
	default:
	}
}

func TestRelayRawTCPTunnelPreservesRelayErrorAndCallsInterceptorOnce(t *testing.T) {
	wantErr := errors.New("raw read failed")
	remote, upstream := net.Pipe()
	defer upstream.Close()
	var callbackCount atomic.Int32
	cfg := testRuntimeConfig(t)
	cfg.state.rawTCPInt = func(context.Context, RawTCPTunnelEvent) { callbackCount.Add(1) }
	ctx := AppendToRequestContext(context.Background(), ReqContext{Hostport: "error.example:1"})
	ctx = context.WithValue(ctx, connContextKey, &biConnContext{config: cfg})
	handler := &mitmProxyHandler{}

	gotErr := handler.relayRawTCPTunnel(ctx, &immediateReadErrorConn{err: wantErr}, remote, false)
	if gotErr != wantErr {
		t.Fatalf("relay error = %v; want identical %v", gotErr, wantErr)
	}
	if got := callbackCount.Load(); got != 1 {
		t.Fatalf("raw TCP callback count = %d; want 1", got)
	}
}

func TestRelayRawTCPTunnelUsesConnectionConfigSnapshot(t *testing.T) {
	oldEvents := make(chan RawTCPTunnelEvent, 2)
	newEvents := make(chan RawTCPTunnelEvent, 2)
	oldCfg := testRuntimeConfig(t)
	oldCfg.state.rawTCPInt = func(_ context.Context, event RawTCPTunnelEvent) { oldEvents <- event }
	newCfg := testRuntimeConfig(t)
	newCfg.state.rawTCPInt = func(_ context.Context, event RawTCPTunnelEvent) { newEvents <- event }
	handler := &mitmProxyHandler{}
	handler.config.Store(oldCfg)

	client, local := net.Pipe()
	remote, upstream := net.Pipe()
	defer client.Close()
	defer upstream.Close()
	ctx := AppendToRequestContext(context.Background(), ReqContext{Hostport: "old.example:1"})
	ctx = context.WithValue(ctx, connContextKey, &biConnContext{config: oldCfg})
	done := make(chan error, 1)
	go func() { done <- handler.relayRawTCPTunnel(ctx, local, remote, false) }()
	var oldEvent RawTCPTunnelEvent
	select {
	case oldEvent = <-oldEvents:
	case <-time.After(time.Second):
		t.Fatal("old interceptor was not invoked")
	}
	if oldEvent.Hostport != "old.example:1" {
		t.Fatalf("old interceptor event = %#v; want old.example:1", oldEvent)
	}
	handler.config.Store(newCfg)
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("old-config relay did not return")
	}
	select {
	case event := <-oldEvents:
		t.Fatalf("old interceptor was invoked more than once: %#v", event)
	default:
	}
	select {
	case event := <-newEvents:
		t.Fatalf("new interceptor observed old tunnel event %#v", event)
	default:
	}

	client, local = net.Pipe()
	remote, upstream = net.Pipe()
	defer client.Close()
	defer upstream.Close()
	ctx = AppendToRequestContext(context.Background(), ReqContext{Hostport: "new.example:2"})
	ctx = context.WithValue(ctx, connContextKey, &biConnContext{config: newCfg})
	done = make(chan error, 1)
	go func() { done <- handler.relayRawTCPTunnel(ctx, local, remote, false) }()
	var newEvent RawTCPTunnelEvent
	select {
	case newEvent = <-newEvents:
	case <-time.After(time.Second):
		t.Fatal("new interceptor was not invoked")
	}
	if newEvent.Hostport != "new.example:2" {
		t.Fatalf("new interceptor event = %#v; want new.example:2", newEvent)
	}
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("new-config relay did not return")
	}
	select {
	case event := <-newEvents:
		t.Fatalf("new interceptor was invoked more than once: %#v", event)
	default:
	}
}

func TestRawTCPInterceptorCalledOncePerTunnelConcurrently(t *testing.T) {
	const tunnelCount = 16
	events := make(chan RawTCPTunnelEvent, tunnelCount)
	cfg := testRuntimeConfig(t)
	cfg.state.rawTCPInt = func(_ context.Context, event RawTCPTunnelEvent) { events <- event }
	handler := &mitmProxyHandler{}
	clients := make([]net.Conn, 0, tunnelCount)
	upstreams := make([]net.Conn, 0, tunnelCount)
	done := make(chan error, tunnelCount)
	for index := range tunnelCount {
		client, local := net.Pipe()
		remote, upstream := net.Pipe()
		clients = append(clients, client)
		upstreams = append(upstreams, upstream)
		ctx := AppendToRequestContext(context.Background(), ReqContext{Hostport: fmt.Sprintf("target-%d.example:1", index)})
		ctx = context.WithValue(ctx, connContextKey, &biConnContext{config: cfg})
		go func(tls bool) { done <- handler.relayRawTCPTunnel(ctx, local, remote, tls) }(index%2 == 0)
	}
	defer func() {
		for _, conn := range clients {
			_ = conn.Close()
		}
		for _, conn := range upstreams {
			_ = conn.Close()
		}
	}()

	eventsByHostport := make(map[string]RawTCPTunnelEvent, tunnelCount)
	eventDeadline := time.After(time.Second)
	for range tunnelCount {
		var event RawTCPTunnelEvent
		select {
		case event = <-events:
		case <-eventDeadline:
			t.Fatalf("timeout waiting for raw TCP callbacks; got %d of %d", len(eventsByHostport), tunnelCount)
		}
		if previous, exists := eventsByHostport[event.Hostport]; exists {
			t.Fatalf("hostport %q observed more than once: %#v, %#v", event.Hostport, previous, event)
		}
		eventsByHostport[event.Hostport] = event
	}
	if got := len(eventsByHostport); got != tunnelCount {
		t.Fatalf("raw TCP event target count = %d; want %d", got, tunnelCount)
	}
	for index := range tunnelCount {
		hostport := fmt.Sprintf("target-%d.example:1", index)
		event, ok := eventsByHostport[hostport]
		if !ok {
			t.Fatalf("missing raw TCP callback for %q", hostport)
		}
		if event.Source != RawTCPTunnelSourceDirect || event.TLS != (index%2 == 0) || event.Request != nil {
			t.Fatalf("raw TCP event for %q = %#v; want direct source, tls=%t, nil request", hostport, event, index%2 == 0)
		}
	}
	for _, conn := range clients {
		_ = conn.Close()
	}
	doneDeadline := time.After(time.Second)
	for range tunnelCount {
		select {
		case <-done:
		case <-doneDeadline:
			t.Fatal("timeout waiting for concurrent raw TCP relays to return")
		}
	}
	select {
	case duplicate := <-events:
		t.Fatalf("raw TCP callback invoked more than once for a tunnel: %#v", duplicate)
	default:
	}
}

func TestDetectHTTPProtocolRejectsBinaryFirstByte(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	result := make(chan tunnelProtocol, 1)
	errCh := make(chan error, 1)
	go func() {
		protocol, err := detectHTTPProtocol(newBufConn(server))
		result <- protocol
		errCh <- err
	}()
	go func() { _, _ = client.Write([]byte{0}) }()

	select {
	case protocol := <-result:
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
		if protocol != tunnelProtocolRaw {
			t.Fatalf("protocol = %v; want raw", protocol)
		}
	case <-time.After(time.Second):
		t.Fatal("binary application detection waited for additional bytes")
	}
}

func TestDetectTLSApplicationProtocolUsesServerFirstData(t *testing.T) {
	client, downstream := net.Pipe()
	upstream, server := net.Pipe()
	defer client.Close()
	defer downstream.Close()
	defer upstream.Close()
	defer server.Close()

	greeting := []byte{0x00, 'r', 'e', 'a', 'd', 'y'}
	go func() { _, _ = server.Write(greeting) }()

	protocol, _, bufferedUpstream, err := detectTLSApplicationProtocol(context.Background(), downstream, upstream, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if protocol != tunnelProtocolRaw {
		t.Fatalf("protocol = %v; want raw", protocol)
	}
	replayed := make([]byte, len(greeting))
	if _, err := io.ReadFull(bufferedUpstream, replayed); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(replayed, greeting) {
		t.Fatalf("replayed greeting = %x; want %x", replayed, greeting)
	}
}

func TestDetectTLSApplicationProtocolPreservesClientHTTPRequest(t *testing.T) {
	client, downstream := net.Pipe()
	upstream, server := net.Pipe()
	defer client.Close()
	defer downstream.Close()
	defer upstream.Close()
	defer server.Close()

	request := []byte("GET /raw-check HTTP/1.1\r\nHost: example.test\r\n\r\n")
	go func() { _, _ = client.Write(request) }()

	protocol, bufferedDownstream, _, err := detectTLSApplicationProtocol(context.Background(), downstream, upstream, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if protocol != tunnelProtocolHTTP {
		t.Fatalf("protocol = %v; want HTTP", protocol)
	}
	replayed := make([]byte, len(request))
	if _, err := io.ReadFull(bufferedDownstream, replayed); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(replayed, request) {
		t.Fatalf("replayed request = %q; want %q", replayed, request)
	}
}

func TestDetectTLSApplicationProtocolStopsOnContextCancel(t *testing.T) {
	client, downstream := net.Pipe()
	upstream, server := net.Pipe()
	defer client.Close()
	defer downstream.Close()
	defer upstream.Close()
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	type detectionResult struct {
		err error
	}
	resultCh := make(chan detectionResult, 1)
	go func() {
		_, _, _, err := detectTLSApplicationProtocol(ctx, downstream, upstream, time.Hour)
		resultCh <- detectionResult{err: err}
	}()
	cancel()

	select {
	case result := <-resultCh:
		if !errors.Is(result.err, context.Canceled) {
			t.Fatalf("detection error = %v; want context canceled", result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("TLS application detection did not stop after context cancellation")
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
	connCtx := &biConnContext{config: cfg}
	connCtx.setTransport(transport)
	return context.WithValue(ctx, connContextKey, connCtx)
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
