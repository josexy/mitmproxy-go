package mitmproxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/josexy/websocket"
)

// startKeepAliveProxy runs the handler behind a real http.Server so tests go
// through the same hijack path as production traffic.
func startKeepAliveProxy(t *testing.T, opt ...Option) net.Listener {
	t.Helper()
	certPath, keyPath := writeTestCA(t)
	handler, err := NewMitmProxyHandler(append([]Option{
		WithCACertPath(certPath),
		WithCAKeyPath(keyPath),
	}, opt...)...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(handler.Cleanup)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler}
	t.Cleanup(func() { _ = server.Close() })
	go func() { _ = server.Serve(listener) }()
	return listener
}

func dialProxy(t *testing.T, listener net.Listener) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return conn, bufio.NewReader(conn)
}

func readProxyResponse(t *testing.T, reader *bufio.Reader, method string) (*http.Response, string) {
	t.Helper()
	response, err := http.ReadResponse(reader, &http.Request{Method: method})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatalf("close response body: %v", err)
	}
	return response, string(body)
}

// readConnectResponse reads the tunnel handshake only. The body of a 200
// response to CONNECT is the tunnel itself, so it must not be drained.
func readConnectResponse(t *testing.T, reader *bufio.Reader) {
	t.Helper()
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d; want 200", response.StatusCode)
	}
}

func assertRawTCPTunnelEvent(t *testing.T, events <-chan RawTCPTunnelEvent, hostport string, source RawTCPTunnelSource, tls bool) RawTCPTunnelEvent {
	t.Helper()
	select {
	case event := <-events:
		if event.Hostport != hostport || event.Source != source || event.TLS != tls {
			t.Fatalf("raw TCP event = %#v; want host=%q source=%v tls=%t", event, hostport, source, tls)
		}
		if source == RawTCPTunnelSourceHTTPConnect && event.Request == nil {
			t.Fatal("HTTP CONNECT raw TCP event has nil Request")
		}
		if source != RawTCPTunnelSourceHTTPConnect && event.Request != nil {
			t.Fatalf("non-CONNECT raw TCP event Request = %#v; want nil", event.Request)
		}
		return event
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for raw TCP event")
		return RawTCPTunnelEvent{}
	}
}

// readHeaderBlock consumes one CRLF terminated header block.
func readHeaderBlock(t *testing.T, reader *bufio.Reader) string {
	t.Helper()
	var block strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read header block: %v", err)
		}
		block.WriteString(line)
		if line == "\r\n" {
			return block.String()
		}
	}
}

// The bytes of a pipelined request sit in the buffered reader the http.Server
// hands over at Hijack. Dropping that reader once it looks drained strands them.
func TestPlainProxyAnswersPipelinedRequests(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = io.WriteString(w, req.URL.Path)
	}))
	defer upstream.Close()

	listener := startKeepAliveProxy(t, WithDisableHTTP2())
	conn, reader := dialProxy(t, listener)

	host := strings.TrimPrefix(upstream.URL, "http://")
	pipelined := fmt.Sprintf("GET %s/a HTTP/1.1\r\nHost: %s\r\n\r\nGET %s/b HTTP/1.1\r\nHost: %s\r\n\r\n",
		upstream.URL, host, upstream.URL, host)
	if _, err := io.WriteString(conn, pipelined); err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{"/a", "/b"} {
		response, body := readProxyResponse(t, reader, http.MethodGet)
		if response.StatusCode != http.StatusOK || body != want {
			t.Fatalf("pipelined response = %d %q; want 200 %q", response.StatusCode, body, want)
		}
	}
}

func TestPlainProxyForwardsPipelinedRequestsUpstream(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = upstream.Close() })
	secondBeforeResponse := make(chan bool, 1)
	go func() {
		conn, acceptErr := upstream.Accept()
		if acceptErr != nil {
			secondBeforeResponse <- false
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		first, readErr := http.ReadRequest(reader)
		if readErr != nil {
			secondBeforeResponse <- false
			return
		}
		_ = first.Body.Close()
		_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		second, readErr := http.ReadRequest(reader)
		pipelined := readErr == nil && second.URL.Path == "/b"
		secondBeforeResponse <- pipelined
		_ = conn.SetReadDeadline(time.Time{})
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\na")
		if !pipelined {
			second, readErr = http.ReadRequest(reader)
		}
		if readErr == nil {
			_ = second.Body.Close()
			_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nb")
		}
	}()

	listener := startKeepAliveProxy(t, WithDisableHTTP2())
	conn, reader := dialProxy(t, listener)
	host := upstream.Addr().String()
	if _, err := fmt.Fprintf(conn,
		"GET http://%s/a HTTP/1.1\r\nHost: %s\r\n\r\nGET http://%s/b HTTP/1.1\r\nHost: %s\r\n\r\n",
		host, host, host, host); err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{"a", "b"} {
		_, body := readProxyResponse(t, reader, http.MethodGet)
		if body != want {
			t.Fatalf("response body = %q; want %q", body, want)
		}
	}
	if pipelined := <-secondBeforeResponse; !pipelined {
		t.Fatal("second request did not reach upstream before the first response")
	}
}

func TestPlainProxyPipelinesAcrossTargetsAndOrdersResponses(t *testing.T) {
	secondReceived := make(chan struct{})
	first := startBlockingPipelineUpstream(t, secondReceived, "a")
	second := startSignalingPipelineUpstream(t, secondReceived, "b")

	listener := startKeepAliveProxy(t, WithDisableHTTP2())
	conn, reader := dialProxy(t, listener)
	if _, err := fmt.Fprintf(conn,
		"GET http://%s/a HTTP/1.1\r\nHost: %s\r\n\r\nGET http://%s/b HTTP/1.1\r\nHost: %s\r\n\r\n",
		first, first, second, second); err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{"a", "b"} {
		_, body := readProxyResponse(t, reader, http.MethodGet)
		if body != want {
			t.Fatalf("ordered response body = %q; want %q", body, want)
		}
	}
}

func TestPlainProxyPipelinesAfterRequestBody(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = upstream.Close() })
	requests := make(chan string, 2)
	go func() {
		conn, acceptErr := upstream.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		for range 2 {
			req, readErr := http.ReadRequest(reader)
			if readErr != nil {
				return
			}
			body, _ := io.ReadAll(req.Body)
			_ = req.Body.Close()
			requests <- req.URL.Path + ":" + string(body)
		}
		_, _ = io.WriteString(conn,
			"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\na"+
				"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nb")
	}()

	listener := startKeepAliveProxy(t, WithDisableHTTP2())
	conn, reader := dialProxy(t, listener)
	host := upstream.Addr().String()
	if _, err := fmt.Fprintf(conn,
		"POST http://%s/a HTTP/1.1\r\nHost: %s\r\nContent-Length: 4\r\n\r\ndata"+
			"GET http://%s/b HTTP/1.1\r\nHost: %s\r\n\r\n",
		host, host, host, host); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"/a:data", "/b:"} {
		select {
		case got := <-requests:
			if got != want {
				t.Fatalf("upstream request = %q; want %q", got, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("upstream did not receive %q before responding", want)
		}
	}
	for _, want := range []string{"a", "b"} {
		_, body := readProxyResponse(t, reader, http.MethodPost)
		if body != want {
			t.Fatalf("response body = %q; want %q", body, want)
		}
	}
}

func TestHTTP1PipelineRunsInterceptorsConcurrently(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = upstream.Close() })
	go func() {
		conn, acceptErr := upstream.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		for range 2 {
			request, readErr := http.ReadRequest(reader)
			if readErr != nil {
				return
			}
			_ = request.Body.Close()
		}
		_, _ = io.WriteString(conn,
			"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\na"+
				"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nb")
	}()

	var active atomic.Int32
	var maximum atomic.Int32
	interceptor := func(ctx context.Context, req *http.Request, next HTTPDelegatedInvoker) (*http.Response, error) {
		current := active.Add(1)
		for {
			old := maximum.Load()
			if current <= old || maximum.CompareAndSwap(old, current) {
				break
			}
		}
		defer active.Add(-1)
		return next.Invoke(req)
	}
	listener := startKeepAliveProxy(t, WithDisableHTTP2(), WithHTTPInterceptor(interceptor))
	conn, reader := dialProxy(t, listener)
	host := upstream.Addr().String()
	if _, err := fmt.Fprintf(conn,
		"GET http://%s/a HTTP/1.1\r\nHost: %s\r\n\r\nGET http://%s/b HTTP/1.1\r\nHost: %s\r\n\r\n",
		host, host, host, host); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		_, _ = readProxyResponse(t, reader, http.MethodGet)
	}
	if got := maximum.Load(); got < 2 {
		t.Fatalf("maximum concurrent interceptors = %d; want at least 2", got)
	}
}

func TestHTTP1PipelineDepthOneIsSequential(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = upstream.Close() })
	pipelined := make(chan bool, 1)
	go func() {
		conn, acceptErr := upstream.Accept()
		if acceptErr != nil {
			pipelined <- false
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		first, readErr := http.ReadRequest(reader)
		if readErr != nil {
			pipelined <- false
			return
		}
		_ = first.Body.Close()
		_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		second, secondErr := http.ReadRequest(reader)
		pipelined <- secondErr == nil
		_ = conn.SetReadDeadline(time.Time{})
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\na")
		if secondErr != nil {
			second, _ = http.ReadRequest(reader)
		}
		if second != nil {
			_ = second.Body.Close()
			_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nb")
		}
	}()

	listener := startKeepAliveProxy(t, WithDisableHTTP2(), WithHTTP1PipelineDepth(1))
	conn, reader := dialProxy(t, listener)
	host := upstream.Addr().String()
	_, _ = fmt.Fprintf(conn,
		"GET http://%s/a HTTP/1.1\r\nHost: %s\r\n\r\nGET http://%s/b HTTP/1.1\r\nHost: %s\r\n\r\n",
		host, host, host, host)
	for range 2 {
		_, _ = readProxyResponse(t, reader, http.MethodGet)
	}
	if <-pipelined {
		t.Fatal("pipeline depth 1 forwarded the second request before the first response")
	}
}

// Requests parsed after the initial http.Server request must retain the
// downstream connection lifetime. Otherwise a disconnected client leaves a
// later long poll running against the upstream server.
func TestHTTP1KeepAliveDisconnectCancelsLaterRequest(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan struct{})
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/warmup" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		close(started)
		select {
		case <-req.Context().Done():
			close(canceled)
		case <-release:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer upstream.Close()
	defer close(release)

	listener := startKeepAliveProxy(t, WithDisableHTTP2())
	conn, reader := dialProxy(t, listener)
	host := strings.TrimPrefix(upstream.URL, "http://")

	if _, err := fmt.Fprintf(conn, "GET %s/warmup HTTP/1.1\r\nHost: %s\r\n\r\n", upstream.URL, host); err != nil {
		t.Fatal(err)
	}
	if response, _ := readProxyResponse(t, reader, http.MethodGet); response.StatusCode != http.StatusNoContent {
		t.Fatalf("warmup status = %d; want 204", response.StatusCode)
	}
	if _, err := fmt.Fprintf(conn, "GET %s/poll HTTP/1.1\r\nHost: %s\r\n\r\n", upstream.URL, host); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("upstream long poll did not start")
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-canceled:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("upstream long poll was not canceled after the downstream disconnected")
	}
}

// Waiting for an upstream response is active work, not an idle client
// connection. The idle timeout starts only after the outstanding response has
// been written, so a long poll can still reuse the downstream connection.
func TestHTTP1IdleTimeoutDoesNotCloseActiveLongPoll(t *testing.T) {
	const idleTimeout = 150 * time.Millisecond
	started := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseSlow := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseSlow()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/slow" {
			close(started)
			<-release
		}
		_, _ = io.WriteString(w, strings.TrimPrefix(req.URL.Path, "/"))
	}))
	defer upstream.Close()

	listener := startKeepAliveProxy(t,
		WithDisableHTTP2(),
		WithIdleConnTimeout(idleTimeout),
	)
	conn, reader := dialProxy(t, listener)
	host := strings.TrimPrefix(upstream.URL, "http://")

	if _, err := fmt.Fprintf(conn, "GET %s/slow HTTP/1.1\r\nHost: %s\r\n\r\n", upstream.URL, host); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("upstream long poll did not start")
	}
	time.Sleep(2 * idleTimeout)
	releaseSlow()
	if response, body := readProxyResponse(t, reader, http.MethodGet); response.StatusCode != http.StatusOK || body != "slow" {
		t.Fatalf("slow response = %d %q; want 200 slow", response.StatusCode, body)
	}

	if _, err := fmt.Fprintf(conn, "GET %s/next HTTP/1.1\r\nHost: %s\r\n\r\n", upstream.URL, host); err != nil {
		t.Fatal(err)
	}
	if response, body := readProxyResponse(t, reader, http.MethodGet); response.StatusCode != http.StatusOK || body != "next" {
		t.Fatalf("next response = %d %q; want 200 next", response.StatusCode, body)
	}
	if err := conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ReadByte(); err == nil {
		t.Fatal("downstream connection closed with an unexpected byte before its idle timeout")
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("downstream connection closed before its idle timeout: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ReadByte(); err == nil {
		t.Fatal("truly idle downstream connection remained open")
	} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		t.Fatal("proxy did not re-arm the idle timeout after the active response completed")
	}
}

type failingResponseBody struct{}

func (failingResponseBody) Read([]byte) (int, error) {
	return 0, errors.New("response body read failed")
}

func (failingResponseBody) Close() error { return nil }

// A terminal writer error must wake the goroutine reading the next request,
// including when idle timeouts are disabled.
func TestHTTP1WriterErrorWakesRequestReader(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {}))
	defer upstream.Close()

	interceptorStarted := make(chan struct{})
	releaseInterceptor := make(chan struct{})
	failed := make(chan error, 1)
	listener := startKeepAliveProxy(t,
		WithDisableHTTP2(),
		WithIdleConnTimeout(0),
		WithHTTPInterceptor(func(ctx context.Context, req *http.Request, next HTTPDelegatedInvoker) (*http.Response, error) {
			close(interceptorStarted)
			<-releaseInterceptor
			return &http.Response{
				Status:        "200 OK",
				StatusCode:    http.StatusOK,
				Proto:         "HTTP/1.1",
				ProtoMajor:    1,
				ProtoMinor:    1,
				Header:        make(http.Header),
				Body:          failingResponseBody{},
				ContentLength: 1,
				Request:       req,
			}, nil
		}),
		WithErrorHandler(func(ec ErrorContext) {
			select {
			case failed <- ec.Error:
			default:
			}
		}),
	)
	conn, _ := dialProxy(t, listener)
	host := strings.TrimPrefix(upstream.URL, "http://")
	if _, err := fmt.Fprintf(conn, "GET %s/fail HTTP/1.1\r\nHost: %s\r\n\r\n", upstream.URL, host); err != nil {
		t.Fatal(err)
	}
	select {
	case <-interceptorStarted:
	case <-time.After(time.Second):
		t.Fatal("interceptor did not start")
	}
	time.Sleep(50 * time.Millisecond)
	close(releaseInterceptor)

	select {
	case err := <-failed:
		if err == nil {
			t.Fatal("proxy reported a nil writer error")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("terminal writer error did not wake the request reader")
	}
}

func TestHTTP1PipelineExpectContinueWaitsForPriorResponse(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = upstream.Close() })
	go func() {
		conn, acceptErr := upstream.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		first, readErr := http.ReadRequest(reader)
		if readErr != nil {
			return
		}
		_ = first.Body.Close()
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\na")
		second, readErr := http.ReadRequest(reader)
		if readErr != nil {
			return
		}
		body, _ := io.ReadAll(second.Body)
		_ = second.Body.Close()
		_, _ = fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	}()

	listener := startKeepAliveProxy(t, WithDisableHTTP2())
	conn, reader := dialProxy(t, listener)
	host := upstream.Addr().String()
	if _, err := fmt.Fprintf(conn,
		"GET http://%s/a HTTP/1.1\r\nHost: %s\r\n\r\n"+
			"POST http://%s/b HTTP/1.1\r\nHost: %s\r\nContent-Length: 4\r\nExpect: 100-continue\r\n\r\n",
		host, host, host, host); err != nil {
		t.Fatal(err)
	}
	first, body := readProxyResponse(t, reader, http.MethodGet)
	if first.StatusCode != http.StatusOK || body != "a" {
		t.Fatalf("first response = %d %q; want 200 a", first.StatusCode, body)
	}
	continued, err := http.ReadResponse(reader, &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatal(err)
	}
	_ = continued.Body.Close()
	if continued.StatusCode != http.StatusContinue {
		t.Fatalf("response after first final = %d; want 100", continued.StatusCode)
	}
	if _, err := io.WriteString(conn, "data"); err != nil {
		t.Fatal(err)
	}
	final, body := readProxyResponse(t, reader, http.MethodPost)
	if final.StatusCode != http.StatusOK || body != "data" {
		t.Fatalf("second final response = %d %q; want 200 data", final.StatusCode, body)
	}
}

func TestHTTP1PipelineDoesNotRetryUnansweredUnsafeRequest(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = upstream.Close() })
	go func() {
		conn, acceptErr := upstream.Accept()
		if acceptErr != nil {
			return
		}
		reader := bufio.NewReader(conn)
		for range 2 {
			request, readErr := http.ReadRequest(reader)
			if readErr != nil {
				_ = conn.Close()
				return
			}
			_, _ = io.Copy(io.Discard, request.Body)
			_ = request.Body.Close()
		}
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\na")
		_ = conn.Close()
	}()

	listener := startKeepAliveProxy(t, WithDisableHTTP2())
	conn, reader := dialProxy(t, listener)
	host := upstream.Addr().String()
	if _, err := fmt.Fprintf(conn,
		"GET http://%s/a HTTP/1.1\r\nHost: %s\r\n\r\n"+
			"POST http://%s/b HTTP/1.1\r\nHost: %s\r\nContent-Length: 4\r\n\r\ndata",
		host, host, host, host); err != nil {
		t.Fatal(err)
	}
	first, body := readProxyResponse(t, reader, http.MethodGet)
	if first.StatusCode != http.StatusOK || body != "a" {
		t.Fatalf("first response = %d %q; want 200 a", first.StatusCode, body)
	}
	second, _ := readProxyResponse(t, reader, http.MethodPost)
	if second.StatusCode != http.StatusBadGateway || !second.Close {
		t.Fatalf("unsafe unanswered response = %d close=%t; want 502 close", second.StatusCode, second.Close)
	}
}

func startBlockingPipelineUpstream(t *testing.T, release <-chan struct{}, body string) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		request, readErr := http.ReadRequest(bufio.NewReader(conn))
		if readErr != nil {
			return
		}
		_ = request.Body.Close()
		select {
		case <-release:
		case <-time.After(time.Second):
			return
		}
		_, _ = fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	}()
	return listener.Addr().String()
}

func startSignalingPipelineUpstream(t *testing.T, received chan<- struct{}, body string) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		request, readErr := http.ReadRequest(bufio.NewReader(conn))
		if readErr != nil {
			return
		}
		_ = request.Body.Close()
		close(received)
		_, _ = fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	}()
	return listener.Addr().String()
}

// The deadline that bounds reading a request header must not follow the
// connection into a protocol that owns it for its whole lifetime.
func TestH2CUpgradeOutlivesHandshakeTimeout(t *testing.T) {
	echo := startEchoServer(t)
	var rawEvents atomic.Int32
	listener := startKeepAliveProxy(t,
		WithHandshakeTimeout(150*time.Millisecond),
		WithRawTCPInterceptor(func(context.Context, RawTCPTunnelEvent) { rawEvents.Add(1) }),
	)
	conn, reader := dialProxy(t, listener)

	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", echo, echo); err != nil {
		t.Fatal(err)
	}
	readConnectResponse(t, reader)

	upgrade := "GET / HTTP/1.1\r\nHost: " + echo +
		"\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAAP__\r\n\r\n"
	if _, err := io.WriteString(conn, upgrade); err != nil {
		t.Fatal(err)
	}
	// The proxy rewrites the upgrade request before forwarding it, so match on
	// the header block rather than on the exact bytes.
	if echoed := readHeaderBlock(t, reader); !strings.Contains(echoed, "Upgrade: h2c") {
		t.Fatalf("forwarded upgrade request = %q", echoed)
	}

	// Well past the handshake timeout the tunnel must still carry traffic.
	for i := range 4 {
		time.Sleep(100 * time.Millisecond)
		message := fmt.Sprintf("ping%d", i)
		if _, err := io.WriteString(conn, message); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		got := make([]byte, len(message))
		if _, err := io.ReadFull(reader, got); err != nil {
			t.Fatalf("h2c tunnel died %v after the upgrade: %v", time.Duration(i+1)*100*time.Millisecond, err)
		}
	}
	if got := rawEvents.Load(); got != 0 {
		t.Fatalf("raw TCP interceptor called %d times for h2c upgrade", got)
	}
}

func TestConnectTunnelRelaysRawTCP(t *testing.T) {
	echo := startEchoServer(t)
	events := make(chan RawTCPTunnelEvent, 6)
	listener := startKeepAliveProxy(t,
		WithDisableHTTP2(),
		WithRawTCPInterceptor(func(_ context.Context, event RawTCPTunnelEvent) { events <- event }),
	)

	for name, payload := range map[string][]byte{
		"binary":        {0xef, 0x01, 0x02, 0x03, 0x00, 0xff, 0x7f, 0x10},
		"text protocol": []byte("GET key\r\n"),
		"rtsp":          []byte("OPTIONS rtsp://example.test/media RTSP/1.0\r\n\r\n"),
	} {
		t.Run(name, func(t *testing.T) {
			conn, reader := dialProxy(t, listener)
			connect := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nX-Raw-Tunnel-Test: %s\r\n\r\n", echo, echo, name)
			if _, err := conn.Write(append([]byte(connect), payload...)); err != nil {
				t.Fatal(err)
			}
			readConnectResponse(t, reader)

			if err := conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(reader, got); err != nil {
				t.Fatalf("read raw CONNECT echo: %v", err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("raw CONNECT echo = %x; want %x", got, payload)
			}
			_ = conn.Close()
			event := assertRawTCPTunnelEvent(t, events, echo, RawTCPTunnelSourceHTTPConnect, false)
			if event.Request.Method != http.MethodConnect || event.Request.RequestURI != echo ||
				event.Request.Host != echo || event.Request.Header.Get("X-Raw-Tunnel-Test") != name ||
				event.Request.Body != http.NoBody {
				t.Fatalf("CONNECT request snapshot = %#v", event.Request)
			}
		})
	}
}

func TestWebsocketDoesNotReportRawTCP(t *testing.T) {
	originErr := make(chan error, 1)
	upgrader := websocket.Upgrader{}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		conn, err := upgrader.Upgrade(w, req, nil)
		if err != nil {
			originErr <- err
			return
		}
		defer conn.Close()
		messageType, payload, err := conn.ReadMessage()
		if err != nil {
			originErr <- err
			return
		}
		originErr <- conn.WriteMessage(messageType, payload)
	}))
	defer origin.Close()

	var rawEvents atomic.Int32
	listener := startKeepAliveProxy(t,
		WithRawTCPInterceptor(func(context.Context, RawTCPTunnelEvent) { rawEvents.Add(1) }),
	)
	proxyURL, err := url.Parse("http://" + listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	dialer := websocket.Dialer{
		Proxy:            http.ProxyURL(proxyURL),
		HandshakeTimeout: time.Second,
	}
	client, response, err := dialer.Dial("ws"+strings.TrimPrefix(origin.URL, "http"), nil)
	if response != nil && response.Body != nil {
		defer response.Body.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	payload := []byte("websocket message")
	if err := client.WriteMessage(websocket.TextMessage, payload); err != nil {
		t.Fatal(err)
	}
	messageType, echoed, err := client.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if messageType != websocket.TextMessage || !bytes.Equal(echoed, payload) {
		t.Fatalf("websocket echo = type %d, %q; want text %q", messageType, echoed, payload)
	}
	if err := <-originErr; err != nil {
		t.Fatal(err)
	}
	if got := rawEvents.Load(); got != 0 {
		t.Fatalf("raw TCP interceptor called %d times for WebSocket", got)
	}
}

func TestConnectTunnelInterceptsExtensionHTTPMethod(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = io.WriteString(w, req.Method)
	}))
	defer upstream.Close()

	listener := startKeepAliveProxy(t,
		WithDisableHTTP2(),
		WithHTTPInterceptor(func(ctx context.Context, req *http.Request, next HTTPDelegatedInvoker) (*http.Response, error) {
			response, err := next.Invoke(req)
			if err == nil {
				response.Header.Set("X-Intercepted", "yes")
			}
			return response, err
		}),
	)
	conn, reader := dialProxy(t, listener)
	host := strings.TrimPrefix(upstream.URL, "http://")
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", host, host); err != nil {
		t.Fatal(err)
	}
	readConnectResponse(t, reader)
	if _, err := fmt.Fprintf(conn, "REPORT /resource HTTP/1.1\r\nHost: %s\r\nContent-Length: 0\r\n\r\n", host); err != nil {
		t.Fatal(err)
	}
	response, body := readProxyResponse(t, reader, "REPORT")
	if response.StatusCode != http.StatusOK || body != "REPORT" {
		t.Fatalf("extension response = %d %q; want 200 REPORT", response.StatusCode, body)
	}
	if got := response.Header.Get("X-Intercepted"); got != "yes" {
		t.Fatalf("X-Intercepted = %q; want yes", got)
	}
}

// A response of unknown length is delimited by closing the connection, so the
// proxy must actually close it instead of waiting for another request.
func TestUnknownLengthResponseClosesConnection(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {}))
	defer upstream.Close()

	listener := startKeepAliveProxy(t, WithDisableHTTP2(), WithHTTPInterceptor(
		func(ctx context.Context, req *http.Request, next HTTPDelegatedInvoker) (*http.Response, error) {
			return &http.Response{
				Status:        "200 OK",
				StatusCode:    http.StatusOK,
				Proto:         "HTTP/1.1",
				ProtoMajor:    1,
				ProtoMinor:    1,
				Header:        http.Header{},
				Body:          io.NopCloser(strings.NewReader("hello")),
				ContentLength: -1,
			}, nil
		}))

	conn, reader := dialProxy(t, listener)
	host := strings.TrimPrefix(upstream.URL, "http://")
	if _, err := fmt.Fprintf(conn, "GET %s/a HTTP/1.1\r\nHost: %s\r\n\r\n", upstream.URL, host); err != nil {
		t.Fatal(err)
	}
	response, body := readProxyResponse(t, reader, http.MethodGet)
	if body != "hello" {
		t.Fatalf("body = %q; want hello", body)
	}
	if !response.Close {
		t.Fatal("response did not announce Connection: close")
	}
	if _, err := reader.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("read after response = %v; want EOF", err)
	}
}

func TestHEADResponseWithoutContentLengthKeepsConnection(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()

	served := make(chan error, 1)
	go func() {
		conn, err := upstream.Accept()
		if err != nil {
			served <- err
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		for range 2 {
			request, err := http.ReadRequest(reader)
			if err != nil {
				served <- err
				return
			}
			_ = request.Body.Close()
			if _, err := io.WriteString(conn, "HTTP/1.1 200 OK\r\n\r\n"); err != nil {
				served <- err
				return
			}
		}
		served <- nil
	}()

	listener := startKeepAliveProxy(t, WithDisableHTTP2())
	conn, reader := dialProxy(t, listener)
	host := upstream.Addr().String()
	for range 2 {
		if _, err := fmt.Fprintf(conn, "HEAD http://%s/x HTTP/1.1\r\nHost: %s\r\n\r\n", host, host); err != nil {
			t.Fatal(err)
		}
		response, _ := readProxyResponse(t, reader, http.MethodHead)
		if response.Close {
			t.Fatal("HEAD response without Content-Length unexpectedly closed the connection")
		}
	}
	if err := <-served; err != nil {
		t.Fatal(err)
	}
}

// An upstream that drops its keep-alive connection while idle must not turn the
// next request into a dropped client connection.
func TestStaleUpstreamConnectionIsReplaced(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	go func() {
		for {
			conn, err := upstream.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				request, err := http.ReadRequest(bufio.NewReader(conn))
				if err != nil {
					return
				}
				_, _ = io.Copy(io.Discard, request.Body)
				_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
				// Answer one request, then drop the idle connection.
				time.Sleep(50 * time.Millisecond)
			}()
		}
	}()

	listener := startKeepAliveProxy(t, WithDisableHTTP2())
	conn, reader := dialProxy(t, listener)

	host := upstream.Addr().String()
	for i, payload := range []string{"a", "b"} {
		request := fmt.Sprintf("POST http://%s/x HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n\r\n%s",
			host, host, len(payload), payload)
		if _, err := io.WriteString(conn, request); err != nil {
			t.Fatalf("write request %d: %v", i+1, err)
		}
		response, body := readProxyResponse(t, reader, http.MethodPost)
		if response.StatusCode != http.StatusOK || body != "ok" {
			t.Fatalf("response %d = %d %q; want 200 ok", i+1, response.StatusCode, body)
		}
		if i == 0 {
			time.Sleep(200 * time.Millisecond) // let the upstream drop its side
		}
	}
}

// Clients reuse a plain proxy connection for any origin, so a changed authority
// is ordinary reuse rather than an error.
func TestPlainProxyKeepAliveRetargets(t *testing.T) {
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = io.WriteString(w, "first")
	}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = io.WriteString(w, "second")
	}))
	defer second.Close()

	listener := startKeepAliveProxy(t, WithDisableHTTP2())
	conn, reader := dialProxy(t, listener)

	for _, want := range []struct{ url, body string }{
		{first.URL, "first"},
		{second.URL, "second"},
		{first.URL, "first"},
	} {
		host := strings.TrimPrefix(want.url, "http://")
		if _, err := fmt.Fprintf(conn, "GET %s/x HTTP/1.1\r\nHost: %s\r\n\r\n", want.url, host); err != nil {
			t.Fatal(err)
		}
		response, body := readProxyResponse(t, reader, http.MethodGet)
		if response.StatusCode != http.StatusOK || body != want.body {
			t.Fatalf("response = %d %q; want 200 %q", response.StatusCode, body, want.body)
		}
	}
}

func TestPlainProxyRetargetHonorsHostFilters(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	listener := startKeepAliveProxy(t,
		WithDisableHTTP2(),
		WithExcludeHosts("127.0.0.1"),
		WithHTTPInterceptor(func(ctx context.Context, req *http.Request, next HTTPDelegatedInvoker) (*http.Response, error) {
			response, err := next.Invoke(req)
			if err == nil {
				response.Header.Set("X-Intercepted", "yes")
			}
			return response, err
		}))
	conn, reader := dialProxy(t, listener)

	ipHost := strings.TrimPrefix(upstream.URL, "http://")
	_, port, err := net.SplitHostPort(ipHost)
	if err != nil {
		t.Fatal(err)
	}
	localHost := net.JoinHostPort("localhost", port)
	for _, test := range []struct {
		target      string
		host        string
		intercepted string
	}{
		{"http://" + localHost + "/first", localHost, "yes"},
		{upstream.URL + "/second", ipHost, ""},
	} {
		if _, err := fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", test.target, test.host); err != nil {
			t.Fatal(err)
		}
		response, body := readProxyResponse(t, reader, http.MethodGet)
		if response.StatusCode != http.StatusOK || body != "ok" {
			t.Fatalf("response = %d %q; want 200 ok", response.StatusCode, body)
		}
		if got := response.Header.Get("X-Intercepted"); got != test.intercepted {
			t.Fatalf("X-Intercepted = %q; want %q", got, test.intercepted)
		}
	}
}

// A CONNECT tunnel is pinned to the authority the client asked for.
func TestConnectTunnelRejectsChangedAuthority(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	listener := startKeepAliveProxy(t, WithDisableHTTP2())
	conn, reader := dialProxy(t, listener)

	host := strings.TrimPrefix(upstream.URL, "http://")
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", host, host); err != nil {
		t.Fatal(err)
	}
	readConnectResponse(t, reader)
	if _, err := io.WriteString(conn, "GET /x HTTP/1.1\r\nHost: elsewhere.test\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, _ := readProxyResponse(t, reader, http.MethodGet)
	if response.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("status = %d; want %d", response.StatusCode, http.StatusMisdirectedRequest)
	}
}

func TestMalformedTunnelRequestIsAnswered(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {}))
	defer upstream.Close()

	listener := startKeepAliveProxy(t, WithDisableHTTP2())
	conn, reader := dialProxy(t, listener)

	host := strings.TrimPrefix(upstream.URL, "http://")
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", host, host); err != nil {
		t.Fatal(err)
	}
	readConnectResponse(t, reader)
	if _, err := io.WriteString(conn, "GET / HTTP/not-a-version\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, _ := readProxyResponse(t, reader, http.MethodGet)
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400", response.StatusCode)
	}
}

// RFC 9112 7.1: chunked framing must not reach an HTTP/1.0 client.
func TestHTTP10ClientNeverSeesChunked(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Transfer-Encoding", "chunked")
		_, _ = io.WriteString(w, "chunked-body")
	}))
	defer upstream.Close()

	listener := startKeepAliveProxy(t, WithDisableHTTP2())
	conn, reader := dialProxy(t, listener)

	host := strings.TrimPrefix(upstream.URL, "http://")
	if _, err := fmt.Fprintf(conn, "GET %s/x HTTP/1.0\r\nHost: %s\r\n\r\n", upstream.URL, host); err != nil {
		t.Fatal(err)
	}
	response, body := readProxyResponse(t, reader, http.MethodGet)
	if len(response.TransferEncoding) != 0 {
		t.Fatalf("transfer encoding = %v; want none for an HTTP/1.0 client", response.TransferEncoding)
	}
	if body != "chunked-body" {
		t.Fatalf("body = %q; want chunked-body", body)
	}
	if !response.Close {
		t.Fatal("an EOF delimited response must announce Connection: close")
	}
}

// A length delimited response can be reused by an HTTP/1.0 client, but only if
// it is told so explicitly.
func TestHTTP10KeepAliveIsAnnounced(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Length", "2")
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	listener := startKeepAliveProxy(t, WithDisableHTTP2())
	conn, reader := dialProxy(t, listener)

	host := strings.TrimPrefix(upstream.URL, "http://")
	for i := range 2 {
		if _, err := fmt.Fprintf(conn, "GET %s/x HTTP/1.0\r\nHost: %s\r\nConnection: keep-alive\r\n\r\n",
			upstream.URL, host); err != nil {
			t.Fatal(err)
		}
		response, body := readProxyResponse(t, reader, http.MethodGet)
		if body != "ok" {
			t.Fatalf("response %d body = %q; want ok", i+1, body)
		}
		if got := response.Header.Get(HttpHeaderConnection); !strings.EqualFold(got, "keep-alive") {
			t.Fatalf("response %d Connection = %q; want keep-alive", i+1, got)
		}
	}
}

func TestWriteHTTP1ResponseCoalescesHeader(t *testing.T) {
	header := http.Header{}
	for key, value := range map[string]string{
		"Content-Type":  "text/plain",
		"Date":          "Sun, 26 Jul 2026 00:00:00 GMT",
		"Server":        "test",
		"Cache-Control": "no-cache",
		"Vary":          "Accept-Encoding",
	} {
		header.Set(key, value)
	}
	response := &http.Response{
		Status:        "200 OK",
		StatusCode:    http.StatusOK,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        header,
		Body:          io.NopCloser(strings.NewReader("hello")),
		ContentLength: 5,
	}
	counter := &writeCountingWriter{}
	if err := writeHTTP1Response(counter, response); err != nil {
		t.Fatal(err)
	}
	// One write for the whole header block, one for the body.
	if counter.writes > 2 {
		t.Fatalf("writes = %d; want at most 2", counter.writes)
	}
	if !strings.HasPrefix(counter.data.String(), "HTTP/1.1 200 OK\r\n") ||
		!strings.HasSuffix(counter.data.String(), "\r\n\r\nhello") {
		t.Fatalf("response bytes = %q", counter.data.String())
	}
}

func TestWriteHTTP1ResponseStreamsBodyWithoutHoldingItBack(t *testing.T) {
	body, writer := io.Pipe()
	defer writer.Close()
	response := &http.Response{
		Status:        "200 OK",
		StatusCode:    http.StatusOK,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{},
		Body:          body,
		ContentLength: -1,
		Close:         true,
	}
	seen := make(chan string, 4)
	go func() {
		_ = writeHTTP1Response(&channelWriter{seen: seen}, response)
	}()

	// The header must reach the wire before the first body byte exists.
	select {
	case chunk := <-seen:
		if !strings.HasPrefix(chunk, "HTTP/1.1 200 OK\r\n") {
			t.Errorf("first write = %q; want the header block", chunk)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("header was held back")
	}
	if _, err := io.WriteString(writer, "tick"); err != nil {
		t.Fatal(err)
	}
	select {
	case chunk := <-seen:
		if chunk != "tick" {
			t.Errorf("body write = %q; want tick", chunk)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("body byte was held back")
	}
}

type writeCountingWriter struct {
	writes int
	data   strings.Builder
}

func (w *writeCountingWriter) Write(data []byte) (int, error) {
	w.writes++
	w.data.Write(data)
	return len(data), nil
}

type channelWriter struct {
	mu   sync.Mutex
	seen chan string
}

func (w *channelWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.seen <- string(data)
	return len(data), nil
}

// Dropping a stale upstream connection must not cost the healthy case its
// connection reuse.
func TestHealthyUpstreamConnectionIsReused(t *testing.T) {
	var accepted atomic.Int64
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	upstream.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			accepted.Add(1)
		}
	}
	upstream.Start()
	defer upstream.Close()

	listener := startKeepAliveProxy(t, WithDisableHTTP2())
	conn, reader := dialProxy(t, listener)

	host := strings.TrimPrefix(upstream.URL, "http://")
	for i := range 3 {
		if _, err := fmt.Fprintf(conn, "GET %s/x HTTP/1.1\r\nHost: %s\r\n\r\n", upstream.URL, host); err != nil {
			t.Fatal(err)
		}
		if response, body := readProxyResponse(t, reader, http.MethodGet); response.StatusCode != http.StatusOK || body != "ok" {
			t.Fatalf("response %d = %d %q; want 200 ok", i+1, response.StatusCode, body)
		}
	}
	if got := accepted.Load(); got != 1 {
		t.Fatalf("upstream connections = %d; want 1 reused connection", got)
	}
}

// A client that requests a large body and then stops reading must not pin the
// proxy goroutine and its upstream connection forever.
func TestStalledClientResponseWriteTimesOut(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		payload := make([]byte, 8<<20)
		w.Header().Set("Content-Length", fmt.Sprint(len(payload)))
		_, _ = w.Write(payload)
	}))
	defer upstream.Close()

	failed := make(chan error, 4)
	listener := startKeepAliveProxy(t,
		WithDisableHTTP2(),
		WithIdleConnTimeout(200*time.Millisecond),
		WithErrorHandler(func(ec ErrorContext) {
			select {
			case failed <- ec.Error:
			default:
			}
		}))

	conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	host := strings.TrimPrefix(upstream.URL, "http://")
	if _, err := fmt.Fprintf(conn, "GET %s/big HTTP/1.1\r\nHost: %s\r\n\r\n", upstream.URL, host); err != nil {
		t.Fatal(err)
	}
	// Never read the response: the socket buffers fill and the write stalls.
	select {
	case err := <-failed:
		if err == nil {
			t.Fatal("proxy reported a nil error")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("stalled response write was never bounded")
	}
}

// An upgrade that arrives after an ordinary request must not be written onto
// the tunnel connection, which by then belongs to the transport.
func TestUpgradeAfterKeepAliveRequestUsesFreshUpstream(t *testing.T) {
	upstream, firstConnectionClosed := startUpgradeAwareUpstream(t)
	listener := startKeepAliveProxy(t)
	conn, reader := dialProxy(t, listener)

	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", upstream, upstream); err != nil {
		t.Fatal(err)
	}
	readConnectResponse(t, reader)

	if _, err := fmt.Fprintf(conn, "GET /first HTTP/1.1\r\nHost: %s\r\n\r\n", upstream); err != nil {
		t.Fatal(err)
	}
	if response, body := readProxyResponse(t, reader, http.MethodGet); response.StatusCode != http.StatusOK || body != "ok" {
		t.Fatalf("first response = %d %q; want 200 ok", response.StatusCode, body)
	}

	upgrade := "GET / HTTP/1.1\r\nHost: " + upstream +
		"\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAAP__\r\n\r\n"
	if _, err := io.WriteString(conn, upgrade); err != nil {
		t.Fatal(err)
	}
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("upgrade was not served on a usable upstream connection: %v", err)
	}
	if line != "ECHO-READY\r\n" {
		t.Fatalf("upgrade response = %q; want ECHO-READY", line)
	}
	select {
	case <-firstConnectionClosed:
	case <-time.After(time.Second):
		t.Fatal("ordinary-request upstream remained open after protocol upgrade")
	}
	if _, err := io.WriteString(conn, "tunnelled\n"); err != nil {
		t.Fatal(err)
	}
	if echoed, err := reader.ReadString('\n'); err != nil || echoed != "tunnelled\n" {
		t.Fatalf("tunnelled bytes = %q, %v; want tunnelled", echoed, err)
	}
}

// startUpgradeAwareUpstream answers ordinary requests with a fixed body and
// turns into an echo server once it sees an h2c upgrade.
func startUpgradeAwareUpstream(t *testing.T) (string, <-chan struct{}) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	firstConnectionClosed := make(chan struct{})
	var accepted atomic.Int64
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			connectionNumber := accepted.Add(1)
			go func() {
				defer conn.Close()
				if connectionNumber == 1 {
					defer close(firstConnectionClosed)
				}
				reader := bufio.NewReader(conn)
				for {
					request, err := http.ReadRequest(reader)
					if err != nil {
						return
					}
					_, _ = io.Copy(io.Discard, request.Body)
					if isH2CUpgrade(request.Header) {
						if _, err := io.WriteString(conn, "ECHO-READY\r\n"); err != nil {
							return
						}
						_, _ = io.Copy(conn, reader)
						return
					}
					if _, err := io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"); err != nil {
						return
					}
				}
			}()
		}
	}()
	return listener.Addr().String(), firstConnectionClosed
}

func startEchoServer(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return listener.Addr().String()
}
