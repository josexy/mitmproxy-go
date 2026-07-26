package mitmproxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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

// The deadline that bounds reading a request header must not follow the
// connection into a protocol that owns it for its whole lifetime.
func TestH2CUpgradeOutlivesHandshakeTimeout(t *testing.T) {
	echo := startEchoServer(t)
	listener := startKeepAliveProxy(t, WithHandshakeTimeout(150*time.Millisecond))
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
	if _, err := io.WriteString(conn, "NOT A REQUEST LINE\r\n\r\n"); err != nil {
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
	upstream := startUpgradeAwareUpstream(t)
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
	if _, err := io.WriteString(conn, "tunnelled\n"); err != nil {
		t.Fatal(err)
	}
	if echoed, err := reader.ReadString('\n'); err != nil || echoed != "tunnelled\n" {
		t.Fatalf("tunnelled bytes = %q, %v; want tunnelled", echoed, err)
	}
}

// startUpgradeAwareUpstream answers ordinary requests with a fixed body and
// turns into an echo server once it sees an h2c upgrade.
func startUpgradeAwareUpstream(t *testing.T) string {
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
	return listener.Addr().String()
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
