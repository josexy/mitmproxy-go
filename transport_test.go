package mitmproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func TestProtocolsForRequest(t *testing.T) {
	tests := []struct {
		name           string
		scheme         string
		protoMajor     int
		disableHTTP2   bool
		wantHTTP1      bool
		wantHTTP2      bool
		wantUnencHTTP2 bool
	}{
		{"http1", "http", 1, false, true, false, false},
		{"h2c", "http", 2, false, false, false, true},
		{"h2c disabled", "http", 2, true, true, false, false},
		{"https h2 enabled", "https", 1, false, true, true, false},
		{"https h2 disabled", "https", 1, true, true, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := protocolsForRequest(tt.scheme, tt.protoMajor, tt.disableHTTP2)
			if got.HTTP1() != tt.wantHTTP1 ||
				got.HTTP2() != tt.wantHTTP2 ||
				got.UnencryptedHTTP2() != tt.wantUnencHTTP2 {
				t.Fatalf("protocols = http1:%v http2:%v h2c:%v; want %v %v %v",
					got.HTTP1(), got.HTTP2(), got.UnencryptedHTTP2(),
					tt.wantHTTP1, tt.wantHTTP2, tt.wantUnencHTTP2)
			}
		})
	}
}

func TestSingleConnTransportGetClientConnValidationAndClose(t *testing.T) {
	tr := newTransport("example.com:80", nil, 0, false)
	req, _ := http.NewRequest(http.MethodGet, "/path", nil)
	if _, err := tr.getClientConn(context.Background(), req); err == nil || err.Error() != "request URL scheme is empty" {
		t.Fatalf("empty scheme err = %v; want empty scheme error", err)
	}

	req, _ = http.NewRequest(http.MethodGet, "ftp://example.com/path", nil)
	if _, err := tr.getClientConn(context.Background(), req); err == nil || err.Error() != `unsupported request URL scheme "ftp"` {
		t.Fatalf("unsupported scheme err = %v", err)
	}

	if err := tr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	req, _ = http.NewRequest(http.MethodGet, "http://example.com/path", nil)
	if _, err := tr.getClientConn(context.Background(), req); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed transport err = %v; want net.ErrClosed", err)
	}
	if err := tr.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestSingleConnTransportRoundTripAndReuse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		for i := 0; i < 2; i++ {
			req, err := http.ReadRequest(bufio.NewReader(conn))
			if err != nil {
				return
			}
			_, _ = io.Copy(io.Discard, req.Body)
			_ = req.Body.Close()
			_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
		}
	}()

	dialCount := 0
	tr := newTransport(
		ln.Addr().String(),
		func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialCount++
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, addr)
		},
		time.Second,
		true,
	)
	defer tr.Close()

	for i := 0; i < 2; i++ {
		req, _ := http.NewRequest(http.MethodGet, "http://"+ln.Addr().String()+"/", nil)
		resp, err := tr.RoundTrip(req)
		if err != nil {
			t.Fatalf("RoundTrip %d: %v", i, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || string(body) != "ok" {
			t.Fatalf("response %d = %d %q; want 200 ok", i, resp.StatusCode, body)
		}
	}
	if dialCount != 1 {
		t.Fatalf("dialCount = %d; want reused single connection", dialCount)
	}
	<-done
}

func TestSingleConnTransportRoundTripClosesOnError(t *testing.T) {
	tr := newTransport(
		"example.com:80",
		func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, errors.New("dial failed")
		},
		0,
		false,
	)
	req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	if _, err := tr.RoundTrip(req); err == nil {
		t.Fatalf("expected round trip error")
	}
	if tr.closed {
		t.Fatalf("dial error should not mark transport closed")
	}
}

func TestSingleConnTransportDoesNotCloseOnCanceledHTTP2Stream(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	cancelStarted := make(chan struct{})
	okStarted := make(chan struct{})
	releaseOK := make(chan struct{})
	protos := &http.Protocols{}
	protos.SetHTTP1(true)
	protos.SetUnencryptedHTTP2(true)
	server := &http.Server{
		Protocols: protos,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/cancel":
				close(cancelStarted)
				<-r.Context().Done()
			case "/ok":
				close(okStarted)
				<-releaseOK
				_, _ = w.Write([]byte("ok"))
			default:
				http.NotFound(w, r)
			}
		}),
	}
	go func() {
		_ = server.Serve(ln)
	}()
	defer server.Close()

	dialCount := 0
	tr := newTransport(
		ln.Addr().String(),
		func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialCount++
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, addr)
		},
		time.Second,
		false,
	)
	defer tr.Close()

	cancelCtx, cancel := context.WithCancel(context.Background())
	cancelReq, _ := http.NewRequestWithContext(cancelCtx, http.MethodGet, "http://"+ln.Addr().String()+"/cancel", nil)
	cancelReq.Proto = "HTTP/2.0"
	cancelReq.ProtoMajor = 2
	cancelReq.ProtoMinor = 0
	cancelErrCh := make(chan error, 1)
	go func() {
		resp, err := tr.RoundTrip(cancelReq)
		if resp != nil {
			_ = resp.Body.Close()
		}
		cancelErrCh <- err
	}()

	select {
	case <-cancelStarted:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for /cancel request")
	}

	okReq, _ := http.NewRequest(http.MethodGet, "http://"+ln.Addr().String()+"/ok", nil)
	okReq.Proto = "HTTP/2.0"
	okReq.ProtoMajor = 2
	okReq.ProtoMinor = 0
	okRespCh := make(chan *http.Response, 1)
	okErrCh := make(chan error, 1)
	go func() {
		resp, err := tr.RoundTrip(okReq)
		if err != nil {
			okErrCh <- err
			return
		}
		okRespCh <- resp
	}()

	select {
	case <-okStarted:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for /ok request")
	}

	cancel()
	if err := <-cancelErrCh; err == nil {
		t.Fatal("canceled request unexpectedly succeeded")
	}
	if tr.closed {
		t.Fatal("canceled stream marked transport closed")
	}

	close(releaseOK)
	select {
	case err := <-okErrCh:
		t.Fatalf("concurrent stream failed after sibling cancellation: %v", err)
	case resp := <-okRespCh:
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || string(body) != "ok" {
			t.Fatalf("response = %d %q, want 200 ok", resp.StatusCode, body)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for /ok response")
	}
	if dialCount != 1 {
		t.Fatalf("dialCount = %d, want one shared HTTP/2 connection", dialCount)
	}
}

func TestSingleConnTransportRetriesReplayableRequestAfterBadClientConn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		firstConn, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = http.ReadRequest(bufio.NewReader(firstConn))
		_ = firstConn.Close()

		secondConn, err := ln.Accept()
		if err != nil {
			return
		}
		defer secondConn.Close()
		req, err := http.ReadRequest(bufio.NewReader(secondConn))
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, req.Body)
		_ = req.Body.Close()
		_, _ = secondConn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
	}()

	dialCount := 0
	tr := newTransport(
		ln.Addr().String(),
		func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialCount++
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, addr)
		},
		time.Second,
		true,
	)
	defer tr.Close()

	req, _ := http.NewRequest(http.MethodGet, "http://"+ln.Addr().String()+"/", nil)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("response = %d %q, want 200 ok", resp.StatusCode, body)
	}
	if dialCount != 2 {
		t.Fatalf("dialCount = %d, want retry on a new connection", dialCount)
	}
	<-done
}

func TestSingleConnTransportRetriesHTTP2RequestAfterBadClientConn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	errCh := make(chan error, 2)
	protos := &http.Protocols{}
	protos.SetHTTP1(true)
	protos.SetUnencryptedHTTP2(true)
	server := &http.Server{
		Protocols: protos,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ProtoMajor != 2 {
				errCh <- fmt.Errorf("origin request proto = %s, want HTTP/2", r.Proto)
				return
			}
			_, _ = w.Write([]byte("ok"))
		}),
	}
	defer server.Close()

	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		firstConn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		if err := closeHTTP2ConnAfterRequestHeaders(firstConn); err != nil {
			errCh <- err
			return
		}
		if err := server.Serve(ln); err != nil && err != http.ErrServerClosed && !errors.Is(err, net.ErrClosed) {
			errCh <- err
		}
	}()

	dialCount := 0
	tr := newTransport(
		ln.Addr().String(),
		func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialCount++
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, addr)
		},
		time.Second,
		false,
	)
	defer tr.Close()

	req, _ := http.NewRequest(http.MethodGet, "http://"+ln.Addr().String()+"/", nil)
	req.Proto = "HTTP/2.0"
	req.ProtoMajor = 2
	req.ProtoMinor = 0
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.ProtoMajor != 2 || resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("response = proto %s status %d body %q, want HTTP/2 200 ok", resp.Proto, resp.StatusCode, body)
	}
	if dialCount != 2 {
		t.Fatalf("dialCount = %d, want HTTP/2 retry on a new connection", dialCount)
	}
	select {
	case err := <-errCh:
		t.Fatal(err)
	default:
	}
	_ = server.Close()
	<-firstDone
}

func TestSingleConnTransportDoesNotRetryNonIdempotentRequestAfterBadClientConn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, req.Body)
		_ = req.Body.Close()
	}()

	dialCount := 0
	tr := newTransport(
		ln.Addr().String(),
		func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialCount++
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, addr)
		},
		time.Second,
		true,
	)
	defer tr.Close()

	req, _ := http.NewRequest(http.MethodPost, "http://"+ln.Addr().String()+"/", nil)
	if _, err := tr.RoundTrip(req); err == nil {
		t.Fatal("RoundTrip unexpectedly succeeded")
	}
	if dialCount != 1 {
		t.Fatalf("dialCount = %d, want no retry for non-idempotent request", dialCount)
	}
	<-done
}

func TestSingleConnTransportDoesNotRetryIdempotencyKeyRequestWithBodyAfterBadClientConn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, req.Body)
		_ = req.Body.Close()
	}()

	dialCount := 0
	tr := newTransport(
		ln.Addr().String(),
		func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialCount++
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, addr)
		},
		time.Second,
		true,
	)
	defer tr.Close()

	req, _ := http.NewRequest(http.MethodPost, "http://"+ln.Addr().String()+"/", nil)
	req.Body = io.NopCloser(strings.NewReader("payload"))
	req.Header["Idempotency-Key"] = []string{}
	req.ContentLength = int64(len("payload"))
	if _, err := tr.RoundTrip(req); err == nil {
		t.Fatal("RoundTrip unexpectedly succeeded")
	}
	if dialCount != 1 {
		t.Fatalf("dialCount = %d, want no retry for request with body", dialCount)
	}
	<-done
}

func TestSingleConnTransportRetriesIdempotencyKeyRequestWithoutBodyAfterBadClientConn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		firstConn, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = http.ReadRequest(bufio.NewReader(firstConn))
		_ = firstConn.Close()

		secondConn, err := ln.Accept()
		if err != nil {
			return
		}
		defer secondConn.Close()
		req, err := http.ReadRequest(bufio.NewReader(secondConn))
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, req.Body)
		_ = req.Body.Close()
		_, _ = secondConn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
	}()

	dialCount := 0
	tr := newTransport(
		ln.Addr().String(),
		func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialCount++
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, addr)
		},
		time.Second,
		true,
	)
	defer tr.Close()

	req, _ := http.NewRequest(http.MethodPost, "http://"+ln.Addr().String()+"/", nil)
	req.Header["Idempotency-Key"] = []string{}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("response = %d %q, want 200 ok", resp.StatusCode, body)
	}
	if dialCount != 2 {
		t.Fatalf("dialCount = %d, want retry on a new connection", dialCount)
	}
	<-done
}

func TestShouldDiscardCanceledErrorWhenClientConnIsClosed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()

	tr := newTransport(
		ln.Addr().String(),
		func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, addr)
		},
		time.Second,
		true,
	)
	defer tr.Close()
	req, _ := http.NewRequest(http.MethodGet, "http://"+ln.Addr().String()+"/", nil)
	clientConn, err := tr.getClientConn(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	_ = clientConn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !shouldDiscardClientConnAfterRoundTripError(ctx, clientConn, context.Canceled) {
		t.Fatal("closed client conn was kept after request cancellation")
	}
	<-done
}

func TestSingleConnTransportClosesRetiredClientConnWhenDrained(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	requestStarted := make(chan struct{})
	releaseResponse := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, req.Body)
		_ = req.Body.Close()
		close(requestStarted)
		<-releaseResponse
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
	}()

	tr := newTransport(
		ln.Addr().String(),
		func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, addr)
		},
		time.Second,
		true,
	)
	defer tr.Close()

	logger, sink := newCaptureLogger(slog.LevelDebug)
	ctx := context.WithValue(context.Background(), connContextKey, &biConnContext{
		config: &runtimeConfig{state: runtimeConfigState{logger: logger}},
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+ln.Addr().String()+"/", nil)
	respCh := make(chan *http.Response, 1)
	errCh := make(chan error, 1)
	go func() {
		resp, err := tr.RoundTrip(req)
		if err != nil {
			errCh <- err
			return
		}
		respCh <- resp
	}()

	select {
	case <-requestStarted:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for request")
	}
	tr.mu.Lock()
	clientConn := tr.clientConn
	tr.mu.Unlock()
	if clientConn == nil {
		t.Fatal("client connection was not cached")
	}
	tr.discardClientConn(req.Context(), clientConn, false)
	tr.mu.Lock()
	retiredCount := len(tr.retired)
	tr.mu.Unlock()
	if retiredCount != 1 {
		t.Fatalf("retired count = %d, want 1 while request is in flight", retiredCount)
	}
	discardLog := requireLogMessage(t, sink, "transport client connection discarded")
	if got := attrBool(discardLog, "close_conn"); got {
		t.Fatal("discard log close_conn = true; want false")
	}
	requireLogMessage(t, sink, "transport retired client connection watching")

	close(releaseResponse)
	var resp *http.Response
	select {
	case err := <-errCh:
		t.Fatalf("RoundTrip: %v", err)
	case resp = <-respCh:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for response")
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	waitForCondition(t, time.Second, func() bool {
		tr.mu.Lock()
		defer tr.mu.Unlock()
		return len(tr.retired) == 0
	})
	if clientConn.Err() == nil {
		t.Fatal("retired client conn remained open after draining")
	}
	closeLog := requireLogMessage(t, sink, "transport retired client connection closed")
	if got := attrString(closeLog, "reason"); got != "drained" {
		t.Fatalf("retired close reason = %q; want drained", got)
	}
	<-done
}

func TestSingleConnTransportUsesNegotiatedHTTP2ForWrappedTLSConn(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Fatalf("origin request proto = %s, want HTTP/2", r.Proto)
		}
		_, _ = w.Write([]byte("ok"))
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	dialCount := 0
	tr := newTransport(
		server.Listener.Addr().String(),
		func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialCount++
			rawConn, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			tlsConn := tls.Client(rawConn, &tls.Config{
				InsecureSkipVerify: true,
				NextProtos:         []string{http2.NextProtoTLS, "http/1.1"},
			})
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				_ = rawConn.Close()
				return nil, err
			}
			if got := tlsConn.ConnectionState().NegotiatedProtocol; got != http2.NextProtoTLS {
				_ = tlsConn.Close()
				return nil, errors.New("test TLS server did not negotiate HTTP/2")
			}
			return struct{ net.Conn }{Conn: tlsConn}, nil
		},
		time.Second,
		false,
	)
	tr.setNegotiatedProtocol(http2.NextProtoTLS)
	defer tr.Close()

	req, _ := http.NewRequest(http.MethodGet, server.URL, nil)
	req.Proto = "HTTP/2.0"
	req.ProtoMajor = 2
	req.ProtoMinor = 0
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.ProtoMajor != 2 || string(body) != "ok" {
		t.Fatalf("response = proto %s body %q, want HTTP/2 ok", resp.Proto, body)
	}
	if dialCount != 1 {
		t.Fatalf("dialCount = %d, want 1", dialCount)
	}
}

func waitForCondition(t *testing.T, timeout time.Duration, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !fn() {
		t.Fatal("condition was not met before timeout")
	}
}

func closeHTTP2ConnAfterRequestHeaders(conn net.Conn) error {
	defer conn.Close()

	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(conn, preface); err != nil {
		return err
	}
	if string(preface) != http2.ClientPreface {
		return fmt.Errorf("client preface = %q, want HTTP/2 client preface", preface)
	}

	framer := http2.NewFramer(conn, conn)
	for {
		frame, err := framer.ReadFrame()
		if err != nil {
			return err
		}
		if _, ok := frame.(*http2.SettingsFrame); ok {
			break
		}
	}
	if err := framer.WriteSettings(); err != nil {
		return err
	}
	if err := framer.WriteSettingsAck(); err != nil {
		return err
	}
	for {
		frame, err := framer.ReadFrame()
		if err != nil {
			return err
		}
		if _, ok := frame.(*http2.HeadersFrame); ok {
			return nil
		}
	}
}
