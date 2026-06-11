package mitmproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
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
