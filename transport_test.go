package mitmproxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
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
	if _, _, err := tr.getClientConn(context.Background(), req); err == nil || err.Error() != "request URL scheme is empty" {
		t.Fatalf("empty scheme err = %v; want empty scheme error", err)
	}

	req, _ = http.NewRequest(http.MethodGet, "ftp://example.com/path", nil)
	if _, _, err := tr.getClientConn(context.Background(), req); err == nil || err.Error() != `unsupported request URL scheme "ftp"` {
		t.Fatalf("unsupported scheme err = %v", err)
	}

	if err := tr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	req, _ = http.NewRequest(http.MethodGet, "http://example.com/path", nil)
	if _, _, err := tr.getClientConn(context.Background(), req); !errors.Is(err, net.ErrClosed) {
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
