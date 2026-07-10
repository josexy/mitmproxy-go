package mitmproxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/josexy/mitmproxy-go/metadata"
)

func TestHostPortNoPort(t *testing.T) {
	tests := []struct {
		raw        string
		hostPort   string
		hostNoPort string
	}{
		{"http://example.com", "example.com:80", "example.com"},
		{"https://example.com", "example.com:443", "example.com"},
		{"wss://example.com", "example.com:443", "example.com"},
		{"http://example.com:8080", "example.com:8080", "example.com"},
		{"http://[::1]", "[::1]:80", "[::1]"},
		{"http://[::1]:8080", "[::1]:8080", "[::1]"},
	}

	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			u, err := url.Parse(tt.raw)
			if err != nil {
				t.Fatal(err)
			}
			hostPort, hostNoPort := hostPortNoPort(u)
			if hostPort != tt.hostPort || hostNoPort != tt.hostNoPort {
				t.Fatalf("hostPortNoPort = %q, %q; want %q, %q", hostPort, hostNoPort, tt.hostPort, tt.hostNoPort)
			}
		})
	}
}

func TestHTTPProxyDialerDial(t *testing.T) {
	t.Run("success with auth header", func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()

		reqCh := make(chan *http.Request, 1)
		go func() {
			req, err := http.ReadRequest(bufio.NewReader(server))
			if err != nil {
				t.Errorf("ReadRequest: %v", err)
				return
			}
			reqCh <- req
			_, _ = server.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		}()

		proxyURL, _ := url.Parse("http://user:pass@proxy.example:8080")
		dialer := &httpProxyDialer{
			proxyURL: proxyURL,
			forwardDial: func(network, addr string) (net.Conn, error) {
				if network != "tcp" || addr != "proxy.example:8080" {
					t.Fatalf("forwardDial = %s, %s; want tcp, proxy.example:8080", network, addr)
				}
				return client, nil
			},
		}
		conn, err := dialer.Dial("tcp", "target.example:443")
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		defer conn.Close()

		req := <-reqCh
		if req.Method != http.MethodConnect || req.Host != "target.example:443" || req.RequestURI != "target.example:443" {
			t.Fatalf("CONNECT request mismatch: method=%s host=%s requestURI=%s", req.Method, req.Host, req.RequestURI)
		}
		wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:pass"))
		if got := req.Header.Get("Proxy-Authorization"); got != wantAuth {
			t.Fatalf("Proxy-Authorization = %q; want %q", got, wantAuth)
		}
	})

	t.Run("CONNECT response honors context cancellation", func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()
		go func() {
			_, _ = http.ReadRequest(bufio.NewReader(server))
			_, _ = io.Copy(io.Discard, server)
		}()
		proxyURL, _ := url.Parse("http://proxy.example")
		dialer := &httpProxyDialer{
			proxyURL: proxyURL,
			forwardDial: func(string, string) (net.Conn, error) {
				return client, nil
			},
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancel()
		if _, err := dialer.DialContext(ctx, "tcp", "target.example:443"); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("DialContext err = %v; want context deadline exceeded", err)
		}
	})

	t.Run("HTTPS proxy", func(t *testing.T) {
		requestCh := make(chan *http.Request, 1)
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			requestCh <- req
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()
		proxyURL, _ := url.Parse(server.URL)
		tlsConfig := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
		dialer := &httpProxyDialer{
			proxyURL:  proxyURL,
			tlsConfig: tlsConfig,
			forwardDial: func(network, addr string) (net.Conn, error) {
				return net.Dial(network, server.Listener.Addr().String())
			},
		}
		conn, err := dialer.Dial("tcp", "target.invalid:443")
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		select {
		case req := <-requestCh:
			if req.Method != http.MethodConnect || req.Host != "target.invalid:443" {
				t.Fatalf("request = %s %s", req.Method, req.Host)
			}
		case <-time.After(time.Second):
			t.Fatal("HTTPS proxy did not receive CONNECT")
		}
	})

	t.Run("forward dial error", func(t *testing.T) {
		wantErr := errors.New("dial failed")
		proxyURL, _ := url.Parse("http://proxy.example")
		dialer := &httpProxyDialer{
			proxyURL: proxyURL,
			forwardDial: func(string, string) (net.Conn, error) {
				return nil, wantErr
			},
		}
		if _, err := dialer.Dial("tcp", "target.example:443"); !errors.Is(err, wantErr) {
			t.Fatalf("Dial err = %v; want %v", err, wantErr)
		}
	})

	t.Run("non-200 status with reason", func(t *testing.T) {
		err := dialHTTPProxyResponse(t, "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
		if err == nil || err.Error() != "Proxy Authentication Required" {
			t.Fatalf("err = %v; want reason phrase", err)
		}
	})

	t.Run("non-200 status without reason", func(t *testing.T) {
		err := dialHTTPProxyResponse(t, "HTTP/1.1 500\r\n\r\n")
		if err == nil || err.Error() != "500" {
			t.Fatalf("err = %v; want raw status", err)
		}
	})

	t.Run("invalid response", func(t *testing.T) {
		err := dialHTTPProxyResponse(t, "not-http\r\n\r\n")
		if err == nil {
			t.Fatalf("expected response parse error")
		}
	})

	t.Run("bounded CONNECT response headers", func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()
		go func() {
			_, _ = http.ReadRequest(bufio.NewReader(server))
			_, _ = server.Write([]byte("HTTP/1.1 200 OK\r\nX-Large: " + strings.Repeat("a", 128)))
		}()
		proxyURL, _ := url.Parse("http://proxy.example")
		dialer := &httpProxyDialer{
			proxyURL:       proxyURL,
			maxHeaderBytes: 64,
			forwardDial: func(string, string) (net.Conn, error) {
				return client, nil
			},
		}
		if _, err := dialer.Dial("tcp", "target.example:443"); !errors.Is(err, ErrHTTPHeaderTooLarge) {
			t.Fatalf("Dial err = %v; want ErrHTTPHeaderTooLarge", err)
		}
	})

	t.Run("preserves bytes after CONNECT response", func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()
		go func() {
			_, _ = http.ReadRequest(bufio.NewReader(server))
			_, _ = server.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\nhello"))
		}()
		proxyURL, _ := url.Parse("http://proxy.example")
		dialer := &httpProxyDialer{
			proxyURL: proxyURL,
			forwardDial: func(string, string) (net.Conn, error) {
				return client, nil
			},
		}
		conn, err := dialer.Dial("tcp", "target.example:443")
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		data := make([]byte, 5)
		if _, err := io.ReadFull(conn, data); err != nil {
			t.Fatal(err)
		}
		if string(data) != "hello" {
			t.Fatalf("buffered data = %q; want hello", data)
		}
	})
}

func dialHTTPProxyResponse(t *testing.T, response string) error {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		_, _ = io.ReadAll(io.LimitReader(server, 4096))
	}()
	go func() {
		time.Sleep(10 * time.Millisecond)
		_, _ = server.Write([]byte(response))
	}()

	proxyURL, _ := url.Parse("http://proxy.example")
	dialer := &httpProxyDialer{
		proxyURL: proxyURL,
		forwardDial: func(string, string) (net.Conn, error) {
			return client, nil
		},
	}
	_, err := dialer.Dial("tcp", "target.example:443")
	return err
}

func TestProxyDialerDirectDialAndRemoteAddr(t *testing.T) {
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
		_, _ = conn.Write([]byte("ok"))
	}()

	dialer := NewProxyDialer(nil, &net.Dialer{Timeout: time.Second})
	conn, err := dialer.DialTCP(ln.Addr().String())
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	defer conn.Close()
	if conn.RemoteAddr().String() != ln.Addr().String() {
		t.Fatalf("RemoteAddr = %s; want %s", conn.RemoteAddr(), ln.Addr())
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ok" {
		t.Fatalf("read = %q, %v; want ok, nil", buf, err)
	}
	<-done
}

func TestProxyDialerTimeoutIncludesProxyHandshake(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan struct{})
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		close(accepted)
		_, _ = http.ReadRequest(bufio.NewReader(conn))
		_, _ = io.Copy(io.Discard, conn)
	}()

	proxyURL := &url.URL{Scheme: "http", Host: listener.Addr().String()}
	dialer := NewProxyDialer(proxyURL, &net.Dialer{Timeout: 30 * time.Millisecond})
	start := time.Now()
	if _, err := dialer.DialContext(context.Background(), "tcp", "localhost:443"); err == nil {
		t.Fatal("DialContext succeeded; want proxy handshake timeout")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("proxy handshake timeout took %s", elapsed)
	}
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("proxy did not accept the connection")
	}
}

func TestProxyDialerResolvesProxyTargetLocally(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	targetCh := make(chan string, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		req, readErr := http.ReadRequest(bufio.NewReader(conn))
		if readErr != nil {
			return
		}
		targetCh <- req.Host
		_, _ = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	}()

	proxyURL := &url.URL{Scheme: "http", Host: listener.Addr().String()}
	dialer := NewProxyDialer(proxyURL, &net.Dialer{Timeout: time.Second})
	conn, err := dialer.DialContext(context.Background(), "tcp", "localhost:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	proxyTarget := <-targetCh
	host, port, err := net.SplitHostPort(proxyTarget)
	if err != nil {
		t.Fatalf("proxy target = %q: %v", proxyTarget, err)
	}
	if net.ParseIP(host) == nil || port != "443" {
		t.Fatalf("proxy target = %q; want a locally resolved IP on port 443", proxyTarget)
	}
	if conn.RemoteAddr().String() != proxyTarget {
		t.Fatalf("RemoteAddr = %q; want %q", conn.RemoteAddr(), proxyTarget)
	}
}

func TestProxyDialerRecordsConnectionTimestampsForHostnames(t *testing.T) {
	dialer := NewProxyDialer(nil, &net.Dialer{Timeout: time.Second})
	md := metadata.NewMD()
	if _, err := dialer.DialTCPContextWithMetadata(context.Background(), "localhost:1", md); err == nil {
		t.Fatalf("DialTCPContextWithMetadata unexpectedly succeeded")
	}
	if _, ok := md.Get(metadata.DNSLookupStartTs); !ok {
		t.Fatalf("DNS lookup start was not recorded")
	}
	if _, ok := md.Get(metadata.DNSLookupCompletedTs); !ok {
		t.Fatalf("DNS lookup done was not recorded")
	}
	if _, ok := md.Get(metadata.SocketConnectStartTs); !ok {
		t.Fatalf("socket connect start was not recorded")
	}
	if _, ok := md.Get(metadata.SocketConnectCompletedTs); !ok {
		t.Fatalf("socket connect done was not recorded")
	}
}

func TestProxyDialerSkipsDNSForIPLiteral(t *testing.T) {
	dialer := NewProxyDialer(nil, &net.Dialer{Timeout: time.Second})
	md := metadata.NewMD()
	if _, err := dialer.DialTCPContextWithMetadata(context.Background(), "127.0.0.1:1", md); err == nil {
		t.Fatalf("DialTCPContextWithMetadata unexpectedly succeeded")
	}
	if _, ok := md.Get(metadata.DNSLookupStartTs); ok {
		t.Fatalf("DNS lookup start was recorded for IP literal")
	}
	if _, ok := md.Get(metadata.DNSLookupCompletedTs); ok {
		t.Fatalf("DNS lookup done was recorded for IP literal")
	}
	if _, ok := md.Get(metadata.SocketConnectStartTs); !ok {
		t.Fatalf("socket connect start was not recorded")
	}
	if _, ok := md.Get(metadata.SocketConnectCompletedTs); !ok {
		t.Fatalf("socket connect done was not recorded")
	}
}

func TestProxyDialerDialContextErrors(t *testing.T) {
	dialer := NewProxyDialer(nil, nil)
	if dialer.dialer == nil || dialer.dialer.Timeout != dialTimeout {
		t.Fatalf("default dialer = %#v; want dialTimeout", dialer.dialer)
	}
	if _, err := dialer.DialContext(context.Background(), "tcp", "bad-address"); err == nil {
		t.Fatalf("invalid address should fail")
	}
}

func TestProxyDialerDNSUsesDialContext(t *testing.T) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	dialer := NewProxyDialer(nil, &net.Dialer{Resolver: resolver})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := dialer.DialContext(ctx, "tcp", "unresolvable.invalid:80"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("DialContext err = %v; want context deadline exceeded", err)
	}
}

func TestEnvironmentProxyHonorsNoProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://proxy.example:8080")
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("NO_PROXY", "private.example")
	proxyURL, err := parseProxyFrom(false, "")
	if err != nil {
		t.Fatal(err)
	}
	dialer := newConfiguredProxyDialer(proxyURL, nil, true)
	got, err := dialer.proxyURLForAddress("private.example:443")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("proxy URL = %v; want direct connection", got)
	}
}

func TestEnvironmentHTTPSProxyIsSelected(t *testing.T) {
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("HTTPS_PROXY", "http://secure-proxy.example:8443")
	t.Setenv("NO_PROXY", "")
	proxyURL, err := parseProxyFrom(false, "")
	if err != nil {
		t.Fatal(err)
	}
	dialer := newConfiguredProxyDialer(proxyURL, nil, true)
	got, err := dialer.proxyURLForAddress("public.example:443")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Host != "secure-proxy.example:8443" {
		t.Fatalf("proxy URL = %v; want secure-proxy.example:8443", got)
	}
}

func TestParseProxyFrom(t *testing.T) {
	oldHTTP, hadHTTP := os.LookupEnv("HTTP_PROXY")
	oldHTTPS, hadHTTPS := os.LookupEnv("HTTPS_PROXY")
	oldNO, hadNO := os.LookupEnv("NO_PROXY")
	defer restoreEnv("HTTP_PROXY", oldHTTP, hadHTTP)
	defer restoreEnv("HTTPS_PROXY", oldHTTPS, hadHTTPS)
	defer restoreEnv("NO_PROXY", oldNO, hadNO)

	t.Setenv("HTTP_PROXY", "")
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("NO_PROXY", "")

	u, err := parseProxyFrom(true, "http://proxy.example:8080")
	if err != nil || u != nil {
		t.Fatalf("disabled parseProxyFrom = %v, %v; want nil, nil", u, err)
	}

	u, err = parseProxyFrom(false, "http://proxy.example:8080")
	if err != nil || u.String() != "http://proxy.example:8080" {
		t.Fatalf("explicit parseProxyFrom = %v, %v", u, err)
	}

	if _, err := parseProxyFrom(false, "://bad"); err == nil {
		t.Fatalf("invalid explicit proxy should fail")
	}

	t.Setenv("HTTP_PROXY", "http://env-proxy.example:8080")
	t.Setenv("HTTPS_PROXY", "")
	u, err = parseProxyFrom(false, "")
	if err != nil || !strings.Contains(u.String(), "env-proxy.example:8080") {
		t.Fatalf("env HTTP proxy = %v, %v", u, err)
	}

	t.Setenv("HTTP_PROXY", "")
	t.Setenv("HTTPS_PROXY", "http://env-https-proxy.example:8443")
	u, err = parseProxyFrom(false, "")
	if err != nil || !strings.Contains(u.String(), "env-https-proxy.example:8443") {
		t.Fatalf("env HTTPS proxy = %v, %v", u, err)
	}
}

func restoreEnv(key, value string, ok bool) {
	if ok {
		_ = os.Setenv(key, value)
		return
	}
	_ = os.Unsetenv(key)
}

func TestNetDialerFuncAndAddrConn(t *testing.T) {
	wantErr := errors.New("x")
	fn := netDialerFunc(func(network, addr string) (net.Conn, error) {
		if network != "tcp" || addr != "addr" {
			t.Fatalf("args = %s, %s; want tcp, addr", network, addr)
		}
		return nil, wantErr
	})
	if _, err := fn.Dial("tcp", "addr"); !errors.Is(err, wantErr) {
		t.Fatalf("Dial err = %v; want %v", err, wantErr)
	}

	conn := &addrConn{raddr: dummyAddr("remote"), Conn: nopConn{}}
	if conn.RemoteAddr().String() != "remote" {
		t.Fatalf("RemoteAddr = %s; want remote", conn.RemoteAddr())
	}
}

type nopConn struct{}

func (nopConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (nopConn) Write(p []byte) (int, error)      { return len(p), nil }
func (nopConn) Close() error                     { return nil }
func (nopConn) LocalAddr() net.Addr              { return dummyAddr("local") }
func (nopConn) RemoteAddr() net.Addr             { return dummyAddr("inner") }
func (nopConn) SetDeadline(time.Time) error      { return nil }
func (nopConn) SetReadDeadline(time.Time) error  { return nil }
func (nopConn) SetWriteDeadline(time.Time) error { return nil }
