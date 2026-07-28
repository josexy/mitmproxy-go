package mitmproxy_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509/pkix"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/josexy/mitmproxy-go"
	"github.com/josexy/mitmproxy-go/internal/cert"
	"github.com/josexy/mitmproxy-go/metadata"
	"golang.org/x/net/http2"
)

var (
	certdir        = "cert"
	mitmCertPath   = "cert/ca.crt"
	mitmKeyPath    = "cert/ca.key"
	serverCertPath = "cert/server.crt"
	serverKeyPath  = "cert/server.key"
)

func initCertPath() {
	tmpDir := os.TempDir()
	certdir = filepath.Join(tmpDir, "cert")
	mitmCertPath = filepath.Join(tmpDir, "cert", "ca.crt")
	mitmKeyPath = filepath.Join(tmpDir, "cert", "ca.key")
	serverCertPath = filepath.Join(tmpDir, "cert", "server.crt")
	serverKeyPath = filepath.Join(tmpDir, "cert", "server.key")
}

type testServerAddrs struct {
	http1 string
	h2    string
	h2c   string
	https string
}

func startSimpleHttpServer(t *testing.T) (testServerAddrs, func()) {
	certificate, err := tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	httpListener := listenLocalhost(t)
	httpsListener := listenLocalhost(t)
	h2cListener := listenLocalhost(t)
	https1Listener := listenLocalhost(t)

	httpServer := &http.Server{
		Handler: mux,
	}
	httpsServer := &http.Server{
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{certificate},
		},
	}
	h2cProtocols := &http.Protocols{}
	h2cProtocols.SetHTTP1(true)
	h2cProtocols.SetUnencryptedHTTP2(true)
	h2cServer := &http.Server{
		Handler:   mux,
		Protocols: h2cProtocols,
	}

	https1Server := &http.Server{
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{certificate},
		},
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}
	go func() {
		t.Logf("start HTTP1.1 server on %s", httpListener.Addr())
		if err := httpServer.Serve(httpListener); err != nil && err != http.ErrServerClosed {
			t.Errorf("HTTP1.1 server failed: %v", err)
		}
	}()
	go func() {
		t.Logf("start HTTP2 over TLS server on %s", httpsListener.Addr())
		if err := httpsServer.ServeTLS(httpsListener, "", ""); err != nil && err != http.ErrServerClosed {
			t.Errorf("HTTP2 over TLS server failed: %v", err)
		}
	}()
	go func() {
		t.Logf("start H2C server on %s", h2cListener.Addr())
		if err := h2cServer.Serve(h2cListener); err != nil && err != http.ErrServerClosed {
			t.Errorf("H2C server failed: %v", err)
		}
	}()
	go func() {
		t.Logf("start HTTP1 over TLS server on %s", https1Listener.Addr())
		if err := https1Server.ServeTLS(https1Listener, "", ""); err != nil && err != http.ErrServerClosed {
			t.Errorf("HTTP1 over TLS server failed: %v", err)
		}
	}()

	addrs := testServerAddrs{
		http1: httpListener.Addr().String(),
		h2:    httpsListener.Addr().String(),
		h2c:   h2cListener.Addr().String(),
		https: https1Listener.Addr().String(),
	}
	return addrs, func() {
		httpServer.Close()
		httpsServer.Close()
		h2cServer.Close()
		https1Server.Close()
	}
}

func listenLocalhost(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

func testHTTPRequest(typ, proxyAddr, targetAddr string) (statusCode int, proto string, err error) {
	u, err := url.Parse(proxyAddr)
	if err != nil {
		return
	}
	u2, err := url.Parse(targetAddr)
	if err != nil {
		return
	}
	proxyDialer := mitmproxy.NewProxyDialer(u, nil)
	conn, err := proxyDialer.Dial("tcp", u2.Host)
	if err != nil {
		return
	}
	var transport http.RoundTripper
	transport = &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return conn, nil
		},
	}
	if typ == "h2" || typ == "https" {
		transport = &http.Transport{
			ForceAttemptHTTP2: true,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return conn, nil
			},
		}
	}
	if typ == "h2c" {
		transport = &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				return conn, nil
			},
		}
	}
	client := &http.Client{
		Transport: transport,
	}
	rsp, err := client.Get(targetAddr)
	if err != nil {
		return
	}
	defer rsp.Body.Close()
	conn.Close()
	return rsp.StatusCode, rsp.Proto, nil
}

func genCACertAndKey() {
	caCert, err := cert.NewCaBuilder().
		Subject(pkix.Name{CommonName: "example.ca.com"}).
		ValidateDays(3650).
		Build()
	if err != nil {
		panic(err)
	}

	keyPem, certPem := caCert.Pem()
	os.Mkdir(certdir, 0755)
	os.WriteFile(mitmCertPath, certPem, 0644)
	os.WriteFile(mitmKeyPath, keyPem, 0644)
}

func genServerCertAndKey() {
	cert, err := cert.NewCertificateBuilder().
		Subject(pkix.Name{CommonName: "localhost"}).
		IPAddresses([]net.IP{net.ParseIP("127.0.0.1")}).
		DNSNames([]string{"localhost"}).
		ValidateDays(365).
		ServerAuth().
		BuildFromCA(nil)
	if err != nil {
		panic(err)
	}

	keyPem, certPem := cert.Pem()
	os.Mkdir(certdir, 0755)
	os.WriteFile(serverCertPath, certPem, 0644)
	os.WriteFile(serverKeyPath, keyPem, 0644)
}

func buildMitmHandler(t *testing.T, interceptor mitmproxy.HTTPInterceptor) mitmproxy.MitmProxyHandler {
	handler, err := mitmproxy.NewMitmProxyHandler(
		mitmproxy.WithCACertPath(mitmCertPath),
		mitmproxy.WithCAKeyPath(mitmKeyPath),
		mitmproxy.WithRootCAs(serverCertPath),
		mitmproxy.WithHTTPInterceptor(interceptor),
		mitmproxy.WithErrorHandler(func(ec mitmproxy.ErrorContext) {
			t.Log(ec.RemoteAddr, ec.Hostport, ec.Error)
		}),
	)
	if err != nil {
		panic(err)
	}
	return handler
}

func TestMitmProxyHandler(t *testing.T) {
	initCertPath()
	genCACertAndKey()
	genServerCertAndKey()
	defer os.RemoveAll(certdir)

	handler := buildMitmHandler(t, func(ctx context.Context, req *http.Request, hi mitmproxy.HTTPDelegatedInvoker) (*http.Response, error) {
		resp, err := hi.Invoke(req)
		t.Logf("url: %s, req_proto: %s, rsp_proto: %s", req.URL, req.Proto, resp.Proto)
		return resp, err
	})

	proxyListener := listenLocalhost(t)
	proxyAddr := "http://" + proxyListener.Addr().String()
	proxyServer := &http.Server{Handler: handler}
	defer proxyServer.Close()

	go func() {
		if err := proxyServer.Serve(proxyListener); err != nil && err != http.ErrServerClosed {
			t.Errorf("proxy server failed: %v", err)
		}
	}()
	addrs, closeFunc := startSimpleHttpServer(t)
	time.Sleep(time.Second * 1)

	tests := []struct {
		typ        string
		proto      string
		addr       string
		statusCode int
	}{
		{"http/1.1", "HTTP/1.1", "http://" + addrs.http1, 200},
		{"h2", "HTTP/2.0", "https://" + addrs.h2, 200},
		{"h2c", "HTTP/2.0", "http://" + addrs.h2c, 200},
		{"https", "HTTP/1.1", "https://" + addrs.https, 200},
	}

	for _, test := range tests {
		statusCode, proto, err := testHTTPRequest(test.typ, proxyAddr, test.addr)
		if err != nil {
			t.Error(err)
		}
		if statusCode != test.statusCode {
			t.Errorf("type: %s, statusCode: %d, want: %d", test.typ, statusCode, test.statusCode)
		}
		if proto != test.proto {
			t.Errorf("type: %s, proto: %s, want: %s", test.typ, proto, test.proto)
		}
	}

	closeFunc()
}

func TestTLSRawTCPThroughMitm(t *testing.T) {
	initCertPath()
	genCACertAndKey()
	genServerCertAndKey()
	defer os.RemoveAll(certdir)

	certificate, err := tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte{0x00, 0x01, 0x02, 'r', 'a', 'w'}
	origin := listenLocalhost(t)
	defer origin.Close()
	originErr := make(chan error, 1)
	go func() {
		conn, acceptErr := origin.Accept()
		if acceptErr != nil {
			originErr <- acceptErr
			return
		}
		defer conn.Close()
		tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{certificate}})
		request := make([]byte, len(payload))
		if _, readErr := io.ReadFull(tlsConn, request); readErr != nil {
			originErr <- readErr
			return
		}
		_, writeErr := tlsConn.Write(request)
		originErr <- writeErr
	}()

	var intercepted atomic.Int32
	handler := buildMitmHandler(t, func(ctx context.Context, req *http.Request, hi mitmproxy.HTTPDelegatedInvoker) (*http.Response, error) {
		intercepted.Add(1)
		return hi.Invoke(req)
	})
	proxyLn := listenLocalhost(t)
	proxyServer := &http.Server{Handler: handler}
	go func() {
		if serveErr := proxyServer.Serve(proxyLn); serveErr != nil && serveErr != http.ErrServerClosed {
			t.Errorf("proxy server failed: %v", serveErr)
		}
	}()
	defer proxyServer.Close()

	proxyURL := &url.URL{Scheme: "http", Host: proxyLn.Addr().String()}
	tunnel, err := mitmproxy.NewProxyDialer(proxyURL, nil).Dial("tcp", origin.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	client := tls.Client(tunnel, &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"})
	defer client.Close()
	if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(client, response); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response, payload) {
		t.Fatalf("response = %x; want %x", response, payload)
	}
	if err := <-originErr; err != nil {
		t.Fatal(err)
	}
	if intercepted.Load() != 0 {
		t.Fatalf("HTTP interceptor called %d times for TLS raw TCP", intercepted.Load())
	}
}

func TestTLSRawTCPWithCustomALPNThroughMitm(t *testing.T) {
	initCertPath()
	genCACertAndKey()
	genServerCertAndKey()
	defer os.RemoveAll(certdir)

	certificate, err := tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	const rawALPN = "raw.test"
	greeting := []byte{0x00, 'r', 'e', 'a', 'd', 'y'}
	origin := listenLocalhost(t)
	defer origin.Close()
	originErr := make(chan error, 1)
	go func() {
		conn, acceptErr := origin.Accept()
		if acceptErr != nil {
			originErr <- acceptErr
			return
		}
		defer conn.Close()
		tlsConn := tls.Server(conn, &tls.Config{
			Certificates: []tls.Certificate{certificate},
			NextProtos:   []string{rawALPN},
		})
		if handshakeErr := tlsConn.Handshake(); handshakeErr != nil {
			originErr <- handshakeErr
			return
		}
		_, writeErr := tlsConn.Write(greeting)
		originErr <- writeErr
	}()

	var intercepted atomic.Int32
	handler := buildMitmHandler(t, func(ctx context.Context, req *http.Request, hi mitmproxy.HTTPDelegatedInvoker) (*http.Response, error) {
		intercepted.Add(1)
		return hi.Invoke(req)
	})
	proxyLn := listenLocalhost(t)
	proxyServer := &http.Server{Handler: handler}
	go func() {
		if serveErr := proxyServer.Serve(proxyLn); serveErr != nil && serveErr != http.ErrServerClosed {
			t.Errorf("proxy server failed: %v", serveErr)
		}
	}()
	defer proxyServer.Close()

	proxyURL := &url.URL{Scheme: "http", Host: proxyLn.Addr().String()}
	tunnel, err := mitmproxy.NewProxyDialer(proxyURL, nil).Dial("tcp", origin.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	client := tls.Client(tunnel, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "localhost",
		NextProtos:         []string{rawALPN},
	})
	defer client.Close()
	if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	if got := client.ConnectionState().NegotiatedProtocol; got != rawALPN {
		t.Fatalf("negotiated ALPN = %q; want %q", got, rawALPN)
	}
	response := make([]byte, len(greeting))
	if _, err := io.ReadFull(client, response); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response, greeting) {
		t.Fatalf("response = %x; want %x", response, greeting)
	}
	if err := <-originErr; err != nil {
		t.Fatal(err)
	}
	if intercepted.Load() != 0 {
		t.Fatalf("HTTP interceptor called %d times for custom-ALPN TLS raw TCP", intercepted.Load())
	}
}

func TestHTTPSConnectionTimestamps(t *testing.T) {
	initCertPath()
	genCACertAndKey()
	genServerCertAndKey()
	defer os.RemoveAll(certdir)

	addrs, closeOrigins := startSimpleHttpServer(t)
	defer closeOrigins()

	mdCh := make(chan metadata.MD, 1)
	handler := buildMitmHandler(t, func(ctx context.Context, req *http.Request, hi mitmproxy.HTTPDelegatedInvoker) (*http.Response, error) {
		resp, err := hi.Invoke(req)
		if err != nil {
			return nil, err
		}
		md, _ := metadata.FromContext(ctx)
		mdCh <- md.MD()
		return resp, nil
	})
	proxyLn := listenLocalhost(t)
	proxyServer := &http.Server{Handler: handler}
	go func() {
		if err := proxyServer.Serve(proxyLn); err != nil && err != http.ErrServerClosed {
			t.Errorf("proxy server failed: %v", err)
		}
	}()
	defer proxyServer.Close()

	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(&url.URL{Scheme: "http", Host: proxyLn.Addr().String()}),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
	resp, err := client.Get("https://" + addrs.https + "/")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	md := <-mdCh
	if md.SocketConnectStartTs.IsZero() || md.SocketConnectCompletedTs.IsZero() {
		t.Fatalf("socket timing missing: %#v", md)
	}
	if md.SSLHandshakeStartTs.IsZero() || md.SSLHandshakeCompletedTs.IsZero() {
		t.Fatalf("SSL timing missing: %#v", md)
	}
	if md.SSLHandshakeCompletedTs.Before(md.SSLHandshakeStartTs) {
		t.Fatalf("SSL handshake completed before it started: %#v", md)
	}
}
