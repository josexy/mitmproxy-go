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

func TestHTTP1TimingPhases(t *testing.T) {
	initCertPath()
	genCACertAndKey()
	genServerCertAndKey()
	defer os.RemoveAll(certdir)

	origin := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			time.Sleep(10 * time.Millisecond)
			_, _ = w.Write([]byte("ok"))
		}),
	}
	originLn := listenLocalhost(t)
	go func() {
		if err := origin.Serve(originLn); err != nil && err != http.ErrServerClosed {
			t.Errorf("origin server failed: %v", err)
		}
	}()
	defer origin.Close()

	timingCh := make(chan metadata.Timing, 1)
	handler := buildMitmHandler(t, func(ctx context.Context, req *http.Request, hi mitmproxy.HTTPDelegatedInvoker) (*http.Response, error) {
		resp, err := hi.Invoke(req)
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		_ = resp.Body.Close()
		resp.Body = io.NopCloser(bytes.NewReader(data))
		md, _ := metadata.FromContext(ctx)
		timingCh <- md.MD().Timing
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
		Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: proxyLn.Addr().String()}),
	}}
	resp, err := client.Post("http://"+originLn.Addr().String()+"/", "text/plain", bytes.NewReader([]byte("payload")))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	timing := <-timingCh
	assertTimingHasPhase(t, timing, metadata.SocketConnect)
	assertTimingHasPhase(t, timing, metadata.RequestUpload)
	assertTimingHasPhase(t, timing, metadata.WaitingResponse)
	assertTimingHasPhase(t, timing, metadata.ResponseDownload)
	if timing.Total <= 0 || timing.End.IsZero() {
		t.Fatalf("timing total/end not recorded: %#v", timing)
	}
}

func TestHTTPSTimingIncludesSSLHandshake(t *testing.T) {
	initCertPath()
	genCACertAndKey()
	genServerCertAndKey()
	defer os.RemoveAll(certdir)

	addrs, closeOrigins := startSimpleHttpServer(t)
	defer closeOrigins()

	timingCh := make(chan metadata.Timing, 1)
	handler := buildMitmHandler(t, func(ctx context.Context, req *http.Request, hi mitmproxy.HTTPDelegatedInvoker) (*http.Response, error) {
		resp, err := hi.Invoke(req)
		if err != nil {
			return nil, err
		}
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		resp.Body = io.NopCloser(bytes.NewReader([]byte("ok")))
		md, _ := metadata.FromContext(ctx)
		timingCh <- md.MD().Timing
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

	timing := <-timingCh
	assertTimingHasPhase(t, timing, metadata.SSLHandshake)
}

func TestKeepAliveTimingSkipsConnectionPhasesForReusedConnection(t *testing.T) {
	initCertPath()
	genCACertAndKey()
	genServerCertAndKey()
	defer os.RemoveAll(certdir)

	origin := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})}
	originLn := listenLocalhost(t)
	go func() {
		if err := origin.Serve(originLn); err != nil && err != http.ErrServerClosed {
			t.Errorf("origin server failed: %v", err)
		}
	}()
	defer origin.Close()

	timingCh := make(chan metadata.Timing, 2)
	handler := buildMitmHandler(t, func(ctx context.Context, req *http.Request, hi mitmproxy.HTTPDelegatedInvoker) (*http.Response, error) {
		resp, err := hi.Invoke(req)
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		_ = resp.Body.Close()
		resp.Body = io.NopCloser(bytes.NewReader(data))
		md, _ := metadata.FromContext(ctx)
		timingCh <- md.MD().Timing
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
		Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: proxyLn.Addr().String()}),
	}}
	for i := 0; i < 2; i++ {
		resp, err := client.Get("http://" + originLn.Addr().String() + "/")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
	}

	<-timingCh
	reusedTiming := <-timingCh
	if !reusedTiming.ConnectionReused {
		t.Fatalf("second request ConnectionReused = false; want true")
	}
	assertTimingMissingPhase(t, reusedTiming, metadata.SocketConnect)
}

func assertTimingHasPhase(t *testing.T, timing metadata.Timing, name metadata.TimingPhaseName) {
	t.Helper()
	for _, phase := range timing.Phases {
		if phase.Name == name {
			if phase.Duration < 0 {
				t.Fatalf("phase %s has negative duration: %#v", name, phase)
			}
			return
		}
	}
	t.Fatalf("timing missing phase %s: %#v", name, timing)
}

func assertTimingMissingPhase(t *testing.T, timing metadata.Timing, name metadata.TimingPhaseName) {
	t.Helper()
	for _, phase := range timing.Phases {
		if phase.Name == name {
			t.Fatalf("timing unexpectedly includes phase %s: %#v", name, timing)
		}
	}
}
