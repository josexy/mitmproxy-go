package mitmproxy_test

import (
	"context"
	"crypto/tls"
	"crypto/x509/pkix"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/josexy/mitmproxy-go"
	"github.com/josexy/mitmproxy-go/internal/cert"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
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
	certdir = filepath.Join(tmpDir, certdir)
	mitmCertPath = filepath.Join(tmpDir, mitmCertPath)
	mitmKeyPath = filepath.Join(tmpDir, mitmKeyPath)
	serverCertPath = filepath.Join(tmpDir, serverCertPath)
	serverKeyPath = filepath.Join(tmpDir, serverKeyPath)
}

func startSimpleHttpServer(t *testing.T) func() {
	certificate, err := tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
	if err != nil {
		panic(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	httpServer := &http.Server{
		Addr:    ":9090",
		Handler: mux,
	}
	httpsServer := &http.Server{
		Addr:    ":9091",
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{certificate},
		},
	}
	h2cServer := &http.Server{
		Addr:    ":9092",
		Handler: h2c.NewHandler(mux, &http2.Server{}),
	}

	https1Server := &http.Server{
		Addr:    ":9093",
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{certificate},
		},
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}
	go func() {
		t.Log("start HTTP1.1 server on :9090")
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			panic(err)
		}
	}()
	go func() {
		t.Log("start HTTP2 over TLS server on :9091")
		if err := httpsServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			panic(err)
		}
	}()
	go func() {
		t.Log("start H2C server on :9092")
		if err := h2cServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			panic(err)
		}
	}()
	go func() {
		t.Log("start HTTP1 over TLS server on :9093")
		if err := https1Server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			panic(err)
		}
	}()

	return func() {
		httpServer.Close()
		httpsServer.Close()
		h2cServer.Close()
		https1Server.Close()
	}
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

func startmitmpgo(t *testing.T, interceptor mitmproxy.HTTPInterceptor) mitmproxy.MitmProxyHandler {
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

	handler := startmitmpgo(t, func(ctx context.Context, req *http.Request, hi mitmproxy.HTTPDelegatedInvoker) (*http.Response, error) {
		resp, err := hi.Invoke(req)
		t.Logf("url: %s, req_proto: %s, rsp_proto: %s", req.URL, req.Proto, resp.Proto)
		return resp, err
	})

	proxyAddr := "http://127.0.0.1:10087"

	go func() { http.ListenAndServe(":10087", handler) }()
	closeFunc := startSimpleHttpServer(t)
	time.Sleep(time.Second * 1)

	tests := []struct {
		typ        string
		proto      string
		addr       string
		statusCode int
	}{
		{"http/1.1", "HTTP/1.1", "http://127.0.0.1:9090", 200},
		{"h2", "HTTP/2.0", "https://127.0.0.1:9091", 200},
		{"h2c", "HTTP/2.0", "http://127.0.0.1:9092", 200},
		{"https", "HTTP/1.1", "https://127.0.0.1:9093", 200},
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
