package mitmproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509/pkix"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/josexy/mitmproxy-go/internal/cert"
)

func TestNewDynamicMitmProxyHandler(t *testing.T) {
	certPath, keyPath := writeRuntimeTestCA(t, "dynamic ca")
	handler, err := NewDynamicMitmProxyHandler(
		WithCACertPath(certPath),
		WithCAKeyPath(keyPath),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Cleanup()

	if _, ok := handler.(RuntimeConfigManager); !ok {
		t.Fatalf("dynamic handler does not implement RuntimeConfigManager")
	}
}

func TestHTTP1PipelineDepthConfiguration(t *testing.T) {
	if got := newOptions().http1PipelineDepth; got != defaultHTTP1PipelineDepth {
		t.Fatalf("default HTTP/1 pipeline depth = %d; want %d", got, defaultHTTP1PipelineDepth)
	}

	certPath, keyPath := writeRuntimeTestCA(t, "pipeline config ca")
	handler, err := NewResourceLimitedDynamicMitmProxyHandler(
		WithCACertPath(certPath),
		WithCAKeyPath(keyPath),
		WithHTTP1PipelineDepth(1),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Cleanup()

	h := handler.(*mitmProxyHandler)
	if got := h.config.Load().state.http1PipelineDepth; got != 1 {
		t.Fatalf("configured HTTP/1 pipeline depth = %d; want 1", got)
	}
	if err := handler.SetHTTP1PipelineDepth(12); err != nil {
		t.Fatal(err)
	}
	if got := h.config.Load().state.http1PipelineDepth; got != 12 {
		t.Fatalf("runtime HTTP/1 pipeline depth = %d; want 12", got)
	}
	if err := handler.SetHTTP1PipelineDepth(0); !errors.Is(err, ErrInvalidHTTP1PipelineDepth) {
		t.Fatalf("SetHTTP1PipelineDepth err = %v; want ErrInvalidHTTP1PipelineDepth", err)
	}
	if got := h.config.Load().state.http1PipelineDepth; got != 12 {
		t.Fatalf("invalid update published depth %d; want 12", got)
	}
}

func TestInvalidHTTP1PipelineDepthRejectsHandler(t *testing.T) {
	certPath, keyPath := writeRuntimeTestCA(t, "invalid pipeline config ca")
	_, err := NewMitmProxyHandler(
		WithCACertPath(certPath),
		WithCAKeyPath(keyPath),
		WithHTTP1PipelineDepth(0),
	)
	if !errors.Is(err, ErrInvalidHTTP1PipelineDepth) {
		t.Fatalf("NewMitmProxyHandler err = %v; want ErrInvalidHTTP1PipelineDepth", err)
	}
}

func TestRuntimeConfigSettersDoNotPublishOnError(t *testing.T) {
	certPath, keyPath := writeRuntimeTestCA(t, "dynamic ca")
	handler, err := NewResourceLimitedDynamicMitmProxyHandler(
		WithCACertPath(certPath),
		WithCAKeyPath(keyPath),
		WithHTTPInterceptor(headerInterceptor("old")),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Cleanup()

	h := handler.(*mitmProxyHandler)
	oldCfg := h.config.Load()
	if err := handler.SetProxy("://bad"); err == nil {
		t.Fatalf("invalid proxy should fail")
	}
	if got := h.config.Load(); got != oldCfg {
		t.Fatalf("invalid proxy published a new config")
	}
	if err := handler.SetRootCAs(filepath.Join(t.TempDir(), "missing.pem")); err == nil {
		t.Fatalf("missing root ca should fail")
	}
	if got := h.config.Load(); got != oldCfg {
		t.Fatalf("invalid root ca published a new config")
	}
	if err := handler.SetClientCerts(map[string]ClientCert{
		"example.com": {CertPath: "missing.crt", KeyPath: "missing.key"},
	}); err == nil {
		t.Fatalf("missing client cert should fail")
	}
	if got := h.config.Load(); got != oldCfg {
		t.Fatalf("invalid client cert published a new config")
	}
	if err := handler.SetMaxWebsocketFramesPerForward(0); !errors.Is(err, ErrInvalidWebsocketFrameBufferSize) {
		t.Fatalf("SetMaxWebsocketFramesPerForward err = %v; want ErrInvalidWebsocketFrameBufferSize", err)
	}
	if got := h.config.Load(); got != oldCfg {
		t.Fatalf("invalid websocket frame size published a new config")
	}
	if err := handler.SetHandshakeTimeout(0); !errors.Is(err, ErrInvalidHandshakeTimeout) {
		t.Fatalf("SetHandshakeTimeout err = %v; want ErrInvalidHandshakeTimeout", err)
	}
	if err := handler.SetMaxHTTPHeaderBytes(0); !errors.Is(err, ErrInvalidHTTPHeaderSize) {
		t.Fatalf("SetMaxHTTPHeaderBytes err = %v; want ErrInvalidHTTPHeaderSize", err)
	}
	if err := handler.SetMaxWebsocketMessageBytes(128 << 20); !errors.Is(err, ErrInvalidWebsocketBufferedBytes) {
		t.Fatalf("SetMaxWebsocketMessageBytes err = %v; want ErrInvalidWebsocketBufferedBytes", err)
	}
	if err := handler.SetMaxWebsocketBufferedBytes(1); !errors.Is(err, ErrInvalidWebsocketBufferedBytes) {
		t.Fatalf("SetMaxWebsocketBufferedBytes err = %v; want ErrInvalidWebsocketBufferedBytes", err)
	}
	if got := h.config.Load(); got != oldCfg {
		t.Fatalf("invalid resource limits published a new config")
	}
}

func TestRuntimeConfigHTTPInterceptorAppliesToNewConnectionsOnly(t *testing.T) {
	certPath, keyPath := writeRuntimeTestCA(t, "dynamic ca")
	handler, err := NewDynamicMitmProxyHandler(
		WithCACertPath(certPath),
		WithCAKeyPath(keyPath),
		WithHTTPInterceptor(headerInterceptor("old")),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Cleanup()

	target := startRuntimeHTTPServer(t)
	proxy := startRuntimeProxyServer(t, handler)

	client1 := newRuntimeProxyClient(t, proxy)
	resp, err := client1.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	if got := resp.Header.Get("X-Runtime-Config"); got != "old" {
		t.Fatalf("old connection first response header = %q; want old", got)
	}
	closeResponseBody(t, resp)

	handler.SetHTTPInterceptor(headerInterceptor("new"))

	resp, err = client1.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	if got := resp.Header.Get("X-Runtime-Config"); got != "old" {
		t.Fatalf("old connection after update header = %q; want old", got)
	}
	closeResponseBody(t, resp)
	client1.CloseIdleConnections()

	client2 := newRuntimeProxyClient(t, proxy)
	defer client2.CloseIdleConnections()
	resp, err = client2.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	defer closeResponseBody(t, resp)
	if got := resp.Header.Get("X-Runtime-Config"); got != "new" {
		t.Fatalf("new connection after update header = %q; want new", got)
	}
}

func TestRuntimeConfigHostFiltersApplyToNewConnections(t *testing.T) {
	certPath, keyPath := writeRuntimeTestCA(t, "dynamic ca")
	handler, err := NewDynamicMitmProxyHandler(
		WithCACertPath(certPath),
		WithCAKeyPath(keyPath),
		WithHTTPInterceptor(headerInterceptor("intercepted")),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Cleanup()

	target := startRuntimeHTTPServer(t)
	proxy := startRuntimeProxyServer(t, handler)

	client := newRuntimeProxyClient(t, proxy)
	resp, err := client.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	closeResponseBody(t, resp)
	if got := resp.Header.Get("X-Runtime-Config"); got != "intercepted" {
		t.Fatalf("initial header = %q; want intercepted", got)
	}
	client.CloseIdleConnections()

	handler.SetHostFilters(nil, []string{"127.0.0.1"})

	client = newRuntimeProxyClient(t, proxy)
	defer client.CloseIdleConnections()
	resp, err = client.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	defer closeResponseBody(t, resp)
	if got := resp.Header.Get("X-Runtime-Config"); got != "" {
		t.Fatalf("excluded host header = %q; want empty passthrough response", got)
	}
}

func TestRuntimeConfigConcurrentSettersAndRequests(t *testing.T) {
	certPath, keyPath := writeRuntimeTestCA(t, "dynamic ca")
	handler, err := NewDynamicMitmProxyHandler(
		WithCACertPath(certPath),
		WithCAKeyPath(keyPath),
		WithHTTPInterceptor(headerInterceptor("initial")),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Cleanup()

	target := startRuntimeHTTPServer(t)
	proxy := startRuntimeProxyServer(t, handler)
	var requests atomic.Int64
	var wg sync.WaitGroup
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	wg.Go(func() {
		for ctx.Err() == nil {
			handler.SetHTTPInterceptor(headerInterceptor("a"))
			handler.SetHTTPInterceptor(headerInterceptor("b"))
			handler.SetHostFilters(nil, nil)
			handler.SetHTTP2Disabled(true)
			handler.SetHTTP2Disabled(false)
			handler.SetIdleConnTimeout(time.Second)
			handler.SetLogger(noopLogger)
			handler.SetLogger(nil)
			_ = handler.SetMaxWebsocketFramesPerForward(1)
		}
	})

	for range 4 {
		wg.Go(func() {
			for ctx.Err() == nil {
				client := newRuntimeProxyClient(t, proxy)
				resp, err := client.Get(target)
				if err == nil {
					closeResponseBody(t, resp)
					requests.Add(1)
				}
				client.CloseIdleConnections()
			}
		})
	}
	wg.Wait()
	if requests.Load() == 0 {
		t.Fatalf("expected at least one request during concurrent setter test")
	}
}

func closeResponseBody(t *testing.T, resp *http.Response) {
	t.Helper()
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

func headerInterceptor(value string) HTTPInterceptor {
	return func(ctx context.Context, req *http.Request, invoker HTTPDelegatedInvoker) (*http.Response, error) {
		resp, err := invoker.Invoke(req)
		if err != nil {
			return nil, err
		}
		resp.Header.Set("X-Runtime-Config", value)
		return resp, nil
	}
}

func startRuntimeHTTPServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Origin", "ok")
			w.Write([]byte("ok"))
		}),
	}
	t.Cleanup(func() { server.Close() })
	go func() {
		if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
			t.Errorf("target server: %v", err)
		}
	}()
	return "http://" + ln.Addr().String()
}

func startRuntimeProxyServer(t *testing.T, handler MitmProxyHandler) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler}
	t.Cleanup(func() { server.Close() })
	go func() {
		if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
			t.Errorf("proxy server: %v", err)
		}
	}()
	return "http://" + ln.Addr().String()
}

func newRuntimeProxyClient(t *testing.T, proxyAddr string) *http.Client {
	t.Helper()
	proxyURL, err := url.Parse(proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			ForceAttemptHTTP2: false,
		},
	}
}

func writeRuntimeTestCA(t *testing.T, commonName string) (string, string) {
	t.Helper()
	ca, err := cert.NewCaBuilder().
		Subject(pkix.Name{CommonName: commonName}).
		ValidateDays(1).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	keyPem, certPem := ca.Pem()
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	if err := os.WriteFile(certPath, certPem, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPem, 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}
