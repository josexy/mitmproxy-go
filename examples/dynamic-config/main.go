package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	mitmproxy "github.com/josexy/mitmproxy-go"
)

func main() {
	var caCertPath string
	var caKeyPath string
	var proxyPort int
	var originPort int
	flag.StringVar(&caCertPath, "cacert", "", "ca cert path")
	flag.StringVar(&caKeyPath, "cakey", "", "ca key path")
	flag.IntVar(&proxyPort, "port", 10086, "proxy port")
	flag.IntVar(&originPort, "origin-port", 18080, "local origin server port")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	slog.SetDefault(logger)

	handler, err := mitmproxy.NewDynamicMitmProxyHandler(
		mitmproxy.WithCACertPath(caCertPath),
		mitmproxy.WithCAKeyPath(caKeyPath),
		mitmproxy.WithHTTPInterceptor(tagInterceptor("initial")),
		mitmproxy.WithIdleConnTimeout(30*time.Second),
		mitmproxy.WithErrorHandler(func(ec mitmproxy.ErrorContext) {
			slog.Error("mitm proxy error",
				slog.String("remote_addr", ec.RemoteAddr),
				slog.String("hostport", ec.Hostport),
				slog.String("error", ec.Error.Error()),
			)
		}),
	)
	if err != nil {
		panic(err)
	}
	defer handler.Cleanup()

	originServer := startOriginServer(originPort)
	defer originServer.Close()

	proxyServer := &http.Server{
		Addr:    fmt.Sprintf("127.0.0.1:%d", proxyPort),
		Handler: handler,
	}
	defer proxyServer.Close()
	go func() {
		if err := proxyServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			panic(err)
		}
	}()

	slog.Info("servers started",
		slog.String("origin", fmt.Sprintf("http://127.0.0.1:%d", originPort)),
		slog.String("proxy", fmt.Sprintf("http://127.0.0.1:%d", proxyPort)),
	)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go runDynamicConfigDemo(ctx, handler, proxyPort, originPort)

	<-ctx.Done()
	slog.Info("exit")
}

func runDynamicConfigDemo(ctx context.Context, handler mitmproxy.DynamicMitmProxyHandler, proxyPort, originPort int) {
	targetURL := fmt.Sprintf("http://127.0.0.1:%d/demo", originPort)
	proxyURL := fmt.Sprintf("http://127.0.0.1:%d", proxyPort)

	oldClient := newProxyClient(proxyURL)
	defer oldClient.CloseIdleConnections()
	newClient := newProxyClient(proxyURL)
	defer newClient.CloseIdleConnections()

	time.Sleep(300 * time.Millisecond)
	requestOnce(ctx, "old connection before update", oldClient, targetURL)

	slog.Info("update config: replace HTTP interceptor")
	handler.SetHTTPInterceptor(tagInterceptor("updated"))

	requestOnce(ctx, "old connection after interceptor update", oldClient, targetURL)
	requestOnce(ctx, "new connection after interceptor update", newClient, targetURL)
	newClient.CloseIdleConnections()

	slog.Info("update config: exclude 127.0.0.1 from interception")
	handler.SetHostFilters(nil, []string{"127.0.0.1"})

	requestOnce(ctx, "old connection after host filter update", oldClient, targetURL)
	requestOnce(ctx, "new connection after host filter update", newClient, targetURL)

	slog.Info("demo complete; press Ctrl+C to exit")
}

func requestOnce(ctx context.Context, label string, client *http.Client, targetURL string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		slog.Error("create request failed", slog.String("label", label), slog.String("error", err.Error()))
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		slog.Error("request failed", slog.String("label", label), slog.String("error", err.Error()))
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	slog.Info("request result",
		slog.String("label", label),
		slog.String("status", resp.Status),
		slog.String("x_mitmpgo_dynamic", resp.Header.Get("X-Mitmpgo-Dynamic")),
		slog.String("x_origin", resp.Header.Get("X-Origin")),
	)
}

func tagInterceptor(tag string) mitmproxy.HTTPInterceptor {
	return func(ctx context.Context, req *http.Request, invoker mitmproxy.HTTPDelegatedInvoker) (*http.Response, error) {
		slog.Info("intercept request",
			slog.String("tag", tag),
			slog.String("method", req.Method),
			slog.String("url", req.URL.String()),
		)
		resp, err := invoker.Invoke(req)
		if err != nil {
			return nil, err
		}
		resp.Header.Set("X-Mitmpgo-Dynamic", tag)
		return resp, nil
	}
}

func startOriginServer(port int) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/demo", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("X-Origin", "dynamic-config-demo")
		w.Write([]byte("ok"))
	})

	server := &http.Server{
		Addr:    fmt.Sprintf("127.0.0.1:%d", port),
		Handler: mux,
	}
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			panic(err)
		}
	}()
	return server
}

func newProxyClient(proxyAddr string) *http.Client {
	proxyURL, err := url.Parse(proxyAddr)
	if err != nil {
		panic(err)
	}
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			ForceAttemptHTTP2: false,
		},
	}
}
