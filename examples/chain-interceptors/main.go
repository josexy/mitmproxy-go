package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/josexy/mitmproxy-go"
)

func main() {
	var caCertPath string
	var caKeyPath string
	var port int
	flag.StringVar(&caCertPath, "cacert", "", "ca cert path")
	flag.StringVar(&caKeyPath, "cakey", "", "ca key path")
	flag.IntVar(&port, "port", 10086, "proxy port")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	slog.SetDefault(logger)

	handler, err := mitmproxy.NewMitmProxyHandler(
		mitmproxy.WithCACertPath(caCertPath),
		mitmproxy.WithCAKeyPath(caKeyPath),
		mitmproxy.WithChainHTTPInterceptor(httpInterceptor1, httpInterceptor2, httpInterceptor3),
	)
	if err != nil {
		panic(err)
	}

	defer handler.Cleanup()
	slog.Info("server started")
	http.ListenAndServe(fmt.Sprintf("%s:%d", "127.0.0.1", port), handler)
}

func httpInterceptor1(ctx context.Context, req *http.Request, invoker mitmproxy.HTTPDelegatedInvoker) (*http.Response, error) {
	slog.Debug("httpInterceptor1 before", slog.String("host", req.Host), slog.String("method", req.Method), slog.String("url", req.URL.String()))
	rsp, err := invoker.Invoke(req)
	if err != nil {
		return rsp, err
	}
	slog.Debug("httpInterceptor1 after", slog.String("status", rsp.Status), slog.String("protocol", rsp.Proto))
	return rsp, err
}

func httpInterceptor2(ctx context.Context, req *http.Request, invoker mitmproxy.HTTPDelegatedInvoker) (*http.Response, error) {
	slog.Debug("httpInterceptor2 before", slog.String("host", req.Host), slog.String("method", req.Method), slog.String("url", req.URL.String()))
	rsp, err := invoker.Invoke(req)
	if err != nil {
		return rsp, err
	}
	slog.Debug("httpInterceptor2 after", slog.String("status", rsp.Status), slog.String("protocol", rsp.Proto))
	return rsp, err
}

func httpInterceptor3(ctx context.Context, req *http.Request, invoker mitmproxy.HTTPDelegatedInvoker) (*http.Response, error) {
	slog.Debug("httpInterceptor3 before", slog.String("host", req.Host), slog.String("method", req.Method), slog.String("url", req.URL.String()))
	rsp, err := invoker.Invoke(req)
	if err != nil {
		return rsp, err
	}
	slog.Debug("httpInterceptor3 after", slog.String("status", rsp.Status), slog.String("protocol", rsp.Proto))
	return rsp, err
}
