package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

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

	httpInterceptor := func(ctx context.Context, req *http.Request, invoker mitmproxy.HTTPDelegatedInvoker) (*http.Response, error) {
		slog.Debug("request", slog.String("host", req.Host), slog.String("method", req.Method), slog.String("url", req.URL.String()))

		rsp, err := invoker.Invoke(req)
		if err != nil {
			return rsp, err
		}

		slog.Debug("response", slog.String("status", rsp.Status), slog.String("protocol", rsp.Proto))
		return rsp, err
	}

	handler, err := mitmproxy.NewMitmProxyHandler(
		mitmproxy.WithCACertPath(caCertPath),
		mitmproxy.WithCAKeyPath(caKeyPath),
		mitmproxy.WithHTTPInterceptor(httpInterceptor),
	)
	if err != nil {
		panic(err)
	}

	slog.Info("server started")
	go func() {
		http.ListenAndServe(fmt.Sprintf("%s:%d", "127.0.0.1", port), handler)
	}()

	inter := make(chan os.Signal, 1)
	signal.Notify(inter, syscall.SIGINT)
	<-inter

	handler.Cleanup()
	slog.Info("exit")
}
