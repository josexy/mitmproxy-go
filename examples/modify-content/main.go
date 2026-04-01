package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"

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

	errorHandler := func(ec mitmproxy.ErrorContext) {
		slog.Error("mitm proxy error",
			slog.String("remote_addr", ec.RemoteAddr),
			slog.String("hostport", ec.Hostport),
			slog.String("error", ec.Error.Error()),
		)
	}

	httpInterceptor := func(ctx context.Context, req *http.Request, invoker mitmproxy.HTTPDelegatedInvoker) (*http.Response, error) {
		req.Header.Add("X-MITMPGO-REQ-HEADER", "MITMPGO")

		rsp, err := invoker.Invoke(req)
		if err != nil {
			return rsp, err
		}

		slog.Debug("HTTP",
			slog.Group("request", slog.String("host", req.Host), slog.String("method", req.Method), slog.String("url", req.URL.String())),
			slog.Group("response", slog.String("status", rsp.Status), slog.String("protocol", rsp.Proto)),
		)

		rsp.Header.Add("X-MITMPGO-RSP-HEADER", "MITMPGO")
		rsp.Body.Close()
		rsp.Body = io.NopCloser(strings.NewReader("hello!"))
		return rsp, err
	}

	handler, err := mitmproxy.NewMitmProxyHandler(
		mitmproxy.WithCACertPath(caCertPath),
		mitmproxy.WithCAKeyPath(caKeyPath),
		mitmproxy.WithHTTPInterceptor(httpInterceptor),
		mitmproxy.WithErrorHandler(errorHandler),
	)
	if err != nil {
		panic(err)
	}

	defer handler.Cleanup()
	slog.Info("server started")
	http.ListenAndServe(fmt.Sprintf("%s:%d", "127.0.0.1", port), handler)
}
