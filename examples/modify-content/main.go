package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"

	"github.com/josexy/mitmproxy-go/v2"
	http "github.com/josexy/xhttp"
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
		// Request header modification: set and remove fields before forwarding.
		req.Header.Set("X-MITMPGO-REQ-HEADER", "MITMPGO")
		req.Header.Set("User-Agent", "mitmproxy-go/modify-content")
		req.Header.Del("Accept-Encoding")

		// Request wire order is configured on the request copy returned by the helper.
		var err error
		req, err = mitmproxy.WithRequestHeaderOrder(req, http.HeaderOrder{
			Headers: []string{"Accept", "x-mitmpgo-req-header", "user-agent"},
		})
		if err != nil {
			return nil, err
		}

		rsp, err := invoker.Invoke(req)
		if err != nil {
			return rsp, err
		}

		slog.Debug("HTTP",
			slog.Group("request", slog.String("host", req.Host), slog.String("method", req.Method), slog.String("url", req.URL.String())),
			slog.Group("response", slog.String("status", rsp.Status), slog.String("protocol", rsp.Proto)),
		)

		// Response header modification: set and remove fields before writing downstream.
		rsp.Header.Set("X-MITMPGO-RSP-HEADER", "MITMPGO")
		rsp.Header.Set("Cache-Control", "no-store")
		body := []byte("hello!")
		_ = rsp.Body.Close()
		rsp.Body = io.NopCloser(bytes.NewReader(body))
		rsp.ContentLength = int64(len(body))
		rsp.Header.Set("Content-Length", strconv.Itoa(len(body)))
		rsp.Header.Del("Content-Encoding")
		rsp.Header.Del("Transfer-Encoding")
		rsp.TransferEncoding = nil
		rsp.Trailer = nil
		// Choose the downstream wire order independently of the upstream response.
		if err := mitmproxy.SetResponseHeaderOrder(rsp, http.HeaderOrder{
			Headers: []string{"x-mitmpgo-rsp-header", "content-length"},
		}); err != nil {
			return nil, err
		}
		return rsp, err
	}

	handler, err := mitmproxy.NewMitmProxyHandler(
		mitmproxy.WithCACertPath(caCertPath),
		mitmproxy.WithCAKeyPath(caKeyPath),
		mitmproxy.WithLogger(logger),
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
