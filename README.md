# mitmproxy-go

An easy-to-use and flexible MITM proxy library for Go that can intercept and inspect HTTP, HTTPS, HTTP/2, h2c, WebSocket, and WSS traffic.

## Features

- HTTP/1.1, HTTP/2, and h2c support
- HTTPS interception with custom CA certificates
- WebSocket and secure WebSocket interception
- HTTP proxy mode and SOCKS5 proxy mode
- HTTP interceptor chaining
- Host include/exclude filtering with wildcard matching
- Upstream proxy support
- Optional custom root CAs and client certificates for mTLS
- Request metadata for TLS, timing, and connection details
- Runtime config updates for new connections

## Installation

```bash
go get github.com/josexy/mitmproxy-go
```

## Prerequisites

HTTPS interception requires a CA certificate and private key:

```bash
chmod +x ./tools/gen_cert.sh
OUTDIR=certs ./tools/gen_cert.sh
```

Clients that use the proxy must trust the generated CA certificate.

## Quick Start

### HTTP Proxy

```go
package main

import (
	"fmt"
	"log"
	"net/http"

	mitmproxy "github.com/josexy/mitmproxy-go"
)

func main() {
	handler, err := mitmproxy.NewMitmProxyHandler(
		mitmproxy.WithCACertPath("certs/ca.crt"),
		mitmproxy.WithCAKeyPath("certs/ca.key"),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer handler.Cleanup()

	fmt.Println("proxy listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", handler))
}
```

### HTTP Interceptor

```go
package main

import (
	"context"
	"fmt"
	"net/http"

	mitmproxy "github.com/josexy/mitmproxy-go"
)

func httpInterceptor(ctx context.Context, req *http.Request, invoker mitmproxy.HTTPDelegatedInvoker) (*http.Response, error) {
	fmt.Printf("-> %s %s\n", req.Method, req.URL)

	resp, err := invoker.Invoke(req)
	if err != nil {
		return nil, err
	}

	fmt.Printf("<- %s\n", resp.Status)
	return resp, nil
}
```

```go
handler, err := mitmproxy.NewMitmProxyHandler(
	mitmproxy.WithCACertPath("certs/ca.crt"),
	mitmproxy.WithCAKeyPath("certs/ca.key"),
	mitmproxy.WithHTTPInterceptor(httpInterceptor),
)
```

### WebSocket Interceptor

```go
package main

import (
	"context"
	"log"
	"net/http"

	mitmproxy "github.com/josexy/mitmproxy-go"
)

func websocketInterceptor(ctx context.Context, req *http.Request, resp *http.Response, fw mitmproxy.WebsocketFramesWatcher) {
	log.Printf("websocket upgrade %s -> %d", req.URL.String(), resp.StatusCode)

	for {
		select {
		case <-ctx.Done():
			return
		case frame, ok := <-fw.Receive():
			if !ok {
				return
			}

			log.Printf("%s %d %q", frame.Direction(), frame.MessageType(), frame.DataBuffer().String())
			if err := frame.Invoke(); err != nil {
				log.Printf("forward websocket frame: %v", err)
			}
		}
	}
}
```

```go
handler, err := mitmproxy.NewMitmProxyHandler(
	mitmproxy.WithCACertPath("certs/ca.crt"),
	mitmproxy.WithCAKeyPath("certs/ca.key"),
	mitmproxy.WithWebsocketInterceptor(websocketInterceptor),
)
```

### SOCKS5 Proxy

```go
package main

import (
	"context"
	"fmt"
	"log"
	"net"

	mitmproxy "github.com/josexy/mitmproxy-go"
)

func main() {
	handler, err := mitmproxy.NewMitmProxyHandler(
		mitmproxy.WithCACertPath("certs/ca.crt"),
		mitmproxy.WithCAKeyPath("certs/ca.key"),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer handler.Cleanup()

	ln, err := net.Listen("tcp", ":1080")
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	fmt.Println("SOCKS5 proxy listening on :1080")
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}

		go func() {
			defer conn.Close()
			_ = handler.ServeSOCKS5(context.Background(), conn)
		}()
	}
}
```

## Options

### Core Options

```go
mitmproxy.WithCACertPath("certs/ca.crt")
mitmproxy.WithCAKeyPath("certs/ca.key")
mitmproxy.WithStreamBaseContext(ctx)
mitmproxy.WithErrorHandler(func(ec mitmproxy.ErrorContext) {})
```

### Upstream and Transport

```go
mitmproxy.WithProxy("http://127.0.0.1:8080")
mitmproxy.WithDisableProxy()
mitmproxy.WithDialer(&net.Dialer{Timeout: 30 * time.Second})
mitmproxy.WithIdleConnTimeout(60 * time.Second)
mitmproxy.WithDisableHTTP2()
mitmproxy.WithSkipVerifySSLFromServer()
```

### TLS and Certificate Options

```go
mitmproxy.WithRootCAs("certs/internal-ca.crt", "certs/partner-ca.crt")
mitmproxy.WithClientCert("example.com", mitmproxy.ClientCert{
	CertPath: "certs/client.crt",
	KeyPath:  "certs/client.key",
})
mitmproxy.WithCertCachePool(2048, 30, 15)
```

### Interceptors

```go
mitmproxy.WithHTTPInterceptor(httpInterceptor)
mitmproxy.WithChainHTTPInterceptor(interceptor1, interceptor2, interceptor3)
mitmproxy.WithWebsocketInterceptor(websocketInterceptor)
mitmproxy.WithMaxWebsocketFramesPerForward(4096)
```

### Host Filtering

```go
mitmproxy.WithIncludeHosts("api.example.com", "*.example.org")
mitmproxy.WithExcludeHosts("*.cdn.com", "static.example.com")
```

`WithExcludeHosts` takes precedence over `WithIncludeHosts`.

## Dynamic Runtime Config

Use `NewDynamicMitmProxyHandler` when runtime updates are needed:

```go
handler, err := mitmproxy.NewDynamicMitmProxyHandler(
	mitmproxy.WithCACertPath("certs/ca.crt"),
	mitmproxy.WithCAKeyPath("certs/ca.key"),
	mitmproxy.WithHTTPInterceptor(initialInterceptor),
)
if err != nil {
	log.Fatal(err)
}

handler.SetHTTPInterceptor(updatedInterceptor)
handler.SetHostFilters(nil, []string{"*.cdn.example.com"})
handler.SetHTTP2Disabled(true)
```

Runtime updates are published as immutable config snapshots. A connection captures one snapshot when it enters `Serve`, `ServeHTTP`, or `ServeSOCKS5`; updates only affect new connections. Existing HTTP keep-alive, HTTP/2, and WebSocket connections continue using the snapshot they started with.

Available runtime setters:

```go
handler.SetProxy("http://127.0.0.1:8080")
handler.SetProxyDisabled(true)
handler.SetDialer(&net.Dialer{Timeout: 30 * time.Second})
handler.SetHostFilters(includeHosts, excludeHosts)
handler.SetRootCAs("certs/internal-ca.crt")
handler.SetClientCerts(map[string]mitmproxy.ClientCert{
	"example.com": {
		CertPath: "certs/client.crt",
		KeyPath:  "certs/client.key",
	},
})

handler.SetIdleConnTimeout(60 * time.Second)
handler.SetSkipVerifySSLFromServer(true)
handler.SetHTTP2Disabled(true)
handler.SetStreamBaseContext(ctx)

handler.SetErrorHandler(errorHandler)
handler.SetHTTPInterceptor(httpInterceptor)
handler.SetChainHTTPInterceptors(interceptor1, interceptor2)
handler.SetWebsocketInterceptor(websocketInterceptor)
err := handler.SetMaxWebsocketFramesPerForward(4096)
```

`SetRootCAs`, `SetClientCerts`, `SetProxy`, `SetProxyDisabled`, `SetDialer`, and `SetMaxWebsocketFramesPerForward` can return errors. If validation fails, the previous runtime config remains active.

CA certificate/key and certificate cache pool settings are initialization-only:

```go
mitmproxy.WithCACertPath("certs/ca.crt")
mitmproxy.WithCAKeyPath("certs/ca.key")
mitmproxy.WithCertCachePool(2048, 30, 15)
```

## Metadata

Interceptors can read connection and TLS metadata from the request context:

```go
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"

	mitmproxy "github.com/josexy/mitmproxy-go"
	"github.com/josexy/mitmproxy-go/metadata"
)

func httpInterceptor(ctx context.Context, req *http.Request, invoker mitmproxy.HTTPDelegatedInvoker) (*http.Response, error) {
	mdCtx, _ := metadata.FromContext(ctx)
	md := mdCtx.MD()

	fmt.Printf("target: %s\n", md.RequestHostport)
	fmt.Printf("local connected at: %v\n", md.LocalConnectionEstablishedTs)
	fmt.Printf("remote connected at: %v\n", md.RemoteConnectionEstablishedTs)
	fmt.Printf("request processed at: %v\n", md.RequestProcessedTs)
	fmt.Printf("total timing: %v\n", md.Timing.Total)
	for _, phase := range md.Timing.Phases {
		fmt.Printf("%s: offset=%v duration=%v\n", phase.Label, phase.Offset, phase.Duration)
	}

	if md.TLSState != nil {
		fmt.Printf("selected ALPN: %s\n", md.TLSState.SelectedALPN)
		fmt.Printf("TLS version: %s\n", tls.VersionName(md.TLSState.SelectedTLSVersion))
		fmt.Printf("cipher suite: %s\n", tls.CipherSuiteName(md.TLSState.SelectedCipherSuite))
	}

	if md.ServerCertificate != nil {
		fmt.Printf("subject: %s\n", md.ServerCertificate.Subject.String())
		fmt.Printf("issuer: %s\n", md.ServerCertificate.Issuer.String())
		fmt.Printf("sha256: %s\n", md.ServerCertificate.Sha256FingerprintHex())
	}

	return invoker.Invoke(req)
}
```

## Examples

Current examples in this repository:

- `examples/helloworld`: minimal HTTP proxy with request/response logging
- `examples/dumper`: HTTP and WebSocket dumping example with metadata logging
- `examples/modify-content`: modifies request headers and response body
- `examples/chain-interceptors`: demonstrates ordered HTTP interceptor chaining
- `examples/dynamic-config`: demonstrates runtime config updates that affect new connections

Run them from the repository root.

### Hello World

```bash
go run ./examples/helloworld/main.go -cacert certs/ca.crt -cakey certs/ca.key -port 10086
```

### Dumper

```bash
# HTTP proxy mode
go run ./examples/dumper/main.go -cacert certs/ca.crt -cakey certs/ca.key -mode http -port 10086

# SOCKS5 proxy mode
go run ./examples/dumper/main.go -cacert certs/ca.crt -cakey certs/ca.key -mode socks5 -port 10086
```

### Modify Content

```bash
go run ./examples/modify-content/main.go -cacert certs/ca.crt -cakey certs/ca.key -port 10086
```

### Chain Interceptors

```bash
go run ./examples/chain-interceptors/main.go -cacert certs/ca.crt -cakey certs/ca.key -port 10086
```

### Dynamic Config

```bash
go run ./examples/dynamic-config/main.go -cacert certs/ca.crt -cakey certs/ca.key -port 10086 -origin-port 18080
```

The demo starts a local origin server, sends proxied requests, then updates the HTTP interceptor and host filters at runtime. Existing keep-alive connections keep their original config snapshot, while new connections use the latest config.

## Notes

- Call `handler.Cleanup()` before shutdown to stop background certificate cache cleanup.
- `WithStreamBaseContext` is useful when you need shared cancellation for long-lived HTTP/2 streams.
- If `WithIncludeHosts` is unset, traffic is intercepted by default unless excluded.

## Development

```bash
go test -v ./...
```

Format modified Go files with:

```bash
gofmt -w <files>
```

## License

This project is available under the terms specified in the repository.
