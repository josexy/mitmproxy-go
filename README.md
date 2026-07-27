# mitmproxy-go

An easy-to-use and flexible MITM proxy library for Go. It can intercept and inspect HTTP, HTTPS, HTTP/2, h2c, WebSocket, and WSS traffic, and it can run as either an HTTP proxy or a SOCKS5 proxy.

## Features

- HTTP/1.1 keep-alive and end-to-end pipelining, HTTP/2 over TLS, and h2c support
- HTTPS interception with custom CA certificates
- WebSocket and secure WebSocket interception
- HTTP proxy mode and SOCKS5 proxy mode
- HTTP interceptor chaining
- Host include/exclude filtering with wildcard matching
- Upstream HTTP CONNECT and SOCKS5 proxy support
- Optional custom root CAs and client certificates for mTLS
- uTLS-based ClientHello and ALPN mirroring for upstream TLS handshakes
- Request metadata for TLS, timing, and connection details
- Optional structured internal logging through `log/slog`
- Runtime config updates for new connections

## Installation

```bash
go get github.com/josexy/mitmproxy-go
```

## Prerequisites

The handler loads a CA certificate and private key at startup. Generate a local CA before running the examples:

```bash
chmod +x ./tools/gen_cert.sh
OUTDIR=certs ./tools/gen_cert.sh
```

The script writes `ca.crt`, `ca.key`, `server.crt`, `server.key`, `client.crt`, and `client.key` to `OUTDIR`. Clients that use the proxy must trust the generated `ca.crt`.

The generator can be customized with environment variables:

```bash
OUTDIR=certs \
CA_DOMAIN=example.ca.com \
DOMAINS=localhost,127.0.0.1 \
IPS=127.0.0.1 \
./tools/gen_cert.sh
```

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

	fmt.Println("proxy listening on 127.0.0.1:8080")
	log.Fatal(http.ListenAndServe("127.0.0.1:8080", handler))
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

	ln, err := net.Listen("tcp", "127.0.0.1:1080")
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	fmt.Println("SOCKS5 proxy listening on 127.0.0.1:1080")
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

The examples intentionally listen on loopback. The handler does not authenticate downstream HTTP proxy clients, and SOCKS5 currently supports only the no-authentication method. Before exposing either listener on a non-loopback address, enforce client authentication and destination ACLs in the surrounding server or network layer. Otherwise the process becomes an open proxy and may expose localhost, private networks, or cloud metadata endpoints.

## Options

### Core Options

```go
mitmproxy.WithCACertPath("certs/ca.crt")
mitmproxy.WithCAKeyPath("certs/ca.key")
mitmproxy.WithStreamBaseContext(ctx)
mitmproxy.WithLogger(slog.Default())
mitmproxy.WithErrorHandler(func(ec mitmproxy.ErrorContext) {})
```

Internal proxy logging is disabled by default. Pass `WithLogger(logger)` to enable structured `slog` output; pass `WithLogger(nil)` to disable it. Log messages are prefixed with `[mitmproxy-go]`. Core logs include connection, routing, TLS, HTTP, HTTP/2, WebSocket, transport retry, and runtime config metadata, but do not log URL credentials/query strings, headers, bodies, WebSocket payloads, or raw certificates.

HTTP/1 pipeline diagnostics are emitted at `Debug` with messages beginning `http1 pipeline` or `http1 upstream`. Correlate a request with `pipeline_sequence` and `target`; `in_flight`, `pipeline_depth`, `status_code`, and duration fields show where it is waiting. Upstream failures, downstream write failures, and automatic serial downgrade are emitted at `Warn` with error and retry/degrade fields.

### Upstream and Transport

```go
mitmproxy.WithProxy("http://127.0.0.1:8080")
mitmproxy.WithProxy("socks5://127.0.0.1:1080")
mitmproxy.WithDisableProxy()
mitmproxy.WithDialer(&net.Dialer{Timeout: 30 * time.Second})
mitmproxy.WithIdleConnTimeout(60 * time.Second)
mitmproxy.WithHandshakeTimeout(10 * time.Second)
mitmproxy.WithMaxHTTPHeaderBytes(1 << 20)
mitmproxy.WithHTTP1PipelineDepth(8)
mitmproxy.WithDisableHTTP2()
mitmproxy.WithSkipVerifySSLFromServer()
```

`WithIdleConnTimeout` defaults to 90 seconds and bounds how long an idle HTTP keep-alive connection, together with the upstream connection pinned to it, is kept around. Pass `0` to disable it.

`WithHTTP1PipelineDepth` defaults to 8 and bounds the number of HTTP/1 requests on one client connection that have not completed writing back. Requests for the same origin are pipelined on one upstream HTTP/1.1 connection; requests for different origins use separate upstream connections and may run concurrently. Responses are always returned in the client's original request order. Set the depth to 1 to retain keep-alive while disabling pipelining. `Expect: 100-continue`, protocol upgrades, and connection-closing requests remain ordering barriers.

If `WithProxy` is not set, `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` environment variables are considered. HTTP, HTTPS CONNECT, SOCKS5, and SOCKS5H upstream proxy URLs are supported. Destination hostnames are resolved locally before the resolved IP address is sent to an upstream proxy. `WithDisableProxy` disables both explicit and environment proxy settings.

`WithDisableHTTP2` forces HTTP/1.1 upstream traffic and disables h2c handling. When HTTP/2 is enabled, h2c prior-knowledge connections can be inspected; HTTP/1.1 `Upgrade: h2c` handshakes are forwarded transparently as passthrough tunnels.

### TLS and Certificate Options

```go
mitmproxy.WithRootCAs("certs/internal-ca.crt", "certs/partner-ca.crt")
mitmproxy.WithClientCert("example.com", mitmproxy.ClientCert{
	CertPath: "certs/client.crt",
	KeyPath:  "certs/client.key",
})
mitmproxy.WithCertCachePool(2048, 30, 15)
```

HTTPS and WSS interception automatically captures the client's TLS ClientHello, fingerprints it with uTLS (`github.com/refraction-networking/utls`), patches SNI/ALPN for the target server, and uses that spec for the upstream TLS handshake. `WithDisableHTTP2` also removes `h2` from mirrored ALPN protocols.

`WithCertCachePool(capacity, intervalSecond, expireSecond)` configures the generated certificate cache. `capacity` must be a multiple of 256 when it is set; the interval and expiration values are seconds.

### Interceptors

```go
mitmproxy.WithHTTPInterceptor(httpInterceptor)
mitmproxy.WithChainHTTPInterceptor(interceptor1, interceptor2, interceptor3)
mitmproxy.WithWebsocketInterceptor(websocketInterceptor)
mitmproxy.WithMaxWebsocketFramesPerForward(4096)
mitmproxy.WithMaxWebsocketMessageBytes(16 << 20)
mitmproxy.WithMaxWebsocketBufferedBytes(64 << 20)
```

When both `WithHTTPInterceptor` and `WithChainHTTPInterceptor` are configured, the single interceptor runs first and then the chain runs in the order provided.

HTTP interceptors may be called concurrently for pipelined requests from the same HTTP/1.1 client connection, just as they may be for HTTP/2 streams and independent clients. Interceptors that share mutable state must synchronize it.

For WebSocket frames received from `WebsocketFramesWatcher`, call either `frame.Invoke()` to forward the frame or `frame.Release()` to drop it and release the backing buffer. `frame.Invoke()` releases the backing buffer after forwarding.

### Host Filtering

```go
mitmproxy.WithIncludeHosts("api.example.com", "*.example.org")
mitmproxy.WithExcludeHosts("*.cdn.com", "static.example.com")
```

`WithExcludeHosts` takes precedence over `WithIncludeHosts`.

## Dynamic Runtime Config

Use `NewResourceLimitedDynamicMitmProxyHandler` when runtime updates, including resource limits, are needed. `NewDynamicMitmProxyHandler` remains available with its original interface for source compatibility:

```go
handler, err := mitmproxy.NewResourceLimitedDynamicMitmProxyHandler(
	mitmproxy.WithCACertPath("certs/ca.crt"),
	mitmproxy.WithCAKeyPath("certs/ca.key"),
	mitmproxy.WithHTTPInterceptor(initialInterceptor),
)
if err != nil {
	log.Fatal(err)
}

handler.SetHTTPInterceptor(updatedInterceptor)
handler.SetHostFilters(nil, []string{"*.cdn.example.com"})
handler.SetLogger(slog.Default())
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
err := handler.SetHandshakeTimeout(10 * time.Second)
err = handler.SetMaxHTTPHeaderBytes(1 << 20)
err = handler.SetHTTP1PipelineDepth(8)
handler.SetSkipVerifySSLFromServer(true)
handler.SetHTTP2Disabled(true)
handler.SetStreamBaseContext(ctx)
handler.SetLogger(logger)

handler.SetErrorHandler(errorHandler)
handler.SetHTTPInterceptor(httpInterceptor)
handler.SetChainHTTPInterceptors(interceptor1, interceptor2)
handler.SetWebsocketInterceptor(websocketInterceptor)
err = handler.SetMaxWebsocketFramesPerForward(4096)
err = handler.SetMaxWebsocketMessageBytes(16 << 20)
err = handler.SetMaxWebsocketBufferedBytes(64 << 20)
```

`SetRootCAs`, `SetClientCerts`, `SetProxy`, `SetProxyDisabled`, `SetDialer`, and resource-limit setters can return errors. If validation fails, the previous runtime config remains active.

`SetHTTPInterceptor` replaces any previously configured HTTP interceptor chain. `SetChainHTTPInterceptors` replaces any previously configured single HTTP interceptor.

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
	"time"

	mitmproxy "github.com/josexy/mitmproxy-go"
	"github.com/josexy/mitmproxy-go/metadata"
)

func httpInterceptor(ctx context.Context, req *http.Request, invoker mitmproxy.HTTPDelegatedInvoker) (*http.Response, error) {
	mdCtx, _ := metadata.FromContext(ctx)
	md := mdCtx.MD()

	fmt.Printf("target: %s\n", md.RequestHostport)
	fmt.Printf("local addr: %s -> %s\n", md.LocalAddrInfo.SourceAddr, md.LocalAddrInfo.DestinationAddr)
	fmt.Printf("remote addr: %s -> %s\n", md.RemoteAddrInfo.SourceAddr, md.RemoteAddrInfo.DestinationAddr)
	fmt.Printf("local connected at: %v\n", md.LocalConnectionEstablishedTs)
	fmt.Printf("remote connected at: %v\n", md.RemoteConnectionEstablishedTs)
	fmt.Printf("dns lookup: %v -> %v (%v)\n",
		md.DNSLookupStartTs, md.DNSLookupCompletedTs,
		durationBetween(md.DNSLookupStartTs, md.DNSLookupCompletedTs))
	fmt.Printf("socket connect: %v -> %v (%v)\n",
		md.SocketConnectStartTs, md.SocketConnectCompletedTs,
		durationBetween(md.SocketConnectStartTs, md.SocketConnectCompletedTs))
	fmt.Printf("ssl handshake: %v -> %v (%v)\n",
		md.SSLHandshakeStartTs, md.SSLHandshakeCompletedTs,
		durationBetween(md.SSLHandshakeStartTs, md.SSLHandshakeCompletedTs))
	fmt.Printf("request processed at: %v\n", md.RequestProcessedTs)

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

func durationBetween(start, end time.Time) time.Duration {
	if start.IsZero() || end.IsZero() || end.Before(start) {
		return 0
	}
	return end.Sub(start)
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

Then send a request through the proxy:

```bash
curl -x http://127.0.0.1:10086 --cacert certs/ca.crt https://example.com
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

This project is available under the MIT License.
