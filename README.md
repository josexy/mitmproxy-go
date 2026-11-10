# mitmproxy-go

An easy-to-use and flexible MITM proxy library for Go. It intercepts and inspects HTTP, HTTPS, HTTP/2, h2c, WebSocket, and WSS traffic, observes classified raw TCP tunnels, and runs as an HTTP proxy or a SOCKS5 proxy. Your application owns the listeners; the library handles interception, forwarding, and observation.

## Contents

- [Features](#features)
- [Installation](#installation)
- [Getting Started](#getting-started)
- [HTTP Interceptors](#http-interceptors)
- [WebSocket Interceptors](#websocket-interceptors)
- [Raw TCP Observation](#raw-tcp-observation)
- [Wire Fidelity](#wire-fidelity)
- [Observability](#observability)
- [Configuration](#configuration)
- [Runtime Configuration](#runtime-configuration)
- [Examples](#examples)
- [Development](#development)

## Features

- **Protocols:** HTTP/1.1 keep-alive and end-to-end pipelining, HTTP/2 over TLS, h2c, WebSocket and WSS, HTTP and SOCKS5 proxy modes
- **Interception:** HTTPS interception with a custom CA, HTTP interceptor chaining, WebSocket frame interception, and pre-relay observation of raw TCP tunnels without exposing payloads
- **Wire fidelity:** preserved header and trailer order for HTTP/1 and HTTP/2; uTLS-based ClientHello and ALPN mirroring; HTTP/2 SETTINGS, connection WINDOW_UPDATE, standalone PRIORITY, HEADERS priority, and pseudo-header fingerprint mirroring
- **Routing:** host include/exclude filtering with wildcards, upstream HTTP CONNECT and SOCKS5 proxies, custom root CAs, and client certificates for mTLS
- **Operations:** connection, TLS, and timing metadata; optional structured logging through `log/slog`; runtime configuration updates for new connections; injectable IP resolution and context dialing for application-owned DNS caches

## Installation

Requires Go 1.27.3 or later.

```bash
go get github.com/josexy/mitmproxy-go/v2
```

## Getting Started

### 1. Generate a CA certificate

The handler loads a CA certificate and private key at startup, and clients that use the proxy must trust that CA. Generate a local one with the bundled script:

```bash
chmod +x ./tools/gen_cert.sh
OUTDIR=certs ./tools/gen_cert.sh
```

The script writes `ca.crt`, `ca.key`, `server.crt`, `server.key`, `client.crt`, and `client.key` to `OUTDIR`. Customize it with environment variables:

```bash
OUTDIR=certs \
CA_DOMAIN=example.ca.com \
DOMAINS=localhost,127.0.0.1 \
IPS=127.0.0.1 \
./tools/gen_cert.sh
```

### 2. Run an HTTP proxy

The handler is an `http.Handler` from `github.com/josexy/xhttp`:

```go
package main

import (
	"log"

	mitmproxy "github.com/josexy/mitmproxy-go/v2"
	http "github.com/josexy/xhttp"
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

	log.Println("proxy listening on 127.0.0.1:8080")
	log.Fatal(http.ListenAndServe("127.0.0.1:8080", handler))
}
```

Try it with `curl -x http://127.0.0.1:8080 --cacert certs/ca.crt https://example.com`.

`ServeHTTP` requires `Request.Body` to be untouched on entry, so do not wrap the handler in middleware that reads or replaces the body. Call `handler.Cleanup()` on shutdown: it closes active proxied connections and stops background certificate-cache maintenance.

### 3. Or run a SOCKS5 proxy

```go
package main

import (
	"context"
	"log"
	"net"

	mitmproxy "github.com/josexy/mitmproxy-go/v2"
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

	log.Println("SOCKS5 proxy listening on 127.0.0.1:1080")
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		// ServeSOCKS5 takes ownership of conn and closes it.
		go func() { _ = handler.ServeSOCKS5(context.Background(), conn) }()
	}
}
```

For transparent or custom entry points, `Serve(ctx, conn)` is the low-level API; it also takes ownership of the connection.

> [!WARNING]
> The examples listen on loopback for a reason. The handler does not authenticate downstream HTTP proxy clients, and SOCKS5 supports only the no-authentication method. Before exposing either listener on a non-loopback address, enforce client authentication and destination ACLs in the surrounding server or network layer. Otherwise the process becomes an open proxy and may expose localhost, private networks, or cloud metadata endpoints.

## HTTP Interceptors

An HTTP interceptor sees each request and decides what to do with it. Call the delegated invoker to forward the request upstream:

```go
func httpInterceptor(ctx context.Context, req *http.Request, invoker mitmproxy.HTTPDelegatedInvoker) (*http.Response, error) {
	log.Printf("-> %s %s", req.Method, req.URL)

	resp, err := invoker.Invoke(req)
	if err != nil {
		return nil, err
	}

	log.Printf("<- %s", resp.Status)
	return resp, nil
}

handler, err := mitmproxy.NewMitmProxyHandler(
	mitmproxy.WithCACertPath("certs/ca.crt"),
	mitmproxy.WithCAKeyPath("certs/ca.key"),
	mitmproxy.WithHTTPInterceptor(httpInterceptor),
)
```

### Chaining and concurrency

`WithChainHTTPInterceptor(i1, i2, i3)` runs interceptors in the order given. When both `WithHTTPInterceptor` and `WithChainHTTPInterceptor` are configured, the single interceptor runs first and then the chain.

Interceptors may be called concurrently: for pipelined requests on the same HTTP/1.1 connection, for HTTP/2 streams, and for independent clients. Interceptors that share mutable state must synchronize it.

### Response bodies

An interceptor may invoke upstream more than once. Close the body of any invoked response you do not return; any left open are released once the returned response finishes. On HTTP/1, invoking again while an earlier response body of the same exchange is still open sends the new request on a separate upstream connection, because the earlier response would otherwise block it on the shared pipelined connection.

### Dropping an exchange

Return `ErrDropHTTP` (also recognized when wrapped) to close the HTTP/1 connection or abort the current HTTP/2 stream without a final response. Return it before `Invoke` to prevent forwarding, or after it to discard the response; the proxy releases invoked response bodies on error.

To interrupt blocked request-body reads, call `AbortHTTPRequestRead(request, cause)` and return `ErrDropHTTP`. Canceling the invoked request context interrupts upstream response reads, including HTTP/1 pipeline bodies.

### Rerouting a request

Call `WithHTTPUpstreamTarget(request, targetURL)` before `Invoke` to override the upstream HTTP/HTTPS scheme and authority for one request, preserving its path, query, and `Host`. The original authority is validated before interception. Same-origin overrides retain connection reuse; cross-origin calls use isolated transports that close with the response body. Proxy, TLS, and cancellation settings still apply, including client certificates and captured fingerprints. HTTPS verification and SNI use the target hostname.

### Observing the downstream send

Call `SetHTTPResponseSendObserver(response, callback)` before returning any response, including locally generated ones. It reports one terminal `HTTPResponseSendResult` with timing, body bytes, the final outgoing initial header block, error, and cancellation status. Body pre-reading does not trigger completion.

HTTP/1 counts body bytes written to the connection; HTTP/2 counts bytes accepted by its response writer and requires flushing END_STREAM and trailers for success. Only a nil `Err` indicates a successful send; neither protocol guarantees peer acknowledgment. Callbacks run synchronously and may overlap across streams, so keep them brief and synchronize shared state.

## WebSocket Interceptors

A WebSocket interceptor receives the upgrade request and response and a stream of frames from both directions:

```go
func websocketInterceptor(ctx context.Context, req *http.Request, resp *http.Response, fw mitmproxy.WebsocketFramesWatcher) {
	log.Printf("websocket upgrade %s -> %d", req.URL, resp.StatusCode)

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

handler, err := mitmproxy.NewMitmProxyHandler(
	mitmproxy.WithCACertPath("certs/ca.crt"),
	mitmproxy.WithCAKeyPath("certs/ca.key"),
	mitmproxy.WithWebsocketInterceptor(websocketInterceptor),
)
```

For every frame, call either `frame.Invoke()` to forward it or `frame.Release()` to drop it; both release the backing buffer. `WithMaxWebsocketFramesPerForward`, `WithMaxWebsocketMessageBytes`, and `WithMaxWebsocketBufferedBytes` bound the frames and bytes waiting for the interceptor.

If upstream answers the upgrade with anything other than `101 Switching Protocols`, that response is forwarded to the client with its body, the client connection is then closed, and the interceptor does not run. `WithHandshakeTimeout` bounds both sides of the opening handshake.

With `WithUpstreamHTTPTrace()` enabled, `WebsocketHandshakeTimingFromContext(ctx)` returns the timing of the successful upstream opening handshake. It does not cover the lifetime of the upgraded connection or any frame processing:

```go
if timing, ok := mitmproxy.WebsocketHandshakeTimingFromContext(ctx); ok {
	log.Printf("upstream handshake request=%s wait=%s response=%s total=%s",
		timing.RequestEndedAt.Sub(timing.RequestStartedAt),
		timing.ResponseStartedAt.Sub(timing.RequestEndedAt),
		timing.ResponseEndedAt.Sub(timing.ResponseStartedAt),
		timing.ResponseEndedAt.Sub(timing.RequestStartedAt),
	)
}
```

## Raw TCP Observation

`WithRawTCPInterceptor` registers an observation-only callback, invoked synchronously once for each classified raw TCP tunnel immediately before relay:

```go
mitmproxy.WithRawTCPInterceptor(func(ctx context.Context, event mitmproxy.RawTCPTunnelEvent) {
	log.Printf("raw tcp tunnel to %s (tls=%t)", event.Hostport, event.TLS)
})
```

- `Hostport` is the requested target.
- `Source` is `RawTCPTunnelSourceHTTPConnect`, `RawTCPTunnelSourceSOCKS5`, or `RawTCPTunnelSourceDirect` for low-level and transparent `Serve` callers.
- `TLS=true` means the stream is decrypted application data inside a successfully intercepted TLS tunnel.
- For HTTP CONNECT tunnels accepted through `ServeHTTP`, `Request` is an isolated, bodyless snapshot of the outer CONNECT request. It stays the outer request even when `TLS=true` and never contains decrypted data. Direct and SOCKS5 events have a nil `Request`.

The callback never receives a connection, buffer, or payload, and cannot allow, reject, or modify relay. A slow callback delays relay; callbacks for different tunnels may run concurrently.

Only traffic that protocol detection explicitly classifies as non-HTTP raw TCP is reported, including plaintext raw streams and decrypted raw application streams inside MITM TLS tunnels. HTTP, WebSocket, host-filter passthrough, h2c upgrade passthrough, dial failures, and protocol-detection failures do not emit events.

## Wire Fidelity

### Header and trailer order

An interceptor can set the downstream response wire order before returning a response. Non-empty `Headers` and `Trailers` slices override the corresponding block; an empty slice keeps the received order, including trailers that arrive after the response body reaches EOF:

```go
if err := mitmproxy.SetResponseHeaderOrder(resp, http.HeaderOrder{
	Headers:  []string{"x-interceptor", "content-length"},
	Trailers: []string{"x-end-b", "x-end-a"},
}); err != nil {
	return nil, err
}
```

The request side returns a request copy. Apply header changes first, then pass the returned request to the invoker:

```go
req.Header.Set("X-Debug", "1")
req, err := mitmproxy.WithRequestHeaderOrder(req, http.HeaderOrder{
	Headers: []string{"x-debug", "host", "user-agent"},
})
if err != nil {
	return nil, err
}
resp, err := invoker.Invoke(req)
```

Request trailer order is resolved after the streaming body reaches EOF, not from the earlier `Trailer` declaration. Declare request trailer names in the initial headers so the upstream writer can send them after the body. Before EOF, `RequestWireHeaderOrder` reports only the declaration order; after EOF, `RequestWireHeaderOrder` and `RequestWireHeaderBlocks` expose the trailer block actually received. These snapshots retain inbound metadata even when an interceptor edits the outgoing headers.

### Exact header blocks

`WithRequestHeaderBlock(request, block)` and `SetResponseHeaderBlock(response, block)` set the outgoing initial header block via `xhttp.HeaderBlock`, preserving interleaved duplicates, empty values, and HTTP/1 casing. Set final `Header` values first: overrides match current values and append remaining fields deterministically. Hop-by-hop sanitization, Host and pseudo-header generation, and framing still apply; received wire metadata, body streaming, and late trailers are unchanged. HTTP/1 response heads that require exact reordering are limited to 64 KiB, and larger heads fail before sending. These overrides apply only to ordinary HTTP interception.

`WithHTTPRequestSendHeaderObserver(request, callback)` requires an explicit `WithRequestHeaderBlock` override. It reports the final sanitized header block and the selected upstream protocol during transport preparation, not per-attempt timing or send completion.

### TLS and HTTP/2 fingerprints

HTTPS and WSS interception captures the client's TLS ClientHello, fingerprints it with [uTLS](https://github.com/refraction-networking/utls), patches SNI and ALPN for the target server, and uses that spec for the upstream handshake. `WithDisableHTTP2` also removes `h2` from the mirrored ALPN protocols.

For HTTP/2, the proxy captures the client's ordered SETTINGS values, initial connection WINDOW_UPDATE, pre-request standalone PRIORITY frames, the priority carried by each request's initial HEADERS frame, and per-request pseudo-header order. It replays the connection-level fingerprint, the pseudo-header order, and HEADERS priority that depends on the connection root (stream 0). A non-root HEADERS dependency remains available as request metadata but is not copied upstream, because HTTP/2 stream IDs are scoped to each connection. The canonical four-part fingerprint string and hash contain only standalone PRIORITY frames. Connections with different connection-level fingerprints use separate upstream HTTP/2 pool entries.

## Observability

### Connection metadata

HTTP, WebSocket, and raw TCP interceptors can read connection and TLS metadata from the callback context:

```go
func httpInterceptor(ctx context.Context, req *http.Request, invoker mitmproxy.HTTPDelegatedInvoker) (*http.Response, error) {
	mdCtx, _ := metadata.FromContext(ctx)
	md := mdCtx.MD()

	log.Printf("target: %s", md.RequestHostport)
	log.Printf("local addr: %s -> %s", md.LocalAddrInfo.SourceAddr, md.LocalAddrInfo.DestinationAddr)
	log.Printf("remote addr: %s -> %s", md.RemoteAddrInfo.SourceAddr, md.RemoteAddrInfo.DestinationAddr)
	log.Printf("dns lookup: %v", durationBetween(md.DNSLookupStartTs, md.DNSLookupCompletedTs))
	log.Printf("socket connect: %v", durationBetween(md.SocketConnectStartTs, md.SocketConnectCompletedTs))
	log.Printf("ssl handshake: %v", durationBetween(md.SSLHandshakeStartTs, md.SSLHandshakeCompletedTs))

	if md.TLSState != nil {
		log.Printf("ALPN=%s version=%s cipher=%s",
			md.TLSState.SelectedALPN,
			tls.VersionName(md.TLSState.SelectedTLSVersion),
			tls.CipherSuiteName(md.TLSState.SelectedCipherSuite))
	}
	if md.ServerCertificate != nil {
		log.Printf("server certificate %s, issued by %s, sha256 %s",
			md.ServerCertificate.Subject, md.ServerCertificate.Issuer, md.ServerCertificate.Sha256FingerprintHex())
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

`metadata` is `github.com/josexy/mitmproxy-go/v2/metadata`. Connection timestamps, including `LocalConnectionEstablishedTs`, `RemoteConnectionEstablishedTs`, and `RequestProcessedTs`, are also available on `md`.

### Upstream HTTP timing

Upstream timing is opt-in. `WithUpstreamHTTPTrace()` enables the shared `httptrace.ClientTrace` instrumentation for ordinary HTTP exchanges and WebSocket opening handshakes. Register an observer inside the interceptor, before calling `invoker.Invoke`:

```go
func timedHTTPInterceptor(ctx context.Context, req *http.Request, invoker mitmproxy.HTTPDelegatedInvoker) (*http.Response, error) {
	ok := mitmproxy.ObserveHTTPExchangeTiming(ctx, func(event mitmproxy.HTTPExchangeTimingEvent) {
		log.Printf("phase=%s attempt=%d at=%s complete=%t err=%v",
			event.Phase, event.Attempt, event.Timestamp.Format(time.RFC3339Nano), event.Complete, event.Error)
	})
	if !ok {
		log.Print("upstream timing is disabled")
	}
	return invoker.Invoke(req)
}
```

The phases have the following origin-facing meanings:

- `request_started`: immediately before the first final upstream transport invocation. A transparent retry starts before its backoff, connection acquisition, and writes, including retries that fail before writing headers.
- `request_ended`: the transport's `WroteRequest` callback, or the invocation error fallback when no callback was delivered.
- `response_started`: the transport's `GotFirstResponseByte` callback, with response-header return as a fallback for custom transports.
- `response_ended`: upstream response body EOF, body error, or early close. Bodyless responses end when their headers have been returned.

`Attempt` starts at 1 and increments for transparent retries; callbacks from superseded attempts are ignored. `Complete` is meaningful on terminal events and is false for write or read errors and for an early response body close. Response completion can happen after the interceptor has returned, and callbacks can arrive from different goroutines, so observers must be concurrency-safe and return quickly. The dumper example shows how to aggregate the four timestamps into request, wait, response, and total durations.

Connection DNS, TCP, TLS, and upstream exchange timestamps share one timing clock per intercepted connection. Windows uses QueryPerformanceCounter to keep short intervals within a coarse system-clock tick; other platforms use Go's system clock. Metadata and timing events expose `time.Time` values.

### Logging

Internal logging is disabled by default. Pass `WithLogger(logger)` to enable structured `slog` output, or `WithLogger(nil)` to disable it again. Messages are prefixed with `[mitmproxy-go]`. Core logs cover connection, routing, TLS, HTTP, HTTP/2, WebSocket, transport retry, and runtime config events, but never log URL credentials or query strings, headers, bodies, WebSocket payloads, or raw certificates.

HTTP/1 pipeline diagnostics are emitted at `Debug` with messages beginning `http1 pipeline` or `http1 upstream`. Correlate a request with `pipeline_sequence` and `target`; the `in_flight`, `pipeline_depth`, `status_code`, and duration fields show where it is waiting. Upstream failures, downstream write failures, and automatic serial downgrade are emitted at `Warn` with error and retry/degrade fields.

### Application DNS caches

`WithIPResolver` supplies the destination lookup performed before an upstream-proxy tunnel, and `WithContextDialer` handles direct connections and proxy endpoints. Pair both with the same resolver or cache to share local results. Direct connections resolve through the context dialer; this does not change which destinations are resolved locally.

Implementations must be concurrency-safe, respect cancellation, and emit `github.com/josexy/xhttp/httptrace` DNS and connection hooks for connection timing. The configured `WithDialer` still bounds the operation timeout and deadline, while a custom context dialer owns its socket options. Without these options, `WithDialer` behavior is unchanged. The hooks are kept when runtime proxy configuration is rebuilt, and applications own their lifetime and cache invalidation.

To report a cache hit as zero DNS duration, a resolver calls `ReportDNSCacheHit(ctx)` before returning its cached result, and a context dialer calls it before its `DNSDone` hook. Only completed cache entries qualify: callers waiting on an active lookup keep their measured duration. TCP and TLS timestamps are unchanged, and proxy-endpoint cache hits do not overwrite destination DNS timing.

## Configuration

### Options

| Option | Default | Purpose |
| --- | --- | --- |
| `WithCACertPath`, `WithCAKeyPath` | required | CA certificate and key used to sign generated certificates |
| `WithLogger` | disabled | Structured internal logging |
| `WithErrorHandler` | none | Callback for proxy errors |
| `WithStreamBaseContext` | `context.Background()` | Base context for HTTP/2 streams, for shared cancellation |
| `WithProxy` | environment | Upstream proxy URL (`http`, `https`, `socks5`, `socks5h`) |
| `WithDisableProxy` | off | Ignore explicit and environment proxy settings |
| `WithDialer` | 15s dial timeout | Dialer for upstream connections |
| `WithIPResolver`, `WithContextDialer` | system | See [Application DNS caches](#application-dns-caches) |
| `WithIdleConnTimeout` | 90s | Idle keep-alive and half-closed tunnel timeout; `0` disables it |
| `WithHandshakeTimeout` | 10s | Protocol sniffing, TLS, SOCKS5, and WebSocket opening handshakes |
| `WithMaxHTTPHeaderBytes` | 1 MiB | Limit for HTTP/1 request headers parsed inside tunnels |
| `WithHTTP1PipelineDepth` | 8 | Outstanding HTTP/1 requests per client connection; `1` disables pipelining |
| `WithDisableHTTP2` | off | Force HTTP/1.1 upstream and disable h2c handling |
| `WithSkipVerifySSLFromServer` | off | Skip upstream certificate verification (testing only) |
| `WithUpstreamHTTPTrace` | off | Upstream HTTP and WebSocket handshake timing |
| `WithRootCAs` | system roots | Additional trusted CAs for upstream servers |
| `WithClientCert` | none | Client certificate for mTLS with a host |
| `WithCertCachePool` | 2048, 30s, 15s | Generated-certificate cache capacity, cleanup interval, and expiry |
| `WithIncludeHosts`, `WithExcludeHosts` | intercept all | See [Host filtering](#host-filtering) |
| `WithHTTPInterceptor`, `WithChainHTTPInterceptor` | none | See [HTTP Interceptors](#http-interceptors) |
| `WithWebsocketInterceptor` | none | See [WebSocket Interceptors](#websocket-interceptors) |
| `WithRawTCPInterceptor` | none | See [Raw TCP Observation](#raw-tcp-observation) |
| `WithMaxWebsocketFramesPerForward` | 2048 | Frames queued for the WebSocket interceptor per direction |
| `WithMaxWebsocketMessageBytes` | 16 MiB | Largest WebSocket message, counting fragments together |
| `WithMaxWebsocketBufferedBytes` | 64 MiB | Payload bytes held for the WebSocket interceptor across both directions; at least the message limit |

### Connections and upstreams

`WithIdleConnTimeout` bounds how long an idle HTTP keep-alive connection, together with the upstream connection pinned to it, is kept around. It also bounds how long a client may stay idle once the upstream side of a raw TCP tunnel has shut down its sending side.

A client that closes, half-closes, or resets its connection ends everything pending on it at once; a close and a half-close look the same to the proxy. HTTP/1 exchanges still waiting for upstream are canceled and their responses are not delivered, and a raw TCP tunnel closes its upstream connection. An upstream server that shuts down its sending side is relayed gracefully instead: the client reads every byte and then EOF, while its own data keeps flowing until it closes.

`WithHTTP1PipelineDepth` bounds the HTTP/1 requests on one client connection that have not finished writing back. Requests for the same origin are pipelined on one upstream HTTP/1.1 connection; requests for different origins use separate upstream connections and may run concurrently. Responses are always returned in the client's request order. `Expect: 100-continue`, protocol upgrades, and connection-closing requests remain ordering barriers.

If `WithProxy` is not set, the `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` environment variables are used. Destination hostnames are resolved locally, and the resolved IP address is sent to the upstream proxy.

When HTTP/2 is enabled, h2c prior-knowledge connections can be inspected, while HTTP/1.1 `Upgrade: h2c` handshakes are forwarded transparently as passthrough tunnels.

### TLS and certificates

```go
mitmproxy.WithRootCAs("certs/internal-ca.crt", "certs/partner-ca.crt")
mitmproxy.WithClientCert("example.com", mitmproxy.ClientCert{
	CertPath: "certs/client.crt",
	KeyPath:  "certs/client.key",
})
mitmproxy.WithCertCachePool(2048, 30, 15)
```

`WithCertCachePool(capacity, intervalSecond, expireSecond)` configures the cache of generated certificates. When set, `capacity` must be a multiple of 256. Concurrent handshakes to the same new host share one certificate generation.

### Host filtering

```go
mitmproxy.WithIncludeHosts("api.example.com", "*.example.org")
mitmproxy.WithExcludeHosts("*.cdn.com", "static.example.com")
```

Host filters choose between interception and passthrough. They are not access-control rules and never block traffic.

- Without `WithIncludeHosts`, all traffic is intercepted unless excluded. `WithExcludeHosts` takes precedence over `WithIncludeHosts`.
- `*` matches one or more non-empty DNS labels: `*.example.com` matches `api.example.com` and `v1.api.example.com`, but not `example.com`.
- Names are matched case-insensitively and normalized with IDNA. IPv4 and IPv6 literals are supported, and one trailing root dot is accepted.
- Empty labels, partial-label wildcards such as `api*.example.com`, ports, and malformed names are rejected with `ErrInvalidHostFilter` when the handler is built.

Passthrough for HTTPS, SOCKS5, and transparent tunnels relays the connection without terminating TLS. A plain proxy connection can carry requests for any origin, so its requests are still parsed and routed one by one; requests to a passthrough host are forwarded without HTTP or WebSocket interceptors. A request to a passthrough host that upgrades to a protocol other than WebSocket is forwarded as sent, minus proxy credentials, and the connection is relayed raw from then on.

## Runtime Configuration

`NewDynamicMitmProxyHandler` returns a handler whose configuration can change at runtime. `NewResourceLimitedDynamicMitmProxyHandler` is a superset that also exposes resource-limit setters:

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
if err := handler.SetHostFilters(nil, []string{"*.cdn.example.com"}); err != nil {
	log.Fatal(err)
}
```

Updates are published as immutable config snapshots. A connection captures one snapshot when it enters `Serve`, `ServeHTTP`, or `ServeSOCKS5`, so updates affect only new connections. Existing keep-alive, HTTP/2, WebSocket, and raw TCP connections keep the snapshot they started with, including a raw TCP callback that fires after an update. If a setter returns an error, the previous configuration stays active.

Setters available on both dynamic handlers:

```go
err = handler.SetProxy("http://127.0.0.1:8080")
err = handler.SetProxyDisabled(true)
err = handler.SetDialer(&net.Dialer{Timeout: 30 * time.Second})
err = handler.SetHostFilters(includeHosts, excludeHosts)
err = handler.SetRootCAs("certs/internal-ca.crt")
err = handler.SetClientCerts(map[string]mitmproxy.ClientCert{
	"example.com": {CertPath: "certs/client.crt", KeyPath: "certs/client.key"},
})

handler.SetIdleConnTimeout(60 * time.Second)
handler.SetSkipVerifySSLFromServer(true)
handler.SetHTTP2Disabled(true)
handler.SetStreamBaseContext(ctx)
handler.SetLogger(logger)

handler.SetErrorHandler(errorHandler)
handler.SetHTTPInterceptor(httpInterceptor)
handler.SetChainHTTPInterceptors(interceptor1, interceptor2)
handler.SetWebsocketInterceptor(websocketInterceptor)
handler.SetRawTCPInterceptor(rawTCPInterceptor)
err = handler.SetMaxWebsocketFramesPerForward(4096)
```

Resource-limit setters, available on `NewResourceLimitedDynamicMitmProxyHandler`:

```go
err = handler.SetHandshakeTimeout(10 * time.Second)
err = handler.SetMaxHTTPHeaderBytes(1 << 20)
err = handler.SetHTTP1PipelineDepth(8)
err = handler.SetMaxWebsocketMessageBytes(16 << 20)
err = handler.SetMaxWebsocketBufferedBytes(64 << 20)
```

`SetHTTPInterceptor` replaces any configured interceptor chain, and `SetChainHTTPInterceptors` replaces any single interceptor. `SetRawTCPInterceptor(nil)` disables raw TCP observation for new connections. The CA certificate and key and `WithCertCachePool` are initialization-only.

## Examples

Run the examples from the repository root after [generating a CA](#1-generate-a-ca-certificate):

| Example | Shows | Command |
| --- | --- | --- |
| `helloworld` | Minimal HTTP proxy with request and response logging | `go run ./examples/helloworld -cacert certs/ca.crt -cakey certs/ca.key -port 10086` |
| `dumper` | HTTP and WebSocket dumping, raw TCP observation, metadata and timing logs | `go run ./examples/dumper -cacert certs/ca.crt -cakey certs/ca.key -mode http -port 10086` |
| `modify-content` | Modifying request headers and the response body | `go run ./examples/modify-content -cacert certs/ca.crt -cakey certs/ca.key -port 10086` |
| `chain-interceptors` | Ordered HTTP interceptor chaining | `go run ./examples/chain-interceptors -cacert certs/ca.crt -cakey certs/ca.key -port 10086` |
| `dynamic-config` | Runtime updates that affect only new connections | `go run ./examples/dynamic-config -cacert certs/ca.crt -cakey certs/ca.key -port 10086 -origin-port 18080` |

Send a request through a running example with:

```bash
curl -x http://127.0.0.1:10086 --cacert certs/ca.crt https://example.com
```

The dumper also runs as a SOCKS5 proxy with `-mode socks5`. It logs ordered HTTP/1 and HTTP/2 header blocks, decoded initial header field-line sizes, late trailer blocks, canonical four-part HTTP/2 fingerprints and hashes, separate standalone and HEADERS priority metadata, TLS negotiation and certificate metadata, body sizes, per-attempt upstream HTTP timing, WebSocket opening-handshake timing, WebSocket frames, and raw TCP tunnel metadata. Header field-line sizes exclude HTTP/1 start lines and terminating empty lines, as well as HTTP/2 framing and HPACK bytes. WebSocket frames are reported separately and are not counted in opening-handshake timing or header sizes.

The `dynamic-config` demo starts a local origin server, sends proxied requests, and then updates the HTTP interceptor and host filters at runtime: existing keep-alive connections keep their original snapshot, while new connections use the latest config.

## Development

```bash
go test ./...
go test -race ./...
go vet ./...
gofmt -w <files>
```

## License

This project is available under the MIT License.
