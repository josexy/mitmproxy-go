# mitmproxy-go 

An easy-use and flexible Man-In-The-Middle (MITM) proxy library for Go that enables transparent interception and inspection of HTTP, HTTPS, HTTP/2, and WebSocket traffic.

## Features

- **Multiple Protocol Support**
  - HTTP/1.1 and HTTP/2 (including h2c - HTTP/2 over cleartext)
  - HTTPS with transparent TLS interception
  - WebSocket and secure WebSocket (WSS)

- **Dual Proxy Modes**
  - HTTP/HTTPS proxy mode
  - SOCKS5 proxy mode

- **Flexible Configuration**
  - Upstream proxy support
  - Custom CA certificates
  - Configurable TLS verification
  - HTTP/2 can be disabled if needed

## Installation

```bash
go get github.com/josexy/mitmproxy-go
```

## Quick Start

### Basic HTTP Proxy

```go
package main

import (
    "context"
    "fmt"
    "log"
    "net/http"

    "github.com/josexy/mitmproxy-go"
)

func main() {
    // Create MITM proxy handler
    handler, err := mitmproxy.NewMitmProxyHandler(
        mitmproxy.WithCACertPath("certs/ca.crt"),
        mitmproxy.WithCAKeyPath("certs/ca.key"),
    )
    if err != nil {
        log.Fatal(err)
    }

    // Start HTTP proxy server
    fmt.Println("Starting proxy on :8080")
    http.ListenAndServe(":8080", handler)
}
```

### With HTTP Interceptor

```go
httpInterceptor := func(ctx context.Context, req *http.Request, invoker mitmproxy.HTTPDelegatedInvoker) (*http.Response, error) {
    // Log request details
    fmt.Printf("→ %s %s\n", req.Method, req.URL)
    fmt.Printf("  Host: %s\n", req.Host)
    fmt.Printf("  Proto: %s\n", req.Proto)

    // Forward the request
    resp, err := invoker.Invoke(req)
    if err != nil {
        return nil, err
    }

    // Log response details
    fmt.Printf("← %s\n", resp.Status)

    return resp, nil
}

handler, err := mitmproxy.NewMitmProxyHandler(
    mitmproxy.WithCACertPath("certs/ca.crt"),
    mitmproxy.WithCAKeyPath("certs/ca.key"),
    mitmproxy.WithHTTPInterceptor(httpInterceptor),
)
```

### With WebSocket Interceptor

```go
websocketInterceptor := func(ctx context.Context, req *http.Request, rsp *http.Response, fw mitmproxy.WebsocketFramesWatcher) {
    // Log WebSocket messages
    log.Printf("WS url: %s", req.URL.String())

    for frame := range fw.GetFrame() {
        dir := frame.Direction()
        msgType := frame.MessageType()
        dataBuf := frame.DataBuffer()
        log.Printf("---> %s %d %s", dir, msgType, dataBuf.String())
        if err := frame.Invoke(); err != nil {
            log.Printf("frame invoke error: %v", err)
        }
        frame.Release()
    }
}

handler, err := mitmproxy.NewMitmProxyHandler(
    mitmproxy.WithCACertPath("certs/ca.crt"),
    mitmproxy.WithCAKeyPath("certs/ca.key"),
    mitmproxy.WithWebsocketInterceptor(websocketInterceptor),
)
```

### SOCKS5 Proxy Mode

```go
func main() {
    handler, err := mitmproxy.NewMitmProxyHandler(
        mitmproxy.WithCACertPath("certs/ca.crt"),
        mitmproxy.WithCAKeyPath("certs/ca.key"),
    )
    if err != nil {
        log.Fatal(err)
    }

    // Listen on TCP port
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

        go func(c net.Conn) {
            defer c.Close()
            handler.ServeSOCKS5(context.Background(), c)
        }(conn)
    }
}
```

## Configuration Options

### Basic Options

```go
// Specify CA certificate and key for TLS interception
mitmproxy.WithCACertPath("path/to/ca.crt")
mitmproxy.WithCAKeyPath("path/to/ca.key")

// Use an upstream proxy
mitmproxy.WithProxy("http://127.0.0.1:8080")

// Disable upstream proxy
mitmproxy.WithDisableProxy()

// Add custom root CA certificates
mitmproxy.WithRootCAs("path/to/root-ca1.crt", "path/to/root-ca2.crt")

// Configure certificate cache pool
mitmproxy.WithCertCachePool(2048, 30, 15)

// Custom dialer with timeout
mitmproxy.WithDialer(&net.Dialer{
    Timeout: 30 * time.Second,
})

// Maximum channel size of WebSocket frames
mitmproxy.WithMaxWebsocketFramesPerForward(4096)
```

### Interceptor Options

```go
// Set HTTP interceptor
mitmproxy.WithHTTPInterceptor(httpInterceptor)

// Set WebSocket interceptor
mitmproxy.WithWebsocketInterceptor(websocketInterceptor)

// Chain multiple HTTP interceptors (executed in order)
mitmproxy.WithChainHTTPInterceptor(interceptor1, interceptor2, interceptor3)

// Set error handler
mitmproxy.WithErrorHandler(func(ec mitmproxy.ErrorContext) {
    log.Printf("Error: %v", ec.Error)
})
```

### Security Options

```go
// Skip SSL verification when connecting to servers (not recommended for production)
mitmproxy.WithSkipVerifySSLFromServer()

// mTLS client-authentication
mitmproxy.WithClientCert("example.com", mitmproxy.ClientCert{CertPath: "certs/client.crt", KeyPath: "certs/client.key" })
```

### Protocol Options

```go
// Disable HTTP/2 support (use HTTP/1.1 only)
mitmproxy.WithDisableHTTP2()
```

### Domain Filtering

```go
// Only intercept specific hosts (supports wildcards)
mitmproxy.WithIncludeHosts("api.example.com", "*.example.org", "example.net")

// Exclude specific hosts from interception (supports wildcards)
mitmproxy.WithExcludeHosts("*.cdn.com", "static.example.com")
```

## Metadata Access

Interceptors can access metadata from the context:

```go
httpInterceptor := func(ctx context.Context, req *http.Request, invoker mitmproxy.HTTPDelegatedInvoker) (*http.Response, error) {
    // Extract metadata from context
    mdCtx, _ := metadata.FromContext(ctx)
    md := mdCtx.MD()

    // Timing information
    fmt.Printf("Connection established at: %v\n", md.ConnectionEstablishedTs)
    fmt.Printf("SSL handshake duration: %v\n",
        md.SSLHandshakeCompletedTs.Sub(md.ConnectionEstablishedTs))

    // Connection details
    fmt.Printf("Source: %s\n", md.SourceAddr)
    fmt.Printf("Destination: %s\n", md.DestinationAddr)

    // TLS information (if HTTPS)
    if md.TLSState != nil {
        fmt.Printf("ALPN: %s\n", md.TLSState.SelectedALPN)
        fmt.Printf("TLS Version: %s\n", tls.VersionName(md.TLSState.SelectedTLSVersion))
        fmt.Printf("Cipher Suite: %s\n", tls.CipherSuiteName(md.TLSState.SelectedCipherSuite))
    }

    // Server certificate (if HTTPS)
    if md.ServerCertificate != nil {
        fmt.Printf("Certificate Subject: %v\n", md.ServerCertificate.Subject)
        fmt.Printf("Certificate Issuer: %v\n", md.ServerCertificate.Issuer)
        fmt.Printf("DNS Names: %v\n", md.ServerCertificate.DNSNames)
        fmt.Printf("SHA256 Fingerprint: %s\n", md.ServerCertificate.Sha256FingerprintHex())
    }

    return invoker.Invoke(req)
}
```

## Examples

A complete working example is available in `examples/dumper/main.go`. Run it with:

```bash
# HTTP proxy mode
go run examples/dumper/main.go -cacert certs/ca.crt -cakey certs/ca.key -mode http -port 10086

# SOCKS5 proxy mode
go run examples/dumper/main.go -cacert certs/ca.crt -cakey certs/ca.key -mode socks5 -port 10086
```

## Generating CA Certificates

For TLS interception to work, you need a CA certificate. Generate one with OpenSSL:

```bash
chmod +x ./tools/gen_cert.sh
OUTDIR=certs ./tools/gen_cert.sh
```

## License

This project is available under the terms specified in the repository.

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.
