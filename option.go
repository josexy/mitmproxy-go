package mitmproxy

import (
	"context"
	"crypto/x509"
	"net"
	"time"

	"github.com/josexy/mitmproxy-go/internal/cert"
)

type ClientCert struct {
	CertPath string
	KeyPath  string
}

type Option interface {
	apply(*options)
}

type OptionFunc func(*options)

func (f OptionFunc) apply(o *options) { f(o) }

// options holds all configuration parameters for the MITM proxy handler.
type options struct {
	streamBaseCtx context.Context // Stream Base Context for h2 connection

	proxy         string      // Upstream proxy URL (e.g., "http://127.0.0.1:8080")
	caCertPath    string      // Path to the CA certificate file for TLS interception
	caKeyPath     string      // Path to the CA private key file for TLS interception
	skipVerifySSL bool        // Skip SSL certificate verification when connecting to servers
	disableHTTP2  bool        // Disable HTTP/2 support, use HTTP/1.1 only
	disableProxy  bool        // Disable upstream proxy usage
	includeHosts  []string    // Whitelist of hosts to intercept (supports wildcards)
	excludeHosts  []string    // Blacklist of hosts to exclude from interception (supports wildcards)
	rootCAs       []string    // Paths to additional root CA certificate files
	dialer        *net.Dialer // Custom dialer for outbound connections

	wsMaxFramesPerForward int // Max frames channel size per single websocket forward

	clientCerts map[string]ClientCert // Client certificate configuration

	// Certificate cache pool configuration
	certCachePool struct {
		Capacity       int // Maximum number of cached certificates
		IntervalSecond int // Cache cleanup interval in seconds
		ExpireSecond   int // Certificate cache expiration time in seconds
	}

	rootCACertPool *x509.CertPool // System and custom root CA certificate pool
	caCert         *cert.Cert     // Loaded CA certificate for TLS interception

	errHandler    ErrorHandler
	httpInt       HTTPInterceptor
	wsInt         WebsocketInterceptor
	chainHttpInts []HTTPInterceptor
}

// newOptions creates a new options instance with default values.
// Default dialer timeout is 15 seconds.
func newOptions(opt ...Option) *options {
	options := &options{
		dialer:                &net.Dialer{Timeout: 15 * time.Second},
		wsMaxFramesPerForward: 2048,
		streamBaseCtx:         context.Background(),
	}
	for _, o := range opt {
		o.apply(options)
	}
	return options
}

// WithStreamBaseContext configures h2 connection stream base context.
//
// Example:
//
//	handler, err := NewMitmProxyHandler(
//	    WithStreamBaseContext(context.Background()),
//	)
func WithStreamBaseContext(baseCtx context.Context) Option {
	return OptionFunc(func(o *options) {
		o.streamBaseCtx = baseCtx
	})
}

// WithProxy configures an upstream proxy server for outbound connections.
//
// The proxy parameter should be a URL in one of these formats:
//   - HTTP proxy: "http://proxy.example.com:8080"
//   - HTTPS proxy: "https://proxy.example.com:8080"
//   - SOCKS5 proxy: "socks5://proxy.example.com:1080"
//
// Example:
//
//	handler, err := NewMitmProxyHandler(
//	    WithProxy("http://127.0.0.1:8080"),
//	)
func WithProxy(proxy string) Option {
	return OptionFunc(func(o *options) {
		o.proxy = proxy
	})
}

// WithDisableProxy disables the use of any upstream proxy server.
// All connections will be made directly to the destination server.
// This option takes precedence over WithProxy if both are specified.
//
// Example:
//
//	handler, err := NewMitmProxyHandler(
//	    WithDisableProxy(),
//	)
func WithDisableProxy() Option {
	return OptionFunc(func(o *options) {
		o.disableProxy = true
	})
}

// WithCACertPath specifies the path to the CA certificate file.
// This certificate is used to sign dynamically generated certificates for TLS interception.
//
// Required for TLS interception to work properly.
//
// Example:
//
//	handler, err := NewMitmProxyHandler(
//	    WithCACertPath("certs/ca.crt"),
//	    WithCAKeyPath("certs/ca.key"),
//	)
func WithCACertPath(caCertPath string) Option {
	return OptionFunc(func(o *options) {
		o.caCertPath = caCertPath
	})
}

// WithCAKeyPath specifies the path to the CA private key file.
// This private key is used together with the CA certificate to sign dynamically generated
// certificates for intercepted HTTPS connections.
//
// Required for TLS interception to work properly.
// The key file must match the CA certificate specified with WithCACertPath.
//
// Example:
//
//	handler, err := NewMitmProxyHandler(
//	    WithCACertPath("certs/ca.crt"),
//	    WithCAKeyPath("certs/ca.key"),
//	)
func WithCAKeyPath(caKeyPath string) Option {
	return OptionFunc(func(o *options) {
		o.caKeyPath = caKeyPath
	})
}

// WithRootCAs adds additional trusted root CA certificates for verifying server certificates.
// This is useful when connecting to servers that use certificates signed by custom or internal CAs.
//
// The system's default root CA pool is used as the base, and these certificates are added to it.
// Multiple certificate file paths can be provided.
//
// Example:
//
//	handler, err := NewMitmProxyHandler(
//	    WithRootCAs("certs/internal-ca.crt", "certs/partner-ca.crt"),
//	)
func WithRootCAs(rootCAPaths ...string) Option {
	return OptionFunc(func(o *options) {
		o.rootCAs = rootCAPaths
	})
}

// WithClientCert configures a client certificate for a specific hostname.
// This certificate will be used for mTLS connections to the specified hostname.
// See https://docs.mitmproxy.org/stable/concepts/certificates/#mutual-tls-mtls-and-client-certificates
//
// Example:
//
//	handler, err := NewMitmProxyHandler(
//	    WithClientCert("example.com", ClientCert{
//	        CertPath: "certs/client.crt",
//	        KeyPath:  "certs/client.key",
//	    }),
//	    WithClientCert("api.example.com", ClientCert{
//	        CertPath: "certs/api.crt",
//	        KeyPath:  "certs/api.key",
//	    }),
//	)
func WithClientCert(hostname string, clientCert ClientCert) Option {
	return OptionFunc(func(o *options) {
		if o.clientCerts == nil {
			o.clientCerts = make(map[string]ClientCert)
		}
		o.clientCerts[hostname] = clientCert
	})
}

// WithDialer sets a custom dialer for establishing outbound connections.
// This allows fine-grained control over connection behavior such as timeouts,
// keep-alive settings, and local address binding.
//
// If not specified, a default dialer with a 10-second timeout is used.
//
// Example:
//
//	handler, err := NewMitmProxyHandler(
//	    WithDialer(&net.Dialer{
//	        Timeout:   30 * time.Second,
//	    }),
//	)
func WithDialer(dialer *net.Dialer) Option {
	return OptionFunc(func(o *options) {
		o.dialer = dialer
	})
}

// WithSkipVerifySSLFromServer disables SSL certificate verification when the proxy
// connects to upstream servers. This allows connecting to servers with self-signed
// certificates or invalid certificate chains.
//
// WARNING: This option should only be used for testing or development purposes.
//
// Example:
//
//	handler, err := NewMitmProxyHandler(
//	    WithSkipVerifySSLFromServer(),
//	)
func WithSkipVerifySSLFromServer() Option {
	return OptionFunc(func(o *options) {
		o.skipVerifySSL = true
	})
}

// WithDisableHTTP2 disables HTTP/2 support in the proxy.
// When enabled, all connections will use HTTP/1.1 even if both client and server support HTTP/2.
// This also disables h2c (HTTP/2 over cleartext) support.
//
// This can be useful for debugging or when working with applications that have
// issues with HTTP/2 implementations.
//
// Example:
//
//	handler, err := NewMitmProxyHandler(
//	    WithDisableHTTP2(),
//	)
func WithDisableHTTP2() Option {
	return OptionFunc(func(o *options) {
		o.disableHTTP2 = true
	})
}

// WithCertCachePool configures the certificate cache pool parameters.
// The cache stores dynamically generated certificates to avoid regenerating them
// for frequently accessed domains, which improves performance.
//
// Parameters:
//   - capacity: Maximum number of certificates to cache (e.g., 2048). capacity must be a multiple of 256
//   - interval: How often to run cache cleanup in milliseconds (e.g., 60 for 1 minute)
//   - expireSecond: How long certificates stay in cache in milliseconds (e.g., 15 for 15 seconds)
//
// If not specified, default values are used.
//
// Example:
//
//	handler, err := NewMitmProxyHandler(
//	    WithCertCachePool(
//	        2048,    // Cache up to 2048 certificates
//	        30,      // Background Check for expired entries every 30 seconds
//	        15,      // Expire cached certificates after 15 seconds
//	    ),
//	)
func WithCertCachePool(capacity, intervalSecond, expireSecond int) Option {
	return OptionFunc(func(o *options) {
		o.certCachePool.Capacity = capacity
		o.certCachePool.IntervalSecond = intervalSecond
		o.certCachePool.ExpireSecond = expireSecond
	})
}

// WithMaxWebsocketFramesPerForward specifies the maximum channel size of frames that can be buffered
// per single websocket forward.
//
// If not specified, default value(2048) is used.
//
// Example:
//
//	handler, err := NewMitmProxyHandler(
//	    WithMaxWebsocketFramesPerForward(2048),
//	)
func WithMaxWebsocketFramesPerForward(maxFrames int) Option {
	return OptionFunc(func(o *options) {
		o.wsMaxFramesPerForward = maxFrames
	})
}

// WithIncludeHosts specifies a whitelist of hosts that should be intercepted.
// Only traffic to these hosts will be intercepted; all other traffic will pass through
// without interception (passthrough mode).
//
// Supports wildcard patterns:
//   - "example.com" - exact match
//   - "*.example.com" - matches any subdomain of example.com
//   - "api.*.example.com" - matches api.staging.example.com, api.prod.example.com, etc.
//
// If this option is not used, all hosts are intercepted by default
// (unless excluded with WithExcludeHosts).
//
// Example:
//
//	handler, err := NewMitmProxyHandler(
//	    WithIncludeHosts(
//	        "api.example.com",
//	        "*.internal.example.com",
//	        "test.example.org",
//	    ),
//	)
func WithIncludeHosts(hosts ...string) Option {
	return OptionFunc(func(o *options) {
		o.includeHosts = hosts
	})
}

// WithExcludeHosts specifies a blacklist of hosts that should NOT be intercepted.
// Traffic to these hosts will pass through without interception (passthrough mode).
//
// Supports wildcard patterns:
//   - "cdn.example.com" - exact match
//   - "*.cdn.com" - matches any subdomain of cdn.com
//   - "static.*.example.com" - matches static.prod.example.com, static.dev.example.com, etc.
//
// This is useful for excluding CDN domains, static content servers, or domains
// that don't need inspection to improve performance.
//
// If both WithIncludeHosts and WithExcludeHosts are used:
//   - WithExcludeHosts takes precedence
//   - A host matching the exclude list will never be intercepted
//   - A host not in the include list will be passed through
//
// Example:
//
//	handler, err := NewMitmProxyHandler(
//	    WithExcludeHosts(
//	        "*.cdn.com",
//	        "static.example.com",
//	        "*.cloudfront.net",
//	    ),
//	)
func WithExcludeHosts(hosts ...string) Option {
	return OptionFunc(func(o *options) {
		o.excludeHosts = hosts
	})
}

// WithErrorHandler sets a custom error handler for the proxy.
// The error handler is called when errors occur during proxy operations.
//
// The ErrorHandler receives an ErrorContext containing:
//   - RemoteAddr: The client's remote address
//   - Hostport: The target host:port being accessed
//   - Error: The error that occurred
//
// If not specified, errors are silently ignored (no default handler).
//
// Example:
//
//	handler, err := NewMitmProxyHandler(
//	    WithErrorHandler(func(ec ErrorContext) {
//	        log.Printf("[%s -> %s] Error: %v", ec.RemoteAddr, ec.Hostport, ec.Error)
//	    }),
//	)
func WithErrorHandler(handler ErrorHandler) Option {
	return OptionFunc(func(o *options) {
		o.errHandler = handler
	})
}

// WithHTTPInterceptor sets a custom HTTP interceptor for the proxy.
// The interceptor allows you to inspect and modify HTTP requests and responses
// as they pass through the proxy.
//
// The HTTPInterceptor is called for each HTTP request with:
//   - context.Context: Request context containing metadata (TLS state, timing, etc.)
//   - *http.Request: The HTTP request to be sent to the server
//   - HTTPDelegatedInvoker: Delegate to invoke the actual request (call to continue the chain)
//
// The interceptor can:
//   - Inspect/modify the request before forwarding
//   - Call the invoker to forward the request to the server
//   - Inspect/modify the response before returning to the client
//   - Short-circuit the request and return a custom response
//
// Example:
//
//	handler, err := NewMitmProxyHandler(
//	    WithHTTPInterceptor(func(ctx context.Context, req *http.Request, invoker HTTPDelegatedInvoker) (*http.Response, error) {
//	        log.Printf("Request: %s %s", req.Method, req.URL)
//	        // Forward request to server
//	        resp, err := invoker.Invoke(req)
//	        if err != nil {
//	            return nil, err
//	        }
//	        log.Printf("Response: %d", resp.StatusCode)
//	        return resp, nil
//	    }),
//	)
func WithHTTPInterceptor(interceptor HTTPInterceptor) Option {
	return OptionFunc(func(o *options) {
		o.httpInt = interceptor
	})
}

// WithWebsocketInterceptor sets a custom WebSocket interceptor for the proxy.
// The interceptor allows you to inspect and modify WebSocket messages
// in both directions (client-to-server and server-to-client) as they pass through the proxy.
//
// The WebsocketInterceptor is called for each WebSocket message with:
//   - context.Context: Request context containing metadata
//   - metadata.WSDirection: Message direction
//   - int: WebSocket message type
//   - *buf.Buffer: Message data buffer (can be read and modified)
//   - *http.Request: The original HTTP upgrade request
//   - WebsocketDelegatedInvoker: Delegate to invoke message forwarding (call to continue)
//
// The interceptor can:
//   - Inspect/modify message data before forwarding
//   - Call the invoker to forward the message
//   - Drop messages by not calling the invoker
//   - Inject custom messages by calling the invoker multiple times
//
// Example:
//
//	handler, err := NewMitmProxyHandler(
//	    WithWebsocketInterceptor(func(ctx context.Context, dir metadata.WSDirection, msgType int, data *buf.Buffer, req *http.Request, invoker WebsocketDelegatedInvoker) error {
//	        log.Printf("[%s] WebSocket message: type=%d, size=%d", dir, msgType, data.Len())
//	        // Forward message
//	        return invoker.Invoke(msgType, data)
//	    }),
//	)
func WithWebsocketInterceptor(interceptor WebsocketInterceptor) Option {
	return OptionFunc(func(o *options) {
		o.wsInt = interceptor
	})
}

// WithChainHTTPInterceptor chains multiple HTTP interceptors together.
// Interceptors are executed in the order they are provided, forming a middleware chain.
// Each interceptor can modify the request, call the next interceptor in the chain,
// and modify the response. And The final interceptor will forwards the request to the server.
//
// Example:
//
//	loggingInterceptor := func(ctx context.Context, req *http.Request, invoker HTTPDelegatedInvoker) (*http.Response, error) {
//	    log.Printf("→ %s %s", req.Method, req.URL)
//	    resp, err := invoker.Invoke(req)
//	    if resp != nil {
//	        log.Printf("← %d", resp.StatusCode)
//	    }
//	    return resp, err
//	}
//
//	modifyInterceptor := func(ctx context.Context, req *http.Request, invoker HTTPDelegatedInvoker) (*http.Response, error) {
//	    req.Header.Set("X-Custom-Header", "value")
//	    return invoker.Invoke(req)
//	}
//
//	handler, err := NewMitmProxyHandler(
//	    WithChainHTTPInterceptor(loggingInterceptor, modifyInterceptor),
//	)
func WithChainHTTPInterceptor(interceptors ...HTTPInterceptor) Option {
	return OptionFunc(func(o *options) {
		o.chainHttpInts = append(o.chainHttpInts, interceptors...)
	})
}
