package mitmproxy

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"slices"
	"time"

	utls "github.com/refraction-networking/utls"
)

var (
	ErrInvalidWebsocketFrameBufferSize = errors.New("websocket frame buffer size must be greater than 0")
	ErrInvalidWebsocketMessageSize     = errors.New("websocket message size must be greater than 0")
	ErrInvalidWebsocketBufferedBytes   = errors.New("websocket buffered bytes must be at least the maximum message size")
	ErrInvalidHTTPHeaderSize           = errors.New("HTTP header size must be greater than 0")
	ErrInvalidHandshakeTimeout         = errors.New("handshake timeout must be greater than 0")
	ErrInvalidHTTP1PipelineDepth       = errors.New("HTTP/1 pipeline depth must be greater than 0")
)

type RuntimeConfigManager interface {
	SetProxy(proxy string) error
	SetProxyDisabled(disabled bool) error
	SetDialer(dialer *net.Dialer) error
	SetHostFilters(includeHosts, excludeHosts []string)
	SetRootCAs(rootCAPaths ...string) error
	SetClientCerts(clientCerts map[string]ClientCert) error

	SetIdleConnTimeout(timeout time.Duration)
	SetSkipVerifySSLFromServer(skip bool)
	SetHTTP2Disabled(disabled bool)
	SetStreamBaseContext(ctx context.Context)
	SetLogger(logger *slog.Logger)

	SetErrorHandler(handler ErrorHandler)
	SetHTTPInterceptor(interceptor HTTPInterceptor)
	SetChainHTTPInterceptors(interceptors ...HTTPInterceptor)
	SetWebsocketInterceptor(interceptor WebsocketInterceptor)
	// SetRawTCPInterceptor replaces the raw TCP tunnel observer used by new
	// connections. Passing nil disables observation for new connections.
	SetRawTCPInterceptor(interceptor RawTCPInterceptor)
	SetMaxWebsocketFramesPerForward(maxFrames int) error
}

type RuntimeResourceLimitManager interface {
	SetHandshakeTimeout(timeout time.Duration) error
	SetMaxHTTPHeaderBytes(maxBytes int) error
	SetHTTP1PipelineDepth(depth int) error
	SetMaxWebsocketMessageBytes(maxBytes int64) error
	SetMaxWebsocketBufferedBytes(maxBytes int64) error
}

type DynamicMitmProxyHandler interface {
	MitmProxyHandler
	RuntimeConfigManager
}

type ResourceLimitedDynamicMitmProxyHandler interface {
	DynamicMitmProxyHandler
	RuntimeResourceLimitManager
}

type runtimeConfigState struct {
	streamBaseCtx context.Context

	proxy         string
	skipVerifySSL bool
	disableHTTP2  bool
	disableProxy  bool
	includeHosts  []string
	excludeHosts  []string
	rootCAs       []string
	dialer        *net.Dialer
	logger        *slog.Logger

	idleConnTimeout       time.Duration
	handshakeTimeout      time.Duration
	maxHTTPHeaderBytes    int
	http1PipelineDepth    int
	wsMaxFramesPerForward int
	wsMaxMessageBytes     int64
	wsMaxBufferedBytes    int64

	clientCerts map[string]ClientCert

	errHandler    ErrorHandler
	httpInt       HTTPInterceptor
	wsInt         WebsocketInterceptor
	rawTCPInt     RawTCPInterceptor
	chainHttpInts []HTTPInterceptor
}

type runtimeConfig struct {
	state runtimeConfigState

	proxyDialer    *proxyDialer
	rootCACertPool *x509.CertPool
	clientCertPool map[string]utls.Certificate
	httpInt        HTTPInterceptor
	domainMatcher  struct {
		include *trieNode
		exclude *trieNode
	}
}

func newRuntimeConfigStateFromOptions(opts *options) runtimeConfigState {
	return runtimeConfigState{
		streamBaseCtx:         opts.streamBaseCtx,
		proxy:                 opts.proxy,
		skipVerifySSL:         opts.skipVerifySSL,
		disableHTTP2:          opts.disableHTTP2,
		disableProxy:          opts.disableProxy,
		includeHosts:          slices.Clone(opts.includeHosts),
		excludeHosts:          slices.Clone(opts.excludeHosts),
		rootCAs:               slices.Clone(opts.rootCAs),
		dialer:                opts.dialer,
		logger:                opts.logger,
		idleConnTimeout:       opts.idleConnTimeout,
		handshakeTimeout:      opts.handshakeTimeout,
		maxHTTPHeaderBytes:    opts.maxHTTPHeaderBytes,
		http1PipelineDepth:    opts.http1PipelineDepth,
		wsMaxFramesPerForward: opts.wsMaxFramesPerForward,
		wsMaxMessageBytes:     opts.wsMaxMessageBytes,
		wsMaxBufferedBytes:    opts.wsMaxBufferedBytes,
		clientCerts:           cloneClientCerts(opts.clientCerts),
		errHandler:            opts.errHandler,
		httpInt:               opts.httpInt,
		wsInt:                 opts.wsInt,
		rawTCPInt:             opts.rawTCPInt,
		chainHttpInts:         slices.Clone(opts.chainHttpInts),
	}
}

func (s runtimeConfigState) clone() runtimeConfigState {
	s.includeHosts = slices.Clone(s.includeHosts)
	s.excludeHosts = slices.Clone(s.excludeHosts)
	s.rootCAs = slices.Clone(s.rootCAs)
	s.clientCerts = cloneClientCerts(s.clientCerts)
	s.chainHttpInts = slices.Clone(s.chainHttpInts)
	return s
}

func buildRuntimeConfig(state runtimeConfigState) (*runtimeConfig, error) {
	state = state.clone()
	if state.streamBaseCtx == nil {
		state.streamBaseCtx = context.Background()
	}
	if state.dialer == nil {
		state.dialer = &net.Dialer{Timeout: dialTimeout}
	}
	state.logger = normalizeLogger(state.logger)
	if state.wsMaxFramesPerForward <= 0 {
		return nil, ErrInvalidWebsocketFrameBufferSize
	}
	if state.wsMaxMessageBytes <= 0 {
		return nil, ErrInvalidWebsocketMessageSize
	}
	if state.wsMaxBufferedBytes < state.wsMaxMessageBytes {
		return nil, ErrInvalidWebsocketBufferedBytes
	}
	if state.maxHTTPHeaderBytes <= 0 {
		return nil, ErrInvalidHTTPHeaderSize
	}
	if state.http1PipelineDepth <= 0 {
		return nil, ErrInvalidHTTP1PipelineDepth
	}
	if state.handshakeTimeout <= 0 {
		return nil, ErrInvalidHandshakeTimeout
	}

	proxyURL, err := parseProxyFrom(state.disableProxy, state.proxy)
	if err != nil {
		return nil, fmt.Errorf("failed to parse proxy url: %w", err)
	}
	rootPool, err := loadRootCAPool(state.rootCAs)
	if err != nil {
		return nil, err
	}
	clientCertPool, err := loadClientCertPool(state.clientCerts)
	if err != nil {
		return nil, err
	}

	includeMatcher, excludeMatcher := newTrieNode(), newTrieNode()
	for _, host := range state.includeHosts {
		includeMatcher.insert(host)
	}
	for _, host := range state.excludeHosts {
		excludeMatcher.insert(host)
	}

	cfg := &runtimeConfig{
		state:          state,
		proxyDialer:    newConfiguredProxyDialer(proxyURL, state.dialer, !state.disableProxy && state.proxy == ""),
		rootCACertPool: rootPool,
		clientCertPool: clientCertPool,
		httpInt:        buildHTTPInterceptorChain(state.httpInt, state.chainHttpInts),
	}
	cfg.domainMatcher.include = includeMatcher
	cfg.domainMatcher.exclude = excludeMatcher
	return cfg, nil
}

func buildHTTPInterceptorChain(interceptor HTTPInterceptor, chain []HTTPInterceptor) HTTPInterceptor {
	interceptors := slices.Clone(chain)
	if interceptor != nil {
		interceptors = append([]HTTPInterceptor{interceptor}, interceptors...)
	}
	switch len(interceptors) {
	case 0:
		return nil
	case 1:
		return interceptors[0]
	default:
		return chainHTTPInterceptors(interceptors)
	}
}

func loadRootCAPool(rootCAPaths []string) (*x509.CertPool, error) {
	if len(rootCAPaths) == 0 {
		return nil, nil
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	for _, path := range rootCAPaths {
		ca, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read root ca file: %w", err)
		}
		if ok := pool.AppendCertsFromPEM(ca); !ok {
			return nil, errors.New("failed to append ca file to cert pool")
		}
	}
	return pool, nil
}

func loadClientCertPool(clientCerts map[string]ClientCert) (map[string]utls.Certificate, error) {
	pool := make(map[string]utls.Certificate, len(clientCerts))
	for hostname, cc := range clientCerts {
		tlsCert, err := utls.LoadX509KeyPair(cc.CertPath, cc.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load client cert: %s:%s %w", cc.CertPath, cc.KeyPath, err)
		}
		pool[normalizeDomain(hostname)] = tlsCert
	}
	return pool, nil
}

func cloneClientCerts(src map[string]ClientCert) map[string]ClientCert {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]ClientCert, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
