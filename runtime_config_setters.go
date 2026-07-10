package mitmproxy

import (
	"context"
	"log/slog"
	"net"
	"slices"
	"time"
)

func (r *mitmProxyHandler) SetProxy(proxy string) error {
	return r.updateRuntimeConfig(func(state runtimeConfigState) (runtimeConfigState, runtimeConfigParts, error) {
		state.proxy = proxy
		state.disableProxy = false
		return state, runtimeConfigParts{proxy: true}, nil
	})
}

func (r *mitmProxyHandler) SetProxyDisabled(disabled bool) error {
	return r.updateRuntimeConfig(func(state runtimeConfigState) (runtimeConfigState, runtimeConfigParts, error) {
		state.disableProxy = disabled
		return state, runtimeConfigParts{proxy: true}, nil
	})
}

func (r *mitmProxyHandler) SetDialer(dialer *net.Dialer) error {
	return r.updateRuntimeConfig(func(state runtimeConfigState) (runtimeConfigState, runtimeConfigParts, error) {
		state.dialer = dialer
		return state, runtimeConfigParts{proxy: true}, nil
	})
}

func (r *mitmProxyHandler) SetHostFilters(includeHosts, excludeHosts []string) {
	_ = r.updateRuntimeConfig(func(state runtimeConfigState) (runtimeConfigState, runtimeConfigParts, error) {
		state.includeHosts = slices.Clone(includeHosts)
		state.excludeHosts = slices.Clone(excludeHosts)
		return state, runtimeConfigParts{domainMatcher: true}, nil
	})
}

func (r *mitmProxyHandler) SetRootCAs(rootCAPaths ...string) error {
	return r.updateRuntimeConfig(func(state runtimeConfigState) (runtimeConfigState, runtimeConfigParts, error) {
		state.rootCAs = slices.Clone(rootCAPaths)
		return state, runtimeConfigParts{rootCAs: true}, nil
	})
}

func (r *mitmProxyHandler) SetClientCerts(clientCerts map[string]ClientCert) error {
	return r.updateRuntimeConfig(func(state runtimeConfigState) (runtimeConfigState, runtimeConfigParts, error) {
		state.clientCerts = cloneClientCerts(clientCerts)
		return state, runtimeConfigParts{clientCerts: true}, nil
	})
}

func (r *mitmProxyHandler) SetIdleConnTimeout(timeout time.Duration) {
	_ = r.updateRuntimeConfig(func(state runtimeConfigState) (runtimeConfigState, runtimeConfigParts, error) {
		state.idleConnTimeout = timeout
		return state, runtimeConfigParts{idleConnTimeout: true}, nil
	})
}

func (r *mitmProxyHandler) SetHandshakeTimeout(timeout time.Duration) error {
	if timeout <= 0 {
		return ErrInvalidHandshakeTimeout
	}
	return r.updateRuntimeConfig(func(state runtimeConfigState) (runtimeConfigState, runtimeConfigParts, error) {
		state.handshakeTimeout = timeout
		return state, runtimeConfigParts{handshakeTimeout: true}, nil
	})
}

func (r *mitmProxyHandler) SetMaxHTTPHeaderBytes(maxBytes int) error {
	if maxBytes <= 0 {
		return ErrInvalidHTTPHeaderSize
	}
	return r.updateRuntimeConfig(func(state runtimeConfigState) (runtimeConfigState, runtimeConfigParts, error) {
		state.maxHTTPHeaderBytes = maxBytes
		return state, runtimeConfigParts{httpHeader: true}, nil
	})
}

func (r *mitmProxyHandler) SetSkipVerifySSLFromServer(skip bool) {
	_ = r.updateRuntimeConfig(func(state runtimeConfigState) (runtimeConfigState, runtimeConfigParts, error) {
		state.skipVerifySSL = skip
		return state, runtimeConfigParts{skipVerifySSL: true}, nil
	})
}

func (r *mitmProxyHandler) SetHTTP2Disabled(disabled bool) {
	_ = r.updateRuntimeConfig(func(state runtimeConfigState) (runtimeConfigState, runtimeConfigParts, error) {
		state.disableHTTP2 = disabled
		return state, runtimeConfigParts{http2: true}, nil
	})
}

func (r *mitmProxyHandler) SetStreamBaseContext(ctx context.Context) {
	_ = r.updateRuntimeConfig(func(state runtimeConfigState) (runtimeConfigState, runtimeConfigParts, error) {
		if ctx == nil {
			ctx = context.Background()
		}
		state.streamBaseCtx = ctx
		return state, runtimeConfigParts{streamBaseContext: true}, nil
	})
}

func (r *mitmProxyHandler) SetLogger(logger *slog.Logger) {
	_ = r.updateRuntimeConfig(func(state runtimeConfigState) (runtimeConfigState, runtimeConfigParts, error) {
		state.logger = logger
		return state, runtimeConfigParts{logger: true}, nil
	})
}

func (r *mitmProxyHandler) SetErrorHandler(handler ErrorHandler) {
	_ = r.updateRuntimeConfig(func(state runtimeConfigState) (runtimeConfigState, runtimeConfigParts, error) {
		state.errHandler = handler
		return state, runtimeConfigParts{errorHandler: true}, nil
	})
}

func (r *mitmProxyHandler) SetHTTPInterceptor(interceptor HTTPInterceptor) {
	_ = r.updateRuntimeConfig(func(state runtimeConfigState) (runtimeConfigState, runtimeConfigParts, error) {
		state.httpInt = interceptor
		state.chainHttpInts = nil
		return state, runtimeConfigParts{httpInterceptor: true}, nil
	})
}

func (r *mitmProxyHandler) SetChainHTTPInterceptors(interceptors ...HTTPInterceptor) {
	_ = r.updateRuntimeConfig(func(state runtimeConfigState) (runtimeConfigState, runtimeConfigParts, error) {
		state.httpInt = nil
		state.chainHttpInts = slices.Clone(interceptors)
		return state, runtimeConfigParts{httpInterceptor: true}, nil
	})
}

func (r *mitmProxyHandler) SetWebsocketInterceptor(interceptor WebsocketInterceptor) {
	_ = r.updateRuntimeConfig(func(state runtimeConfigState) (runtimeConfigState, runtimeConfigParts, error) {
		state.wsInt = interceptor
		return state, runtimeConfigParts{websocketInterceptor: true}, nil
	})
}

func (r *mitmProxyHandler) SetMaxWebsocketFramesPerForward(maxFrames int) error {
	if maxFrames <= 0 {
		logConfigAttrs(context.Background(), r.config.Load(), slog.LevelWarn, "runtime config update failed",
			slog.Any("parts", []string{"websocket"}),
			slog.Int("max_websocket_frames_per_forward", maxFrames),
			errorAttr(ErrInvalidWebsocketFrameBufferSize),
		)
		return ErrInvalidWebsocketFrameBufferSize
	}
	return r.updateRuntimeConfig(func(state runtimeConfigState) (runtimeConfigState, runtimeConfigParts, error) {
		state.wsMaxFramesPerForward = maxFrames
		return state, runtimeConfigParts{websocket: true}, nil
	})
}

func (r *mitmProxyHandler) SetMaxWebsocketMessageBytes(maxBytes int64) error {
	if maxBytes <= 0 {
		return ErrInvalidWebsocketMessageSize
	}
	return r.updateRuntimeConfig(func(state runtimeConfigState) (runtimeConfigState, runtimeConfigParts, error) {
		if state.wsMaxBufferedBytes < maxBytes {
			return state, runtimeConfigParts{websocket: true}, ErrInvalidWebsocketBufferedBytes
		}
		state.wsMaxMessageBytes = maxBytes
		return state, runtimeConfigParts{websocket: true}, nil
	})
}

func (r *mitmProxyHandler) SetMaxWebsocketBufferedBytes(maxBytes int64) error {
	if maxBytes <= 0 {
		return ErrInvalidWebsocketBufferedBytes
	}
	return r.updateRuntimeConfig(func(state runtimeConfigState) (runtimeConfigState, runtimeConfigParts, error) {
		if maxBytes < state.wsMaxMessageBytes {
			return state, runtimeConfigParts{websocket: true}, ErrInvalidWebsocketBufferedBytes
		}
		state.wsMaxBufferedBytes = maxBytes
		return state, runtimeConfigParts{websocket: true}, nil
	})
}

type runtimeConfigParts struct {
	proxy                bool
	rootCAs              bool
	clientCerts          bool
	domainMatcher        bool
	httpInterceptor      bool
	logger               bool
	idleConnTimeout      bool
	handshakeTimeout     bool
	httpHeader           bool
	skipVerifySSL        bool
	http2                bool
	streamBaseContext    bool
	errorHandler         bool
	websocketInterceptor bool
	websocket            bool
}

func (p runtimeConfigParts) names() []string {
	names := make([]string, 0, 8)
	if p.proxy {
		names = append(names, "proxy")
	}
	if p.rootCAs {
		names = append(names, "root_cas")
	}
	if p.clientCerts {
		names = append(names, "client_certs")
	}
	if p.domainMatcher {
		names = append(names, "host_filters")
	}
	if p.httpInterceptor {
		names = append(names, "http_interceptor")
	}
	if p.logger {
		names = append(names, "logger")
	}
	if p.idleConnTimeout {
		names = append(names, "idle_conn_timeout")
	}
	if p.handshakeTimeout {
		names = append(names, "handshake_timeout")
	}
	if p.httpHeader {
		names = append(names, "max_http_header_bytes")
	}
	if p.skipVerifySSL {
		names = append(names, "skip_verify_ssl")
	}
	if p.http2 {
		names = append(names, "http2")
	}
	if p.streamBaseContext {
		names = append(names, "stream_base_context")
	}
	if p.errorHandler {
		names = append(names, "error_handler")
	}
	if p.websocketInterceptor {
		names = append(names, "websocket_interceptor")
	}
	if p.websocket {
		names = append(names, "websocket")
	}
	return names
}

func (r *mitmProxyHandler) updateRuntimeConfig(update func(runtimeConfigState) (runtimeConfigState, runtimeConfigParts, error)) error {
	r.configMu.Lock()
	defer r.configMu.Unlock()

	oldCfg := r.config.Load()
	nextState, parts, err := update(r.runtimeState.clone())
	if err != nil {
		logConfigAttrs(context.Background(), oldCfg, slog.LevelWarn, "runtime config update failed",
			slog.Any("parts", parts.names()),
			errorAttr(err),
		)
		return err
	}
	nextCfg, err := rebuildRuntimeConfig(oldCfg, nextState, parts)
	if err != nil {
		logConfigAttrs(context.Background(), oldCfg, slog.LevelWarn, "runtime config update failed",
			slog.Any("parts", parts.names()),
			errorAttr(err),
		)
		return err
	}
	r.runtimeState = nextCfg.state
	r.config.Store(nextCfg)
	logConfigAttrs(context.Background(), nextCfg, slog.LevelInfo, "runtime config updated",
		slog.Any("parts", parts.names()),
	)
	return nil
}

func rebuildRuntimeConfig(oldCfg *runtimeConfig, state runtimeConfigState, parts runtimeConfigParts) (*runtimeConfig, error) {
	state = state.clone()
	if state.streamBaseCtx == nil {
		state.streamBaseCtx = context.Background()
	}
	if state.dialer == nil {
		state.dialer = &net.Dialer{Timeout: dialTimeout}
	}
	state.logger = normalizeLogger(state.logger)

	cfg := &runtimeConfig{
		state:          state,
		proxyDialer:    oldCfg.proxyDialer,
		rootCACertPool: oldCfg.rootCACertPool,
		clientCertPool: oldCfg.clientCertPool,
		httpInt:        oldCfg.httpInt,
	}
	cfg.domainMatcher = oldCfg.domainMatcher

	if parts.proxy {
		proxyURL, err := parseProxyFrom(state.disableProxy, state.proxy)
		if err != nil {
			return nil, err
		}
		cfg.proxyDialer = newConfiguredProxyDialer(proxyURL, state.dialer, !state.disableProxy && state.proxy == "")
	}
	if parts.rootCAs {
		rootPool, err := loadRootCAPool(state.rootCAs)
		if err != nil {
			return nil, err
		}
		cfg.rootCACertPool = rootPool
	}
	if parts.clientCerts {
		clientCertPool, err := loadClientCertPool(state.clientCerts)
		if err != nil {
			return nil, err
		}
		cfg.clientCertPool = clientCertPool
	}
	if parts.domainMatcher {
		includeMatcher, excludeMatcher := newTrieNode(), newTrieNode()
		for _, host := range state.includeHosts {
			includeMatcher.insert(host)
		}
		for _, host := range state.excludeHosts {
			excludeMatcher.insert(host)
		}
		cfg.domainMatcher.include = includeMatcher
		cfg.domainMatcher.exclude = excludeMatcher
	}
	if parts.httpInterceptor {
		cfg.httpInt = buildHTTPInterceptorChain(state.httpInt, state.chainHttpInts)
	}

	return cfg, nil
}
