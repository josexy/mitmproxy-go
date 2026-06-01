package mitmproxy

import (
	"context"
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
		return state, runtimeConfigParts{}, nil
	})
}

func (r *mitmProxyHandler) SetSkipVerifySSLFromServer(skip bool) {
	_ = r.updateRuntimeConfig(func(state runtimeConfigState) (runtimeConfigState, runtimeConfigParts, error) {
		state.skipVerifySSL = skip
		return state, runtimeConfigParts{}, nil
	})
}

func (r *mitmProxyHandler) SetHTTP2Disabled(disabled bool) {
	_ = r.updateRuntimeConfig(func(state runtimeConfigState) (runtimeConfigState, runtimeConfigParts, error) {
		state.disableHTTP2 = disabled
		return state, runtimeConfigParts{}, nil
	})
}

func (r *mitmProxyHandler) SetStreamBaseContext(ctx context.Context) {
	_ = r.updateRuntimeConfig(func(state runtimeConfigState) (runtimeConfigState, runtimeConfigParts, error) {
		if ctx == nil {
			ctx = context.Background()
		}
		state.streamBaseCtx = ctx
		return state, runtimeConfigParts{}, nil
	})
}

func (r *mitmProxyHandler) SetErrorHandler(handler ErrorHandler) {
	_ = r.updateRuntimeConfig(func(state runtimeConfigState) (runtimeConfigState, runtimeConfigParts, error) {
		state.errHandler = handler
		return state, runtimeConfigParts{}, nil
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
		return state, runtimeConfigParts{}, nil
	})
}

func (r *mitmProxyHandler) SetMaxWebsocketFramesPerForward(maxFrames int) error {
	if maxFrames <= 0 {
		return ErrInvalidWebsocketFrameBufferSize
	}
	return r.updateRuntimeConfig(func(state runtimeConfigState) (runtimeConfigState, runtimeConfigParts, error) {
		state.wsMaxFramesPerForward = maxFrames
		return state, runtimeConfigParts{}, nil
	})
}

type runtimeConfigParts struct {
	proxy           bool
	rootCAs         bool
	clientCerts     bool
	domainMatcher   bool
	httpInterceptor bool
}

func (r *mitmProxyHandler) updateRuntimeConfig(update func(runtimeConfigState) (runtimeConfigState, runtimeConfigParts, error)) error {
	r.configMu.Lock()
	defer r.configMu.Unlock()

	oldCfg := r.config.Load()
	nextState, parts, err := update(r.runtimeState.clone())
	if err != nil {
		return err
	}
	nextCfg, err := rebuildRuntimeConfig(oldCfg, nextState, parts)
	if err != nil {
		return err
	}
	r.runtimeState = nextCfg.state
	r.config.Store(nextCfg)
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
		cfg.proxyDialer = NewProxyDialer(proxyURL, state.dialer)
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
