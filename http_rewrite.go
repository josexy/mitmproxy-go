package mitmproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	http "github.com/josexy/xhttp"
	utls "github.com/refraction-networking/utls"
)

// ErrDropHTTP terminates the current HTTP exchange without a final response.
// An HTTP/1 connection is closed; HTTP/2 resets only the affected stream.
// Interceptors may wrap this sentinel. Return it before Invoke to avoid sending
// the request upstream, or after Invoke to suppress an upstream response.
var ErrDropHTTP = errors.New("mitmproxy: HTTP exchange dropped")

type httpUpstreamTargetKey struct{}

type httpUpstreamTarget struct {
	scheme, authority, address string
}

// WithHTTPUpstreamTarget returns a shallow copy of req with an explicit upstream
// routing override. Only target's http/https scheme and authority are used;
// req's path, query and Host remain unchanged. The override is consumed after
// interceptor execution, independently of the original connection target.
// Same-origin overrides reuse the validated route's transport. Cross-origin
// invocations own their transport, retaining proxy, TLS trust, client
// certificates, captured TLS fingerprints and cancellation configuration.
func WithHTTPUpstreamTarget(req *http.Request, target *url.URL) (*http.Request, error) {
	if req == nil || target == nil || target.Opaque != "" || target.User != nil || (target.Scheme != "http" && target.Scheme != "https") || target.Hostname() == "" {
		return nil, errors.New("mitmproxy: upstream target requires an http/https URL with an authority and no userinfo")
	}
	port := target.Port()
	if port == "" {
		port = "80"
		if target.Scheme == "https" {
			port = "443"
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return nil, errors.New("mitmproxy: invalid upstream target port")
	}
	// Parse rejects invalid escaped hosts and invalid port syntax even for URLs
	// constructed directly rather than by url.Parse.
	if _, err := url.Parse(target.Scheme + "://" + target.Host); err != nil {
		return nil, fmt.Errorf("mitmproxy: invalid upstream target: %w", err)
	}
	t := httpUpstreamTarget{target.Scheme, target.Host, net.JoinHostPort(target.Hostname(), port)}
	return req.WithContext(context.WithValue(req.Context(), httpUpstreamTargetKey{}, t)), nil
}

func (r *mitmProxyHandler) invokeHTTPUpstream(req *http.Request, fallback HTTPDelegatedInvoker, original httpUpstreamTarget) (*http.Response, error) {
	if req == nil {
		return nil, errors.New("mitmproxy: nil request")
	}
	// Interceptors cannot reintroduce connection-scoped headers on either path.
	removeHopByHopRequestHeaders(req.Header)
	target, override := req.Context().Value(httpUpstreamTargetKey{}).(httpUpstreamTarget)
	if !override {
		return fallback.Invoke(req)
	}
	if req.URL == nil {
		closeRequestBody(req)
		return nil, errors.New("mitmproxy: nil request URL")
	}
	connCtx, ok := req.Context().Value(connContextKey).(*biConnContext)
	if !ok {
		closeRequestBody(req)
		return nil, errors.New("mitmproxy: missing connection context")
	}
	prepared := req.Clone(req.Context())
	prepared.Trailer = req.Trailer
	prepared.URL.Scheme, prepared.URL.Host = target.scheme, target.authority
	prepared.RequestURI = ""
	if target.scheme == original.scheme && strings.EqualFold(target.address, original.address) {
		// The override still authorizes the edited path/Host, but it need not
		// discard keep-alive or HTTP/2 multiplexing for the same destination.
		return fallback.Invoke(prepared)
	}
	// Dial before transport selection: the rewritten TLS origin may negotiate
	// a different HTTP version than the original origin.
	first, alpn, err := dialHTTPRewriteTarget(prepared, connCtx, target)
	if err != nil {
		closeRequestBody(req)
		return nil, err
	}
	var mu sync.Mutex
	initial := first
	transport := newTransport(target.address, func(ctx context.Context, _, _ string) (net.Conn, error) {
		mu.Lock()
		conn := initial
		initial = nil
		mu.Unlock()
		if conn != nil {
			return conn, nil
		}
		next := prepared.WithContext(ctx)
		conn, negotiated, err := dialHTTPRewriteTarget(next, connCtx, target)
		if target.scheme == "https" && negotiated == "" {
			negotiated = "http/1.1"
		}
		if err == nil && negotiated != alpn {
			_ = conn.Close()
			return nil, errors.New("mitmproxy: rewritten upstream changed negotiated HTTP protocol")
		}
		return conn, err
	}, connCtx.config.state.idleConnTimeout, connCtx.config.state.disableHTTP2, 1)
	// HTTPS without negotiated ALPN is HTTP/1.1, even for an HTTP/2 client.
	if target.scheme == "https" && alpn == "" {
		alpn = "http/1.1"
	}
	transport.setNegotiatedALPN(alpn)
	response, err := transport.RoundTrip(prepared)
	if err != nil {
		_ = transport.Close()
		mu.Lock()
		if initial != nil {
			_ = initial.Close()
			initial = nil
		}
		mu.Unlock()
		return nil, err
	}
	if response.Body == nil {
		response.Body = http.NoBody
	}
	response.Body = &httpRewriteBody{ReadCloser: response.Body, transport: transport}
	return response, nil
}

func dialHTTPRewriteTarget(req *http.Request, connCtx *biConnContext, target httpUpstreamTarget) (net.Conn, string, error) {
	ctx := req.Context()
	// Do not update connection-wide metadata for a target used by just one
	// stream. The existing proxy dialer retains configured/environment proxies.
	raw, err := connCtx.config.proxyDialer.DialTCPContext(ctx, target.address)
	if err != nil || target.scheme == "http" {
		return raw, "", err
	}
	cfg := connCtx.config
	host, _, _ := net.SplitHostPort(target.address)
	protos := []string{"http/1.1"}
	if req.ProtoMajor == 2 && !cfg.state.disableHTTP2 {
		protos = []string{"h2", "http/1.1"}
	}
	if connCtx.clientHello != nil {
		protos = filteredClientHelloProtos(connCtx.clientHello.info.SupportedProtos, cfg.state.disableHTTP2)
	}
	config := &utls.Config{ServerName: host, NextProtos: protos, RootCAs: cfg.rootCACertPool, InsecureSkipVerify: cfg.state.skipVerifySSL}
	if certificate, ok := cfg.clientCertPool[normalizeDomain(host)]; ok {
		config.Certificates = []utls.Certificate{certificate}
	}
	id := utls.HelloGolang
	if connCtx.clientHello != nil {
		id = utls.HelloCustom
	}
	conn := utls.UClient(raw, config, id)
	if connCtx.clientHello != nil {
		spec, err := clientHelloSpecFromRaw(connCtx.clientHello.raw, host, protos)
		if err == nil {
			err = conn.ApplyPreset(spec)
		}
		if err != nil {
			_ = raw.Close()
			return nil, "", err
		}
	}
	handshakeCtx, cancel := context.WithTimeout(ctx, cfg.state.handshakeTimeout)
	defer cancel()
	clear := setDeadlineFromContext(handshakeCtx, raw)
	err = conn.HandshakeContext(handshakeCtx)
	clear()
	if err != nil {
		_ = raw.Close()
		return nil, "", err
	}
	return conn, conn.ConnectionState().NegotiatedProtocol, nil
}

type httpRewriteBody struct {
	io.ReadCloser
	transport *singleConnTransport
	once      sync.Once
}

func (b *httpRewriteBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(func() { _ = b.transport.Close() })
	return err
}

// HTTPResponseSendResult describes the downstream send, not the upstream read.
// EndedAt is the terminal observation time, including failures; Err must be nil
// before interpreting it as successful completion. BodyBytes excludes HTTP
// headers and transfer framing and counts bytes accepted by downstream writes.
type HTTPResponseSendResult struct {
	HeaderBlock http.HeaderBlock
	StartedAt   time.Time
	EndedAt     time.Time
	BodyBytes   int64
	Err         error
	Canceled    bool
}

// Invocation cancellation interrupts HTTP/1 draining reads and resets only the
// corresponding upstream HTTP/2 stream. It also releases dropped responses an
// interceptor did not return to the proxy.
type httpInvocationBody struct {
	io.ReadCloser
	cancel context.CancelFunc
	once   sync.Once
	err    error
}

func (b *httpInvocationBody) Close() error {
	b.once.Do(func() { b.cancel(); b.err = b.ReadCloser.Close() })
	return b.err
}
