package mitmproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/josexy/mitmproxy-go/buf"
	"github.com/josexy/mitmproxy-go/internal/cert"
	"github.com/josexy/mitmproxy-go/internal/iocopy"
	"github.com/josexy/mitmproxy-go/metadata"
	"github.com/josexy/websocket"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

var (
	ErrServerCertUnavailable = errors.New("cannot found an available server tls certificate")
	ErrShortTLSPacket        = errors.New("short tls packet")
	ErrRequestContextMissing = errors.New("request context missing")
	ErrInvalidProxyRequest   = errors.New("invalid proxy request")
	ErrHijackNotSupported    = errors.New("http response hijack not supported")
)

type contextKey struct {
	name string
}

func (k *contextKey) String() string { return "mitmproxy-go context value " + k.name }

var (
	connContextKey = &contextKey{"connection-context"}
	reqContextKey  = &contextKey{"request-context"}
)

type ReqContext struct {
	Hostport          string
	Request           *http.Request
	HttpConnectMethod bool
}

func AppendToRequestContext(ctx context.Context, reqCtx ReqContext) context.Context {
	return context.WithValue(ctx, reqContextKey, reqCtx)
}

func FromRequestContext(ctx context.Context) (ReqContext, bool) {
	reqCtx, ok := ctx.Value(reqContextKey).(ReqContext)
	if !ok {
		return ReqContext{}, false
	}
	return reqCtx, true
}

func ParseHostPort(req *http.Request) (string, error) {
	var target string
	if req.Method != http.MethodConnect {
		target = req.Host
	} else {
		target = req.RequestURI
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil || port == "" {
		host = target
		if req.Method != http.MethodConnect {
			port = "80"
		}
		// ipv6
		if len(host) > 0 && host[0] == '[' {
			host = target[1 : len(host)-1]
		}
	}
	if len(host) == 0 {
		return "", err
	}
	return net.JoinHostPort(host, port), nil
}

var _ http.Hijacker = (*fakeHttpResponseWriter)(nil)
var _ http.ResponseWriter = (*fakeHttpResponseWriter)(nil)

type fakeHttpResponseWriter struct {
	conn   net.Conn
	bufRW  *bufio.ReadWriter
	header http.Header
}

func newFakeHttpResponseWriter(conn net.Conn) *fakeHttpResponseWriter {
	return &fakeHttpResponseWriter{
		conn:  conn,
		bufRW: bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn)),
	}
}

// Hijack hijack the connection for websocket
func (f *fakeHttpResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return f.conn, f.bufRW, nil
}

// implemented http.ResponseWriter but nothing to do
func (f *fakeHttpResponseWriter) Header() http.Header {
	if f.header == nil {
		f.header = make(http.Header)
	}
	return f.header
}

func (f *fakeHttpResponseWriter) Write([]byte) (int, error) { return 0, nil }
func (f *fakeHttpResponseWriter) WriteHeader(int)           {}

type localClientConn struct {
	net.Conn
	connCtx   *biConnContext
	closeChan chan struct{}
	lock      sync.Mutex
	closed    bool
	closeErr  error
}

type remoteClientConn struct {
	net.Conn
	connCtx   *biConnContext
	innerConn net.Conn
	lock      sync.Mutex
	closed    bool
	closeErr  error
}

func (c *localClientConn) waitClose() { <-c.closeChan }

func (c *localClientConn) Close() error {
	c.lock.Lock()
	if c.closed {
		c.lock.Unlock()
		return c.closeErr
	}
	c.closed = true
	c.closeErr = c.Conn.Close()
	c.lock.Unlock()
	close(c.closeChan)

	if c.connCtx.remote != nil {
		c.connCtx.remote.Close()
	}
	return c.closeErr
}

func (c *remoteClientConn) Close() error {
	c.lock.Lock()
	if c.closed {
		c.lock.Unlock()
		return c.closeErr
	}
	c.closed = true
	c.closeErr = c.Conn.Close()
	c.lock.Unlock()
	return c.closeErr
}

type biConnContext struct {
	local     *localClientConn
	remote    *remoteClientConn
	transport *singleConnTransport
	config    *runtimeConfig

	baseMetadata connectionMetadataRecorder
	remoteDialMu sync.Mutex
	remoteDialFn func(context.Context, string, string) (net.Conn, error)
}

func (c *biConnContext) dialRemote(ctx context.Context, network, addr string) (net.Conn, error) {
	c.remoteDialMu.Lock()
	dialFn := c.remoteDialFn
	c.remoteDialMu.Unlock()
	if dialFn == nil {
		return nil, errors.New("remote dialer missing in context")
	}
	return dialFn(ctx, network, addr)
}

func (c *biConnContext) setRemoteDialer(dialFn func(context.Context, string, string) (net.Conn, error)) {
	c.remoteDialMu.Lock()
	c.remoteDialFn = dialFn
	c.remoteDialMu.Unlock()
}

func (c *biConnContext) dialTCPWithMetadata(ctx context.Context, hostport string) (net.Conn, error) {
	recorder := connectionMetadataRecorderForContext(ctx, c.baseMetadata)
	start := time.Now()
	logConfigAttrs(ctx, c.config, slog.LevelDebug, "upstream tcp dial started",
		slog.String("network", "tcp"),
		slog.String("addr", hostport),
	)
	if recorder == nil {
		conn, err := c.config.proxyDialer.DialTCPContext(ctx, hostport)
		if err != nil {
			logConfigAttrs(ctx, c.config, slog.LevelDebug, "upstream tcp dial failed",
				slog.String("network", "tcp"),
				slog.String("addr", hostport),
				slog.Duration("duration", time.Since(start)),
				errorAttr(err),
			)
			return nil, err
		}
		logConfigAttrs(ctx, c.config, slog.LevelDebug, "upstream tcp dial completed",
			slog.String("network", "tcp"),
			slog.String("addr", hostport),
			slog.Duration("duration", time.Since(start)),
		)
		return conn, nil
	}
	conn, err := c.config.proxyDialer.DialTCPContextWithMetadata(ctx, hostport, recorder)
	if err != nil {
		logConfigAttrs(ctx, c.config, slog.LevelDebug, "upstream tcp dial failed",
			slog.String("network", "tcp"),
			slog.String("addr", hostport),
			slog.Duration("duration", time.Since(start)),
			errorAttr(err),
		)
		return nil, err
	}
	logConfigAttrs(ctx, c.config, slog.LevelDebug, "upstream tcp dial completed",
		slog.String("network", "tcp"),
		slog.String("addr", hostport),
		slog.Duration("duration", time.Since(start)),
	)
	setRemoteConnectionMetadata(recorder, conn, time.Now())
	return conn, nil
}

type ErrorContext struct {
	RemoteAddr string
	Hostport   string
	Error      error
}

type ErrorHandler func(ErrorContext)

type MitmProxyHandler interface {
	CACertPath() string

	// low-level api, Serve will take over net.Conn and call the Close function.
	Serve(context.Context, net.Conn) error
	// high-level application api
	// ServeSOCKS5 will take over net.Conn and call the Close function
	ServeSOCKS5(context.Context, net.Conn) error
	ServeHTTP(http.ResponseWriter, *http.Request)

	Cleanup()
}

type mitmProxyHandler struct {
	*options
	configMu       sync.Mutex
	config         atomic.Pointer[runtimeConfig]
	runtimeState   runtimeConfigState
	priKeyPool     *priKeyPool
	serverCertPool *certPool
	activeMu       sync.Mutex
	activeConns    map[*localClientConn]struct{}
	closed         bool
}

func NewMitmProxyHandler(opt ...Option) (MitmProxyHandler, error) {
	return newMitmProxyHandler(opt...)
}

func NewDynamicMitmProxyHandler(opt ...Option) (DynamicMitmProxyHandler, error) {
	return newMitmProxyHandler(opt...)
}

func newMitmProxyHandler(opt ...Option) (*mitmProxyHandler, error) {
	opts := newOptions(opt...)
	var err error
	opts.caCert, err = cert.LoadCACertificate(opts.caCertPath, opts.caKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load ca cert: %s", err)
	}
	if opts.certCachePool.Capacity > 0 && opts.certCachePool.Capacity%256 != 0 {
		return nil, fmt.Errorf("cert cache capacity must be a multiple of %d", 256)
	}
	runtimeState := newRuntimeConfigStateFromOptions(opts)
	runtimeConfig, err := buildRuntimeConfig(runtimeState)
	if err != nil {
		return nil, err
	}

	handler := &mitmProxyHandler{
		options:      opts,
		runtimeState: runtimeState,
		priKeyPool:   newPriKeyPool(opts.certCachePool.Capacity),
		activeConns:  make(map[*localClientConn]struct{}),
		serverCertPool: newServerCertPool(opts.certCachePool.Capacity,
			time.Duration(opts.certCachePool.IntervalSecond)*time.Second,
			time.Duration(opts.certCachePool.ExpireSecond)*time.Second,
		),
	}
	handler.config.Store(runtimeConfig)
	certCacheCapacity := opts.certCachePool.Capacity
	if certCacheCapacity <= 0 {
		certCacheCapacity = 2048
	}
	certCacheIntervalSeconds := opts.certCachePool.IntervalSecond
	if certCacheIntervalSeconds <= 0 {
		certCacheIntervalSeconds = 30
	}
	certCacheExpireSeconds := opts.certCachePool.ExpireSecond
	if certCacheExpireSeconds <= 0 {
		certCacheExpireSeconds = 15
	}
	logConfigAttrs(context.Background(), runtimeConfig, slog.LevelInfo, "mitm handler initialized",
		slog.Bool("proxy_configured", runtimeConfig.proxyDialer != nil && runtimeConfig.proxyDialer.proxyURL != nil),
		slog.Bool("disable_http2", runtimeConfig.state.disableHTTP2),
		slog.Bool("include_hosts_configured", len(runtimeConfig.state.includeHosts) > 0),
		slog.Bool("exclude_hosts_configured", len(runtimeConfig.state.excludeHosts) > 0),
		slog.Int("cert_cache_capacity", certCacheCapacity),
		slog.Int("cert_cache_interval_seconds", certCacheIntervalSeconds),
		slog.Int("cert_cache_expire_seconds", certCacheExpireSeconds),
	)
	return handler, nil
}

func newHTTP2Server(cfg *runtimeConfig) *http2.Server {
	server := &http2.Server{}
	if cfg != nil {
		server.IdleTimeout = cfg.state.idleConnTimeout
	}
	return server
}

func (r *mitmProxyHandler) Cleanup() {
	closed := r.closeActiveConns()
	r.serverCertPool.Stop()
	logConfigAttrs(context.Background(), r.config.Load(), slog.LevelInfo, "cleanup active connections",
		slog.Int("active_connections", closed),
	)
}

func (r *mitmProxyHandler) isClosed() bool {
	r.activeMu.Lock()
	defer r.activeMu.Unlock()
	return r.closed
}

func (r *mitmProxyHandler) trackActiveConn(conn *localClientConn) bool {
	r.activeMu.Lock()
	defer r.activeMu.Unlock()
	if r.closed {
		return false
	}
	r.activeConns[conn] = struct{}{}
	return true
}

func (r *mitmProxyHandler) untrackActiveConn(conn *localClientConn) {
	r.activeMu.Lock()
	delete(r.activeConns, conn)
	r.activeMu.Unlock()
}

func (r *mitmProxyHandler) closeActiveConns() int {
	r.activeMu.Lock()
	r.closed = true
	conns := make([]*localClientConn, 0, len(r.activeConns))
	for conn := range r.activeConns {
		conns = append(conns, conn)
	}
	r.activeMu.Unlock()

	for _, conn := range conns {
		if conn.connCtx != nil && conn.connCtx.transport != nil {
			_ = conn.connCtx.transport.Close()
		}
		_ = conn.Close()
	}
	return len(conns)
}

func (r *mitmProxyHandler) CACertPath() string {
	return r.caCertPath
}

func (r *mitmProxyHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	var err error
	remoteAddr, hostport := req.RemoteAddr, ""
	defer func() {
		if err != nil {
			r.handleError(ErrorContext{
				RemoteAddr: remoteAddr,
				Hostport:   hostport,
				Error:      err,
			})
		}
	}()
	hj, ok := w.(http.Hijacker)
	if !ok {
		err = ErrHijackNotSupported
		return
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		return
	}
	if rw != nil {
		conn = newBufConnExt(conn, rw)
	}
	request := req
	hostport, err = ParseHostPort(req)
	if err != nil {
		conn.Close()
		return
	}
	if req.Method == http.MethodConnect {
		request = nil
	} else if req.URL != nil && len(req.URL.Scheme) == 0 {
		// directly access proxy server and url scheme is empty
		err = ErrInvalidProxyRequest
		conn.Close()
		return
	}
	_ = r.Serve(AppendToRequestContext(req.Context(), ReqContext{
		Hostport:          hostport,
		Request:           request,
		HttpConnectMethod: req.Method == http.MethodConnect,
	}), conn)
}

func (r *mitmProxyHandler) ServeSOCKS5(ctx context.Context, conn net.Conn) error {
	var hostport string
	var err error
	defer func() {
		if err != nil {
			r.handleError(ErrorContext{
				RemoteAddr: remoteAddrOrDefault(conn.RemoteAddr()),
				Hostport:   hostport,
				Error:      err,
			})
		}
	}()
	if err = r.handleSocks5Handshake(ctx, conn); err != nil {
		conn.Close()
		return err
	}
	if hostport, err = r.handleSocks5Request(ctx, conn); err != nil {
		conn.Close()
		return err
	}
	retErr := r.Serve(AppendToRequestContext(ctx, ReqContext{
		Hostport:          hostport,
		Request:           nil,
		HttpConnectMethod: false,
	}), conn)
	return retErr
}

func (r *mitmProxyHandler) Serve(ctx context.Context, conn net.Conn) (err error) {
	reqCtx, ok := FromRequestContext(ctx)
	if !ok {
		conn.Close()
		return ErrRequestContextMissing
	}
	if r.isClosed() {
		conn.Close()
		return net.ErrClosed
	}
	cfg := r.config.Load()
	logConfigAttrs(ctx, cfg, slog.LevelDebug, "serve connection",
		slog.String("source_addr", remoteAddrOrDefault(conn.RemoteAddr())),
		slog.String("hostport", reqCtx.Hostport),
		slog.Bool("http_connect", reqCtx.HttpConnectMethod),
	)

	defer func() {
		if err != nil {
			handleErrorWithConfig(cfg, ErrorContext{
				RemoteAddr: remoteAddrOrDefault(conn.RemoteAddr()),
				Hostport:   reqCtx.Hostport,
				Error:      err,
			})
		}
	}()
	localConnEstTs := time.Now()
	md := metadata.NewMD()
	md.SetLocalConnectionEstablishedTs(localConnEstTs)
	md.SetRequestReceivedTs(localConnEstTs)
	md.SetRequestHostport(reqCtx.Hostport)
	dialStart := time.Now()
	logConfigAttrs(ctx, cfg, slog.LevelDebug, "upstream tcp dial started",
		slog.String("network", "tcp"),
		slog.String("addr", reqCtx.Hostport),
	)
	dstConn, err := cfg.proxyDialer.DialTCPContextWithMetadata(ctx, reqCtx.Hostport, md)
	if err != nil {
		conn.Close()
		logConfigAttrs(ctx, cfg, slog.LevelDebug, "upstream tcp dial failed",
			slog.String("network", "tcp"),
			slog.String("addr", reqCtx.Hostport),
			slog.Duration("duration", time.Since(dialStart)),
			errorAttr(err),
		)
		return fmt.Errorf("failed to connect to %s: %s", reqCtx.Hostport, err)
	}
	logConfigAttrs(ctx, cfg, slog.LevelDebug, "upstream tcp dial completed",
		slog.String("network", "tcp"),
		slog.String("addr", reqCtx.Hostport),
		slog.Duration("duration", time.Since(dialStart)),
	)
	remoteConnEstTs := time.Now()

	local := &localClientConn{
		Conn:      conn,
		closeChan: make(chan struct{}),
	}
	remote := &remoteClientConn{
		Conn: dstConn,
	}
	connCtx := &biConnContext{local: local, remote: remote, config: cfg, baseMetadata: md}
	local.connCtx, remote.connCtx = connCtx, connCtx
	conn, dstConn = local, remote
	if !r.trackActiveConn(local) {
		local.Close()
		return net.ErrClosed
	}
	defer r.untrackActiveConn(local)
	remote.innerConn = remote
	initialRemoteConn := remote.innerConn
	initialRemoteConnUsed := false
	connCtx.setRemoteDialer(func(ctx context.Context, network, addr string) (net.Conn, error) {
		connCtx.remoteDialMu.Lock()
		if !initialRemoteConnUsed {
			initialRemoteConnUsed = true
			conn := initialRemoteConn
			connCtx.remoteDialMu.Unlock()
			if conn == nil {
				return nil, errors.New("remote connection missing in context")
			}
			return conn, nil
		}
		connCtx.remoteDialMu.Unlock()
		return connCtx.dialTCPWithMetadata(ctx, reqCtx.Hostport)
	})
	connCtx.transport = newTransport(reqCtx.Hostport, func(ctx context.Context, network, addr string) (net.Conn, error) {
		return connCtx.dialRemote(ctx, network, addr)
	}, cfg.state.idleConnTimeout, cfg.state.disableHTTP2)

	defer local.Close()
	defer connCtx.transport.Close()

	if reqCtx.HttpConnectMethod {
		if _, err = conn.Write(HttpResponseConnectionEstablished); err != nil {
			return err
		}
	}

	passthrough, reason := shouldPassthroughRequest(cfg, reqCtx.Hostport)
	logConfigAttrs(ctx, cfg, slog.LevelDebug, "passthrough decision",
		slog.String("hostport", reqCtx.Hostport),
		slog.Bool("passthrough", passthrough),
		slog.String("reason", reason),
	)
	if passthrough {
		return r.passthroughTunnel(ctx, conn, dstConn)
	}

	md.SetLocalConnectionAddrInfo(metadata.ConnectionAddrInfo{
		SourceAddr:      getRemoteAddrPortFromConn(conn),
		DestinationAddr: getLocalAddrPortFromConn(conn),
	})
	setRemoteConnectionMetadata(md, dstConn, remoteConnEstTs)
	ctx = context.WithValue(metadata.AppendToContext(ctx, md), connContextKey, connCtx)

	return r.handleTunnelRequest(ctx, reqCtx.Request != nil)
}

func shouldPassthroughRequest(cfg *runtimeConfig, hostport string) (bool, string) {
	host, _, _ := net.SplitHostPort(hostport)

	if len(cfg.state.excludeHosts) > 0 {
		if found := cfg.domainMatcher.exclude.match(host); found {
			return true, "exclude_host"
		}
	}

	if len(cfg.state.includeHosts) > 0 {
		found := cfg.domainMatcher.include.match(host)
		if !found {
			return true, "not_in_include_hosts"
		}
	}

	return false, "intercept"
}

func (r *mitmProxyHandler) passthroughTunnel(ctx context.Context, srcConn, dstConn net.Conn) error {
	reqCtx, _ := FromRequestContext(ctx)
	// only write the request for none-CONNECT request
	if reqCtx.Request != nil {
		// we should copy the request to dst connection firstly
		// TODO: if upload large file, this will cause performance problem
		if err := reqCtx.Request.Write(dstConn); err != nil {
			return err
		}
	}
	return iocopy.IoCopyBidirectional(dstConn, srcConn)
}

func (r *mitmProxyHandler) handleError(ec ErrorContext) {
	cfg := r.config.Load()
	handleErrorWithConfig(cfg, ec)
}

func handleErrorWithConfig(cfg *runtimeConfig, ec ErrorContext) {
	if ec.Error != nil {
		logConfigAttrs(context.Background(), cfg, slog.LevelError, "proxy error",
			slog.String("remote_addr", ec.RemoteAddr),
			slog.String("hostport", ec.Hostport),
			errorAttr(ec.Error),
		)
	}
	if cfg != nil && cfg.state.errHandler != nil && ec.Error != nil {
		cfg.state.errHandler(ec)
	}
}

func cloneMetadataContext(ctx context.Context) context.Context {
	src, ok := metadata.FromContext(ctx)
	if !ok {
		return ctx
	}
	return metadata.AppendToContext(ctx, src.Clone())
}

type remoteConnectionMetadataRecorder interface {
	SetRemoteConnectionEstablishedTs(time.Time)
	SetRemoteConnectionAddrInfo(metadata.ConnectionAddrInfo)
}

type connectionMetadataRecorder interface {
	dialTimestampRecorder
	remoteConnectionMetadataRecorder
}

type multiConnectionMetadataRecorder struct {
	recorders []connectionMetadataRecorder
}

func connectionMetadataRecorderForContext(ctx context.Context, base connectionMetadataRecorder) connectionMetadataRecorder {
	recorders := make([]connectionMetadataRecorder, 0, 2)
	if md, ok := metadata.FromContext(ctx); ok {
		recorders = append(recorders, md)
	}
	if base != nil {
		recorders = append(recorders, base)
	}
	switch len(recorders) {
	case 0:
		return nil
	case 1:
		return recorders[0]
	default:
		return multiConnectionMetadataRecorder{recorders: recorders}
	}
}

func (m multiConnectionMetadataRecorder) SetDNSLookupStartTs(v time.Time) {
	for _, recorder := range m.recorders {
		recorder.SetDNSLookupStartTs(v)
	}
}

func (m multiConnectionMetadataRecorder) SetDNSLookupCompletedTs(v time.Time) {
	for _, recorder := range m.recorders {
		recorder.SetDNSLookupCompletedTs(v)
	}
}

func (m multiConnectionMetadataRecorder) SetSocketConnectStartTs(v time.Time) {
	for _, recorder := range m.recorders {
		recorder.SetSocketConnectStartTs(v)
	}
}

func (m multiConnectionMetadataRecorder) SetSocketConnectCompletedTs(v time.Time) {
	for _, recorder := range m.recorders {
		recorder.SetSocketConnectCompletedTs(v)
	}
}

func (m multiConnectionMetadataRecorder) SetRemoteConnectionEstablishedTs(v time.Time) {
	for _, recorder := range m.recorders {
		recorder.SetRemoteConnectionEstablishedTs(v)
	}
}

func (m multiConnectionMetadataRecorder) SetRemoteConnectionAddrInfo(v metadata.ConnectionAddrInfo) {
	for _, recorder := range m.recorders {
		recorder.SetRemoteConnectionAddrInfo(v)
	}
}

func setRemoteConnectionMetadata(md remoteConnectionMetadataRecorder, conn net.Conn, established time.Time) {
	if md == nil || conn == nil {
		return
	}
	md.SetRemoteConnectionEstablishedTs(established)
	md.SetRemoteConnectionAddrInfo(metadata.ConnectionAddrInfo{
		SourceAddr:      getLocalAddrPortFromConn(conn),
		DestinationAddr: getRemoteAddrPortFromConn(conn),
	})
}

type capturedClientHello struct {
	info *tls.ClientHelloInfo
	raw  []byte
}

type upstreamTLSHandshakeResult struct {
	conn               net.Conn
	hello              capturedClientHello
	negotiatedProtocol string
}

func (r *mitmProxyHandler) initiateSSLHandshakeWithClientHello(ctx context.Context, hello capturedClientHello, conn net.Conn) (net.Conn, *tls.Config, error) {
	connCtx := ctx.Value(connContextKey).(*biConnContext)
	cfg := connCtx.config
	reqCtx, _ := FromRequestContext(ctx)
	md, _ := metadata.FromContext(ctx)
	chi := hello.info

	serverName := chi.ServerName
	protos := filteredClientHelloProtos(chi.SupportedProtos, cfg.state.disableHTTP2)

	host, _, _ := net.SplitHostPort(reqCtx.Hostport)
	if serverName == "" {
		serverName = host
	}
	logConfigAttrs(ctx, cfg, slog.LevelDebug, "tls client hello captured",
		slog.String("hostport", reqCtx.Hostport),
		slog.String("server_name", serverName),
		slog.Any("alpn", protos),
	)
	tlsConfig := &utls.Config{
		// Get clientHello alpnProtocols from client and forward to server
		NextProtos: protos,
		ServerName: serverName,
		RootCAs:    cfg.rootCACertPool,
	}
	if cfg.state.skipVerifySSL {
		tlsConfig.InsecureSkipVerify = true
	}
	if len(cfg.clientCertPool) > 0 {
		if clientCert, ok := cfg.clientCertPool[host]; ok {
			// mTLS client-authentication
			tlsConfig.Certificates = []utls.Certificate{clientCert}
			logConfigAttrs(ctx, cfg, slog.LevelDebug, "client certificate selected",
				slog.String("host", host),
			)
		}
	}

	clientHelloSpec, err := clientHelloSpecFromRaw(hello.raw, serverName, protos)
	if err != nil {
		return nil, nil, err
	}
	tlsClientConn := utls.UClient(conn, tlsConfig, utls.HelloCustom)
	if err := tlsClientConn.ApplyPreset(clientHelloSpec); err != nil {
		return nil, nil, fmt.Errorf("apply client hello fingerprint: %w", err)
	}
	// send client hello and do tls handshake
	md.SetSSLHandshakeStartTs(time.Now())
	clearHandshakeDeadline := setDeadlineForTimeout(conn, cfg.state.idleConnTimeout)
	err = tlsClientConn.HandshakeContext(ctx)
	clearHandshakeDeadline()
	if err != nil {
		return nil, nil, fmt.Errorf("upstream tls handshake: %w", err)
	}
	tlsConnEstTs := time.Now()
	cs := tlsClientConn.ConnectionState()
	if cs.NegotiatedProtocol == "" {
		// fallback to http/1.1 if the server doesn't support ALPN or doesn't return the negotiated protocol
		cs.NegotiatedProtocol = "http/1.1"
	}
	var foundCert *x509.Certificate
	for _, cert := range cs.PeerCertificates {
		if !cert.IsCA {
			foundCert = cert
		}
	}
	if foundCert == nil {
		return nil, nil, ErrServerCertUnavailable
	}
	logConfigAttrs(ctx, cfg, slog.LevelDebug, "upstream tls handshake completed",
		slog.String("hostport", reqCtx.Hostport),
		slog.String("server_name", serverName),
		slog.String("selected_alpn", cs.NegotiatedProtocol),
		slog.Uint64("selected_tls_version", uint64(cs.Version)),
		slog.Uint64("selected_cipher_suite", uint64(cs.CipherSuite)),
	)
	md.SetSSLHandshakeCompletedTs(tlsConnEstTs)
	md.SetConnectionTLSState(&metadata.TLSState{
		ServerName:          chi.ServerName,
		CipherSuites:        chi.CipherSuites,
		TLSVersions:         chi.SupportedVersions,
		ALPN:                chi.SupportedProtos,
		SelectedCipherSuite: cs.CipherSuite,
		SelectedTLSVersion:  cs.Version,
		SelectedALPN:        cs.NegotiatedProtocol,
	})
	md.SetConnectionServerCertificate(&metadata.ServerCertificate{
		Version:            foundCert.Version,
		SerialNumber:       foundCert.SerialNumber,
		SignatureAlgorithm: foundCert.SignatureAlgorithm,
		Subject:            foundCert.Subject,
		Issuer:             foundCert.Issuer,
		NotBefore:          foundCert.NotBefore,
		NotAfter:           foundCert.NotAfter,
		DNSNames:           foundCert.DNSNames,
		IPAddresses:        foundCert.IPAddresses,
		RawContent:         foundCert.Raw,
	})

	// Get server certificate from local cache pool
	if serverCert, err := r.serverCertPool.Get(host); err == nil {
		logConfigAttrs(ctx, cfg, slog.LevelDebug, "server certificate cache hit",
			slog.String("host", host),
		)
		return tlsClientConn, &tls.Config{
			SessionTicketsDisabled: true,
			// Server selected negotiated protocol
			NextProtos:   []string{cs.NegotiatedProtocol},
			Certificates: []tls.Certificate{serverCert},
		}, nil
	}
	// Get private key from local cache pool
	privateKey, err := r.priKeyPool.Get()
	if err != nil {
		return nil, nil, err
	}
	serverCert, err := cert.NewCertificateBuilder().
		ServerAuth().
		ValidateDays(365).
		PrivateKey(privateKey).
		Subject(foundCert.Subject).
		DNSNames(foundCert.DNSNames).
		IPAddresses(foundCert.IPAddresses).
		BuildFromCA(r.caCert)
	if err != nil {
		return nil, nil, err
	}

	certificate := serverCert.Certificate()
	r.serverCertPool.Set(host, certificate)
	logConfigAttrs(ctx, cfg, slog.LevelDebug, "server certificate generated",
		slog.String("host", host),
	)
	return tlsClientConn, &tls.Config{
		SessionTicketsDisabled: true,
		// Server selected negotiated protocol
		NextProtos:   []string{cs.NegotiatedProtocol},
		Certificates: []tls.Certificate{certificate},
	}, nil
}

func (r *mitmProxyHandler) setTLSRemoteDialer(connCtx *biConnContext, hostport string, firstConn net.Conn, hello capturedClientHello) {
	var mu sync.Mutex
	initialConn := firstConn
	initialConnConsumed := false
	connCtx.setRemoteDialer(func(ctx context.Context, network, addr string) (net.Conn, error) {
		mu.Lock()
		if !initialConnConsumed {
			initialConnConsumed = true
			conn := initialConn
			initialConn = nil
			mu.Unlock()
			if conn == nil {
				return nil, errors.New("remote tls connection missing in context")
			}
			return conn, nil
		}
		mu.Unlock()

		rawConn, err := connCtx.dialTCPWithMetadata(ctx, hostport)
		if err != nil {
			return nil, err
		}
		tlsConn, _, err := r.initiateSSLHandshakeWithClientHello(ctx, hello, rawConn)
		if err != nil {
			rawConn.Close()
			return nil, err
		}
		return tlsConn, nil
	})
}

func isTLS(data []byte) bool {
	// Ref: https: //github.com/mitmproxy/mitmproxy/blob/main/mitmproxy/net/tls.py
	// TLS ClientHello magic, works for SSLv3, TLSv1.0, TLSv1.1, TLSv1.2, and TLSv1.3
	// http://www.moserware.com/2009/06/first-few-milliseconds-of-https.html#client-hello
	// https://tls13.ulfheim.net/
	// We assume that a client sending less than 3 bytes initially is not a TLS client.
	return data[0] == 0x16 && data[1] == 0x03 && data[2] <= 0x03
}

func setReadDeadlineForTimeout(conn net.Conn, timeout time.Duration) func() {
	if timeout <= 0 {
		return func() {}
	}
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	return func() { _ = conn.SetReadDeadline(time.Time{}) }
}

// setDeadlineForTimeout bounds a blocking handshake (which both reads and
// writes) so a hung peer cannot pin the goroutine and connection forever. The
// returned func clears the deadline so subsequent I/O is not affected.
func setDeadlineForTimeout(conn net.Conn, timeout time.Duration) func() {
	if timeout <= 0 {
		return func() {}
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	return func() { _ = conn.SetDeadline(time.Time{}) }
}

func (r *mitmProxyHandler) handleTunnelRequest(ctx context.Context, consumedRequest bool) (err error) {
	connCtx := ctx.Value(connContextKey).(*biConnContext)
	reqCtx, _ := FromRequestContext(ctx)
	var srcConn net.Conn = connCtx.local
	var dstConn net.Conn = connCtx.remote

	var data []byte

	if !consumedRequest {
		bufConn := newBufConn(srcConn)
		data, err = bufConn.Peek(3)
		if err != nil {
			return fmt.Errorf("short buffer to peek: %s", err)
		}
		srcConn = bufConn
	}

	fakerw := newFakeHttpResponseWriter(srcConn)

	var tlsRequest bool
	// Check if the common http/websocket request with tls
	if len(data) >= 3 && isTLS(data) {
		tlsRequest = true
		clientHelloInfoCh := make(chan capturedClientHello, 1)
		tlsConnCh := make(chan upstreamTLSHandshakeResult, 1)
		tlsConfigCh := make(chan *tls.Config, 1)
		errCh := make(chan error, 1)
		captureConn := newClientHelloCaptureConn(srcConn)
		tlsConn := tls.Server(captureConn, &tls.Config{
			SessionTicketsDisabled: true,
			GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
				rawClientHello, err := captureConn.RawClientHello()
				if err != nil {
					return nil, fmt.Errorf("capture client hello: %w", err)
				}
				clientHelloInfoCh <- capturedClientHello{
					info: chi,
					raw:  rawClientHello,
				}
				select {
				case err := <-errCh:
					return nil, err
				case cfg := <-tlsConfigCh:
					return cfg, nil
				}
			},
		})
		go func(c net.Conn) {
			chi, ok := <-clientHelloInfoCh
			if !ok {
				return
			}
			conn, tlsConfig, err := r.initiateSSLHandshakeWithClientHello(ctx, chi, c)
			if err != nil {
				errCh <- err
			} else {
				tlsConfigCh <- tlsConfig
				negotiatedProtocol := ""
				if len(tlsConfig.NextProtos) > 0 {
					negotiatedProtocol = tlsConfig.NextProtos[0]
				}
				tlsConnCh <- upstreamTLSHandshakeResult{
					conn:               conn,
					hello:              chi,
					negotiatedProtocol: negotiatedProtocol,
				}
			}
		}(dstConn)
		// read client hello and do tls handshake. Bound it so a slow client,
		// or a stalled upstream handshake that GetConfigForClient() blocks on,
		// cannot pin this goroutine and the connection forever.
		clearHandshakeDeadline := setDeadlineForTimeout(srcConn, connCtx.config.state.idleConnTimeout)
		err = tlsConn.HandshakeContext(ctx)
		clearHandshakeDeadline()
		if err != nil {
			// if tls handshake failed before GetConfigForClient(),
			// we should close the channel in order to quit the goroutine
			close(clientHelloInfoCh)
			select {
			case result := <-tlsConnCh:
				// if tls handshake failed after GetConfigForClient() succeed,
				// we should close the tls connection if it has been created
				result.conn.Close()
			default:
				// tls handshake failed if GetConfigForClient() failed
			}
			return fmt.Errorf("tls server handshake failed: %s", err)
		}
		// wait for tls handshake
		result := <-tlsConnCh
		dstConn = result.conn
		connCtx.remote.innerConn = dstConn
		connCtx.transport.setNegotiatedProtocol(result.negotiatedProtocol)
		r.setTLSRemoteDialer(connCtx, reqCtx.Hostport, dstConn, result.hello)
		srcConn = tlsConn
		fakerw = newFakeHttpResponseWriter(srcConn)
		logConfigAttrs(ctx, connCtx.config, slog.LevelDebug, "tls tunnel negotiated",
			slog.String("hostport", reqCtx.Hostport),
			slog.String("selected_alpn", result.negotiatedProtocol),
		)

		state := tlsConn.ConnectionState()
		// If the result of the negotiation is http2,
		// then we should hand over the process of processing the http2 stream to the underlying go http2 library,
		// and finally we only need to get the [http.Request] and process the [http.ResponseWriter].
		// Early process http2
		if state.NegotiatedProtocol == http2.NextProtoTLS {
			logConfigAttrs(ctx, connCtx.config, slog.LevelDebug, "http2 connection serving",
				slog.String("hostport", reqCtx.Hostport),
				slog.String("mode", "tls"),
			)
			newCtx, cancel := context.WithCancel(connCtx.config.state.streamBaseCtx)
			go func() {
				connCtx.local.waitClose()
				cancel()
			}()
			newHTTP2Server(connCtx.config).ServeConn(srcConn, &http2.ServeConnOpts{
				Context: newCtx,
				Handler: r.serveHTTP2Handler(ctx),
			})
			return
		}
	}

	request := reqCtx.Request
	for {
		reqCtx, _ := FromRequestContext(ctx)
		nextCtx, earlyDone, isWsUpgrade, err := r.distinguishHTTPRequest(ctx, fakerw, request, tlsRequest)
		if err != nil || earlyDone {
			if request == nil && isExpectedIdleReadClose(err) {
				return nil
			}
			return err
		}
		request = nil

		nextReqCtx, _ := FromRequestContext(nextCtx)
		if !requestMatchesHostport(nextReqCtx.Request, reqCtx.Hostport) {
			return fmt.Errorf("http keep-alive target changed from %s to %s", reqCtx.Hostport, nextReqCtx.Request.Host)
		}
		nextCtx = cloneMetadataContext(nextCtx)
		if md, ok := metadata.FromContext(nextCtx); ok {
			md.SetRequestReceivedTs(time.Now())
		}

		if isWsUpgrade {
			return r.relayConnForWS(nextCtx, srcConn, dstConn)
		}
		response, err := r.relayConnForHTTP(nextCtx, srcConn)
		if err != nil {
			return err
		}
		if shouldCloseHTTP1(nextReqCtx.Request, response) {
			return nil
		}
	}
}

func shouldCloseHTTP1(req *http.Request, response *http.Response) bool {
	if req == nil || req.ProtoMajor != 1 {
		return true
	}
	if req.Close {
		return true
	}
	return response != nil && response.Close
}

func requestMatchesHostport(req *http.Request, hostport string) bool {
	if req == nil {
		return false
	}
	requestHostport := req.Host
	if requestHostport == "" && req.URL != nil {
		requestHostport = req.URL.Host
	}
	host, port := splitHostOptionalPort(hostport)
	requestHost, requestPort := splitHostOptionalPort(requestHostport)
	if !strings.EqualFold(requestHost, host) {
		return false
	}
	return port == "" || requestPort == "" || requestPort == port
}

func splitHostOptionalPort(hostport string) (string, string) {
	host, port, err := net.SplitHostPort(hostport)
	if err == nil {
		return host, port
	}
	if strings.HasPrefix(hostport, "[") {
		if end := strings.Index(hostport, "]"); end > 0 {
			return hostport[1:end], ""
		}
	}
	return hostport, ""
}

func isExpectedIdleReadClose(err error) bool {
	if err == nil ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.ECONNABORTED) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "forcibly closed") ||
		strings.Contains(msg, "connection was aborted") ||
		strings.Contains(msg, "i/o timeout")
}

func (r *mitmProxyHandler) handlePrefaceOrH2CRequest(ctx context.Context, rw http.ResponseWriter, req *http.Request) (bool, error) {
	connCtx := ctx.Value(connContextKey).(*biConnContext)
	// Handle h2c with prior knowledge (RFC 7540 Section 3.4)
	if req.Method == "PRI" && len(req.Header) == 0 && req.URL.Path == "*" && req.Proto == "HTTP/2.0" {
		conn, err := initH2CWithPriorKnowledge(rw)
		if err != nil {
			return false, err
		}
		reqCtx, _ := FromRequestContext(ctx)
		logConfigAttrs(ctx, connCtx.config, slog.LevelDebug, "h2c prior knowledge",
			slog.String("hostport", reqCtx.Hostport),
		)
		newCtx, cancel := context.WithCancel(connCtx.config.state.streamBaseCtx)
		go func() {
			connCtx.local.waitClose()
			cancel()
		}()
		newHTTP2Server(connCtx.config).ServeConn(conn, &http2.ServeConnOpts{
			Context:          newCtx,
			Handler:          r.serveHTTP2Handler(ctx),
			SawClientPreface: true,
		})
		return true, nil
	}
	// Handle Upgrade to h2c (RFC 7540 Section 3.2).
	//
	// Unlike h2c prior knowledge, the first h2c-upgrade request is an
	// HTTP/1.1 hop-by-hop handshake that the upstream may need to observe.
	// Go does not expose a high-level client API for "stream 1 was already
	// sent as an HTTP/1.1 upgrade request, now read its HTTP/2 response".
	// Keep this path transparent: forward the upgrade request and then tunnel
	// the upgraded connection without MITM-parsing the HTTP/2 streams.
	if isH2CUpgrade(req.Header) {
		reqCtx, _ := FromRequestContext(ctx)
		logConfigAttrs(ctx, connCtx.config, slog.LevelDebug, "h2c upgrade passthrough",
			slog.String("hostport", reqCtx.Hostport),
			slog.String("method", requestMethod(req)),
			slog.String("url", requestURL(req)),
		)
		return true, r.passthroughH2CUpgrade(ctx, rw, req)
	}
	return false, nil
}

// passthroughH2CUpgrade forwards the HTTP/1.1 h2c upgrade handshake to the
// upstream and then tunnels the upgraded HTTP/2 bytes in both directions.
func (r *mitmProxyHandler) passthroughH2CUpgrade(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
	connCtx := ctx.Value(connContextKey).(*biConnContext)
	srcConn, rwc, err := http.NewResponseController(rw).Hijack()
	if err != nil {
		return err
	}
	if rwc != nil {
		srcConn = newBufConnExt(srcConn, rwc)
	}

	if err := writeH2CUpgradeRequestHeaders(connCtx.remote, req); err != nil {
		return err
	}
	return iocopy.IoCopyBidirectional(connCtx.remote, srcConn)
}

func writeH2CUpgradeRequestHeaders(dst io.Writer, req *http.Request) error {
	bw := bufio.NewWriter(dst)
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	requestURI := "/"
	if req.URL != nil {
		if uri := req.URL.RequestURI(); uri != "" {
			requestURI = uri
		}
	}
	if _, err := fmt.Fprintf(bw, "%s %s HTTP/1.1\r\n", method, requestURI); err != nil {
		return err
	}

	host := req.Host
	if host == "" && req.URL != nil {
		host = req.URL.Host
	}
	if host != "" {
		if _, err := fmt.Fprintf(bw, "Host: %s\r\n", host); err != nil {
			return err
		}
	}

	header := req.Header.Clone()
	removeProxyHeaders(header)
	header.Del("Host")
	header.Del(HttpHeaderContentLength)
	header.Del(HttpHeaderTransferEncoding)

	if req.ContentLength > 0 {
		if _, err := fmt.Fprintf(bw, "Content-Length: %d\r\n", req.ContentLength); err != nil {
			return err
		}
	} else if len(req.TransferEncoding) > 0 {
		if _, err := fmt.Fprintf(bw, "Transfer-Encoding: %s\r\n", strings.Join(req.TransferEncoding, ", ")); err != nil {
			return err
		}
	}

	if err := header.Write(bw); err != nil {
		return err
	}
	if _, err := io.WriteString(bw, "\r\n"); err != nil {
		return err
	}
	return bw.Flush()
}

func (r *mitmProxyHandler) distinguishHTTPRequest(ctx context.Context, fakerw *fakeHttpResponseWriter, request *http.Request, tlsRequest bool) (newCtx context.Context, earlyDone bool, upgrade bool, retErr error) {
	connCtx := ctx.Value(connContextKey).(*biConnContext)
	reqCtx, _ := FromRequestContext(ctx)

	// Read the http request for https/wss via tls tunnel

	// Need to read the request
	if request == nil {
		_, rw, err := fakerw.Hijack()
		if err != nil {
			retErr = err
			return
		}
		clearDeadline := setReadDeadlineForTimeout(fakerw.conn, connCtx.config.state.idleConnTimeout)
		request, err = http.ReadRequest(rw.Reader)
		clearDeadline()
		if err != nil {
			retErr = err
			return
		}
	}

	if !connCtx.config.state.disableHTTP2 {
		earlyDone, retErr = r.handlePrefaceOrH2CRequest(ctx, fakerw, request)
		if retErr != nil || earlyDone {
			return
		}
	}

	if tlsRequest {
		request.URL.Scheme = "https"
	} else {
		request.URL.Scheme = "http"
	}
	request.URL.Host = request.Host

	if upgrade = isWSUpgrade(request.Header); upgrade {
		if tlsRequest {
			request.URL.Scheme = "wss"
		} else {
			request.URL.Scheme = "ws"
		}
	}
	logConfigAttrs(ctx, connCtx.config, slog.LevelDebug, "http request parsed",
		slog.String("hostport", reqCtx.Hostport),
		slog.String("method", requestMethod(request)),
		slog.String("url", requestURL(request)),
		slog.String("proto", requestProto(request)),
		slog.Bool("websocket_upgrade", upgrade),
	)

	removeProxyHeaders(request.Header)
	// patch the new request to the request context
	reqCtx.Request = request
	newCtx = AppendToRequestContext(ctx, reqCtx)

	return
}

type wsFrameImpl struct {
	dir     WSDirection
	msgType int
	dataBuf *buf.Buffer

	released atomic.Bool
	dst      *websocket.Conn
}

func (f *wsFrameImpl) Direction() WSDirection { return f.dir }

func (f *wsFrameImpl) MessageType() int { return f.msgType }

func (f *wsFrameImpl) DataBuffer() *buf.Buffer { return f.dataBuf }

func (f *wsFrameImpl) Invoke() error {
	err := f.dst.WriteMessage(f.msgType, f.dataBuf.Bytes())
	f.Release()
	return err
}

func (f *wsFrameImpl) Release() {
	if f.released.CompareAndSwap(false, true) {
		releaseBuffer(f.dataBuf)
	}
}

type wsFramesWatcherImpl struct {
	framesCh  chan WsFrame
	closeOnce sync.Once
}

func (w *wsFramesWatcherImpl) Receive() <-chan WsFrame { return w.framesCh }

func (w *wsFramesWatcherImpl) send(ctx context.Context, frame WsFrame) bool {
	select {
	case <-ctx.Done():
		return false
	case w.framesCh <- frame:
		return true
	}
}

func (w *wsFramesWatcherImpl) close() {
	w.closeOnce.Do(func() {
		close(w.framesCh)
	})
}

func (r *mitmProxyHandler) relayConnForWS(ctx context.Context, srcConn, dstConn net.Conn) (err error) {
	connCtx := ctx.Value(connContextKey).(*biConnContext)
	cfg := connCtx.config
	reqCtx, _ := FromRequestContext(ctx)
	reqClone := reqCtx.Request.Clone(reqCtx.Request.Context())
	if reqClone.Body != nil {
		data, err := io.ReadAll(reqClone.Body)
		if err != nil {
			return err
		}
		reqClone.Body.Close()
		reqClone.Body = io.NopCloser(bytes.NewReader(data))
		reqCtx.Request.Body = io.NopCloser(bytes.NewReader(data))
	}

	wsDstConn, resp, err := websocket.DialWithPreparedRequestAndNetConn(reqClone, dstConn)
	if err != nil {
		return err
	}
	wsSrcConn, err := websocket.UpgradeWithPreparedResponseAndNetConn(resp, srcConn)
	if err != nil {
		wsDstConn.Close()
		return err
	}
	logConfigAttrs(ctx, cfg, slog.LevelDebug, "websocket upgraded",
		slog.String("hostport", reqCtx.Hostport),
		slog.String("method", requestMethod(reqCtx.Request)),
		slog.String("url", requestURL(reqCtx.Request)),
		slog.Int("status_code", resp.StatusCode),
	)

	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(err)
	go func() {
		<-ctx.Done()
		wsSrcConn.Close()
		wsDstConn.Close()
	}()

	var fw *wsFramesWatcherImpl
	if cfg.state.wsInt != nil {
		fw = &wsFramesWatcherImpl{
			framesCh: make(chan WsFrame, cfg.state.wsMaxFramesPerForward*2),
		}
		go cfg.state.wsInt(ctx, reqCtx.Request, resp, fw)
	}

	errCh := make(chan error, 2)
	reportErr := func(err error) {
		select {
		case errCh <- err:
		default:
		}
	}
	relayWSMessage := func(ctx context.Context, dir WSDirection, src, dst *websocket.Conn) {
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			msgType, buffer, err := readBufferFromWSConn(src)
			if err != nil {
				if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
					logConfigAttrs(ctx, cfg, slog.LevelDebug, "websocket relay read closed",
						slog.String("hostport", reqCtx.Hostport),
						slog.String("direction", dir.String()),
						errorAttr(err),
					)
				} else {
					logConfigAttrs(ctx, cfg, slog.LevelWarn, "websocket relay read failed",
						slog.String("hostport", reqCtx.Hostport),
						slog.String("direction", dir.String()),
						errorAttr(err),
					)
				}
				reportErr(err)
				break
			}
			logConfigAttrs(ctx, cfg, slog.LevelDebug, "websocket frame",
				slog.String("hostport", reqCtx.Hostport),
				slog.String("direction", dir.String()),
				slog.Int("message_type", msgType),
				slog.Int("bytes", buffer.Len()),
			)
			if fw != nil {
				// MUST release buffer manually
				frame := &wsFrameImpl{
					dir:     dir,
					msgType: msgType,
					dataBuf: buffer,
					dst:     dst,
				}
				if !fw.send(ctx, frame) {
					frame.Release()
					return
				}
			} else {
				if err := dst.WriteMessage(msgType, buffer.Bytes()); err != nil {
					releaseBuffer(buffer)
					reportErr(err)
					break
				}
				releaseBuffer(buffer)
			}
		}
	}

	var wg sync.WaitGroup
	wg.Go(func() { relayWSMessage(ctx, Send, wsSrcConn, wsDstConn) })
	wg.Go(func() { relayWSMessage(ctx, Receive, wsDstConn, wsSrcConn) })
	doneCh := make(chan struct{})
	go func() {
		wg.Wait()
		close(doneCh)
	}()
	select {
	case err = <-errCh:
		cancel(err)
	case <-ctx.Done():
		err = context.Cause(ctx)
	case <-doneCh:
		err = context.Cause(ctx)
	}
	if err == nil {
		err = io.EOF
	}
	cancel(err)
	<-doneCh
	if fw != nil {
		fw.close()
	}
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, context.Canceled) {
		logConfigAttrs(ctx, cfg, slog.LevelWarn, "websocket relay ended",
			slog.String("hostport", reqCtx.Hostport),
			errorAttr(err),
		)
	} else {
		logConfigAttrs(ctx, cfg, slog.LevelDebug, "websocket relay ended",
			slog.String("hostport", reqCtx.Hostport),
			errorAttr(err),
		)
	}
	return
}

func (r *mitmProxyHandler) relayConnForHTTP(ctx context.Context, srcConn net.Conn) (response *http.Response, err error) {
	reqCtx, _ := FromRequestContext(ctx)
	response, err = r.roundTripWithContext(ctx, reqCtx.Request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if err = response.Write(srcConn); err != nil {
		return nil, err
	}
	return
}

func (r *mitmProxyHandler) roundTripWithContext(ctx context.Context, req *http.Request) (response *http.Response, err error) {
	connCtx := ctx.Value(connContextKey).(*biConnContext)
	reqCtx, _ := FromRequestContext(ctx)
	md, _ := metadata.FromContext(ctx)
	if connCtx.transport == nil {
		return nil, errors.New("transport missing in connection context")
	}

	reqCtx.Request = req
	ctx = metadata.AppendToContext(AppendToRequestContext(req.Context(), reqCtx), md)
	req = req.WithContext(context.WithValue(ctx, connContextKey, connCtx))
	start := time.Now()
	logConfigAttrs(ctx, connCtx.config, slog.LevelDebug, "http request",
		slog.String("hostport", reqCtx.Hostport),
		slog.String("method", requestMethod(req)),
		slog.String("url", requestURL(req)),
		slog.String("proto", requestProto(req)),
	)
	// Only one http interceptor will be invoked
	if connCtx.config.httpInt != nil {
		response, err = connCtx.config.httpInt(ctx, req, HTTPDelegatedInvokerFunc(connCtx.transport.RoundTrip))
	} else {
		response, err = connCtx.transport.RoundTrip(req)
	}
	if err != nil {
		err = fmt.Errorf("transport RoundTrip %s failed: %s", reqCtx.Hostport, err)
		logConfigAttrs(ctx, connCtx.config, slog.LevelDebug, "http request failed",
			slog.String("hostport", reqCtx.Hostport),
			slog.String("method", requestMethod(req)),
			slog.String("url", requestURL(req)),
			slog.Duration("duration", time.Since(start)),
			errorAttr(err),
		)
		return
	}
	logConfigAttrs(ctx, connCtx.config, slog.LevelDebug, "http response",
		slog.String("hostport", reqCtx.Hostport),
		slog.String("method", requestMethod(req)),
		slog.String("url", requestURL(req)),
		slog.String("proto", response.Proto),
		slog.Int("status_code", response.StatusCode),
		slog.Duration("duration", time.Since(start)),
	)
	return
}

func (r *mitmProxyHandler) serveHTTP2Handler(ctx context.Context) http.Handler {
	reqCtx, _ := FromRequestContext(ctx)
	connCtx := ctx.Value(connContextKey).(*biConnContext)
	baseMD, _ := metadata.FromContext(ctx)
	baseMD.SetStreamBody(true)

	// the http.ResponseWriter actually is net/http/h2_bundle.go http2responseWriter
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		streamCtx := cloneMetadataContext(ctx)
		md, _ := metadata.FromContext(streamCtx)
		md.SetRequestReceivedTs(time.Now())

		if req.URL.Scheme == "" {
			if req.TLS != nil {
				req.URL.Scheme = "https"
			} else {
				req.URL.Scheme = "http"
			}
		}
		if req.URL.Host == "" {
			req.URL.Host = req.Host
		}
		// the request body size may be zero
		if req.ContentLength == 0 {
			if req.Body != nil {
				req.Body.Close()
			}
			req.Body = http.NoBody
			req.GetBody = func() (io.ReadCloser, error) { return http.NoBody, nil }
		}
		response, err := r.roundTripWithContext(streamCtx, req)
		if err != nil {
			handleErrorWithConfig(connCtx.config, ErrorContext{
				Hostport:   reqCtx.Hostport,
				RemoteAddr: req.RemoteAddr,
				Error:      err,
			})
			return
		}
		for k, vv := range response.Header {
			for _, v := range vv {
				rw.Header().Add(k, v)
			}
		}
		rw.WriteHeader(response.StatusCode)
		body := response.Body
		if body != nil {
			defer body.Close()
			// CAN NOT use response.Write(rw) because it is used for HTTP1
			if err = r.forwardStreamBody(rw, body); err != nil {
				handleErrorWithConfig(connCtx.config, ErrorContext{
					Hostport:   reqCtx.Hostport,
					RemoteAddr: req.RemoteAddr,
					Error:      fmt.Errorf("write http2 body failed: %s", err),
				})
				return
			}
		}

		// Copy trailers
		for k, vv := range response.Trailer {
			for _, v := range vv {
				rw.Header().Add(http2.TrailerPrefix+k, v)
			}
		}
	})
}

func (r *mitmProxyHandler) forwardStreamBody(rw http.ResponseWriter, body io.Reader) error {
	flusher, ok := rw.(http.Flusher)
	if !ok {
		// This should never happen for http2
		return iocopy.IoCopy(rw, body)
	}
	buffer := acquireHTTP2BodyBuffer()
	defer releaseHTTP2BodyBuffer(buffer)
	for {
		n, err := body.Read(buffer)
		if n > 0 {
			if _, writeErr := rw.Write(buffer[:n]); writeErr != nil {
				return fmt.Errorf("write to http.ResponseWriter failed: %s", writeErr)
			}
			// Flush the response to keep the client happy
			flusher.Flush()
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read from response body failed: %s", err)
		}
	}
	return nil
}

func getLocalAddrPortFromConn(conn net.Conn) (addrport netip.AddrPort) {
	if tcpAddr, ok := conn.LocalAddr().(*net.TCPAddr); ok {
		addr, _ := netip.AddrFromSlice(tcpAddr.IP)
		addrport = netip.AddrPortFrom(addr, uint16(tcpAddr.Port))
	}
	return
}

func getRemoteAddrPortFromConn(conn net.Conn) (addrport netip.AddrPort) {
	if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		addr, _ := netip.AddrFromSlice(tcpAddr.IP)
		addrport = netip.AddrPortFrom(addr, uint16(tcpAddr.Port))
	}
	return
}

func remoteAddrOrDefault(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
}
