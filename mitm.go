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
	"strconv"
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
	Socks5Connect     bool
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
	if req == nil {
		return "", ErrInvalidProxyRequest
	}
	var target string
	if req.Method != http.MethodConnect {
		target = req.Host
	} else {
		target = req.RequestURI
	}
	target = strings.TrimSpace(target)
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		if req.Method == http.MethodConnect {
			return "", fmt.Errorf("invalid CONNECT target %q: %w", target, err)
		}
		if strings.HasPrefix(target, "[") && strings.HasSuffix(target, "]") {
			host = target[1 : len(target)-1]
		} else {
			if strings.Contains(target, ":") {
				return "", fmt.Errorf("invalid request host %q: %w", target, err)
			}
			host = target
		}
		port = "80"
	}
	if host == "" || port == "" {
		return "", fmt.Errorf("invalid proxy target %q", target)
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", fmt.Errorf("invalid proxy target port %q", port)
	}
	return net.JoinHostPort(host, strconv.Itoa(portNumber)), nil
}

var _ http.Hijacker = (*fakeHttpResponseWriter)(nil)
var _ http.ResponseWriter = (*fakeHttpResponseWriter)(nil)

type fakeHttpResponseWriter struct {
	conn          net.Conn
	bufRW         *bufio.ReadWriter
	requestReader *boundedHTTPRequestReader
	header        http.Header
}

func newFakeHttpResponseWriter(conn net.Conn) *fakeHttpResponseWriter {
	requestReader := newBoundedHTTPRequestReader(conn)
	return &fakeHttpResponseWriter{
		conn:          conn,
		bufRW:         bufio.NewReadWriter(requestReader.reader, bufio.NewWriter(conn)),
		requestReader: requestReader,
	}
}

func (f *fakeHttpResponseWriter) ReadRequest(maxHeaderBytes int) (*http.Request, error) {
	return f.requestReader.ReadRequest(maxHeaderBytes)
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
	local  *localClientConn
	remote *remoteClientConn
	config *runtimeConfig

	baseMetadata connectionMetadataRecorder
	remoteDialMu sync.Mutex
	remoteDialFn func(context.Context, string, string) (net.Conn, error)

	// transport is replaced when a plain proxy connection is reused for a new
	// origin, and it is read by Cleanup from another goroutine.
	transportMu sync.Mutex
	transport   *singleConnTransport
}

func (c *biConnContext) currentTransport() *singleConnTransport {
	c.transportMu.Lock()
	defer c.transportMu.Unlock()
	return c.transport
}

// setTransport installs transport and returns the one it replaced.
func (c *biConnContext) setTransport(transport *singleConnTransport) *singleConnTransport {
	c.transportMu.Lock()
	previous := c.transport
	c.transport = transport
	c.transportMu.Unlock()
	return previous
}

func (c *biConnContext) closeTransport() {
	if transport := c.setTransport(nil); transport != nil {
		_ = transport.Close()
	}
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
	// ServeHTTP requires Request.Body to be untouched on entry. Do not wrap
	// this handler with middleware that reads or replaces Body.
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

func NewResourceLimitedDynamicMitmProxyHandler(opt ...Option) (ResourceLimitedDynamicMitmProxyHandler, error) {
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
		priKeyPool:   newPriKeyPool(),
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
		if conn.connCtx != nil {
			if transport := conn.connCtx.currentTransport(); transport != nil {
				_ = transport.Close()
			}
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
	request := req
	hostport, err = ParseHostPort(req)
	if err != nil {
		conn.Close()
		return
	}
	if req.Method == http.MethodConnect {
		request = nil
		if rw != nil {
			conn = newBufConnExt(conn, rw)
		}
	} else if req.URL != nil && len(req.URL.Scheme) == 0 {
		// directly access proxy server and url scheme is empty
		err = ErrInvalidProxyRequest
		conn.Close()
		return
	} else {
		request, conn, err = rebindRequestBodyAfterHijack(req, conn, rw)
		if err != nil {
			conn.Close()
			return
		}
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
	cfg := r.config.Load()
	handshakeCtx, cancelHandshake := context.WithTimeout(ctx, cfg.state.handshakeTimeout)
	clearDeadline := setDeadlineFromContext(handshakeCtx, conn)
	defer cancelHandshake()
	defer clearDeadline()
	if err = r.handleSocks5Handshake(handshakeCtx, conn); err != nil {
		conn.Close()
		return err
	}
	if hostport, err = r.handleSocks5Request(handshakeCtx, conn); err != nil {
		conn.Close()
		return err
	}
	clearDeadline()
	cancelHandshake()
	retErr := r.Serve(AppendToRequestContext(ctx, ReqContext{
		Hostport:          hostport,
		Request:           nil,
		HttpConnectMethod: false,
		Socks5Connect:     true,
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
		if reqCtx.Socks5Connect {
			_ = writeSocks5Reply(conn, socks5ReplyForError(err), nil)
		}
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
	if reqCtx.Socks5Connect {
		if err = writeSocks5Reply(conn, socks5ReplySucceeded, dstConn.LocalAddr()); err != nil {
			conn.Close()
			dstConn.Close()
			return err
		}
	}

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
		if addr == "" {
			addr = reqCtx.Hostport
		}
		connCtx.remoteDialMu.Lock()
		// The already established connection belongs to the target it was
		// dialed for; a retargeted transport has to dial its own.
		if !initialRemoteConnUsed && addr == reqCtx.Hostport {
			initialRemoteConnUsed = true
			conn := initialRemoteConn
			connCtx.remoteDialMu.Unlock()
			if conn == nil {
				return nil, errors.New("remote connection missing in context")
			}
			return conn, nil
		}
		connCtx.remoteDialMu.Unlock()
		return connCtx.dialTCPWithMetadata(ctx, addr)
	})
	connCtx.setTransport(newTransportForTarget(connCtx, reqCtx.Hostport))

	defer local.Close()
	defer func() {
		if transport := connCtx.currentTransport(); transport != nil {
			_ = transport.Close()
		}
	}()

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
		return r.passthroughTunnel(ctx, conn, dstConn, cfg.state.handshakeTimeout)
	}

	md.SetLocalConnectionAddrInfo(metadata.ConnectionAddrInfo{
		SourceAddr:      getRemoteAddrPortFromConn(conn),
		DestinationAddr: getLocalAddrPortFromConn(conn),
	})
	setRemoteConnectionMetadata(md, dstConn, remoteConnEstTs)
	ctx = context.WithValue(metadata.AppendToContext(ctx, md), connContextKey, connCtx)

	return r.handleTunnelRequest(ctx, reqCtx.Request != nil)
}

func newTransportForTarget(connCtx *biConnContext, hostport string) *singleConnTransport {
	return newTransport(hostport, func(ctx context.Context, network, addr string) (net.Conn, error) {
		return connCtx.dialRemote(ctx, network, addr)
	}, connCtx.config.state.idleConnTimeout, connCtx.config.state.disableHTTP2, connCtx.config.state.http1PipelineDepth)
}

// retargetTunnel points a plain proxy connection at a new upstream. Such a
// connection is not bound to a single origin: clients reuse it for any host,
// and Go's own http.Transport does exactly that because it leaves the target
// out of the pool key for http:// requests sent through an HTTP proxy.
func (r *mitmProxyHandler) retargetTunnel(ctx context.Context, connCtx *biConnContext, hostport string) error {
	if r.isClosed() {
		return net.ErrClosed
	}
	previous := connCtx.setTransport(newTransportForTarget(connCtx, hostport))
	if previous != nil {
		_ = previous.Close()
	}
	logConfigAttrs(ctx, connCtx.config, slog.LevelDebug, "http keep-alive retargeted",
		slog.String("hostport", hostport),
	)
	return nil
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

func (r *mitmProxyHandler) passthroughTunnel(ctx context.Context, srcConn, dstConn net.Conn, initialActivityTimeout time.Duration) error {
	reqCtx, _ := FromRequestContext(ctx)
	// only write the request for none-CONNECT request
	if reqCtx.Request != nil {
		// we should copy the request to dst connection firstly
		// TODO: if upload large file, this will cause performance problem
		request := withoutForwardedExpectContinue(reqCtx.Request)
		if err := request.Write(dstConn); err != nil {
			return err
		}
	} else {
		srcConn, dstConn = connsWithInitialActivityDeadline(initialActivityTimeout, srcConn, dstConn)
	}
	return iocopy.IoCopyBidirectional(dstConn, srcConn)
}

type initialActivityDeadline struct {
	once  sync.Once
	conns []net.Conn
}

func connsWithInitialActivityDeadline(timeout time.Duration, first, second net.Conn) (net.Conn, net.Conn) {
	if timeout <= 0 {
		return first, second
	}
	conns := []net.Conn{first, second}
	deadline := &initialActivityDeadline{conns: conns}
	for _, conn := range conns {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}
	return &activityTrackingConn{Conn: conns[0], deadline: deadline}, &activityTrackingConn{Conn: conns[1], deadline: deadline}
}

func (d *initialActivityDeadline) clear() {
	d.once.Do(func() {
		for _, conn := range d.conns {
			_ = conn.SetDeadline(time.Time{})
		}
	})
}

type activityTrackingConn struct {
	net.Conn
	deadline *initialActivityDeadline
}

func (c *activityTrackingConn) Read(data []byte) (int, error) {
	n, err := c.Conn.Read(data)
	if n > 0 {
		c.deadline.clear()
	}
	return n, err
}

func (c *activityTrackingConn) Write(data []byte) (int, error) {
	n, err := c.Conn.Write(data)
	if n > 0 {
		c.deadline.clear()
	}
	return n, err
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
		if clientCert, ok := cfg.clientCertPool[normalizeDomain(serverName)]; ok {
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
	clearHandshakeDeadline := setDeadlineForTimeout(conn, cfg.state.handshakeTimeout)
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

	certCacheKey := certificateCacheKey(serverName, host)
	// Get server certificate from local cache pool
	if serverCert, err := r.serverCertPool.Get(certCacheKey); err == nil {
		logConfigAttrs(ctx, cfg, slog.LevelDebug, "server certificate cache hit",
			slog.String("host", certCacheKey),
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
	r.serverCertPool.Set(certCacheKey, certificate)
	logConfigAttrs(ctx, cfg, slog.LevelDebug, "server certificate generated",
		slog.String("host", certCacheKey),
	)
	return tlsClientConn, &tls.Config{
		SessionTicketsDisabled: true,
		// Server selected negotiated protocol
		NextProtos:   []string{cs.NegotiatedProtocol},
		Certificates: []tls.Certificate{certificate},
	}, nil
}

func certificateCacheKey(serverName, host string) string {
	if serverName = normalizeDomain(serverName); serverName != "" {
		return serverName
	}
	return normalizeDomain(host)
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

type tunnelProtocol uint8

const (
	tunnelProtocolHTTP tunnelProtocol = iota
	tunnelProtocolTLS
	tunnelProtocolRaw
)

func detectTunnelProtocol(conn *bufConn) (tunnelProtocol, error) {
	data, err := conn.Peek(3)
	if err != nil {
		return tunnelProtocolRaw, err
	}
	if isTLS(data) {
		return tunnelProtocolTLS, nil
	}

	const (
		requestLineMethod = iota
		requestLineTarget
		requestLineVersion
	)
	state := requestLineMethod
	methodEnd, targetEnd, targetBytes := 0, 0, 0
	versionStart := 0
	for width := 1; width <= conn.r.Size(); width++ {
		data, err = conn.Peek(width)
		if err != nil {
			return tunnelProtocolRaw, err
		}
		value := data[width-1]
		switch state {
		case requestLineMethod:
			if value == ' ' {
				if width == 1 {
					return tunnelProtocolRaw, nil
				}
				methodEnd = width - 1
				state = requestLineTarget
				continue
			}
			if !isHTTPMethodByte(value) {
				return tunnelProtocolRaw, nil
			}
		case requestLineTarget:
			if value == ' ' {
				if targetBytes == 0 {
					return tunnelProtocolRaw, nil
				}
				targetEnd = width - 1
				versionStart = width
				state = requestLineVersion
				continue
			}
			if value <= ' ' || value >= 0x7f {
				return tunnelProtocolRaw, nil
			}
			targetBytes++
		case requestLineVersion:
			if value == '\n' {
				versionEnd := width - 1
				if versionEnd > versionStart && data[versionEnd-1] == '\r' {
					versionEnd--
				}
				method := string(data[:methodEnd])
				target := string(data[methodEnd+1 : targetEnd])
				version := string(data[versionStart:versionEnd])
				major, _, ok := http.ParseHTTPVersion(version)
				if ok && (major == 1 || (method == "PRI" && target == "*" && version == "HTTP/2.0")) {
					return tunnelProtocolHTTP, nil
				}
				return tunnelProtocolRaw, nil
			}
			if !isPotentialHTTPVersion(data[versionStart:width]) {
				return tunnelProtocolRaw, nil
			}
		}
	}

	// A request line longer than the sniff buffer is still HTTP-like once it
	// has a method and target. Let the bounded HTTP parser apply the configured
	// header limit instead of silently bypassing interception.
	if state == requestLineTarget && targetBytes > 0 {
		return tunnelProtocolHTTP, nil
	}
	if state == requestLineVersion && isPotentialHTTPVersion(data[versionStart:]) {
		return tunnelProtocolHTTP, nil
	}
	return tunnelProtocolRaw, nil
}

func isHTTPMethodByte(value byte) bool {
	if value >= '0' && value <= '9' || value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z' {
		return true
	}
	switch value {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	default:
		return false
	}
}

func isPotentialHTTPVersion(data []byte) bool {
	const prefix = "HTTP/"
	if len(data) <= len(prefix) {
		return string(data) == prefix[:len(data)]
	}

	majorDigits, minorDigits := 0, 0
	dot := false
	version := data[len(prefix):]
	for index, value := range version {
		switch {
		case value >= '0' && value <= '9':
			if dot {
				minorDigits++
			} else {
				majorDigits++
			}
		case value == '.' && !dot && majorDigits > 0:
			dot = true
		case value == '\r' && dot && minorDigits > 0 && index == len(version)-1:
			return true
		default:
			return false
		}
	}
	return majorDigits > 0
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

	protocol := tunnelProtocolHTTP

	if !consumedRequest {
		bufConn := newBufConn(srcConn)
		clearDeadline := setReadDeadlineForTimeout(srcConn, connCtx.config.state.handshakeTimeout)
		protocol, err = detectTunnelProtocol(bufConn)
		clearDeadline()
		if err != nil {
			return fmt.Errorf("short buffer to peek: %s", err)
		}
		srcConn = bufConn
		if protocol == tunnelProtocolRaw {
			connCtx.closeTransport()
			logConfigAttrs(ctx, connCtx.config, slog.LevelDebug, "raw tunnel passthrough",
				slog.String("hostport", reqCtx.Hostport),
			)
			return r.passthroughTunnel(ctx, srcConn, dstConn, connCtx.config.state.handshakeTimeout)
		}
	}

	fakerw := newFakeHttpResponseWriter(srcConn)

	var tlsRequest bool
	// Check if the common http/websocket request with tls
	if protocol == tunnelProtocolTLS {
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
		handshakeCtx, cancelHandshake := context.WithTimeout(ctx, connCtx.config.state.handshakeTimeout)
		clearDeadline := setDeadlineFromContext(handshakeCtx, srcConn)
		go func(c net.Conn) {
			chi, ok := <-clientHelloInfoCh
			if !ok {
				return
			}
			conn, tlsConfig, err := r.initiateSSLHandshakeWithClientHello(handshakeCtx, chi, c)
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
		// Bound both sides of the coordinated downstream/upstream handshake.
		if err = tlsConn.HandshakeContext(handshakeCtx); err != nil {
			cancelHandshake()
			clearDeadline()
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
		cancelHandshake()
		clearDeadline()
		dstConn = result.conn
		connCtx.remote.innerConn = dstConn
		if transport := connCtx.currentTransport(); transport != nil {
			transport.setNegotiatedProtocol(result.negotiatedProtocol)
		}
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
	firstRead := request == nil
	// Only a plain proxy connection carries absolute-URI requests that the
	// client may point at any origin. A CONNECT tunnel, a SOCKS5 connection and
	// a transparent connection are all pinned to the target their client
	// selected out of band, so for those a changing authority is a request
	// smuggling attempt rather than ordinary connection reuse.
	canRetarget := consumedRequest && !reqCtx.HttpConnectMethod && !reqCtx.Socks5Connect
	if connCtx.config.state.http1PipelineDepth > 1 {
		return r.serveHTTP1Pipeline(ctx, fakerw, request, tlsRequest, firstRead, canRetarget, srcConn)
	}
	for {
		reqCtx, _ := FromRequestContext(ctx)
		nextCtx, earlyDone, isWsUpgrade, err := r.distinguishHTTPRequest(ctx, fakerw, request, tlsRequest, firstRead)
		if err != nil || earlyDone {
			if request == nil && isExpectedIdleReadClose(err) {
				return nil
			}
			if _, ok := errors.AsType[*requestParseError](err); ok {
				writeHTTP1ErrorResponse(srcConn, statusCodeForRequestError(err))
			}
			return err
		}
		request = nil
		firstRead = false

		nextReqCtx, _ := FromRequestContext(nextCtx)
		if !requestMatchesHostport(nextReqCtx.Request, reqCtx.Hostport) {
			if !canRetarget {
				writeHTTP1ErrorResponse(srcConn, http.StatusMisdirectedRequest)
				return fmt.Errorf("http keep-alive target changed from %s to %s", reqCtx.Hostport, nextReqCtx.Request.Host)
			}
			hostport, err := ParseHostPort(nextReqCtx.Request)
			if err != nil {
				writeHTTP1ErrorResponse(srcConn, http.StatusBadRequest)
				return err
			}
			if err = r.retargetTunnel(ctx, connCtx, hostport); err != nil {
				writeHTTP1ErrorResponse(srcConn, http.StatusBadGateway)
				return err
			}
			reqCtx.Hostport, nextReqCtx.Hostport = hostport, hostport
			ctx = AppendToRequestContext(ctx, reqCtx)
			nextCtx = AppendToRequestContext(nextCtx, nextReqCtx)
		}
		nextCtx = cloneMetadataContext(nextCtx)
		if md, ok := metadata.FromContext(nextCtx); ok {
			md.SetRequestReceivedTs(time.Now())
			md.SetRequestHostport(nextReqCtx.Hostport)
		}
		passthrough, passthroughReason := shouldPassthroughRequest(connCtx.config, nextReqCtx.Hostport)
		logConfigAttrs(nextCtx, connCtx.config, slog.LevelDebug, "http keep-alive interception decision",
			slog.String("hostport", nextReqCtx.Hostport),
			slog.Bool("passthrough", passthrough),
			slog.String("reason", passthroughReason),
		)

		if isWsUpgrade {
			// Take the upstream connection from the dialer rather than reusing
			// the one established with the tunnel: on a keep-alive connection
			// an earlier request may already have handed it to the transport,
			// and writing a handshake onto it would corrupt that stream.
			connCtx.closeTransport()
			wsConn, err := connCtx.dialRemote(nextCtx, "tcp", nextReqCtx.Hostport)
			if err != nil {
				return err
			}
			return r.relayConnForWS(nextCtx, newBufConnExt(srcConn, fakerw.bufRW), wsConn)
		}
		response, err := r.relayConnForHTTP(nextCtx, srcConn, !passthrough)
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

// requestParseError marks a failure to read or parse an HTTP/1 request from the
// client, as opposed to a failure that happened once the connection had already
// been handed over to another protocol. Only the former can still be answered
// with an HTTP error response.
type requestParseError struct{ err error }

func (e *requestParseError) Error() string { return e.err.Error() }
func (e *requestParseError) Unwrap() error { return e.err }

// prepareHTTP1Response settles the response framing before a single byte
// reaches the client, so that shouldCloseHTTP1 agrees with what is actually put
// on the wire.
//
// [http.Response.Write] applies the "unknown body length implies close" rule to
// a private copy of the response, so a response written with Connection: close
// would otherwise leave response.Close false and the proxy would keep waiting
// for another request on a connection the client believes is ending.
func prepareHTTP1Response(req *http.Request, response *http.Response) error {
	if response == nil {
		return nil
	}
	if response.Request == nil {
		// [http.Response.Write] needs it to know a response to HEAD carries no
		// body despite its Content-Length.
		response.Request = req
	}
	// Mirror the probe [http.Response.Write] performs to tell an empty body
	// apart from one of unknown length.
	if response.ContentLength == 0 && response.Body != nil && response.Body != http.NoBody {
		var probe [1]byte
		n, err := response.Body.Read(probe[:])
		if err != nil && err != io.EOF {
			return err
		}
		if n == 0 {
			response.Body = http.NoBody
		} else {
			response.ContentLength = -1
			response.Body = struct {
				io.Reader
				io.Closer
			}{io.MultiReader(bytes.NewReader(probe[:1]), response.Body), response.Body}
		}
	}

	// RFC 9112 7.1: chunked must not be sent to an HTTP/1.0 client. Drop back
	// to a body delimited by connection close, which every HTTP/1.0 client
	// understands.
	if requestIsHTTP10(req) && chunkedTransferEncoding(response.TransferEncoding) {
		response.TransferEncoding = nil
		response.ContentLength = -1
	}

	// A body of unknown length can only be delimited by closing the connection.
	// HEAD, 1xx, 204 and 304 responses have no body, so their missing length
	// does not affect connection reuse.
	if response.ContentLength < 0 && !chunkedTransferEncoding(response.TransferEncoding) {
		if http1ResponseBodyAllowed(req, response.StatusCode) {
			response.Close = true
		} else {
			// Response.Write otherwise applies its unknown-length close rule to
			// a private copy even though no body needs delimiting.
			response.ContentLength = 0
		}
	}

	// An HTTP/1.0 client assumes the connection closes after the response
	// unless it is told otherwise.
	if requestIsHTTP10(req) && !response.Close && !req.Close {
		response.Header.Set(HttpHeaderConnection, "keep-alive")
	}
	return nil
}

func requestIsHTTP10(req *http.Request) bool {
	return req != nil && req.ProtoMajor == 1 && req.ProtoMinor == 0
}

func chunkedTransferEncoding(te []string) bool {
	return len(te) > 0 && strings.EqualFold(te[len(te)-1], "chunked")
}

func http1ResponseBodyAllowed(req *http.Request, statusCode int) bool {
	if req != nil && req.Method == http.MethodHead {
		return false
	}
	return statusCode >= 200 &&
		statusCode != http.StatusNoContent &&
		statusCode != http.StatusNotModified
}

// writeHTTP1Response coalesces the status line and header block into a single
// write. [http.Response.Write] emits four writes per header field, which on a
// raw connection is four syscalls and on a TLS connection four TLS records. The
// body is streamed straight through so responses that trickle are not delayed.
func writeHTTP1Response(dst io.Writer, response *http.Response) error {
	writer := &http1ResponseWriter{dst: dst}
	err := response.Write(writer)
	if flushErr := writer.flush(); err == nil {
		err = flushErr
	}
	return err
}

// maxBufferedResponseHeaderBytes bounds how much of a response is held back
// while looking for the end of the header block.
const maxBufferedResponseHeaderBytes = 64 << 10

type http1ResponseWriter struct {
	dst        io.Writer
	buf        []byte
	headerDone bool
}

func (w *http1ResponseWriter) Write(data []byte) (int, error) {
	if w.headerDone {
		return w.dst.Write(data)
	}
	w.buf = append(w.buf, data...)
	if index := bytes.Index(w.buf, []byte("\r\n\r\n")); index >= 0 {
		w.headerDone = true
		pending := w.buf
		w.buf = nil
		if _, err := w.dst.Write(pending); err != nil {
			return 0, err
		}
		return len(data), nil
	}
	if len(w.buf) >= maxBufferedResponseHeaderBytes {
		if err := w.flush(); err != nil {
			return 0, err
		}
		w.headerDone = true
	}
	return len(data), nil
}

func (w *http1ResponseWriter) flush() error {
	if len(w.buf) == 0 {
		return nil
	}
	pending := w.buf
	w.buf = nil
	_, err := w.dst.Write(pending)
	return err
}

// writeHTTP1ErrorResponse answers a request the proxy could not act on. Without
// it the client only sees the connection disappear and cannot tell a rejected
// request apart from a network failure.
func writeHTTP1ErrorResponse(dst io.Writer, statusCode int) {
	_, _ = fmt.Fprintf(dst, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
		statusCode, http.StatusText(statusCode))
}

func statusCodeForRequestError(err error) int {
	if errors.Is(err, ErrHTTPHeaderTooLarge) {
		return http.StatusRequestHeaderFieldsTooLarge
	}
	return http.StatusBadRequest
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
	if requestPort == "" {
		requestPort = "80"
		if req.TLS != nil || (req.URL != nil && (strings.EqualFold(req.URL.Scheme, "https") || strings.EqualFold(req.URL.Scheme, "wss"))) {
			requestPort = "443"
		}
	}
	return port == requestPort
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
	waitForPriorResponses := func() {
		if done, _ := ctx.Value(http1PriorResponsesDoneKey{}).(<-chan struct{}); done != nil {
			<-done
		}
	}
	// Handle h2c with prior knowledge (RFC 7540 Section 3.4)
	if req.Method == "PRI" && len(req.Header) == 0 && req.URL.Path == "*" && req.Proto == "HTTP/2.0" {
		waitForPriorResponses()
		conn, err := initH2CWithPriorKnowledge(rw, connCtx.config.state.handshakeTimeout)
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
		waitForPriorResponses()
		if closePool, _ := ctx.Value(http1H2CUpgradeClosePoolKey{}).(func()); closePool != nil {
			closePool()
		}
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
	reqCtx, _ := FromRequestContext(ctx)
	srcConn, rwc, err := http.NewResponseController(rw).Hijack()
	if err != nil {
		return err
	}
	if rwc != nil {
		srcConn = newBufConnExt(srcConn, rwc)
	}

	// As for the WebSocket handshake, the tunnel connection may already belong
	// to the transport by the time a keep-alive connection reaches an upgrade.
	connCtx.closeTransport()
	dstConn, err := connCtx.dialRemote(ctx, "tcp", reqCtx.Hostport)
	if err != nil {
		return err
	}
	if err := writeH2CUpgradeRequestHeaders(dstConn, req); err != nil {
		return err
	}
	return iocopy.IoCopyBidirectional(dstConn, srcConn)
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

func (r *mitmProxyHandler) distinguishHTTPRequest(ctx context.Context, fakerw *fakeHttpResponseWriter, request *http.Request, tlsRequest, firstRead bool) (newCtx context.Context, earlyDone bool, upgrade bool, retErr error) {
	connCtx := ctx.Value(connContextKey).(*biConnContext)
	reqCtx, _ := FromRequestContext(ctx)

	// Read the http request for https/wss via tls tunnel

	// Need to read the request
	if request == nil {
		var clearDeadline func()
		if readState, _ := ctx.Value(http1SessionReadStateKey{}).(*http1SessionReadState); readState != nil {
			clearDeadline = readState.beginRead(firstRead)
		} else {
			readTimeout := connCtx.config.state.idleConnTimeout
			if firstRead {
				readTimeout = connCtx.config.state.handshakeTimeout
			}
			clearDeadline = setReadDeadlineForTimeout(fakerw.conn, readTimeout)
		}
		// The deadline must be cleared before anything that takes over the
		// connection for its whole lifetime (an h2c session, an upgrade
		// passthrough), otherwise that connection inherits it and dies once it
		// expires no matter how much traffic is flowing.
		var err error
		request, err = fakerw.ReadRequest(connCtx.config.state.maxHTTPHeaderBytes)
		clearDeadline()
		if err != nil {
			retErr = &requestParseError{err: err}
			return
		}
		// http.ReadRequest does not attach the connection-scoped server
		// context that net/http gives the initial request. Bind every manually
		// parsed keep-alive request to this session before adding request-body
		// state, otherwise downstream cancellation is lost after request one.
		request = request.WithContext(ctx)
	}
	request = prepareHijackedRequestBody(request, request, fakerw.conn)

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

	if upgrade {
		sanitizeWebsocketUpgradeHeaders(request.Header)
	} else {
		removeHopByHopRequestHeaders(request.Header)
	}
	// patch the new request to the request context
	reqCtx.Request = request
	newCtx = AppendToRequestContext(ctx, reqCtx)

	return
}

type wsFrameImpl struct {
	dir     WSDirection
	msgType int
	dataBuf *buf.Buffer

	state atomic.Uint32
	dst   *websocket.Conn
	// Invoked exactly once when the frame is forwarded or discarded so its
	// payload no longer counts against the interceptor's buffered-byte budget.
	onRelease     func(int64)
	reservedBytes int64
}

func (f *wsFrameImpl) Direction() WSDirection { return f.dir }

func (f *wsFrameImpl) MessageType() int { return f.msgType }

func (f *wsFrameImpl) DataBuffer() *buf.Buffer { return f.dataBuf }

func (f *wsFrameImpl) Invoke() error {
	if !f.state.CompareAndSwap(0, 1) {
		return ErrWebsocketFrameReleased
	}
	err := f.dst.WriteMessage(f.msgType, f.dataBuf.Bytes())
	f.releaseResources()
	f.state.Store(2)
	return err
}

func (f *wsFrameImpl) Release() {
	if f.state.CompareAndSwap(0, 2) {
		f.releaseResources()
	}
}

func (f *wsFrameImpl) releaseResources() {
	releaseBuffer(f.dataBuf)
	if f.onRelease != nil {
		f.onRelease(f.reservedBytes)
	}
}

type wsFramesWatcherImpl struct {
	framesCh  chan WsFrame
	closeOnce sync.Once
	// bufferedBytes includes frames queued in framesCh and frames currently
	// held by the interceptor. The budget is shared by both traffic directions.
	bufferedBytes  atomic.Int64
	maxBuffered    int64
	budgetReleased chan struct{}
}

func (w *wsFramesWatcherImpl) Receive() <-chan WsFrame { return w.framesCh }

func (w *wsFramesWatcherImpl) send(ctx context.Context, frame *wsFrameImpl) bool {
	size := int64(frame.dataBuf.Len())
	// Reserve bytes before publishing the frame so every frame visible to the
	// interceptor is already included in the aggregate memory budget.
	if !w.reserve(ctx, size) {
		return false
	}
	frame.onRelease = w.release
	frame.reservedBytes = size
	select {
	case <-ctx.Done():
		frame.Release()
		return false
	case w.framesCh <- frame:
		return true
	}
}

func (w *wsFramesWatcherImpl) reserve(ctx context.Context, size int64) bool {
	if size > w.maxBuffered {
		return false
	}
	for {
		current := w.bufferedBytes.Load()
		if current <= w.maxBuffered-size && w.bufferedBytes.CompareAndSwap(current, current+size) {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-w.budgetReleased:
			// Waiting here applies backpressure to the corresponding WebSocket
			// reader until the interceptor invokes or releases another frame.
		}
	}
}

func (w *wsFramesWatcherImpl) release(size int64) {
	w.bufferedBytes.Add(-size)
	select {
	case w.budgetReleased <- struct{}{}:
	default:
	}
}

func (w *wsFramesWatcherImpl) close() {
	w.closeOnce.Do(func() {
		close(w.framesCh)
		// Return buffers and byte reservations for frames that the interceptor
		// did not consume before the connection shut down.
		for frame := range w.framesCh {
			frame.Release()
		}
	})
}

func startWebsocketInterceptor(ctx context.Context, cancel context.CancelCauseFunc, interceptor WebsocketInterceptor, request *http.Request, response *http.Response, watcher WebsocketFramesWatcher) {
	go func() {
		interceptor(ctx, request, response, watcher)
		cancel(io.EOF)
	}()
}

func (r *mitmProxyHandler) relayConnForWS(ctx context.Context, srcConn, dstConn net.Conn) (err error) {
	connCtx := ctx.Value(connContextKey).(*biConnContext)
	cfg := connCtx.config
	reqCtx, _ := FromRequestContext(ctx)
	reqClone := reqCtx.Request.Clone(reqCtx.Request.Context())
	if reqClone.Body != nil {
		limit := int64(cfg.state.maxHTTPHeaderBytes)
		if reqClone.ContentLength > limit {
			return fmt.Errorf("websocket upgrade body exceeds %d bytes", limit)
		}
		data, err := io.ReadAll(io.LimitReader(reqClone.Body, limit+1))
		if err != nil {
			return err
		}
		if int64(len(data)) > limit {
			return fmt.Errorf("websocket upgrade body exceeds %d bytes", limit)
		}
		reqClone.Body.Close()
		reqClone.Body = io.NopCloser(bytes.NewReader(data))
		reqCtx.Request.Body = io.NopCloser(bytes.NewReader(data))
	}

	boundedDstConn := newBoundedHTTPHeaderConn(dstConn, cfg.state.maxHTTPHeaderBytes)
	wsDstConn, resp, err := websocket.DialWithPreparedRequestAndNetConn(reqClone, boundedDstConn)
	if err != nil {
		return err
	}
	sanitizeWebsocketUpgradeHeaders(resp.Header)
	wsSrcConn, err := websocket.UpgradeWithPreparedResponseAndNetConn(resp, srcConn)
	if err != nil {
		wsDstConn.Close()
		return err
	}
	// Enforce the per-message limit on complete logical messages from both
	// peers; fragmented WebSocket messages still count as one combined message.
	wsSrcConn.SetReadLimit(cfg.state.wsMaxMessageBytes)
	wsDstConn.SetReadLimit(cfg.state.wsMaxMessageBytes)
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
		// framesCh bounds the number of pending interceptor items, while
		// maxBuffered independently bounds their combined payload bytes across
		// both relay directions.
		fw = &wsFramesWatcherImpl{
			framesCh:       make(chan WsFrame, cfg.state.wsMaxFramesPerForward*2),
			maxBuffered:    cfg.state.wsMaxBufferedBytes,
			budgetReleased: make(chan struct{}, 1),
		}
		startWebsocketInterceptor(ctx, cancel, cfg.state.wsInt, reqCtx.Request, resp, fw)
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
			// The interceptor API exposes a complete message buffer, so reject an
			// oversized message while reading it rather than after it is queued.
			msgType, buffer, err := readBufferFromWSConn(src, cfg.state.wsMaxMessageBytes)
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
				// Ownership of buffer transfers to the frame. Invoke or Release returns
				// both the pooled buffer and its buffered-byte reservation.
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

func (r *mitmProxyHandler) relayConnForHTTP(ctx context.Context, srcConn net.Conn, intercept bool) (response *http.Response, err error) {
	connCtx := ctx.Value(connContextKey).(*biConnContext)
	reqCtx, _ := FromRequestContext(ctx)
	response, err = r.roundTripWithContextMode(ctx, reqCtx.Request, intercept)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	removeHopByHopHeaders(response.Header)
	if !beginHijackedFinalResponse(reqCtx.Request) {
		response.Close = true
	}
	if err = prepareHTTP1Response(reqCtx.Request, response); err != nil {
		return nil, err
	}
	// A client that stops reading must not pin this goroutine and the upstream
	// connection forever. The deadline is per write, so a slow but progressing
	// transfer of any size is unaffected.
	writer := &stallGuardConn{Conn: srcConn, timeout: connCtx.config.state.idleConnTimeout}
	defer writer.clearDeadline()
	if err = writeHTTP1Response(writer, response); err != nil {
		return nil, err
	}
	return
}

type stallGuardConn struct {
	net.Conn
	timeout time.Duration
}

func (c *stallGuardConn) Write(data []byte) (int, error) {
	if c.timeout > 0 {
		_ = c.Conn.SetWriteDeadline(time.Now().Add(c.timeout))
	}
	return c.Conn.Write(data)
}

func (c *stallGuardConn) clearDeadline() {
	if c.timeout > 0 {
		_ = c.Conn.SetWriteDeadline(time.Time{})
	}
}

func (r *mitmProxyHandler) roundTripWithContext(ctx context.Context, req *http.Request) (response *http.Response, err error) {
	return r.roundTripWithContextMode(ctx, req, true)
}

func (r *mitmProxyHandler) roundTripWithContextMode(ctx context.Context, req *http.Request, intercept bool) (response *http.Response, err error) {
	connCtx := ctx.Value(connContextKey).(*biConnContext)
	transport := connCtx.currentTransport()
	if transport == nil {
		return nil, errors.New("transport missing in connection context")
	}
	return r.roundTripWithInvoker(ctx, req, intercept, HTTPDelegatedInvokerFunc(transport.RoundTrip))
}

func (r *mitmProxyHandler) roundTripWithInvoker(ctx context.Context, req *http.Request, intercept bool, invoker HTTPDelegatedInvoker) (response *http.Response, err error) {
	connCtx := ctx.Value(connContextKey).(*biConnContext)
	reqCtx, _ := FromRequestContext(ctx)
	md, _ := metadata.FromContext(ctx)

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
	if intercept && connCtx.config.httpInt != nil {
		response, err = connCtx.config.httpInt(ctx, req, invoker)
	} else {
		response, err = invoker.Invoke(req)
	}
	if err != nil {
		err = fmt.Errorf("transport RoundTrip %s failed: %w", reqCtx.Hostport, err)
		logConfigAttrs(ctx, connCtx.config, slog.LevelDebug, "http request failed",
			slog.String("hostport", reqCtx.Hostport),
			slog.String("method", requestMethod(req)),
			slog.String("url", requestURL(req)),
			slog.Duration("duration", time.Since(start)),
			errorAttr(err),
		)
		return
	}
	if response == nil {
		err = errors.New("HTTP interceptor returned a nil response without an error")
		return nil, err
	}
	if response.Body == nil {
		response.Body = http.NoBody
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
		if !requestMatchesHostport(req, reqCtx.Hostport) {
			err := fmt.Errorf("http2 authority %q does not match connection target %q", req.Host, reqCtx.Hostport)
			handleErrorWithConfig(connCtx.config, ErrorContext{
				Hostport:   reqCtx.Hostport,
				RemoteAddr: req.RemoteAddr,
				Error:      err,
			})
			http.Error(rw, http.StatusText(http.StatusMisdirectedRequest), http.StatusMisdirectedRequest)
			return
		}

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
		removeHopByHopRequestHeaders(req.Header)
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
			status := http.StatusBadGateway
			if errors.Is(err, context.DeadlineExceeded) {
				status = http.StatusGatewayTimeout
			} else {
				var netErr net.Error
				if errors.As(err, &netErr) && netErr.Timeout() {
					status = http.StatusGatewayTimeout
				}
			}
			http.Error(rw, http.StatusText(status), status)
			return
		}
		removeHopByHopHeaders(response.Header)
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
			if err = r.forwardStreamBody(rw, body, shouldFlushHTTP2Response(response)); err != nil {
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

func shouldFlushHTTP2Response(response *http.Response) bool {
	if response == nil {
		return false
	}
	contentType := strings.ToLower(response.Header.Get(HttpHeaderContentType))
	return response.ContentLength < 0 || strings.HasPrefix(contentType, "text/event-stream")
}

func (r *mitmProxyHandler) forwardStreamBody(rw http.ResponseWriter, body io.Reader, flushEachWrite bool) error {
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
			if flushEachWrite {
				flusher.Flush()
			}
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
