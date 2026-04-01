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
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/josexy/mitmproxy-go/buf"
	"github.com/josexy/mitmproxy-go/internal/cert"
	"github.com/josexy/mitmproxy-go/internal/iocopy"
	"github.com/josexy/mitmproxy-go/metadata"
	"github.com/josexy/websocket"
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
		header: make(http.Header),
		conn:   conn,
		bufRW:  bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn)),
	}
}

// Hijack hijack the connection for websocket
func (f *fakeHttpResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return f.conn, f.bufRW, nil
}

// implemented http.ResponseWriter but nothing to do
func (f *fakeHttpResponseWriter) Header() http.Header       { return f.header }
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

	if c.connCtx.local != nil {
		c.connCtx.local.Close()
	}
	return c.closeErr
}

type biConnContext struct {
	local  *localClientConn
	remote *remoteClientConn
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
	proxyDialer    *proxyDialer
	priKeyPool     *priKeyPool
	serverCertPool *certPool
	clientCertPool map[string]tls.Certificate
	h2s            *http2.Server
	transport      *UnifiedTransport
	domainMatcher  struct {
		include *trieNode
		exclude *trieNode
	}
}

func NewMitmProxyHandler(opt ...Option) (MitmProxyHandler, error) {
	opts := newOptions(opt...)
	var err error
	opts.caCert, err = cert.LoadCACertificate(opts.caCertPath, opts.caKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load ca cert: %s", err)
	}
	clientCertPool := make(map[string]tls.Certificate, len(opts.clientCerts))
	for hostname, cc := range opts.clientCerts {
		tlsCert, err := tls.LoadX509KeyPair(cc.CertPath, cc.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load client cert: %s:%s %s", cc.CertPath, cc.KeyPath, err)
		}
		clientCertPool[hostname] = tlsCert
	}
	if len(opts.rootCAs) > 0 {
		opts.rootCACertPool, err = x509.SystemCertPool()
		if err != nil || opts.rootCACertPool == nil {
			opts.rootCACertPool = x509.NewCertPool()
		}
		for _, path := range opts.rootCAs {
			ca, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("failed to read root ca file: %s", err)
			}
			if ok := opts.rootCACertPool.AppendCertsFromPEM(ca); !ok {
				return nil, errors.New("failed to append ca file to cert pool")
			}
		}
	}
	proxyURL, err := parseProxyFrom(opts.disableProxy, opts.proxy)
	if err != nil {
		return nil, fmt.Errorf("failed to parse proxy url: %s", err)
	}

	dialFn := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if connCtx, ok := ctx.Value(connContextKey).(*biConnContext); ok {
			return connCtx.remote.innerConn, nil
		}
		return nil, errors.New("connContextKey missing in context")
	}

	includeMatcher, excludeMatcher := newTrieNode(), newTrieNode()
	for _, host := range opts.includeHosts {
		includeMatcher.insert(host)
	}
	for _, host := range opts.excludeHosts {
		excludeMatcher.insert(host)
	}

	handler := &mitmProxyHandler{
		options:        opts,
		h2s:            &http2.Server{},
		transport:      NewTransport(dialFn),
		proxyDialer:    NewProxyDialer(proxyURL, opts.dialer),
		priKeyPool:     newPriKeyPool(opts.certCachePool.Capacity),
		clientCertPool: clientCertPool,
		serverCertPool: newServerCertPool(opts.certCachePool.Capacity,
			time.Duration(opts.certCachePool.IntervalSecond)*time.Second,
			time.Duration(opts.certCachePool.ExpireSecond)*time.Second,
		),
	}
	handler.domainMatcher.include = includeMatcher
	handler.domainMatcher.exclude = excludeMatcher
	handler.chainHTTPInterceptors()
	return handler, nil
}

func (r *mitmProxyHandler) chainHTTPInterceptors() {
	interceptors := r.chainHttpInts
	if r.httpInt != nil {
		interceptors = append([]HTTPInterceptor{r.httpInt}, r.chainHttpInts...)
	}
	var chainedInt HTTPInterceptor
	if len(interceptors) == 0 {
		chainedInt = nil
	} else if len(interceptors) == 1 {
		chainedInt = interceptors[0]
	} else {
		chainedInt = chainHTTPInterceptors(interceptors)
	}
	r.httpInt = chainedInt
}

func (r *mitmProxyHandler) Cleanup() {
	r.serverCertPool.Stop()
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
	conn, _, err := hj.Hijack()
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

	defer func() {
		if err != nil {
			r.handleError(ErrorContext{
				RemoteAddr: remoteAddrOrDefault(conn.RemoteAddr()),
				Hostport:   reqCtx.Hostport,
				Error:      err,
			})
		}
	}()

	dstConn, err := r.proxyDialer.DialTCPContext(ctx, reqCtx.Hostport)
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to connect to %s: %s", reqCtx.Hostport, err)
	}

	local := &localClientConn{
		Conn:      conn,
		closeChan: make(chan struct{}),
	}
	remote := &remoteClientConn{
		Conn: dstConn,
	}
	connCtx := &biConnContext{local, remote}
	local.connCtx, remote.connCtx = connCtx, connCtx
	conn, dstConn = local, remote
	remote.innerConn = remote

	defer local.Close()

	nowTs := time.Now()

	if reqCtx.HttpConnectMethod {
		conn.Write(HttpResponseConnectionEstablished)
	}

	if r.shouldPassthroughRequest(reqCtx.Hostport) {
		return r.passthroughTunnel(ctx, conn, dstConn)
	}

	md := metadata.NewMD()
	md.Set(metadata.ConnectionEstablishedTs, nowTs)
	md.Set(metadata.RequestReceivedTs, nowTs)
	md.Set(metadata.RequestHostport, reqCtx.Hostport)
	md.Set(metadata.ConnectionSourceAddrPort, getAddrPortFromConn(conn))
	md.Set(metadata.ConnectionDestinationAddrPort, getAddrPortFromConn(dstConn))
	ctx = context.WithValue(metadata.AppendToContext(ctx, md), connContextKey, connCtx)

	return r.handleTunnelRequest(ctx, reqCtx.Request != nil)
}

func (r *mitmProxyHandler) shouldPassthroughRequest(hostport string) bool {
	host, _, _ := net.SplitHostPort(hostport)

	if len(r.excludeHosts) > 0 {
		if found := r.domainMatcher.exclude.match(host); found {
			// passthrough
			return true
		}
	}

	if len(r.includeHosts) > 0 {
		found := r.domainMatcher.include.match(host)
		return !found
	}

	// not passthrough
	return false
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
	if r.errHandler != nil && ec.Error != nil {
		r.errHandler(ec)
	}
}

func (r *mitmProxyHandler) initiateSSLHandshakeWithClientHello(ctx context.Context, chi *tls.ClientHelloInfo, conn net.Conn) (net.Conn, *tls.Config, error) {
	reqCtx, _ := FromRequestContext(ctx)
	md, _ := metadata.FromContext(ctx)

	serverName := chi.ServerName
	protos := chi.SupportedProtos

	if r.disableHTTP2 {
		protos = slices.DeleteFunc(protos, func(e string) bool { return e == http2.NextProtoTLS })
	}

	host, _, _ := net.SplitHostPort(reqCtx.Hostport)
	if serverName == "" {
		serverName = host
	}
	tlsConfig := &tls.Config{
		// Get clientHello alpnProtocols from client and forward to server
		NextProtos:   protos,
		ServerName:   serverName,
		CipherSuites: chi.CipherSuites,
		RootCAs:      r.rootCACertPool,
	}
	if r.skipVerifySSL {
		tlsConfig.InsecureSkipVerify = true
	}
	if len(r.clientCertPool) > 0 {
		if clientCert, ok := r.clientCertPool[host]; ok {
			// mTLS client-authentication
			tlsConfig.Certificates = []tls.Certificate{clientCert}
		}
	}

	tlsClientConn := tls.Client(conn, tlsConfig)
	// send client hello and do tls handshake
	if err := tlsClientConn.HandshakeContext(ctx); err != nil {
		return nil, nil, err
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
	md.Set(metadata.SSLHandshakeCompletedTs, tlsConnEstTs)
	md.Set(metadata.ConnectionTLSState, &metadata.TLSState{
		ServerName:          chi.ServerName,
		CipherSuites:        chi.CipherSuites,
		TLSVersions:         chi.SupportedVersions,
		ALPN:                chi.SupportedProtos,
		SelectedCipherSuite: cs.CipherSuite,
		SelectedTLSVersion:  cs.Version,
		SelectedALPN:        cs.NegotiatedProtocol,
	})
	md.Set(metadata.ConnectionServerCertificate, &metadata.ServerCertificate{
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
	return tlsClientConn, &tls.Config{
		SessionTicketsDisabled: true,
		// Server selected negotiated protocol
		NextProtos:   []string{cs.NegotiatedProtocol},
		Certificates: []tls.Certificate{certificate},
	}, nil
}

func isTLS(data []byte) bool {
	// Ref: https: //github.com/mitmproxy/mitmproxy/blob/main/mitmproxy/net/tls.py
	// TLS ClientHello magic, works for SSLv3, TLSv1.0, TLSv1.1, TLSv1.2, and TLSv1.3
	// http://www.moserware.com/2009/06/first-few-milliseconds-of-https.html#client-hello
	// https://tls13.ulfheim.net/
	// We assume that a client sending less than 3 bytes initially is not a TLS client.
	return data[0] == 0x16 && data[1] == 0x03 && data[2] <= 0x03
}

func (r *mitmProxyHandler) handleTunnelRequest(ctx context.Context, consumedRequest bool) (err error) {
	connCtx := ctx.Value(connContextKey).(*biConnContext)
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

	var tlsRequest bool
	// Check if the common http/websocket request with tls
	if len(data) >= 3 && isTLS(data) {
		tlsRequest = true
		clientHelloInfoCh := make(chan *tls.ClientHelloInfo, 1)
		tlsConnCh := make(chan net.Conn, 1)
		tlsConfigCh := make(chan *tls.Config, 1)
		errCh := make(chan error, 1)
		tlsConn := tls.Server(srcConn, &tls.Config{
			SessionTicketsDisabled: true,
			GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
				clientHelloInfoCh <- chi
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
				tlsConnCh <- conn
			}
		}(dstConn)
		// read client hello and do tls handshake
		if err = tlsConn.HandshakeContext(ctx); err != nil {
			// if tls handshake failed before GetConfigForClient(),
			// we should close the channel in order to quit the goroutine
			close(clientHelloInfoCh)
			select {
			case conn := <-tlsConnCh:
				// if tls handshake failed after GetConfigForClient() succeed,
				// we should close the tls connection if it has been created
				conn.Close()
			default:
				// tls handshake failed if GetConfigForClient() failed
			}
			return fmt.Errorf("tls server handshake failed: %s", err)
		}
		// wait for tls handshake
		dstConn = <-tlsConnCh
		connCtx.remote.innerConn = dstConn
		srcConn = tlsConn

		state := tlsConn.ConnectionState()
		// If the result of the negotiation is http2,
		// then we should hand over the process of processing the http2 stream to the underlying go http2 library,
		// and finally we only need to get the [http.Request] and process the [http.ResponseWriter].
		// Early process http2
		if state.NegotiatedProtocol == http2.NextProtoTLS {
			newCtx, cancel := context.WithCancel(r.streamBaseCtx)
			go func() {
				connCtx.local.waitClose()
				cancel()
			}()
			r.h2s.ServeConn(srcConn, &http2.ServeConnOpts{
				Context: newCtx,
				Handler: r.serveHTTP2Handler(ctx),
			})
			return
		}
	}

	ctx, earlyDone, isWsUpgrade, err := r.distinguishHTTPRequest(ctx, srcConn, tlsRequest)
	if err != nil || earlyDone {
		return
	}
	if isWsUpgrade {
		return r.relayConnForWS(ctx, srcConn, dstConn)
	}
	return r.relayConnForHTTP(ctx, srcConn)
}

func (r *mitmProxyHandler) handlePrefaceOrH2CRequest(ctx context.Context, rw http.ResponseWriter, req *http.Request) (bool, error) {
	// Handle h2c with prior knowledge (RFC 7540 Section 3.4)
	if req.Method == "PRI" && len(req.Header) == 0 && req.URL.Path == "*" && req.Proto == "HTTP/2.0" {
		conn, err := initH2CWithPriorKnowledge(rw)
		if err != nil {
			return false, err
		}
		connCtx := ctx.Value(connContextKey).(*biConnContext)
		newCtx, cancel := context.WithCancel(r.streamBaseCtx)
		go func() {
			connCtx.local.waitClose()
			cancel()
		}()
		r.h2s.ServeConn(conn, &http2.ServeConnOpts{
			Context:          newCtx,
			Handler:          r.serveHTTP2Handler(ctx),
			SawClientPreface: true,
		})
		return true, nil
	}
	// Handle Upgrade to h2c (RFC 7540 Section 3.2)
	if isH2CUpgrade(req.Header) {
		removeProxyHeaders(req.Header)
		conn, settings, err := upgradeH2C(rw, req)
		if err != nil {
			return false, err
		}
		connCtx := ctx.Value(connContextKey).(*biConnContext)
		newCtx, cancel := context.WithCancel(r.streamBaseCtx)
		go func() {
			connCtx.local.waitClose()
			cancel()
		}()
		r.h2s.ServeConn(conn, &http2.ServeConnOpts{
			Context:        newCtx,
			Handler:        r.serveHTTP2Handler(ctx),
			UpgradeRequest: req,
			Settings:       settings,
		})
		return true, nil
	}
	return false, nil
}

func (r *mitmProxyHandler) distinguishHTTPRequest(ctx context.Context, srcConn net.Conn, tlsRequest bool) (newCtx context.Context, earlyDone bool, upgrade bool, retErr error) {
	reqCtx, _ := FromRequestContext(ctx)

	// Read the http request for https/wss via tls tunnel
	fakerw := newFakeHttpResponseWriter(srcConn)
	request := reqCtx.Request

	// Need to read the request
	if request == nil {
		_, rw, err := fakerw.Hijack()
		if err != nil {
			retErr = err
			return
		}
		request, err = http.ReadRequest(rw.Reader)
		if err != nil {
			retErr = err
			return
		}
	}

	if !r.disableHTTP2 {
		// If it's a SOCKS proxy, then the request might be h2c.
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

	once    sync.Once
	invoker WebsocketDelegatedInvoker
}

func (f *wsFrameImpl) Direction() WSDirection { return f.dir }

func (f *wsFrameImpl) MessageType() int { return f.msgType }

func (f *wsFrameImpl) DataBuffer() *buf.Buffer { return f.dataBuf }

func (f *wsFrameImpl) Invoke() error {
	err := f.invoker.Invoke(f.msgType, f.dataBuf)
	f.Release()
	return err
}

func (f *wsFrameImpl) Release() {
	f.once.Do(func() { releaseBuffer(f.dataBuf) })
}

type wsFramesWatcherImpl struct {
	framesCh  chan WsFrame
	closeOnce sync.Once
	closed    atomic.Bool
}

func (w *wsFramesWatcherImpl) GetFrame() <-chan WsFrame { return w.framesCh }

func (w *wsFramesWatcherImpl) send(frame WsFrame) {
	if w.closed.Load() {
		return
	}
	w.framesCh <- frame
}

func (w *wsFramesWatcherImpl) close() {
	w.closeOnce.Do(func() {
		w.closed.Store(true)
		close(w.framesCh)
	})
}

func (r *mitmProxyHandler) relayConnForWS(ctx context.Context, srcConn, dstConn net.Conn) (err error) {
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
		return err
	}

	ctx, cancel := context.WithCancelCause(ctx)

	var fw *wsFramesWatcherImpl
	if r.wsInt != nil {
		fw = &wsFramesWatcherImpl{
			framesCh: make(chan WsFrame, r.wsMaxFramesPerForward*2),
		}
		go r.wsInt(ctx, reqCtx.Request, resp, fw)
	}

	errCh := make(chan error, 2)
	relayWSMessage := func(ctx context.Context, dir WSDirection, src, dst *websocket.Conn) {
		defer func() {
			if fw != nil {
				fw.close()
			}
		}()
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			msgType, buffer, err := readBufferFromWSConn(src)
			if err != nil {
				errCh <- err
				break
			}
			if fw != nil {
				// MUST release buffer manually
				fw.send(&wsFrameImpl{
					dir:     dir,
					msgType: msgType,
					dataBuf: buffer,
					invoker: wrapperInvoker(dst.WriteMessage),
				})
			} else {
				dst.WriteMessage(msgType, buffer.Bytes())
				releaseBuffer(buffer)
			}
		}
	}
	go relayWSMessage(ctx, Send, wsSrcConn, wsDstConn)
	go relayWSMessage(ctx, Receive, wsDstConn, wsSrcConn)
	err = <-errCh
	cancel(err)
	return
}

func (r *mitmProxyHandler) relayConnForHTTP(ctx context.Context, srcConn net.Conn) (err error) {
	reqCtx, _ := FromRequestContext(ctx)
	response, err := r.roundTripWithContext(ctx, reqCtx.Request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	response.Write(srcConn)
	return
}

func (r *mitmProxyHandler) roundTripWithContext(ctx context.Context, req *http.Request) (response *http.Response, err error) {
	connCtx := ctx.Value(connContextKey).(*biConnContext)
	reqCtx, _ := FromRequestContext(ctx)
	md, _ := metadata.FromContext(ctx)

	reqCtx.Request = req
	ctx = metadata.AppendToContext(AppendToRequestContext(req.Context(), reqCtx), md)
	req = req.WithContext(context.WithValue(ctx, connContextKey, connCtx))
	// Only one http interceptor will be invoked
	if r.httpInt != nil {
		response, err = r.httpInt(ctx, req, HTTPDelegatedInvokerFunc(r.transport.RoundTrip))
	} else {
		response, err = r.transport.RoundTrip(req)
	}
	if err != nil {
		err = fmt.Errorf("transport RoundTrip %s failed: %s", reqCtx.Hostport, err)
	}
	return
}

func (r *mitmProxyHandler) serveHTTP2Handler(ctx context.Context) http.Handler {
	reqCtx, _ := FromRequestContext(ctx)
	md, _ := metadata.FromContext(ctx)
	md.Set(metadata.StreamBody, true)

	// the http.ResponseWriter actually is net/http/h2_bundle.go http2responseWriter
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		md.Set(metadata.RequestReceivedTs, time.Now())

		// Must be set scheme "https" to enable HTTP2 transport!!!
		// This is different from HTTP1 transport!!!
		/*
			net/http/h2_bundle.go (*http2Transport).RoundTripOpt
			switch req.URL.Scheme {
			case "https":
				// Always okay.
			case "http":
				if !t.AllowHTTP && !opt.allowHTTP {
					return nil, errors.New("http2: unencrypted HTTP/2 not enabled")
				}
			default:
				return nil, errors.New("http2: unsupported scheme")
			}
		*/
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
		response, err := r.roundTripWithContext(ctx, req)
		if err != nil {
			r.handleError(ErrorContext{
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
				r.handleError(ErrorContext{
					Hostport:   reqCtx.Hostport,
					RemoteAddr: req.RemoteAddr,
					Error:      fmt.Errorf("write http2 body failed: %s", err),
				})
				return
			}
		}

		// Copy trailers for grpc
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
		n, err := body.Read(*buffer)
		if n > 0 {
			if _, writeErr := rw.Write((*buffer)[:n]); writeErr != nil {
				return writeErr
			}
			// Flush the response to keep the client happy
			flusher.Flush()
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func getAddrPortFromConn(conn net.Conn) (addrport netip.AddrPort) {
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
