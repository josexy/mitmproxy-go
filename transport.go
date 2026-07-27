package mitmproxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/textproto"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

type singleConnTransport struct {
	hostport      string
	dialFn        func(ctx context.Context, network, addr string) (net.Conn, error)
	idleTimeout   time.Duration
	disableHTTP2  bool
	pipelineDepth int

	mu            sync.Mutex
	clientConn    *http.ClientConn
	http1Conn     *http1PipelineConn
	http1Degraded bool
	retired       []*http.ClientConn
	upstream      string
	closed        bool
}

func newTransport(
	hostport string,
	dialFn func(ctx context.Context, network, addr string) (net.Conn, error),
	idleConnTimeout time.Duration,
	disableHTTP2 bool,
	pipelineDepth ...int,
) *singleConnTransport {
	depth := 0
	if len(pipelineDepth) > 0 && pipelineDepth[0] > 0 {
		depth = pipelineDepth[0]
	}
	return &singleConnTransport{
		hostport:      hostport,
		dialFn:        dialFn,
		idleTimeout:   idleConnTimeout,
		disableHTTP2:  disableHTTP2,
		pipelineDepth: depth,
	}
}

func (t *singleConnTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.shouldUseHTTP1Pipeline(req) {
		return t.roundTripHTTP1(req)
	}
	logger := loggerFromContext(req.Context())
	for attempt := 0; ; attempt++ {
		start := time.Now()
		logAttrs(req.Context(), logger, slog.LevelDebug, "transport round trip started",
			slog.String("hostport", t.hostport),
			slog.String("method", requestMethod(req)),
			slog.String("url", requestURL(req)),
			slog.Int("attempt", attempt),
		)
		clientConn, err := t.getClientConn(req.Context(), req)
		if err != nil {
			logAttrs(req.Context(), logger, slog.LevelWarn, "transport client connection failed",
				slog.String("hostport", t.hostport),
				slog.String("method", requestMethod(req)),
				slog.String("url", requestURL(req)),
				slog.Int("attempt", attempt),
				errorAttr(err),
			)
			closeRequestBody(req)
			return nil, err
		}
		resp, err := clientConn.RoundTrip(req)
		if err == nil {
			logAttrs(req.Context(), logger, slog.LevelDebug, "transport round trip completed",
				slog.String("hostport", t.hostport),
				slog.String("method", requestMethod(req)),
				slog.String("url", requestURL(req)),
				slog.Int("attempt", attempt),
				slog.Int("status_code", resp.StatusCode),
				slog.Duration("duration", time.Since(start)),
			)
			return resp, nil
		}
		discard := shouldDiscardClientConnAfterRoundTripError(req.Context(), clientConn, err)
		nextReq, retry := replayableRequest(req)
		retry = attempt == 0 && discard && retry
		if discard || retry {
			logAttrs(req.Context(), logger, slog.LevelWarn, "transport round trip failed",
				slog.String("hostport", t.hostport),
				slog.String("method", requestMethod(req)),
				slog.String("url", requestURL(req)),
				slog.Int("attempt", attempt),
				slog.Bool("discard", discard),
				slog.Bool("retry", retry),
				slog.Duration("duration", time.Since(start)),
				errorAttr(err),
				clientConnErrorAttr(clientConn),
			)
		}
		if discard {
			t.discardClientConn(req.Context(), clientConn, shouldCloseDiscardedClientConn(clientConn, err))
		}
		if retry {
			req = nextReq
			continue
		}
		return nil, err
	}
}

func (t *singleConnTransport) shouldUseHTTP1Pipeline(req *http.Request) bool {
	if t.pipelineDepth < 1 || req == nil || req.URL == nil || req.ProtoMajor != 1 {
		return false
	}
	t.mu.Lock()
	upstream := t.upstream
	t.mu.Unlock()
	return req.URL.Scheme == "http" || upstream == "http/1.1"
}

func (t *singleConnTransport) roundTripHTTP1(req *http.Request) (*http.Response, error) {
	logger := loggerFromContext(req.Context())
	for attempt := 0; ; attempt++ {
		conn, err := t.getHTTP1PipelineConn(req.Context())
		if err != nil {
			closeRequestBody(req)
			return nil, err
		}
		response, err := conn.RoundTrip(req)
		if err == nil {
			return response, nil
		}

		nextReq, retry := replayableRequest(req)
		retry = attempt == 0 && retry
		degraded := t.discardHTTP1PipelineConn(conn)
		info := http1RequestInfo(req)
		logAttrs(req.Context(), logger, slog.LevelWarn, "http1 upstream round trip failed",
			slog.Uint64("pipeline_sequence", info.sequence),
			slog.String("target", info.target),
			slog.String("hostport", t.hostport),
			slog.String("method", requestMethod(req)),
			slog.String("url", requestURL(req)),
			slog.Int("attempt", attempt),
			slog.Bool("retry", retry),
			slog.Bool("degraded", degraded),
			errorAttr(err),
		)
		if retry {
			req = nextReq
			continue
		}
		return nil, err
	}
}

func (t *singleConnTransport) getHTTP1PipelineConn(ctx context.Context) (*http1PipelineConn, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil, net.ErrClosed
	}
	if t.http1Conn != nil && t.http1Conn.Err() == nil {
		return t.http1Conn, nil
	}
	if t.http1Conn != nil {
		_ = t.http1Conn.Close()
		t.http1Conn = nil
	}

	conn, err := t.dialFn(ctx, "tcp", t.hostport)
	if err != nil {
		return nil, err
	}
	depth := t.pipelineDepth
	if t.http1Degraded {
		depth = 1
	}
	t.http1Conn = newHTTP1PipelineConn(conn, depth, t.idleTimeout)
	logAttrs(ctx, loggerFromContext(ctx), slog.LevelDebug, "http1 upstream connection created",
		slog.String("hostport", t.hostport),
		slog.Int("pipeline_depth", depth),
		slog.Bool("degraded", t.http1Degraded),
	)
	return t.http1Conn, nil
}

func (t *singleConnTransport) discardHTTP1PipelineConn(conn *http1PipelineConn) bool {
	t.mu.Lock()
	if t.http1Conn != conn {
		degraded := t.http1Degraded
		t.mu.Unlock()
		return degraded
	}
	t.http1Conn = nil
	t.http1Degraded = true
	t.mu.Unlock()
	_ = conn.Close()
	return true
}

func closeRequestBody(req *http.Request) {
	if req == nil || req.Body == nil {
		return
	}
	_ = req.Body.Close()
}

func shouldDiscardClientConnAfterRoundTripError(ctx context.Context, clientConn *http.ClientConn, err error) bool {
	if err == nil {
		return false
	}
	if clientConn.Err() != nil {
		return true
	}
	if isRequestCanceledRoundTripError(ctx, err) {
		return false
	}
	return isClientConnUnusableRoundTripError(err)
}

func replayableRequest(req *http.Request) (*http.Request, bool) {
	if !isReplayableRequest(req) {
		return nil, false
	}
	if requestHasNoBody(req) {
		return req, true
	}
	return nil, false
}

func requestHasNoBody(req *http.Request) bool {
	if req == nil {
		return false
	}
	return req.Body == nil || req.Body == http.NoBody
}

func isReplayableRequest(req *http.Request) bool {
	if req == nil {
		return false
	}
	switch req.Method {
	case "", http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	}
	return headerHasKey(req.Header, "Idempotency-Key") || headerHasKey(req.Header, "X-Idempotency-Key")
}

func headerHasKey(header http.Header, key string) bool {
	if header == nil {
		return false
	}
	canonical := textproto.CanonicalMIMEHeaderKey(key)
	if _, ok := header[canonical]; ok {
		return true
	}
	for k := range header {
		if strings.EqualFold(k, key) {
			return true
		}
	}
	return false
}

func isRequestCanceledRoundTripError(ctx context.Context, err error) bool {
	if ctx != nil && ctx.Err() != nil {
		return true
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "request canceled") ||
		strings.Contains(msg, "context canceled") ||
		strings.Contains(msg, "context deadline exceeded")
}

func isClientConnUnusableRoundTripError(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "client conn not usable") ||
		strings.Contains(msg, "client conn is closed") ||
		strings.Contains(msg, "use of closed network connection") ||
		strings.Contains(msg, "server's graceful shutdown goaway")
}

// unusableClientConnReason reports why a cached client connection can no longer
// serve a request, or "" when it is still good. A connection at its concurrency
// limit reports no available slots too, so in-flight requests are what tells a
// busy connection apart from a closed one.
func unusableClientConnReason(clientConn *http.ClientConn) string {
	if clientConn.Err() != nil {
		return "error"
	}
	if clientConn.Available() == 0 && clientConn.InFlight() == 0 {
		return "closed"
	}
	return ""
}

func shouldCloseDiscardedClientConn(clientConn *http.ClientConn, err error) bool {
	if clientConn.Err() != nil {
		return true
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "client conn is closed") ||
		strings.Contains(msg, "use of closed network connection") {
		return true
	}
	return clientConn.InFlight() == 0
}

func (t *singleConnTransport) Close() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	clientConn := t.clientConn
	t.clientConn = nil
	http1Conn := t.http1Conn
	t.http1Conn = nil
	retired := t.retired
	t.retired = nil
	t.mu.Unlock()

	if clientConn != nil {
		_ = clientConn.Close()
	}
	if http1Conn != nil {
		_ = http1Conn.Close()
	}
	for _, conn := range retired {
		_ = conn.Close()
	}
	return nil
}

func (t *singleConnTransport) setNegotiatedProtocol(proto string) {
	t.mu.Lock()
	t.upstream = proto
	t.mu.Unlock()
}

func (t *singleConnTransport) discardClientConn(ctx context.Context, clientConn *http.ClientConn, closeConn bool) {
	if ctx == nil {
		ctx = context.Background()
	} else {
		ctx = context.WithoutCancel(ctx)
	}
	logger := loggerFromContext(ctx)

	t.mu.Lock()
	if t.clientConn != clientConn {
		t.mu.Unlock()
		logAttrs(ctx, logger, slog.LevelDebug, "transport client connection discard skipped",
			slog.String("hostport", t.hostport),
			slog.Bool("close_conn", closeConn),
			slog.String("reason", "not_current"),
			slog.Int("in_flight", clientConn.InFlight()),
			clientConnErrorAttr(clientConn),
		)
		return
	}
	t.clientConn = nil
	if !closeConn {
		t.retired = append(t.retired, clientConn)
	}
	retiredCount := len(t.retired)
	t.mu.Unlock()

	logAttrs(ctx, logger, slog.LevelDebug, "transport client connection discarded",
		slog.String("hostport", t.hostport),
		slog.Bool("close_conn", closeConn),
		slog.Int("retired_count", retiredCount),
		slog.Int("in_flight", clientConn.InFlight()),
		clientConnErrorAttr(clientConn),
	)
	if closeConn {
		_ = clientConn.Close()
	} else {
		t.watchRetiredClientConn(ctx, logger, clientConn)
	}
}

func (t *singleConnTransport) watchRetiredClientConn(ctx context.Context, logger *slog.Logger, clientConn *http.ClientConn) {
	logAttrs(ctx, logger, slog.LevelDebug, "transport retired client connection watching",
		slog.String("hostport", t.hostport),
		slog.Int("in_flight", clientConn.InFlight()),
		clientConnErrorAttr(clientConn),
	)
	clientConn.SetStateHook(func(cc *http.ClientConn) {
		if reason := retiredClientConnCloseReason(cc); reason != "" {
			t.closeRetiredClientConn(ctx, logger, cc, reason)
		}
	})
	if reason := retiredClientConnCloseReason(clientConn); reason != "" {
		t.closeRetiredClientConn(ctx, logger, clientConn, reason)
	}
}

func retiredClientConnCloseReason(clientConn *http.ClientConn) string {
	if clientConn.Err() != nil {
		return "error"
	}
	if clientConn.InFlight() == 0 {
		return "drained"
	}
	return ""
}

func (t *singleConnTransport) closeRetiredClientConn(ctx context.Context, logger *slog.Logger, clientConn *http.ClientConn, reason string) {
	t.mu.Lock()
	idx := -1
	for i, retired := range t.retired {
		if retired == clientConn {
			idx = i
			break
		}
	}
	if idx < 0 {
		t.mu.Unlock()
		logAttrs(ctx, logger, slog.LevelDebug, "transport retired client connection close skipped",
			slog.String("hostport", t.hostport),
			slog.String("reason", "not_retired"),
			slog.Int("in_flight", clientConn.InFlight()),
			clientConnErrorAttr(clientConn),
		)
		return
	}
	t.retired = append(t.retired[:idx], t.retired[idx+1:]...)
	retiredCount := len(t.retired)
	t.mu.Unlock()

	clientConn.SetStateHook(nil)
	_ = clientConn.Close()
	logAttrs(ctx, logger, slog.LevelDebug, "transport retired client connection closed",
		slog.String("hostport", t.hostport),
		slog.String("reason", reason),
		slog.Int("retired_count", retiredCount),
		slog.Int("in_flight", clientConn.InFlight()),
		clientConnErrorAttr(clientConn),
	)
}

func clientConnErrorAttr(clientConn *http.ClientConn) slog.Attr {
	return namedErrorAttr("client_conn_error", clientConn.Err())
}

func (t *singleConnTransport) getClientConn(ctx context.Context, req *http.Request) (*http.ClientConn, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil, net.ErrClosed
	}
	if t.clientConn != nil {
		// An upstream that closed the connection while it sat idle is only
		// noticed once a request has been written, and by then a request with a
		// body can no longer be replayed. Check before handing it out.
		reason := unusableClientConnReason(t.clientConn)
		if reason == "" {
			logAttrs(ctx, loggerFromContext(ctx), slog.LevelDebug, "transport client connection reused",
				slog.String("hostport", t.hostport),
				slog.String("method", requestMethod(req)),
				slog.String("url", requestURL(req)),
			)
			return t.clientConn, nil
		}
		stale := t.clientConn
		t.clientConn = nil
		logAttrs(ctx, loggerFromContext(ctx), slog.LevelDebug, "transport stale client connection dropped",
			slog.String("hostport", t.hostport),
			slog.String("reason", reason),
			clientConnErrorAttr(stale),
		)
		_ = stale.Close()
	}

	scheme := req.URL.Scheme
	if scheme == "" {
		return nil, errors.New("request URL scheme is empty")
	}
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("unsupported request URL scheme %q", scheme)
	}

	connScheme, protos := clientConnSchemeAndProtocols(scheme, req.ProtoMajor, t.disableHTTP2, t.upstream)
	baseTransport := &http.Transport{
		DialContext:        t.dialFn,
		DialTLSContext:     t.dialFn,
		DisableCompression: true,
		IdleConnTimeout:    t.idleTimeout,
		Protocols:          protos,
	}
	clientConn, err := baseTransport.NewClientConn(ctx, connScheme, t.hostport)
	if err != nil {
		return nil, err
	}
	t.clientConn = clientConn
	logAttrs(ctx, loggerFromContext(ctx), slog.LevelDebug, "transport client connection created",
		slog.String("hostport", t.hostport),
		slog.String("scheme", connScheme),
		slog.Bool("disable_http2", t.disableHTTP2),
	)
	return clientConn, nil
}

func clientConnSchemeAndProtocols(scheme string, protoMajor int, disableHTTP2 bool, negotiatedProtocol string) (string, *http.Protocols) {
	if scheme == "https" {
		switch negotiatedProtocol {
		case http2.NextProtoTLS:
			if !disableHTTP2 {
				return "http", protocolsForExistingHTTP2Conn()
			}
		case "http/1.1":
			return "http", protocolsForHTTP1()
		}
	}
	return scheme, protocolsForRequest(scheme, protoMajor, disableHTTP2)
}

func protocolsForRequest(scheme string, protoMajor int, disableHTTP2 bool) *http.Protocols {
	switch {
	case scheme == "http" && protoMajor == 2 && !disableHTTP2:
		return protocolsForExistingHTTP2Conn()
	case scheme == "https":
		protos := protocolsForHTTP1()
		if !disableHTTP2 {
			protos.SetHTTP2(true)
		}
		return protos
	default:
		return protocolsForHTTP1()
	}
}

func protocolsForHTTP1() *http.Protocols {
	protos := &http.Protocols{}
	protos.SetHTTP1(true)
	return protos
}

func protocolsForExistingHTTP2Conn() *http.Protocols {
	protos := &http.Protocols{}
	protos.SetUnencryptedHTTP2(true)
	return protos
}
