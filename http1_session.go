package mitmproxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/josexy/mitmproxy-go/metadata"
)

type http1SessionResult struct {
	response *http.Response
	err      error
}

type http1SessionItem struct {
	ctx      context.Context
	request  *http.Request
	result   chan http1SessionResult
	ticket   *http1TargetTicket
	prior    <-chan struct{}
	written  chan struct{}
	queuedAt time.Time
}

type http1PriorResponsesDoneKey struct{}
type http1H2CUpgradeClosePoolKey struct{}
type http1SessionReadStateKey struct{}

// http1SessionReadState separates a genuinely idle downstream connection from
// one whose next request is being read while earlier responses are still in
// flight. The latter has no read deadline; once the last response is written,
// the writer arms the ordinary idle timeout for the blocked reader.
type http1SessionReadState struct {
	conn             net.Conn
	idleTimeout      time.Duration
	handshakeTimeout time.Duration

	mu      sync.Mutex
	reading bool
	active  int
	stopped bool
}

func (s *http1SessionReadState) beginRead(first bool) func() {
	s.mu.Lock()
	s.reading = true
	if s.stopped {
		_ = s.conn.SetReadDeadline(time.Now())
	} else {
		timeout := s.idleTimeout
		if first {
			timeout = s.handshakeTimeout
		} else if s.active > 0 {
			timeout = 0
		}
		s.setReadDeadlineLocked(timeout)
	}
	s.mu.Unlock()

	return sync.OnceFunc(func() {
		s.mu.Lock()
		s.reading = false
		if s.stopped {
			_ = s.conn.SetReadDeadline(time.Now())
		} else {
			_ = s.conn.SetReadDeadline(time.Time{})
		}
		s.mu.Unlock()
	})
}

func (s *http1SessionReadState) requestStarted() {
	s.mu.Lock()
	s.active++
	if s.stopped {
		_ = s.conn.SetReadDeadline(time.Now())
	}
	s.mu.Unlock()
}

func (s *http1SessionReadState) requestFinished() {
	s.mu.Lock()
	if s.active > 0 {
		s.active--
	}
	if s.stopped {
		_ = s.conn.SetReadDeadline(time.Now())
	} else if s.active == 0 && s.reading {
		s.setReadDeadlineLocked(s.idleTimeout)
	}
	s.mu.Unlock()
}

func (s *http1SessionReadState) terminateRead() {
	s.mu.Lock()
	s.stopped = true
	_ = s.conn.SetReadDeadline(time.Now())
	s.mu.Unlock()
}

func (s *http1SessionReadState) setReadDeadlineLocked(timeout time.Duration) {
	if timeout <= 0 {
		_ = s.conn.SetReadDeadline(time.Time{})
		return
	}
	_ = s.conn.SetReadDeadline(time.Now().Add(timeout))
}

type http1TargetEntry struct {
	transport *singleConnTransport
	tail      chan struct{}
	active    int
	lastUsed  uint64
}

type http1TargetPool struct {
	connCtx *biConnContext
	mu      sync.Mutex
	entries map[string]*http1TargetEntry
	limit   int
	clock   uint64
}

func newHTTP1TargetPool(connCtx *biConnContext, initialKey string, limit int) *http1TargetPool {
	pool := &http1TargetPool{connCtx: connCtx, entries: make(map[string]*http1TargetEntry), limit: max(1, limit)}
	ready := make(chan struct{})
	close(ready)
	pool.clock++
	pool.entries[initialKey] = &http1TargetEntry{transport: connCtx.currentTransport(), tail: ready, lastUsed: pool.clock}
	return pool
}

func (p *http1TargetPool) register(ctx context.Context, key, hostport string) *http1TargetTicket {
	p.mu.Lock()
	var evicted *singleConnTransport
	evictedTarget := ""
	created := false
	entry := p.entries[key]
	if entry == nil {
		created = true
		if len(p.entries) >= p.limit {
			var victimKey string
			var victim *http1TargetEntry
			for candidateKey, candidate := range p.entries {
				if candidate.active != 0 || (victim != nil && candidate.lastUsed >= victim.lastUsed) {
					continue
				}
				victimKey, victim = candidateKey, candidate
			}
			if victim != nil {
				delete(p.entries, victimKey)
				evicted = victim.transport
				evictedTarget = victimKey
			}
		}
		ready := make(chan struct{})
		close(ready)
		entry = &http1TargetEntry{
			transport: newTransportForTarget(p.connCtx, hostport),
			tail:      ready,
		}
		p.entries[key] = entry
	}
	p.clock++
	entry.active++
	entry.lastUsed = p.clock
	turn := entry.tail
	next := make(chan struct{})
	entry.tail = next
	targetCount := len(p.entries)
	targetInFlight := entry.active
	p.mu.Unlock()
	if evicted != nil {
		_ = evicted.Close()
	}
	logConfigAttrs(ctx, p.connCtx.config, slog.LevelDebug, "http1 pipeline target selected",
		slog.String("target", key),
		slog.Bool("created", created),
		slog.String("evicted_target", evictedTarget),
		slog.Int("target_count", targetCount),
		slog.Int("target_in_flight", targetInFlight),
	)
	return &http1TargetTicket{transport: entry.transport, turn: turn, next: next, pool: p, entry: entry}
}

func (p *http1TargetPool) complete(entry *http1TargetEntry) {
	p.mu.Lock()
	if entry.active > 0 {
		entry.active--
	}
	p.clock++
	entry.lastUsed = p.clock
	p.mu.Unlock()
}

func (p *http1TargetPool) Close() {
	p.mu.Lock()
	transports := make([]*singleConnTransport, 0, len(p.entries))
	seen := make(map[*singleConnTransport]struct{}, len(p.entries))
	for _, entry := range p.entries {
		if entry.transport == nil {
			continue
		}
		if _, ok := seen[entry.transport]; ok {
			continue
		}
		seen[entry.transport] = struct{}{}
		transports = append(transports, entry.transport)
	}
	p.entries = nil
	p.mu.Unlock()
	for _, transport := range transports {
		_ = transport.Close()
	}
}

type http1TargetTicket struct {
	transport *singleConnTransport
	turn      <-chan struct{}
	next      chan struct{}

	mu           sync.Mutex
	invoked      bool
	advance      sync.Once
	completeOnce sync.Once
	pool         *http1TargetPool
	entry        *http1TargetEntry
}

func (t *http1TargetTicket) Invoke(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	first := !t.invoked
	t.invoked = true
	t.mu.Unlock()
	if !first {
		return t.transport.RoundTrip(req)
	}
	select {
	case <-t.turn:
	case <-req.Context().Done():
		t.release()
		return nil, context.Cause(req.Context())
	}
	ctx := context.WithValue(req.Context(), http1PipelineQueuedHookKey{}, t.release)
	response, err := t.transport.RoundTrip(req.WithContext(ctx))
	// Dial and validation failures happen before the exchange reaches the
	// pipeline queue, so ensure the following ticket is never stranded.
	t.release()
	return response, err
}

func (t *http1TargetTicket) finish() {
	t.mu.Lock()
	invoked := t.invoked
	t.mu.Unlock()
	if !invoked {
		t.release()
	}
}

func (t *http1TargetTicket) release() {
	t.advance.Do(func() { close(t.next) })
}

func (t *http1TargetTicket) complete() {
	t.completeOnce.Do(func() { t.pool.complete(t.entry) })
}

func (r *mitmProxyHandler) serveHTTP1Pipeline(
	ctx context.Context,
	fakerw *fakeHttpResponseWriter,
	request *http.Request,
	tlsRequest, firstRead, canRetarget bool,
	srcConn net.Conn,
) (retErr error) {
	connCtx := ctx.Value(connContextKey).(*biConnContext)
	baseReqCtx, _ := FromRequestContext(ctx)
	started := time.Now()
	defer func() {
		logConfigAttrs(ctx, connCtx.config, slog.LevelDebug, "http1 pipeline session stopped",
			slog.String("hostport", baseReqCtx.Hostport),
			slog.Duration("session_duration", time.Since(started)),
			errorAttr(retErr),
		)
	}()
	initialScheme := "http"
	if tlsRequest {
		initialScheme = "https"
	}
	pool := newHTTP1TargetPool(connCtx, initialScheme+"://"+baseReqCtx.Hostport, connCtx.config.state.http1PipelineDepth)
	defer pool.Close()

	depth := connCtx.config.state.http1PipelineDepth
	readState := &http1SessionReadState{
		conn:             srcConn,
		idleTimeout:      connCtx.config.state.idleConnTimeout,
		handshakeTimeout: connCtx.config.state.handshakeTimeout,
	}
	logConfigAttrs(ctx, connCtx.config, slog.LevelDebug, "http1 pipeline session started",
		slog.String("hostport", baseReqCtx.Hostport),
		slog.Int("pipeline_depth", depth),
		slog.Bool("tls", tlsRequest),
		slog.Bool("can_retarget", canRetarget),
	)
	items := make(chan *http1SessionItem, depth)
	slots := make(chan struct{}, depth)
	stop := make(chan struct{})
	writerDone := make(chan error, 1)
	go func() {
		writerDone <- r.writeHTTP1Session(srcConn, items, slots, stop, readState, connCtx.config.state.idleConnTimeout)
	}()

	closeItems := sync.OnceFunc(func() { close(items) })
	waitWriter := func() error {
		closeItems()
		return <-writerDone
	}

	priorWritten := make(chan struct{})
	close(priorWritten)
	var sequence uint64
	for {
		select {
		case slots <- struct{}{}:
		case <-stop:
			return waitWriter()
		}

		parseCtx := context.WithValue(ctx, http1PriorResponsesDoneKey{}, (<-chan struct{})(priorWritten))
		parseCtx = context.WithValue(parseCtx, http1H2CUpgradeClosePoolKey{}, (func())(pool.Close))
		parseCtx = context.WithValue(parseCtx, http1SessionReadStateKey{}, readState)
		nextCtx, earlyDone, wsUpgrade, err := r.distinguishHTTPRequest(parseCtx, fakerw, request, tlsRequest, firstRead)
		if err != nil || earlyDone {
			<-slots
			writerErr := waitWriter()
			if earlyDone && err == nil {
				return writerErr
			}
			if request == nil && isExpectedIdleReadClose(err) {
				return writerErr
			}
			if _, ok := errors.AsType[*requestParseError](err); ok {
				writeHTTP1ErrorResponse(srcConn, statusCodeForRequestError(err))
			}
			return errors.Join(err, writerErr)
		}
		request = nil
		firstRead = false

		nextReqCtx, _ := FromRequestContext(nextCtx)
		hostport := baseReqCtx.Hostport
		if !requestMatchesHostport(nextReqCtx.Request, hostport) {
			if !canRetarget {
				<-slots
				_ = waitWriter()
				writeHTTP1ErrorResponse(srcConn, http.StatusMisdirectedRequest)
				return fmt.Errorf("http keep-alive target changed from %s to %s", hostport, nextReqCtx.Request.Host)
			}
			hostport, err = ParseHostPort(nextReqCtx.Request)
			if err != nil {
				<-slots
				_ = waitWriter()
				writeHTTP1ErrorResponse(srcConn, http.StatusBadRequest)
				return err
			}
		}
		nextReqCtx.Hostport = hostport
		nextCtx = AppendToRequestContext(nextCtx, nextReqCtx)
		nextCtx = cloneMetadataContext(nextCtx)
		if md, ok := metadata.FromContext(nextCtx); ok {
			md.SetRequestReceivedTs(time.Now())
			md.SetRequestHostport(hostport)
		}

		if wsUpgrade {
			logConfigAttrs(nextCtx, connCtx.config, slog.LevelDebug, "http1 pipeline upgrade barrier",
				slog.String("upgrade", "websocket"),
				slog.String("hostport", hostport),
				slog.Int("in_flight", len(slots)-1),
			)
			<-slots
			if err := waitWriter(); err != nil {
				return err
			}
			pool.Close()
			wsConn, err := connCtx.dialRemote(nextCtx, "tcp", hostport)
			if err != nil {
				return err
			}
			return r.relayConnForWS(nextCtx, newBufConnExt(srcConn, fakerw.bufRW), wsConn)
		}

		passthrough, _ := shouldPassthroughRequest(connCtx.config, hostport)
		scheme := nextReqCtx.Request.URL.Scheme
		target := scheme + "://" + hostport
		ticket := pool.register(nextCtx, target, hostport)
		sequence++
		requestInfo := http1PipelineRequestInfo{sequence: sequence, target: target}
		nextReqCtx.Request = nextReqCtx.Request.WithContext(context.WithValue(nextReqCtx.Request.Context(), http1PipelineRequestInfoKey{}, requestInfo))
		item := &http1SessionItem{
			ctx:      nextCtx,
			request:  nextReqCtx.Request,
			result:   make(chan http1SessionResult, 1),
			ticket:   ticket,
			prior:    priorWritten,
			written:  make(chan struct{}),
			queuedAt: time.Now(),
		}
		logConfigAttrs(nextCtx, connCtx.config, slog.LevelDebug, "http1 pipeline request queued",
			slog.Uint64("pipeline_sequence", sequence),
			slog.String("target", target),
			slog.Int("in_flight", len(slots)),
			slog.Int("pipeline_depth", depth),
			slog.Bool("expect_continue", hijackedRequestNeedsContinue(item.request)),
			slog.Bool("connection_close", item.request.Close),
		)
		priorWritten = item.written
		select {
		case items <- item:
			readState.requestStarted()
		case <-stop:
			<-slots
			ticket.finish()
			return waitWriter()
		}
		go func() {
			if hijackedRequestNeedsContinue(item.request) {
				logConfigAttrs(item.ctx, connCtx.config, slog.LevelDebug, "http1 pipeline expect-continue barrier",
					slog.Uint64("pipeline_sequence", requestInfo.sequence),
					slog.String("target", requestInfo.target),
				)
				<-item.prior
			}
			response, roundTripErr := r.roundTripWithInvoker(item.ctx, item.request, !passthrough, ticket)
			ticket.finish()
			item.result <- http1SessionResult{response: response, err: roundTripErr}
		}()

		select {
		case <-hijackedRequestBodyDone(item.request):
		case result := <-item.result:
			item.result <- result
			// A final response before the original body boundary makes later
			// bytes ambiguous. The writer will add Connection: close.
			return waitWriter()
		case <-stop:
			return waitWriter()
		}
		if item.request.Close {
			return waitWriter()
		}
	}
}

func (r *mitmProxyHandler) writeHTTP1Session(
	srcConn net.Conn,
	items <-chan *http1SessionItem,
	slots chan struct{},
	stop chan struct{},
	readState *http1SessionReadState,
	idleTimeout time.Duration,
) (retErr error) {
	var stopOnce sync.Once
	stopWriter := func() { stopOnce.Do(func() { close(stop) }) }
	defer stopWriter()
	for item := range items {
		result := <-item.result
		response := result.response
		if result.err != nil || response == nil {
			info := http1RequestInfo(item.request)
			logAttrs(item.ctx, loggerFromContext(item.ctx), slog.LevelWarn, "http1 pipeline request failed",
				slog.Uint64("pipeline_sequence", info.sequence),
				slog.String("target", info.target),
				errorAttr(result.err),
			)
			response = &http.Response{
				StatusCode:    http.StatusBadGateway,
				Status:        "502 Bad Gateway",
				Proto:         "HTTP/1.1",
				ProtoMajor:    1,
				ProtoMinor:    1,
				Header:        make(http.Header),
				Body:          http.NoBody,
				ContentLength: 0,
				Close:         true,
				Request:       item.request,
			}
			retErr = result.err
		}
		removeHopByHopHeaders(response.Header)
		if !beginHijackedFinalResponse(item.request) {
			response.Close = true
		}
		if err := prepareHTTP1Response(item.request, response); err != nil {
			_ = response.Body.Close()
			item.ticket.complete()
			close(item.written)
			<-slots
			readState.requestFinished()
			readState.terminateRead()
			return err
		}
		writer := &stallGuardConn{Conn: srcConn, timeout: idleTimeout}
		err := writeHTTP1Response(writer, response)
		writer.clearDeadline()
		closeErr := response.Body.Close()
		info := http1RequestInfo(item.request)
		level := slog.LevelDebug
		if err != nil || closeErr != nil {
			level = slog.LevelWarn
		}
		logAttrs(item.ctx, loggerFromContext(item.ctx), level, "http1 pipeline response written",
			slog.Uint64("pipeline_sequence", info.sequence),
			slog.String("target", info.target),
			slog.Int("status_code", response.StatusCode),
			slog.Bool("connection_close", shouldCloseHTTP1(item.request, response)),
			slog.Int("in_flight", len(slots)),
			slog.Duration("request_duration", time.Since(item.queuedAt)),
			errorAttr(err),
			namedErrorAttr("body_close_error", closeErr),
		)
		item.ticket.complete()
		close(item.written)
		<-slots
		readState.requestFinished()
		if err != nil {
			readState.terminateRead()
			return err
		}
		if closeErr != nil {
			readState.terminateRead()
			return closeErr
		}
		if shouldCloseHTTP1(item.request, response) {
			readState.terminateRead()
			return retErr
		}
	}
	return retErr
}

var _ HTTPDelegatedInvoker = (*http1TargetTicket)(nil)
