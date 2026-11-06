package mitmproxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	http "github.com/josexy/xhttp"
	"github.com/josexy/xhttp/httptrace"
)

var (
	errHTTP1PipelineClosed       = errors.New("HTTP/1 pipeline connection closed")
	errHTTP1ResponseNotDrained   = errors.New("HTTP/1 response closed before EOF with too much remaining to drain")
	errHTTP1ResponseCloseConcurs = errors.New("HTTP/1 response closed during a read")
)

// An early-closed response is drained up to this bound, which keeps its
// pipelined connection, and the requests queued behind it, usable. A longer or
// slower remainder closes the connection instead.
const (
	http1MaxResponseDrainBytes = 256 << 10
	http1MaxResponseDrainTime  = time.Second
)

type http1PipelineQueuedHookKey struct{}

func notifyHTTP1PipelineQueued(req *http.Request) {
	if req == nil {
		return
	}
	if hook, _ := req.Context().Value(http1PipelineQueuedHookKey{}).(func()); hook != nil {
		hook()
	}
}

type http1PipelineResult struct {
	response *http.Response
	err      error
}

type http1PipelineRequestInfo struct {
	sequence uint64
	target   string
}

type http1PipelineRequestInfoKey struct{}

func http1RequestInfo(req *http.Request) http1PipelineRequestInfo {
	if req == nil {
		return http1PipelineRequestInfo{}
	}
	info, _ := req.Context().Value(http1PipelineRequestInfoKey{}).(http1PipelineRequestInfo)
	return info
}

type http1PipelineExchange struct {
	request *http.Request
	result  chan http1PipelineResult

	pipeline    *http1PipelineConn
	releaseOnce sync.Once
	stopCancel  func() bool
	queuedAt    time.Time
	info        http1PipelineRequestInfo
}

func (e *http1PipelineExchange) release() {
	e.releaseOnce.Do(func() {
		if e.stopCancel != nil {
			e.stopCancel()
		}
		<-e.pipeline.slots
		e.pipeline.endActivity()
	})
}

// http1PipelineConn owns one HTTP/1 connection. Requests and responses are
// serialized independently, which permits several requests to be on the wire
// while preserving HTTP/1's mandatory response ordering.
type http1PipelineConn struct {
	conn        net.Conn
	reader      *bufio.Reader
	idleTimeout time.Duration

	writeQueue chan *http1PipelineExchange
	readQueue  chan *http1PipelineExchange
	slots      chan struct{}
	done       chan struct{}

	closeOnce sync.Once
	errMu     sync.Mutex
	err       error

	activityMu sync.Mutex
	active     int
	idleTimer  *time.Timer
}

func newHTTP1PipelineConn(conn net.Conn, depth int, idleTimeout time.Duration) *http1PipelineConn {
	if depth < 1 {
		depth = 1
	}
	p := &http1PipelineConn{
		conn:        conn,
		reader:      bufio.NewReader(conn),
		idleTimeout: idleTimeout,
		writeQueue:  make(chan *http1PipelineExchange, depth),
		readQueue:   make(chan *http1PipelineExchange, depth),
		slots:       make(chan struct{}, depth),
		done:        make(chan struct{}),
	}
	p.armIdleTimerLocked()
	go p.writeLoop()
	go p.readLoop()
	return p
}

func (p *http1PipelineConn) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, errors.New("HTTP/1 pipeline: nil request")
	}
	ctx := req.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	select {
	case p.slots <- struct{}{}:
		p.beginActivity()
	case <-p.done:
		return nil, p.connectionError()
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	}

	exchange := &http1PipelineExchange{
		request:  req,
		result:   make(chan http1PipelineResult, 1),
		pipeline: p,
		queuedAt: time.Now(),
		info:     http1RequestInfo(req),
	}
	exchange.stopCancel = context.AfterFunc(ctx, func() { p.closeWithError(context.Cause(ctx)) })
	select {
	case p.writeQueue <- exchange:
		notifyHTTP1PipelineQueued(req)
		logAttrs(ctx, loggerFromContext(ctx), slog.LevelDebug, "http1 upstream request queued",
			slog.Uint64("pipeline_sequence", exchange.info.sequence),
			slog.String("target", exchange.info.target),
			slog.Int("in_flight", len(p.slots)),
			slog.Int("pipeline_depth", cap(p.slots)),
		)
	case <-p.done:
		exchange.release()
		return nil, p.connectionError()
	case <-ctx.Done():
		exchange.release()
		return nil, context.Cause(ctx)
	}

	select {
	case result := <-exchange.result:
		if result.err != nil {
			exchange.release()
		}
		return result.response, result.err
	case <-p.done:
		exchange.release()
		return nil, p.connectionError()
	case <-ctx.Done():
		// HTTP/1 cannot cancel an individual pipelined exchange without losing
		// response framing for everything behind it, so cancel the connection.
		p.closeWithError(context.Cause(ctx))
		exchange.release()
		return nil, context.Cause(ctx)
	}
}

func (p *http1PipelineConn) Close() error {
	p.closeWithError(errHTTP1PipelineClosed)
	return nil
}

func (p *http1PipelineConn) Err() error {
	select {
	case <-p.done:
		return p.connectionError()
	default:
		return nil
	}
}

func (p *http1PipelineConn) connectionError() error {
	p.errMu.Lock()
	defer p.errMu.Unlock()
	if p.err == nil {
		return errHTTP1PipelineClosed
	}
	return p.err
}

func (p *http1PipelineConn) closeWithError(err error) {
	if err == nil {
		err = errHTTP1PipelineClosed
	}
	p.closeOnce.Do(func() {
		p.errMu.Lock()
		p.err = err
		p.errMu.Unlock()

		p.activityMu.Lock()
		if p.idleTimer != nil {
			p.idleTimer.Stop()
		}
		p.activityMu.Unlock()

		close(p.done)
		_ = p.conn.Close()
	})
}

func (p *http1PipelineConn) beginActivity() {
	p.activityMu.Lock()
	p.active++
	if p.idleTimer != nil {
		p.idleTimer.Stop()
	}
	p.activityMu.Unlock()
}

func (p *http1PipelineConn) endActivity() {
	p.activityMu.Lock()
	if p.active > 0 {
		p.active--
	}
	if p.active == 0 {
		p.armIdleTimerLocked()
	}
	p.activityMu.Unlock()
}

func (p *http1PipelineConn) armIdleTimerLocked() {
	if p.idleTimeout <= 0 {
		return
	}
	if p.idleTimer == nil {
		p.idleTimer = time.AfterFunc(p.idleTimeout, func() {
			p.closeWithError(errHTTP1PipelineClosed)
		})
		return
	}
	p.idleTimer.Reset(p.idleTimeout)
}

func (p *http1PipelineConn) writeLoop() {
	for {
		select {
		case exchange := <-p.writeQueue:
			// Register the exchange with the ordered response reader before
			// writing its body. HTTP/1 servers may legitimately send a final
			// response while an upload is still in progress; the read loop must
			// be able to fire GotFirstResponseByte without waiting for
			// Request.Write (and WroteRequest) to finish.
			select {
			case p.readQueue <- exchange:
			case <-p.done:
				exchange.release()
				return
			}
			request := withoutForwardedExpectContinue(exchange.request)
			var err error
			if len(request.Trailer) > 0 {
				// Resolve trailer order only after Write has consumed the body.
				// The writer buffers header blocks, never the streaming payload.
				writer := &http1ResponseWriter{dst: p.conn, request: request, chunked: true}
				err = request.Write(writer)
				if flushErr := writer.flush(); err == nil {
					err = flushErr
				}
			} else {
				err = request.Write(p.conn)
			}
			if request.Body != nil {
				_ = request.Body.Close()
			}
			if err != nil {
				exchange.result <- http1PipelineResult{err: err}
				p.closeWithError(err)
				return
			}
			logAttrs(exchange.request.Context(), loggerFromContext(exchange.request.Context()), slog.LevelDebug, "http1 upstream request written",
				slog.Uint64("pipeline_sequence", exchange.info.sequence),
				slog.String("target", exchange.info.target),
				slog.Duration("queue_duration", time.Since(exchange.queuedAt)),
			)
		case <-p.done:
			return
		}
	}
}

func (p *http1PipelineConn) readLoop() {
	for {
		// Keep a read outstanding even while the connection is idle. Besides
		// waiting for the next response, this notices an upstream FIN before a
		// request with an unreplayable body is written to a stale connection.
		if _, err := p.reader.Peek(1); err != nil {
			p.closeWithError(err)
			return
		}
		select {
		case exchange := <-p.readQueue:
			trace := httptrace.ContextClientTrace(exchange.request.Context())
			if trace != nil && trace.GotFirstResponseByte != nil {
				trace.GotFirstResponseByte()
			}
			response, err := p.readFinalResponse(exchange.request)
			if err != nil {
				exchange.result <- http1PipelineResult{err: err}
				p.closeWithError(err)
				return
			}
			response.Request = exchange.request
			logAttrs(exchange.request.Context(), loggerFromContext(exchange.request.Context()), slog.LevelDebug, "http1 upstream response received",
				slog.Uint64("pipeline_sequence", exchange.info.sequence),
				slog.String("target", exchange.info.target),
				slog.Int("status_code", response.StatusCode),
				slog.Duration("round_trip_duration", time.Since(exchange.queuedAt)),
			)
			body := newHTTP1PipelineResponseBody(p, exchange, response.Body)
			response.Body = body
			exchange.result <- http1PipelineResult{response: response}

			select {
			case <-body.done:
			case <-p.done:
				exchange.release()
				return
			}
			if response.Close {
				p.closeWithError(io.EOF)
				return
			}
		case <-p.done:
			return
		}
	}
}

func (p *http1PipelineConn) readFinalResponse(req *http.Request) (*http.Response, error) {
	for {
		response, err := http.ReadResponse(p.reader, req)
		if err != nil {
			return nil, err
		}
		if response.StatusCode < 100 || response.StatusCode >= 200 || response.StatusCode == http.StatusSwitchingProtocols {
			return response, nil
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
	}
}

type http1PipelineResponseBody struct {
	pipeline *http1PipelineConn
	exchange *http1PipelineExchange
	body     io.ReadCloser
	done     chan struct{}

	// readMu guards reading and closed, so Close never drains concurrently
	// with a caller's Read on the shared connection reader.
	readMu  sync.Mutex
	reading int
	closed  bool

	finishOnce sync.Once
	closeOnce  sync.Once
	closeErr   error
}

func newHTTP1PipelineResponseBody(p *http1PipelineConn, exchange *http1PipelineExchange, body io.ReadCloser) *http1PipelineResponseBody {
	if body == nil {
		body = http.NoBody
	}
	b := &http1PipelineResponseBody{
		pipeline: p,
		exchange: exchange,
		body:     body,
		done:     make(chan struct{}),
	}
	if body == http.NoBody {
		b.finish()
	}
	return b
}

func (b *http1PipelineResponseBody) Read(data []byte) (int, error) {
	b.readMu.Lock()
	if b.closed {
		b.readMu.Unlock()
		return 0, http.ErrBodyReadAfterClose
	}
	b.reading++
	b.readMu.Unlock()
	n, err := b.body.Read(data)
	b.readMu.Lock()
	b.reading--
	b.readMu.Unlock()
	if err == io.EOF {
		b.finish()
	}
	return n, err
}

// streamDone reports whether the response no longer occupies the connection,
// which is already true for a bodyless response nobody has read.
func (b *http1PipelineResponseBody) streamDone() bool {
	select {
	case <-b.done:
		return true
	default:
		return false
	}
}

// Close keeps the connection reusable when the unread remainder is short:
// HTTP/1 cannot skip a response, so it drains a bounded amount and otherwise
// closes the connection. Only an error closing the body itself is returned.
func (b *http1PipelineResponseBody) Close() error {
	b.closeOnce.Do(func() {
		b.readMu.Lock()
		b.closed = true
		reading := b.reading > 0
		b.readMu.Unlock()
		if b.streamDone() {
			b.closeErr = b.body.Close()
			return
		}
		// Closing a parsed body that has not reached EOF reads all of its
		// remainder, so every path that abandons the remainder closes the
		// connection first; the body then fails fast and its error is moot.
		if reading {
			// Draining would race the blocked Read. Closing the connection
			// also interrupts that Read.
			b.pipeline.closeWithError(errHTTP1ResponseCloseConcurs)
			_ = b.body.Close()
			b.finish()
			return
		}

		_ = b.pipeline.conn.SetReadDeadline(time.Now().Add(http1MaxResponseDrainTime))
		n, drainErr := io.CopyN(io.Discard, b.body, http1MaxResponseDrainBytes+1)
		_ = b.pipeline.conn.SetReadDeadline(time.Time{})
		switch {
		case drainErr == io.EOF:
			drainErr = nil
		case drainErr == nil && n > http1MaxResponseDrainBytes:
			drainErr = errHTTP1ResponseNotDrained
		}
		if drainErr != nil {
			b.pipeline.closeWithError(drainErr)
			_ = b.body.Close()
		} else {
			b.closeErr = b.body.Close()
		}
		b.finish()
	})
	return b.closeErr
}

func (b *http1PipelineResponseBody) finish() {
	b.finishOnce.Do(func() {
		close(b.done)
		b.exchange.release()
	})
}
