package mitmproxy

import (
	"bufio"
	"context"
	"errors"
	"github.com/josexy/xhttp"
	"github.com/josexy/xhttp/httptrace"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"
)

var errHTTP1PipelineClosed = errors.New("HTTP/1 pipeline connection closed")

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
	queuedAt    time.Time
	info        http1PipelineRequestInfo
}

func (e *http1PipelineExchange) release() {
	e.releaseOnce.Do(func() {
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
			err := request.Write(p.conn)
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
	n, err := b.body.Read(data)
	if err == io.EOF {
		b.finish()
	}
	return n, err
}

func (b *http1PipelineResponseBody) Close() error {
	b.closeOnce.Do(func() {
		select {
		case <-b.done:
			b.closeErr = b.body.Close()
			return
		default:
		}

		if b.pipeline.idleTimeout > 0 {
			_ = b.pipeline.conn.SetReadDeadline(time.Now().Add(b.pipeline.idleTimeout))
		}
		_, copyErr := io.Copy(io.Discard, b.body)
		if b.pipeline.idleTimeout > 0 {
			_ = b.pipeline.conn.SetReadDeadline(time.Time{})
		}
		closeErr := b.body.Close()
		b.closeErr = errors.Join(copyErr, closeErr)
		b.finish()
		if b.closeErr != nil {
			b.pipeline.closeWithError(b.closeErr)
		}
	})
	return b.closeErr
}

func (b *http1PipelineResponseBody) finish() {
	b.finishOnce.Do(func() {
		close(b.done)
		b.exchange.release()
	})
}
