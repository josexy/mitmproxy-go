package mitmproxy

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	http "github.com/josexy/xhttp"
	"github.com/josexy/xhttp/httptrace"
)

var errNilHTTPTraceResponse = errors.New("upstream transport returned a nil response without an error")

// HTTPExchangeTimingPhase identifies one origin-facing HTTP lifecycle event.
type HTTPExchangeTimingPhase string

const (
	HTTPExchangeRequestStarted  HTTPExchangeTimingPhase = "request_started"
	HTTPExchangeRequestEnded    HTTPExchangeTimingPhase = "request_ended"
	HTTPExchangeResponseStarted HTTPExchangeTimingPhase = "response_started"
	HTTPExchangeResponseEnded   HTTPExchangeTimingPhase = "response_ended"
)

// HTTPExchangeTimingEvent describes one timing transition for the current
// upstream transport attempt. Complete distinguishes an EOF/bodyless terminal
// event from an early Close or read/write failure.
type HTTPExchangeTimingEvent struct {
	Phase     HTTPExchangeTimingPhase
	Timestamp time.Time
	Attempt   int
	Complete  bool
	Error     error
}

type httpExchangeTimingContextKey struct{}
type httpTraceAttemptContextKey struct{}

type httpExchangeTiming struct {
	mu              sync.Mutex
	clock           timingClock
	attempt         int
	requestEnded    bool
	responseStarted bool
	responseEnded   bool
	observers       []func(HTTPExchangeTimingEvent)
}

func newHTTPExchangeTiming(clock timingClock) *httpExchangeTiming {
	if clock == nil {
		clock = systemTimingClock{}
	}
	return &httpExchangeTiming{clock: clock}
}

func withHTTPExchangeTiming(ctx context.Context, timing *httpExchangeTiming) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, httpExchangeTimingContextKey{}, timing)
}

// ObserveHTTPExchangeTiming registers an observer for events emitted after the
// interceptor starts. It returns false when WithUpstreamHTTPTrace was not
// enabled for this request. Observers must return quickly; different transport
// callbacks may invoke an observer from different goroutines.
func ObserveHTTPExchangeTiming(ctx context.Context, observer func(HTTPExchangeTimingEvent)) bool {
	if ctx == nil || observer == nil {
		return false
	}
	timing, ok := ctx.Value(httpExchangeTimingContextKey{}).(*httpExchangeTiming)
	if !ok || timing == nil {
		return false
	}
	timing.mu.Lock()
	timing.observers = append(timing.observers, observer)
	timing.mu.Unlock()
	return true
}

func (t *httpExchangeTiming) startAttempt() int {
	t.mu.Lock()
	timestamp := t.clock.Now()
	t.attempt++
	attempt := t.attempt
	t.requestEnded = false
	t.responseStarted = false
	t.responseEnded = false
	observers := append([]func(HTTPExchangeTimingEvent){}, t.observers...)
	t.mu.Unlock()
	t.notify(observers, HTTPExchangeTimingEvent{
		Phase:     HTTPExchangeRequestStarted,
		Timestamp: timestamp,
		Attempt:   attempt,
	})
	return attempt
}

func (t *httpExchangeTiming) traceRequest(request *http.Request) (*http.Request, *httpTraceAttempt) {
	attempt := &httpTraceAttempt{timing: t}
	request = request.WithContext(context.WithValue(request.Context(), httpTraceAttemptContextKey{}, attempt))
	return attempt.traceRequest(request), attempt
}

func (a *httpTraceAttempt) traceRequest(request *http.Request) *http.Request {
	attempt := a.timing.startAttempt()
	a.attempt.Store(int64(attempt))
	trace := &httptrace.ClientTrace{
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			a.timing.requestFinished(attempt, info.Err)
		},
		GotFirstResponseByte: func() {
			a.timing.responseFirstByte(attempt)
		},
	}
	return request.WithContext(httptrace.WithClientTrace(request.Context(), trace))
}

// Start the replacement attempt before backoff, connection acquisition or any
// writes. Each trace captures its own attempt ID, so late callbacks from an
// earlier connection cannot be attributed to the replacement request.
func traceHTTPRetry(request *http.Request, previousErr error) *http.Request {
	state, _ := request.Context().Value(httpTraceAttemptContextKey{}).(*httpTraceAttempt)
	if state == nil {
		return request
	}
	state.timing.requestFinished(state.current(), previousErr)
	return state.traceRequest(request)
}

func (t *httpExchangeTiming) requestFinished(attempt int, writeErr error) {
	t.mu.Lock()
	if attempt != t.attempt || t.requestEnded {
		t.mu.Unlock()
		return
	}
	timestamp := t.clock.Now()
	t.requestEnded = true
	observers := t.observersForEventLocked()
	t.mu.Unlock()
	t.notify(observers, HTTPExchangeTimingEvent{
		Phase:     HTTPExchangeRequestEnded,
		Timestamp: timestamp,
		Attempt:   attempt,
		Complete:  writeErr == nil,
		Error:     writeErr,
	})
}

func (t *httpExchangeTiming) responseFirstByte(attempt int) {
	t.mu.Lock()
	if attempt != t.attempt || t.responseStarted {
		t.mu.Unlock()
		return
	}
	timestamp := t.clock.Now()
	t.responseStarted = true
	observers := append([]func(HTTPExchangeTimingEvent){}, t.observers...)
	t.mu.Unlock()
	t.notify(observers, HTTPExchangeTimingEvent{
		Phase:     HTTPExchangeResponseStarted,
		Timestamp: timestamp,
		Attempt:   attempt,
	})
}

func (t *httpExchangeTiming) responseFinished(attempt int, complete bool, responseErr error) {
	t.mu.Lock()
	if attempt != t.attempt || t.responseEnded {
		t.mu.Unlock()
		return
	}
	timestamp := t.clock.Now()
	t.responseEnded = true
	observers := t.observersForEventLocked()
	t.mu.Unlock()
	t.notify(observers, HTTPExchangeTimingEvent{
		Phase:     HTTPExchangeResponseEnded,
		Timestamp: timestamp,
		Attempt:   attempt,
		Complete:  complete,
		Error:     responseErr,
	})
}

func (t *httpExchangeTiming) observeResult(
	request *http.Request,
	response *http.Response,
	invokeErr error,
	attemptState *httpTraceAttempt,
) {
	attempt := attemptState.current()
	if invokeErr != nil || response == nil {
		if invokeErr == nil {
			invokeErr = errNilHTTPTraceResponse
		}
		t.invokeFailed(attempt, invokeErr)
		return
	}
	// Custom transports are not required to implement httptrace. Falling back
	// at RoundTrip return still gives them a useful response-header boundary.
	t.responseFirstByte(attempt)
	if responseHasNoEntityBody(request, response) {
		t.responseFinished(attempt, true, nil)
		return
	}
	response.Body = &httpTimingResponseBody{
		source:  response.Body,
		timing:  t,
		attempt: attempt,
	}
}

func (t *httpExchangeTiming) invokeFailed(attempt int, invokeErr error) {
	if !t.isCurrentAttempt(attempt) {
		return
	}
	t.requestFinished(attempt, invokeErr)
	t.mu.Lock()
	responseStarted := attempt == t.attempt && t.responseStarted && !t.responseEnded
	if attempt == t.attempt && !responseStarted {
		t.observers = nil
	}
	t.mu.Unlock()
	if responseStarted {
		t.responseFinished(attempt, false, invokeErr)
	}
}

func (t *httpExchangeTiming) isCurrentAttempt(attempt int) bool {
	t.mu.Lock()
	current := attempt == t.attempt
	t.mu.Unlock()
	return current
}

func (t *httpExchangeTiming) observersForEventLocked() []func(HTTPExchangeTimingEvent) {
	observers := append([]func(HTTPExchangeTimingEvent){}, t.observers...)
	if t.requestEnded && t.responseEnded {
		t.observers = nil
	}
	return observers
}

func (t *httpExchangeTiming) notify(observers []func(HTTPExchangeTimingEvent), event HTTPExchangeTimingEvent) {
	for _, observer := range observers {
		observer(event)
	}
}

type httpTraceAttempt struct {
	timing  *httpExchangeTiming
	attempt atomic.Int64
}

func (a *httpTraceAttempt) current() int {
	return int(a.attempt.Load())
}

type httpTimingResponseBody struct {
	source  io.ReadCloser
	timing  *httpExchangeTiming
	attempt int
	done    atomic.Bool
}

func (b *httpTimingResponseBody) Read(buffer []byte) (int, error) {
	n, err := b.source.Read(buffer)
	if err != nil {
		b.finish(err == io.EOF, normalizeHTTPTraceError(err))
	}
	return n, err
}

func (b *httpTimingResponseBody) Close() error {
	err := b.source.Close()
	b.finish(false, err)
	return err
}

func (b *httpTimingResponseBody) finish(complete bool, err error) {
	if !b.done.CompareAndSwap(false, true) {
		return
	}
	b.timing.responseFinished(b.attempt, complete, err)
}

func normalizeHTTPTraceError(err error) error {
	if err == io.EOF {
		return nil
	}
	return err
}

func responseHasNoEntityBody(request *http.Request, response *http.Response) bool {
	if response == nil || response.Body == nil || response.Body == http.NoBody {
		return true
	}
	return !http1ResponseBodyAllowed(request, response.StatusCode)
}
