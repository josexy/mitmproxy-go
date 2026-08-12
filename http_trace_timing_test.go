package mitmproxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/url"
	"reflect"
	"sync"
	"testing"
	"time"

	http "github.com/josexy/xhttp"
	"github.com/josexy/xhttp/httptrace"
)

type sequenceTimingClock struct {
	timestamps []time.Time
	next       int
}

func (c *sequenceTimingClock) Now() time.Time {
	if c.next >= len(c.timestamps) {
		panic("sequence timing clock exhausted")
	}
	value := c.timestamps[c.next]
	c.next++
	return value
}

func TestObserveHTTPExchangeTimingRequiresEnabledContext(t *testing.T) {
	if ObserveHTTPExchangeTiming(context.Background(), func(HTTPExchangeTimingEvent) {}) {
		t.Fatal("observer registered without an HTTP exchange timing collector")
	}
}

func TestHTTPExchangeTimingEmitsLifecycleAndBodyEOF(t *testing.T) {
	base := time.Date(2026, time.August, 12, 20, 0, 0, 123_000_000, time.Local)
	clock := &sequenceTimingClock{timestamps: []time.Time{
		base,
		base.Add(125 * time.Microsecond),
		base.Add(275 * time.Millisecond),
		base.Add(275*time.Millisecond + 175*time.Microsecond),
	}}
	timing := newHTTPExchangeTiming(clock)
	ctx := withHTTPExchangeTiming(context.Background(), timing)
	var events []HTTPExchangeTimingEvent
	if !ObserveHTTPExchangeTiming(ctx, func(event HTTPExchangeTimingEvent) {
		events = append(events, event)
	}) {
		t.Fatal("observer was not registered")
	}

	request := &http.Request{Method: http.MethodGet, Body: http.NoBody}
	request, attempt := timing.traceRequest(request)
	trace := httptrace.ContextClientTrace(request.Context())
	trace.WroteHeaders()
	trace.WroteRequest(httptrace.WroteRequestInfo{})
	trace.GotFirstResponseByte()
	response := &http.Response{
		StatusCode:    http.StatusOK,
		Body:          io.NopCloser(bytes.NewBufferString("ok")),
		ContentLength: 2,
	}
	timing.observeResult(request, response, nil, attempt)
	if _, err := io.ReadAll(response.Body); err != nil {
		t.Fatal(err)
	}

	want := []HTTPExchangeTimingEvent{
		{Phase: HTTPExchangeRequestStarted, Timestamp: clock.timestamps[0], Attempt: 1},
		{Phase: HTTPExchangeRequestEnded, Timestamp: clock.timestamps[1], Attempt: 1, Complete: true},
		{Phase: HTTPExchangeResponseStarted, Timestamp: clock.timestamps[2], Attempt: 1},
		{Phase: HTTPExchangeResponseEnded, Timestamp: clock.timestamps[3], Attempt: 1, Complete: true},
	}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("events = %#v, want %#v", events, want)
	}
}

func TestHTTPExchangeTimingStartsNewAttemptForRetryAndIgnoresStaleTrace(t *testing.T) {
	base := time.Date(2026, time.August, 12, 20, 0, 0, 0, time.UTC)
	clock := &sequenceTimingClock{timestamps: []time.Time{
		base,
		base.Add(time.Microsecond),
		base.Add(2 * time.Microsecond),
	}}
	timing := newHTTPExchangeTiming(clock)
	ctx := withHTTPExchangeTiming(context.Background(), timing)
	var events []HTTPExchangeTimingEvent
	ObserveHTTPExchangeTiming(ctx, func(event HTTPExchangeTimingEvent) {
		events = append(events, event)
	})

	firstRequest, _ := timing.traceRequest(&http.Request{})
	firstTrace := httptrace.ContextClientTrace(firstRequest.Context())
	firstTrace.WroteHeaders()
	secondRequest, _ := timing.traceRequest(&http.Request{})
	secondTrace := httptrace.ContextClientTrace(secondRequest.Context())

	// These callbacks belong to the superseded invocation and must not update
	// the logical exchange after attempt 2 starts.
	firstTrace.WroteRequest(httptrace.WroteRequestInfo{})
	firstTrace.GotFirstResponseByte()
	secondTrace.WroteHeaders()
	secondTrace.WroteRequest(httptrace.WroteRequestInfo{})

	if got := []HTTPExchangeTimingPhase{events[0].Phase, events[1].Phase, events[2].Phase}; !reflect.DeepEqual(got, []HTTPExchangeTimingPhase{
		HTTPExchangeRequestStarted,
		HTTPExchangeRequestStarted,
		HTTPExchangeRequestEnded,
	}) {
		t.Fatalf("phases = %v", got)
	}
	if events[0].Attempt != 1 || events[1].Attempt != 2 || events[2].Attempt != 2 {
		t.Fatalf("attempts = %d, %d, %d", events[0].Attempt, events[1].Attempt, events[2].Attempt)
	}
}

func TestHTTPExchangeTimingTreatsSecondWroteHeadersAsTransparentRetry(t *testing.T) {
	base := time.Date(2026, time.August, 12, 20, 0, 0, 0, time.UTC)
	clock := &sequenceTimingClock{timestamps: []time.Time{base, base.Add(time.Microsecond)}}
	timing := newHTTPExchangeTiming(clock)
	ctx := withHTTPExchangeTiming(context.Background(), timing)
	var events []HTTPExchangeTimingEvent
	ObserveHTTPExchangeTiming(ctx, func(event HTTPExchangeTimingEvent) { events = append(events, event) })

	request, _ := timing.traceRequest(&http.Request{})
	trace := httptrace.ContextClientTrace(request.Context())
	trace.WroteHeaders()
	trace.WroteHeaders()

	if len(events) != 2 || events[0].Attempt != 1 || events[1].Attempt != 2 ||
		events[1].Phase != HTTPExchangeRequestStarted {
		t.Fatalf("retry events = %#v", events)
	}
}

func TestHTTPExchangeTimingMarksEarlyBodyCloseIncomplete(t *testing.T) {
	base := time.Date(2026, time.August, 12, 20, 0, 0, 0, time.UTC)
	clock := &sequenceTimingClock{timestamps: []time.Time{base, base.Add(time.Microsecond), base.Add(2 * time.Microsecond)}}
	timing := newHTTPExchangeTiming(clock)
	ctx := withHTTPExchangeTiming(context.Background(), timing)
	var events []HTTPExchangeTimingEvent
	ObserveHTTPExchangeTiming(ctx, func(event HTTPExchangeTimingEvent) { events = append(events, event) })

	request, attempt := timing.traceRequest(&http.Request{Method: http.MethodGet})
	response := &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBufferString("body"))}
	timing.observeResult(request, response, nil, attempt)
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	last := events[len(events)-1]
	if last.Phase != HTTPExchangeResponseEnded || last.Complete || last.Error != nil {
		t.Fatalf("response end = %#v", last)
	}
}

func TestHTTPExchangeTimingCompletesBodylessResponseAtHeaders(t *testing.T) {
	base := time.Date(2026, time.August, 12, 20, 0, 0, 0, time.UTC)
	clock := &sequenceTimingClock{timestamps: []time.Time{base, base.Add(time.Microsecond), base.Add(2 * time.Microsecond)}}
	timing := newHTTPExchangeTiming(clock)
	ctx := withHTTPExchangeTiming(context.Background(), timing)
	var events []HTTPExchangeTimingEvent
	ObserveHTTPExchangeTiming(ctx, func(event HTTPExchangeTimingEvent) { events = append(events, event) })

	request, attempt := timing.traceRequest(&http.Request{Method: http.MethodHead})
	response := &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}
	timing.observeResult(request, response, nil, attempt)
	if got := events[len(events)-1]; got.Phase != HTTPExchangeResponseEnded || !got.Complete {
		t.Fatalf("bodyless response end = %#v", got)
	}
}

func TestHTTPExchangeTimingPropagatesResponseReadError(t *testing.T) {
	readErr := errors.New("broken response body")
	base := time.Date(2026, time.August, 12, 20, 0, 0, 0, time.UTC)
	clock := &sequenceTimingClock{timestamps: []time.Time{base, base.Add(time.Microsecond), base.Add(2 * time.Microsecond)}}
	timing := newHTTPExchangeTiming(clock)
	ctx := withHTTPExchangeTiming(context.Background(), timing)
	var events []HTTPExchangeTimingEvent
	ObserveHTTPExchangeTiming(ctx, func(event HTTPExchangeTimingEvent) { events = append(events, event) })

	request, attempt := timing.traceRequest(&http.Request{Method: http.MethodGet})
	response := &http.Response{StatusCode: http.StatusOK, Body: errorReadCloser{err: readErr}}
	timing.observeResult(request, response, nil, attempt)
	_, _ = response.Body.Read(make([]byte, 1))
	last := events[len(events)-1]
	if last.Phase != HTTPExchangeResponseEnded || last.Complete || !errors.Is(last.Error, readErr) {
		t.Fatalf("response error event = %#v", last)
	}
}

func TestHTTPTimingResponseBodyFinishesOnceConcurrently(t *testing.T) {
	timing := newHTTPExchangeTiming(systemTimingClock{})
	attempt := timing.startAttempt()
	events := make(chan HTTPExchangeTimingEvent, 64)
	ObserveHTTPExchangeTiming(withHTTPExchangeTiming(context.Background(), timing), func(event HTTPExchangeTimingEvent) {
		events <- event
	})
	body := &httpTimingResponseBody{timing: timing, attempt: attempt}

	start := make(chan struct{})
	var wait sync.WaitGroup
	for index := range 64 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			body.finish(index%2 == 0, errors.New("terminal response"))
		}()
	}
	close(start)
	wait.Wait()

	if !body.done.Load() {
		t.Fatal("response body was not marked finished")
	}
	if got := len(events); got != 1 {
		t.Fatalf("response terminal events = %d, want 1", got)
	}
}

func TestHTTPExchangeTimingEndsStartedResponseOnInvokeError(t *testing.T) {
	invokeErr := errors.New("response headers failed")
	base := time.Date(2026, time.August, 12, 20, 0, 0, 0, time.UTC)
	clock := &sequenceTimingClock{timestamps: []time.Time{
		base,
		base.Add(time.Microsecond),
		base.Add(2 * time.Microsecond),
		base.Add(3 * time.Microsecond),
	}}
	timing := newHTTPExchangeTiming(clock)
	ctx := withHTTPExchangeTiming(context.Background(), timing)
	var events []HTTPExchangeTimingEvent
	ObserveHTTPExchangeTiming(ctx, func(event HTTPExchangeTimingEvent) { events = append(events, event) })

	request, attempt := timing.traceRequest(&http.Request{Method: http.MethodGet})
	httptrace.ContextClientTrace(request.Context()).GotFirstResponseByte()
	timing.observeResult(request, nil, invokeErr, attempt)

	last := events[len(events)-1]
	if last.Phase != HTTPExchangeResponseEnded || last.Complete || !errors.Is(last.Error, invokeErr) {
		t.Fatalf("response error event = %#v", last)
	}
}

func TestRoundTripWithInvokerUpstreamHTTPTraceIsOptIn(t *testing.T) {
	for _, test := range []struct {
		name    string
		enabled bool
	}{
		{name: "disabled", enabled: false},
		{name: "enabled", enabled: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var events []HTTPExchangeTimingEvent
			var observerAvailable bool
			config := &runtimeConfig{state: runtimeConfigState{upstreamHTTPTrace: test.enabled}}
			config.httpInt = func(ctx context.Context, request *http.Request, next HTTPDelegatedInvoker) (*http.Response, error) {
				observerAvailable = ObserveHTTPExchangeTiming(ctx, func(event HTTPExchangeTimingEvent) {
					events = append(events, event)
				})
				return next.Invoke(request)
			}

			connCtx := &biConnContext{config: config}
			ctx := context.WithValue(context.Background(), connContextKey, connCtx)
			ctx = AppendToRequestContext(ctx, ReqContext{Hostport: "example.test:80"})
			request := &http.Request{
				Method: http.MethodGet,
				URL:    &url.URL{Scheme: "http", Host: "example.test", Path: "/"},
				Host:   "example.test",
				Header: make(http.Header),
				Body:   http.NoBody,
			}
			invoker := HTTPDelegatedInvokerFunc(func(request *http.Request) (*http.Response, error) {
				trace := httptrace.ContextClientTrace(request.Context())
				if test.enabled {
					if trace == nil {
						t.Fatal("enabled request has no client trace")
					}
					trace.WroteHeaders()
					trace.WroteRequest(httptrace.WroteRequestInfo{})
					trace.GotFirstResponseByte()
				} else if trace != nil {
					t.Fatal("disabled request unexpectedly has a client trace")
				}
				return &http.Response{
					StatusCode:    http.StatusOK,
					Status:        "200 OK",
					Header:        make(http.Header),
					Body:          io.NopCloser(bytes.NewBufferString("ok")),
					ContentLength: 2,
					Request:       request,
				}, nil
			})

			response, err := (&mitmProxyHandler{}).roundTripWithInvoker(ctx, request, true, invoker)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadAll(response.Body); err != nil {
				t.Fatal(err)
			}
			if observerAvailable != test.enabled {
				t.Fatalf("observer available = %t, want %t", observerAvailable, test.enabled)
			}
			if !test.enabled {
				if len(events) != 0 {
					t.Fatalf("disabled events = %#v", events)
				}
				return
			}
			want := []HTTPExchangeTimingPhase{
				HTTPExchangeRequestStarted,
				HTTPExchangeRequestEnded,
				HTTPExchangeResponseStarted,
				HTTPExchangeResponseEnded,
			}
			got := make([]HTTPExchangeTimingPhase, len(events))
			for index := range events {
				got[index] = events[index].Phase
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("phases = %v, want %v", got, want)
			}
		})
	}
}

type errorReadCloser struct {
	err error
}

func (r errorReadCloser) Read([]byte) (int, error) { return 0, r.err }
func (r errorReadCloser) Close() error             { return nil }
