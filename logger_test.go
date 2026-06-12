package mitmproxy

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

type capturedLogRecord struct {
	level   slog.Level
	message string
	attrs   map[string]any
}

type captureLogSink struct {
	mu      sync.Mutex
	records []capturedLogRecord
}

func (s *captureLogSink) append(record capturedLogRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, record)
}

func (s *captureLogSink) recordsSnapshot() []capturedLogRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]capturedLogRecord(nil), s.records...)
}

func (s *captureLogSink) countMessage(message string) int {
	count := 0
	want := logMessage(message)
	for _, record := range s.recordsSnapshot() {
		if record.message == want {
			count++
		}
	}
	return count
}

type captureLogHandler struct {
	sink  *captureLogSink
	level slog.Level
	attrs []slog.Attr
}

func newCaptureLogger(level slog.Level) (*slog.Logger, *captureLogSink) {
	sink := &captureLogSink{}
	return slog.New(&captureLogHandler{sink: sink, level: level}), sink
}

func (h *captureLogHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

func (h *captureLogHandler) Handle(_ context.Context, record slog.Record) error {
	attrs := make(map[string]any, len(h.attrs)+record.NumAttrs())
	for _, attr := range h.attrs {
		attrs[attr.Key] = attr.Value.Any()
	}
	record.Attrs(func(attr slog.Attr) bool {
		attrs[attr.Key] = attr.Value.Any()
		return true
	})
	h.sink.append(capturedLogRecord{
		level:   record.Level,
		message: record.Message,
		attrs:   attrs,
	})
	return nil
}

func (h *captureLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	next := &captureLogHandler{
		sink:  h.sink,
		level: h.level,
		attrs: append([]slog.Attr(nil), h.attrs...),
	}
	next.attrs = append(next.attrs, attrs...)
	return next
}

func (h *captureLogHandler) WithGroup(string) slog.Handler {
	return &captureLogHandler{
		sink:  h.sink,
		level: h.level,
		attrs: append([]slog.Attr(nil), h.attrs...),
	}
}

func TestWithLoggerRecordsHTTPProxyFlow(t *testing.T) {
	certPath, keyPath := writeRuntimeTestCA(t, "logger ca")
	logger, sink := newCaptureLogger(slog.LevelDebug)
	handler, err := NewMitmProxyHandler(
		WithCACertPath(certPath),
		WithCAKeyPath(keyPath),
		WithLogger(logger),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Cleanup()

	target := startRuntimeHTTPServer(t)
	proxy := startRuntimeProxyServer(t, handler)
	client := newRuntimeProxyClient(t, proxy)
	defer client.CloseIdleConnections()

	resp, err := client.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	closeResponseBody(t, resp)

	requireLogMessage(t, sink, "serve connection")
	requireLogMessage(t, sink, "http request")
	responseLog := requireLogMessage(t, sink, "http response")
	if got := attrInt(responseLog, "status_code"); got != http.StatusOK {
		t.Fatalf("http response status_code = %d; want %d", got, http.StatusOK)
	}
	if got := attrString(responseLog, "hostport"); got == "" {
		t.Fatalf("http response hostport was empty")
	}
}

func TestLoggerDefaultsToNoop(t *testing.T) {
	tests := []struct {
		name string
		opt  []Option
	}{
		{name: "default"},
		{name: "nil logger", opt: []Option{WithLogger(nil)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certPath, keyPath := writeRuntimeTestCA(t, "noop logger ca")
			opts := []Option{WithCACertPath(certPath), WithCAKeyPath(keyPath)}
			opts = append(opts, tt.opt...)
			handler, err := NewMitmProxyHandler(opts...)
			if err != nil {
				t.Fatal(err)
			}
			defer handler.Cleanup()

			target := startRuntimeHTTPServer(t)
			proxy := startRuntimeProxyServer(t, handler)
			client := newRuntimeProxyClient(t, proxy)
			defer client.CloseIdleConnections()

			resp, err := client.Get(target)
			if err != nil {
				t.Fatal(err)
			}
			closeResponseBody(t, resp)
		})
	}
}

func TestSetLoggerAppliesToNewConnectionsOnly(t *testing.T) {
	certPath, keyPath := writeRuntimeTestCA(t, "dynamic logger ca")
	oldLogger, oldSink := newCaptureLogger(slog.LevelDebug)
	newLogger, newSink := newCaptureLogger(slog.LevelDebug)
	handler, err := NewDynamicMitmProxyHandler(
		WithCACertPath(certPath),
		WithCAKeyPath(keyPath),
		WithLogger(oldLogger),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Cleanup()

	target := startRuntimeHTTPServer(t)
	proxy := startRuntimeProxyServer(t, handler)
	client1 := newRuntimeProxyClient(t, proxy)

	resp, err := client1.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	closeResponseBody(t, resp)
	if got := oldSink.countMessage("http response"); got != 1 {
		t.Fatalf("old logger http response count = %d; want 1", got)
	}

	handler.SetLogger(newLogger)

	resp, err = client1.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	closeResponseBody(t, resp)
	if got := oldSink.countMessage("http response"); got != 2 {
		t.Fatalf("old keep-alive logger http response count = %d; want 2", got)
	}
	if got := newSink.countMessage("http response"); got != 0 {
		t.Fatalf("new logger http response count before new connection = %d; want 0", got)
	}
	client1.CloseIdleConnections()

	client2 := newRuntimeProxyClient(t, proxy)
	defer client2.CloseIdleConnections()
	resp, err = client2.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	closeResponseBody(t, resp)
	if got := newSink.countMessage("http response"); got != 1 {
		t.Fatalf("new logger http response count after new connection = %d; want 1", got)
	}
}

func TestTransportLogsRetryForReplayableRequest(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		firstConn, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = http.ReadRequest(newBufioReader(firstConn))
		_ = firstConn.Close()

		secondConn, err := ln.Accept()
		if err != nil {
			return
		}
		defer secondConn.Close()
		req, err := http.ReadRequest(newBufioReader(secondConn))
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, req.Body)
		_ = req.Body.Close()
		_, _ = secondConn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
	}()

	logger, sink := newCaptureLogger(slog.LevelDebug)
	tr := newTransport(
		ln.Addr().String(),
		func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, addr)
		},
		time.Second,
		true,
	)
	defer tr.Close()

	ctx := context.WithValue(context.Background(), connContextKey, &biConnContext{
		config: &runtimeConfig{state: runtimeConfigState{logger: logger}},
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+ln.Addr().String()+"/", nil)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	<-done

	record := requireLogMessage(t, sink, "transport round trip failed")
	if got := attrBool(record, "retry"); !got {
		t.Fatalf("transport retry log retry = false; want true")
	}
	if got := attrBool(record, "discard"); !got {
		t.Fatalf("transport retry log discard = false; want true")
	}
}

func TestTransportDoesNotLogRetryForNonReplayableRequest(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		req, err := http.ReadRequest(newBufioReader(conn))
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, req.Body)
		_ = req.Body.Close()
	}()

	logger, sink := newCaptureLogger(slog.LevelDebug)
	tr := newTransport(
		ln.Addr().String(),
		func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, addr)
		},
		time.Second,
		true,
	)
	defer tr.Close()

	ctx := context.WithValue(context.Background(), connContextKey, &biConnContext{
		config: &runtimeConfig{state: runtimeConfigState{logger: logger}},
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+ln.Addr().String()+"/", nil)
	if _, err := tr.RoundTrip(req); err == nil {
		t.Fatal("RoundTrip unexpectedly succeeded")
	}
	<-done

	for _, record := range sink.recordsSnapshot() {
		if record.message == logMessage("transport round trip failed") && attrBool(record, "retry") {
			t.Fatalf("non-replayable request logged retry=true: %#v", record.attrs)
		}
	}
}

func newBufioReader(conn net.Conn) *bufio.Reader {
	return bufio.NewReader(conn)
}

func requireLogMessage(t *testing.T, sink *captureLogSink, message string) capturedLogRecord {
	t.Helper()
	want := logMessage(message)
	for _, record := range sink.recordsSnapshot() {
		if record.message == want {
			return record
		}
	}
	t.Fatalf("missing log message %q; records = %#v", want, sink.recordsSnapshot())
	return capturedLogRecord{}
}

func attrString(record capturedLogRecord, key string) string {
	val, _ := record.attrs[key].(string)
	return val
}

func attrBool(record capturedLogRecord, key string) bool {
	val, _ := record.attrs[key].(bool)
	return val
}

func attrInt(record capturedLogRecord, key string) int {
	switch val := record.attrs[key].(type) {
	case int:
		return val
	case int64:
		return int(val)
	default:
		return 0
	}
}
