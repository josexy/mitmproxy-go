package main

import (
	"bytes"
	"compress/gzip"
	"io"
	"runtime"
	"testing"
	"time"

	"github.com/josexy/mitmproxy-go/v2"
	http "github.com/josexy/xhttp"
)

func TestHTTPExchangeTimingLoggerTracksAndResetsAttempts(t *testing.T) {
	base := time.Date(2026, time.August, 12, 22, 0, 0, 0, time.UTC)
	logger := &httpExchangeTimingLogger{}
	events := []mitmproxy.HTTPExchangeTimingEvent{
		{Phase: mitmproxy.HTTPExchangeRequestStarted, Timestamp: base, Attempt: 1},
		{Phase: mitmproxy.HTTPExchangeResponseStarted, Timestamp: base.Add(time.Millisecond), Attempt: 1},
		{Phase: mitmproxy.HTTPExchangeRequestEnded, Timestamp: base.Add(2 * time.Millisecond), Attempt: 1},
		{Phase: mitmproxy.HTTPExchangeResponseEnded, Timestamp: base.Add(3 * time.Millisecond), Attempt: 1},
	}
	var timing httpAttemptTiming
	for _, event := range events {
		timing = logger.apply(event)
	}
	if timing.RequestStartedAt != events[0].Timestamp || timing.RequestEndedAt != events[2].Timestamp ||
		timing.ResponseStartedAt != events[1].Timestamp || timing.ResponseEndedAt != events[3].Timestamp {
		t.Fatalf("attempt 1 timing = %+v", timing)
	}

	retryStarted := base.Add(4 * time.Millisecond)
	timing = logger.apply(mitmproxy.HTTPExchangeTimingEvent{
		Phase:     mitmproxy.HTTPExchangeRequestStarted,
		Timestamp: retryStarted,
		Attempt:   2,
	})
	if timing.Attempt != 2 || timing.RequestStartedAt != retryStarted ||
		!timing.RequestEndedAt.IsZero() || !timing.ResponseStartedAt.IsZero() || !timing.ResponseEndedAt.IsZero() {
		t.Fatalf("attempt 2 timing was not reset: %+v", timing)
	}
}

func TestInitialHeaderFieldsSize(t *testing.T) {
	tests := []struct {
		name   string
		blocks []http.HeaderBlock
		want   int64
	}{
		{name: "missing", want: -1},
		{
			name: "fields",
			blocks: []http.HeaderBlock{{
				Kind: http.HeaderBlockInitial,
				Fields: []http.HeaderField{
					{Name: "Host", Value: "example.test"},
					{Name: "X-Empty", Value: ""},
					{Name: "X-Repeat", Value: "one"},
					{Name: "X-Repeat", Value: "two"},
					{Name: "X-Name", Value: "中文"},
				},
			}},
			want: int64(len(
				"Host: example.test\r\n" +
					"X-Empty: \r\n" +
					"X-Repeat: one\r\n" +
					"X-Repeat: two\r\n" +
					"X-Name: 中文\r\n",
			)),
		},
		{
			name: "ignores informational and trailers",
			blocks: []http.HeaderBlock{
				{Kind: http.HeaderBlockInformational, Fields: []http.HeaderField{{Name: "Link", Value: "early"}}},
				{Kind: http.HeaderBlockInitial, Fields: []http.HeaderField{{Name: ":status", Value: "200"}}},
				{Kind: http.HeaderBlockTrailer, Fields: []http.HeaderField{{Name: "Digest", Value: "done"}}},
			},
			want: int64(len(":status: 200\r\n")),
		},
		{
			name: "truncated",
			blocks: []http.HeaderBlock{{
				Kind:      http.HeaderBlockInitial,
				Truncated: true,
				Fields:    []http.HeaderField{{Name: "Host", Value: "example.test"}},
			}},
			want: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := initialHeaderFieldsSize(tt.blocks); got != tt.want {
				t.Fatalf("initialHeaderFieldsSize() = %d; want %d", got, tt.want)
			}
		})
	}
}

func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes()
}

type closeRecorder struct {
	io.Reader
	closed bool
}

func (r *closeRecorder) Close() error {
	r.closed = true
	return nil
}

// A body whose encoding breaks part way through must still be proxied in full.
func TestBodyDecoderPassesThroughCorruptEncoding(t *testing.T) {
	payload := bytes.Repeat([]byte("abcdefgh"), 64<<10)
	corrupt := gzipBytes(t, payload)
	for i := 200; i < 400; i++ {
		corrupt[i] ^= 0xff
	}
	corrupt = append(corrupt, make([]byte, 256<<10)...)
	body, err := newBodyDecoder(io.NopCloser(bytes.NewReader(corrupt)), "gzip", CHUNK_TYPE_RSP)
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		n   int64
		err error
	}
	done := make(chan result, 1)
	go func() {
		n, err := io.Copy(io.Discard, body)
		done <- result{n, err}
	}()
	select {
	case got := <-done:
		if got.err != nil || got.n != int64(len(corrupt)) {
			t.Fatalf("proxied %d bytes, err %v; want %d bytes", got.n, got.err, len(corrupt))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("proxied body blocked behind a failed decoder")
	}
}

// Closing a body before EOF must release the decoder goroutine and the
// original body.
func TestBodyDecoderCloseBeforeEOFReleasesResources(t *testing.T) {
	compressed := gzipBytes(t, bytes.Repeat([]byte("x"), 1<<20))
	before := runtime.NumGoroutine()
	var originals []*closeRecorder
	for range 20 {
		original := &closeRecorder{Reader: bytes.NewReader(compressed)}
		originals = append(originals, original)
		body, err := newBodyDecoder(original, "gzip", CHUNK_TYPE_RSP)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := body.Read(make([]byte, 100)); err != nil {
			t.Fatal(err)
		}
		if err := body.Close(); err != nil {
			t.Fatal(err)
		}
	}
	for _, original := range originals {
		if !original.closed {
			t.Fatal("original body was not closed")
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := runtime.NumGoroutine(); got > before {
		t.Fatalf("goroutines = %d after early closes; want at most %d", got, before)
	}
}

func TestBodySizeReaderDoesNotLimitReads(t *testing.T) {
	payload := bytes.Repeat([]byte("y"), 64<<10)
	reader := newBodySizeReader(io.NopCloser(bytes.NewReader(payload)), CHUNK_TYPE_RSP).(*bodySizeReader)
	n, err := reader.Read(make([]byte, 32<<10))
	if err != nil || n != 32<<10 {
		t.Fatalf("first read = %d, %v; want %d", n, err, 32<<10)
	}
	if _, err := io.Copy(io.Discard, reader); err != nil {
		t.Fatal(err)
	}
	if reader.size != int64(len(payload)) {
		t.Fatalf("size = %d; want %d", reader.size, len(payload))
	}
}
