package main

import (
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
