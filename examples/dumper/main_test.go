package main

import (
	"testing"

	http "github.com/josexy/xhttp"
)

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
