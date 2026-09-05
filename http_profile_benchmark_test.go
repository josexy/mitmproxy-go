package mitmproxy

import (
	"bufio"
	"strings"
	"testing"

	http "github.com/josexy/xhttp"
)

func BenchmarkRequestWireHeaderBlocks(b *testing.B) {
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(
		"GET / HTTP/1.1\r\nHost: example.test\r\nX-A: one\r\nX-B: two\r\nX-C: three\r\n\r\n",
	)))
	if err != nil {
		b.Fatal(err)
	}
	req = ensureRequestWireProfile(req)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if blocks := RequestWireHeaderBlocks(req); len(blocks) != 1 {
			b.Fatalf("block count = %d; want 1", len(blocks))
		}
	}
}

func BenchmarkResponseWireHeaderBlocks(b *testing.B) {
	response := &http.Response{}
	source := []http.HeaderBlock{{
		Kind: http.HeaderBlockInitial,
		Fields: []http.HeaderField{
			{Name: ":status", Value: "200"},
			{Name: "x-a", Value: "one"},
			{Name: "x-b", Value: "two"},
		},
	}}
	registerResponseWireProfile(response, nil, func() []http.HeaderBlock {
		return cloneHeaderBlocks(source)
	})
	b.Cleanup(func() { unregisterResponseWireProfile(response) })
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if blocks := ResponseWireHeaderBlocks(response); len(blocks) != 1 {
			b.Fatalf("block count = %d; want 1", len(blocks))
		}
	}
}
