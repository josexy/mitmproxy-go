package mitmproxy

import (
	"bytes"
	"io"
	"testing"

	http "github.com/josexy/xhttp"
)

var benchmarkHTTP1Bytes []byte

func BenchmarkHTTP1ResponseWriterChunkedTrailers(b *testing.B) {
	wire := []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-A,X-B\r\n\r\n" +
		"10;source=test\r\n0123456789abcdef\r\n0\r\nX-A: one\r\nX-B: two\r\n\r\n")
	response := &http.Response{Trailer: http.Header{"X-A": {"one"}, "X-B": {"two"}}}
	registerResponseWireProfile(response, func() http.HeaderOrder {
		return http.HeaderOrder{Trailers: []string{"x-b", "x-a"}}
	})
	b.Cleanup(func() { unregisterResponseWireProfile(response) })
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		writer := &http1ResponseWriter{dst: io.Discard, response: response, chunked: true}
		if _, err := writer.Write(wire); err != nil {
			b.Fatal(err)
		}
		if err := writer.flush(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReorderHTTP1ResponseHeader(b *testing.B) {
	wire := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Alpha: one\r\nX-Zeta: first\r\nX-Zeta: second\r\n\r\n")
	delimiter := bytes.Index(wire, []byte("\r\n\r\n"))
	order := []string{"x-zeta", "content-length", "x-alpha"}
	b.ReportAllocs()
	for b.Loop() {
		benchmarkHTTP1Bytes = reorderHTTP1ResponseHeader(wire, delimiter, order)
	}
}
