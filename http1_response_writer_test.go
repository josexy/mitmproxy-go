package mitmproxy

import (
	"bytes"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"

	http "github.com/josexy/xhttp"
)

func TestHTTP1ResponseWriterReordersSerializedHeaderGroups(t *testing.T) {
	wire := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Alpha: one\r\nX-Zeta: first\r\nX-Zeta: second\r\n\r\nok")
	got := reorderHTTP1ResponseHeader(wire, bytes.Index(wire, []byte("\r\n\r\n")), []string{"x-zeta", "content-length", "x-alpha"})
	text := string(got)
	zeta := strings.Index(text, "X-Zeta: first")
	length := strings.Index(text, "Content-Length: 2")
	alpha := strings.Index(text, "X-Alpha: one")
	if zeta < 0 || length < 0 || alpha < 0 || !(zeta < length && length < alpha) {
		t.Fatalf("unexpected ordered response:\n%s", text)
	}
	if !strings.HasSuffix(text, "\r\n\r\nok") {
		t.Fatalf("body or delimiter changed: %q", text)
	}
}

func TestHTTP1ResponseWriterReordersChunkedTrailersWithoutBufferingBody(t *testing.T) {
	var dst bytes.Buffer
	response := &http.Response{Trailer: http.Header{
		"X-Trailer-A": {"a"},
		"X-Trailer-B": {"b"},
	}}
	registerResponseWireProfile(response, func() http.HeaderOrder {
		return http.HeaderOrder{Trailers: []string{"x-trailer-b", "x-trailer-a"}}
	})
	defer unregisterResponseWireProfile(response)
	w := &http1ResponseWriter{dst: &dst, response: response, chunked: true}

	parts := []string{
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Trailer-A,X-Trailer-B\r\n\r\n",
		"3\r\n",
		"0\r\n", // This is body data, not the terminating chunk.
		"\r\n",
		"0\r\n",
		"X-Trailer-A: a\r\n",
		"X-Trailer-B: b\r\n\r\n",
	}
	for _, part := range parts {
		if _, err := w.Write([]byte(part)); err != nil {
			t.Fatal(err)
		}
	}
	got := dst.String()
	if !strings.Contains(got, "3\r\n0\r\n\r\n0\r\n") {
		t.Fatalf("chunked body changed: %q", got)
	}
	b := strings.LastIndex(got, "X-Trailer-B: b")
	a := strings.LastIndex(got, "X-Trailer-A: a")
	if b < 0 || a < 0 || b > a {
		t.Fatalf("unexpected trailer order: %q", got)
	}
}

func TestHTTP1ResponseWriterPreservesChunkedWireAcrossFragmentation(t *testing.T) {
	wire := []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Trailer-A,X-Trailer-B\r\n\r\n" +
		"a;source=test\r\n0123456789\r\n" +
		"0\r\nX-Trailer-A: a\r\nX-Trailer-B: b\r\n\r\n")
	want := []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Trailer-A,X-Trailer-B\r\n\r\n" +
		"a;source=test\r\n0123456789\r\n" +
		"0\r\nX-Trailer-B: b\r\nX-Trailer-A: a\r\n\r\n")
	response := &http.Response{Trailer: http.Header{
		"X-Trailer-A": {"a"},
		"X-Trailer-B": {"b"},
	}}
	registerResponseWireProfile(response, func() http.HeaderOrder {
		return http.HeaderOrder{Trailers: []string{"x-trailer-b", "x-trailer-a"}}
	})
	defer unregisterResponseWireProfile(response)

	check := func(t *testing.T, parts [][]byte) {
		t.Helper()
		var dst bytes.Buffer
		writer := &http1ResponseWriter{dst: &dst, response: response, chunked: true}
		for _, part := range parts {
			if _, err := writer.Write(part); err != nil {
				t.Fatal(err)
			}
		}
		if err := writer.flush(); err != nil {
			t.Fatal(err)
		}
		if got := dst.Bytes(); !bytes.Equal(got, want) {
			t.Fatalf("serialized response changed:\n got %q\nwant %q", got, want)
		}
	}

	t.Run("contiguous", func(t *testing.T) { check(t, [][]byte{wire}) })
	t.Run("one_byte_at_a_time", func(t *testing.T) {
		parts := make([][]byte, len(wire))
		for i := range wire {
			parts[i] = wire[i : i+1]
		}
		check(t, parts)
	})
	for split := 0; split <= len(wire); split++ {
		t.Run(fmt.Sprintf("split_%d", split), func(t *testing.T) {
			check(t, [][]byte{wire[:split], wire[split:]})
		})
	}
}

func TestParseHTTP1ChunkSize(t *testing.T) {
	tests := []struct {
		line string
		want int64
		ok   bool
	}{
		{line: "0", want: 0, ok: true},
		{line: "a", want: 10, ok: true},
		{line: "+a", want: 10, ok: true},
		{line: "-0", want: 0, ok: true},
		{line: " 10 ;source=test", want: 16, ok: true},
		{line: "7fffffffffffffff", want: int64(^uint64(0) >> 1), ok: true},
		{line: "", ok: false},
		{line: "-1", ok: false},
		{line: "g", ok: false},
		{line: "8000000000000000", ok: false},
	}
	for _, test := range tests {
		t.Run(test.line, func(t *testing.T) {
			got, err := parseHTTP1ChunkSize([]byte(test.line))
			if (err == nil) != test.ok || (err == nil && got != test.want) {
				t.Fatalf("parseHTTP1ChunkSize(%q) = %d, %v; want %d, ok=%v", test.line, got, err, test.want, test.ok)
			}
		})
	}
}

func TestReorderHTTP1ResponseHeaderPreservesGroupSemantics(t *testing.T) {
	tests := []struct {
		name  string
		wire  string
		order []string
		want  string
	}{
		{
			name:  "repeated lines stay together and stable",
			wire:  "HTTP/1.1 200 OK\r\nX-B: first\r\nX-A: one\r\nx-b: second\r\n\r\n",
			order: []string{"x-b", "x-a"},
			want:  "HTTP/1.1 200 OK\r\nX-B: first\r\nx-b: second\r\nX-A: one\r\n\r\n",
		},
		{
			name:  "unlisted names use lowercase alphabetical fallback",
			wire:  "HTTP/1.1 200 OK\r\nX-Z: z\r\nX-A: a\r\nX-B: b\r\n\r\n",
			order: []string{"x-b"},
			want:  "HTTP/1.1 200 OK\r\nX-B: b\r\nX-A: a\r\nX-Z: z\r\n\r\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wire := []byte(test.wire)
			delimiter := bytes.Index(wire, []byte("\r\n\r\n"))
			if got := string(reorderHTTP1ResponseHeader(wire, delimiter, test.order)); got != test.want {
				t.Fatalf("reordered response = %q; want %q", got, test.want)
			}
		})
	}
}

func TestHTTP1ResponseWriterCombinesNameAndOccurrenceOrder(t *testing.T) {
	response := &http.Response{
		StatusCode: 200, ProtoMajor: 1, ProtoMinor: 1,
		Header: http.Header{
			"X-Repeat": {"one", "two", ""},
			"X-Middle": {"middle"},
			"X-A":      {"updated"},
			"X-Z":      {"z"},
		},
		Body: io.NopCloser(strings.NewReader("ok")), ContentLength: 2,
	}
	if err := SetResponseHeaderOrder(response, http.HeaderOrder{Headers: []string{"x-z", "x-a", "x-repeat", "x-middle"}}); err != nil {
		t.Fatal(err)
	}
	if err := SetResponseHeaderBlock(response, http.HeaderBlock{Kind: http.HeaderBlockInitial, Fields: []http.HeaderField{
		{Name: "x-rEpEaT", Value: "two"},
		{Name: "X-Middle", Value: "middle"},
		{Name: "X-Repeat", Value: "one"},
		{Name: "content-length", Value: "999"},
		{Name: "X-A", Value: "stale"},
		{Name: "X-Deleted", Value: "gone"},
	}}); err != nil {
		t.Fatal(err)
	}
	var observed HTTPResponseSendResult
	if err := SetHTTPResponseSendObserver(response, func(result HTTPResponseSendResult) { observed = result }); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := writeHTTP1Response(&output, response); err != nil {
		t.Fatal(err)
	}
	const want = "HTTP/1.1 200 OK\r\nx-rEpEaT: two\r\nX-Middle: middle\r\nX-Repeat: one\r\ncontent-length: 2\r\nX-Z: z\r\nX-A: updated\r\nX-Repeat: \r\n\r\nok"
	if output.String() != want {
		t.Fatalf("wire = %q; want %q", output.String(), want)
	}
	wantFields := []http.HeaderField{
		{Name: "x-rEpEaT", Value: "two"}, {Name: "X-Middle", Value: "middle"},
		{Name: "X-Repeat", Value: "one"}, {Name: "content-length", Value: "2"},
		{Name: "X-Z", Value: "z"}, {Name: "X-A", Value: "updated"}, {Name: "X-Repeat", Value: ""},
	}
	if observed.Err != nil || observed.BodyBytes != 2 || !reflect.DeepEqual(observed.HeaderBlock.Fields, wantFields) {
		t.Fatalf("send observation = %+v; want fields %+v and 2 body bytes", observed, wantFields)
	}
}

func TestHTTP1ResponseWriterPreservesWhitespaceWithoutExactOverride(t *testing.T) {
	wire := []byte("HTTP/1.1 200 OK\r\nX-A:\t one \t\r\nx-B:\r\nX-A: two\r\n\r\nbody")
	got := reorderHTTP1ResponseHeader(wire, bytes.Index(wire, []byte("\r\n\r\n")), []string{"x-b", "x-a"})
	const want = "HTTP/1.1 200 OK\r\nx-B:\r\nX-A:\t one \t\r\nX-A: two\r\n\r\nbody"
	if string(got) != want {
		t.Fatalf("wire = %q; want %q", got, want)
	}
}
