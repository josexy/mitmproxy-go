package mitmproxy

import (
	"bufio"
	"io"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	http "github.com/josexy/xhttp"
)

func TestSetResponseHeaderOrderPreservesWireMetadataAndLateTrailers(t *testing.T) {
	resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(
		"HTTP/1.1 200 OK\r\nX-A: a\r\nX-B: b\r\nTransfer-Encoding: chunked\r\nTrailer: X-End-A, X-End-B\r\n\r\n"+
			"2\r\nok\r\n0\r\nX-End-B: b\r\nX-End-A: a\r\n\r\n",
	)), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	wireOrder := ResponseWireHeaderOrder(resp)
	wireBlocks := ResponseWireHeaderBlocks(resp)
	requested := http.HeaderOrder{Headers: []string{"X-B", "x-a"}, Trailers: []string{"X-End-A", "X-End-B"}}
	if err := SetResponseHeaderOrder(resp, requested); err != nil {
		t.Fatal(err)
	}
	requested.Headers[0], requested.Trailers[0] = "mutated", "mutated"
	want := http.HeaderOrder{Headers: []string{"x-b", "x-a"}, Trailers: []string{"x-end-a", "x-end-b"}}
	if got := responseHeaderOrder(resp); !reflect.DeepEqual(got, want) {
		t.Fatalf("outgoing order = %v; want %v", got, want)
	}
	copy := responseHeaderOrder(resp)
	copy.Headers[0] = "mutated"
	copy.Trailers[0] = "mutated"
	if got := responseHeaderOrder(resp); !reflect.DeepEqual(got, want) {
		t.Fatalf("outgoing order accessor exposed shared state: %v", got)
	}
	if !reflect.DeepEqual(ResponseWireHeaderOrder(resp), wireOrder) || !reflect.DeepEqual(ResponseWireHeaderBlocks(resp), wireBlocks) {
		t.Fatal("sending override changed received metadata")
	}
	// Replacing just Headers clears the old trailer override. Actual incoming
	// trailer order must still become visible later, at EOF.
	if err := SetResponseHeaderOrder(resp, http.HeaderOrder{Headers: []string{"x-b"}}); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil || string(body) != "ok" {
		t.Fatalf("body = %q, %v", body, err)
	}
	if got := responseHeaderOrder(resp); !slices.Equal(got.Headers, []string{"x-b"}) || !slices.Equal(got.Trailers, []string{"x-end-b", "x-end-a"}) {
		t.Fatalf("order after EOF = %v", got)
	}
	wireOrder.Trailers = []string{"x-end-b", "x-end-a"}
	if got := ResponseWireHeaderOrder(resp); !reflect.DeepEqual(got, wireOrder) {
		t.Fatalf("received order after EOF = %v; want %v", got, wireOrder)
	}
	if err := SetResponseHeaderOrder(resp, http.HeaderOrder{Trailers: []string{"x-end-a"}}); err != nil {
		t.Fatal(err)
	}
	if got := responseHeaderOrder(resp); !slices.Equal(got.Headers, wireOrder.Headers) || !slices.Equal(got.Trailers, []string{"x-end-a"}) {
		t.Fatalf("trailer-only override = %v", got)
	}
	if err := SetResponseHeaderOrder(resp, http.HeaderOrder{}); err != nil {
		t.Fatal(err)
	}
	if got := responseHeaderOrder(resp); !reflect.DeepEqual(got, wireOrder) {
		t.Fatalf("cleared override = %v; want %v", got, wireOrder)
	}
}

func TestSetResponseHeaderOrderRejectsInvalidWithoutChangingPriorOrder(t *testing.T) {
	if err := SetResponseHeaderOrder(nil, http.HeaderOrder{}); err == nil {
		t.Fatal("nil response accepted")
	}
	resp := &http.Response{}
	want := http.HeaderOrder{Headers: []string{":status", "x-b"}, Trailers: []string{"x-end"}}
	if err := SetResponseHeaderOrder(resp, http.HeaderOrder{Headers: []string{":STATUS", "X-B"}, Trailers: []string{"X-End"}}); err != nil {
		t.Fatal(err)
	}
	for name, order := range map[string]http.HeaderOrder{
		"empty name":        {Headers: []string{""}},
		"whitespace":        {Headers: []string{"x b"}},
		"newline":           {Headers: []string{"x-b\r\n"}},
		"non-ascii":         {Headers: []string{"x-Key"}},
		"unicode pseudo":    {Headers: []string{":ſtatus"}},
		"duplicate":         {Headers: []string{"X-B", "x-b"}},
		"request pseudo":    {Headers: []string{":method"}},
		"late pseudo":       {Headers: []string{"x-b", ":status"}},
		"trailer pseudo":    {Trailers: []string{":status"}},
		"forbidden trailer": {Trailers: []string{"Content-Length"}},
		"trailer duplicate": {Headers: []string{"x-a"}, Trailers: []string{"X-End", "x-end"}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := SetResponseHeaderOrder(resp, order); err == nil {
				t.Fatal("invalid order accepted")
			}
			if got := responseHeaderOrder(resp); !reflect.DeepEqual(got, want) {
				t.Fatalf("failed setter changed prior order: %v", got)
			}
		})
	}
}

func TestSetResponseHeaderOrderRegistryConcurrencyAndIsolation(t *testing.T) {
	resp := &http.Response{}
	other := &http.Response{}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 50 {
				if err := SetResponseHeaderOrder(resp, http.HeaderOrder{Headers: []string{"x-a"}}); err != nil {
					t.Error(err)
				}
				_ = responseHeaderOrder(resp)
				_ = ResponseWireHeaderBlocks(resp)
				if got := ResponseWireHeaderOrder(resp); len(got.Headers) != 0 {
					t.Error("outgoing order leaked into received metadata")
				}
				if err := SetResponseHeaderOrder(resp, http.HeaderOrder{}); err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
	if got := responseHeaderOrder(other); len(got.Headers) != 0 || len(got.Trailers) != 0 {
		t.Fatalf("unrelated response inherited override: %v", got)
	}
}
