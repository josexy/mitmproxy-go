package mitmproxy

import (
	"bufio"
	"bytes"
	"io"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	nethttp2 "github.com/josexy/net/http2"
	http "github.com/josexy/xhttp"
)

func TestRequestWireProfilePreservesHTTP1OrderAcrossContextClone(t *testing.T) {
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(
		"GET / HTTP/1.1\r\nX-Zeta: one\r\nHost: example.test\r\nx-Alpha: two\r\nTrailer: X-Trailer-B, X-Trailer-A\r\n\r\n",
	)))
	if err != nil {
		t.Fatal(err)
	}

	req = ensureRequestWireProfile(req)
	cloned := req.WithContext(req.Context())
	profile := requestWireProfileFromRequest(cloned)
	if profile == nil {
		t.Fatal("wire profile missing after WithContext")
	}
	if got, want := profile.headerOrder, []string{"x-zeta", "host", "x-alpha", "trailer"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("header order = %v; want %v", got, want)
	}
	if got, want := profile.trailerOrder, []string{"x-trailer-b", "x-trailer-a"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("trailer order = %v; want %v", got, want)
	}
}

func TestWithRequestHeaderOrderWritesHTTP1WireOrder(t *testing.T) {
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(
		"GET http://example.test/path HTTP/1.1\r\nX-Zeta: one\r\nHost: example.test\r\nx-Alpha: two\r\n\r\n",
	)))
	if err != nil {
		t.Fatal(err)
	}
	req = ensureRequestWireProfile(req)
	req.RequestURI = ""
	req, err = withRequestHeaderOrder(req)
	if err != nil {
		t.Fatal(err)
	}

	var wire bytes.Buffer
	if err := req.Write(&wire); err != nil {
		t.Fatal(err)
	}
	header := wire.String()
	zeta := strings.Index(header, "X-Zeta: one\r\n")
	host := strings.Index(header, "Host: example.test\r\n")
	alpha := strings.Index(header, "X-Alpha: two\r\n")
	if zeta < 0 || host < 0 || alpha < 0 || !(zeta < host && host < alpha) {
		t.Fatalf("unexpected HTTP/1 header order:\n%s", header)
	}
}

func TestRequestWireProfileCopiesHTTP2Fingerprint(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.test/", nil)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := http.Fingerprint{
		Settings: []http.Setting{
			{ID: http.SettingMaxConcurrentStreams, Val: 100},
			{ID: http.SettingInitialWindowSize, Val: 6291456},
		},
		WindowUpdate: 15663105,
		Priorities: []http.FingerprintPriority{
			{StreamID: 3, StreamDep: 0, Weight: 201},
		},
		HeaderPriority:    &http.FingerprintHeaderPriority{StreamDep: 0, Exclusive: true, Weight: 101},
		PseudoHeaderOrder: []string{":method", ":authority", ":scheme", ":path"},
	}
	req, err = http.WithRequestFingerprint(req, fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	req = ensureRequestWireProfile(req)

	profile := requestWireProfileFromRequest(req.WithContext(req.Context()))
	if profile == nil || profile.fingerprint == nil {
		t.Fatal("HTTP/2 fingerprint missing from wire profile")
	}
	fingerprint.Settings[0].Val++
	fingerprint.HeaderPriority.Weight++
	fingerprint.PseudoHeaderOrder[0] = ":authority"
	if got := profile.fingerprint.Settings[0].Val; got != 100 {
		t.Fatalf("captured setting = %d; want 100", got)
	}
	if got := profile.fingerprint.PseudoHeaderOrder[0]; got != ":method" {
		t.Fatalf("captured pseudo order starts with %q; want :method", got)
	}
	if got := profile.fingerprint.HeaderPriority; got == nil || got.Weight != 101 {
		t.Fatalf("captured HEADERS priority = %#v; want weight 101", got)
	}
}

func TestConvertHTTP2FingerprintPreservesNonCanonicalHeaderPriority(t *testing.T) {
	source := http.Fingerprint{
		Settings:          []http.Setting{{ID: http.SettingHeaderTableSize, Val: 65536}},
		WindowUpdate:      15663105,
		Priorities:        []http.FingerprintPriority{{StreamID: 3, StreamDep: 0, Weight: 201}},
		HeaderPriority:    &http.FingerprintHeaderPriority{StreamDep: 0, Exclusive: true, Weight: 101},
		PseudoHeaderOrder: []string{":method", ":authority", ":scheme", ":path"},
	}
	converted := convertHTTP2Fingerprint(source)
	if got := converted.String(); got != source.String() {
		t.Fatalf("converted fingerprint string = %q; want %q", got, source.String())
	}
	wantHeaderPriority := &nethttp2.FingerprintHeaderPriority{StreamDep: 0, Exclusive: true, Weight: 101}
	if !reflect.DeepEqual(converted.HeaderPriority, wantHeaderPriority) {
		t.Fatalf("converted HEADERS priority = %#v; want %#v", converted.HeaderPriority, wantHeaderPriority)
	}
	converted.HeaderPriority.Weight++
	if source.HeaderPriority.Weight != 101 {
		t.Fatal("converted HEADERS priority shares state with source")
	}
}

func TestConvertHTTP2FingerprintDropsConnectionRelativeHeaderPriority(t *testing.T) {
	source := http.Fingerprint{
		HeaderPriority: &http.FingerprintHeaderPriority{
			StreamDep: 3,
			Exclusive: true,
			Weight:    101,
		},
		PseudoHeaderOrder: []string{":method", ":authority", ":scheme", ":path"},
	}
	converted := convertHTTP2Fingerprint(source)
	if converted.HeaderPriority != nil {
		t.Fatalf("converted HEADERS priority = %#v; want nil", converted.HeaderPriority)
	}
	if source.HeaderPriority == nil || source.HeaderPriority.StreamDep != 3 {
		t.Fatal("conversion mutated captured fingerprint metadata")
	}
}

func TestWireHeaderOrderAccessorsReturnDefensiveSnapshots(t *testing.T) {
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(
		"GET / HTTP/1.1\r\nX-Zeta: one\r\nHost: example.test\r\nX-Alpha: two\r\nTrailer: X-Trailer-B, X-Trailer-A\r\n\r\n",
	)))
	if err != nil {
		t.Fatal(err)
	}
	gotRequest := RequestWireHeaderOrder(req)
	wantRequest := http.HeaderOrder{
		Headers:  []string{"x-zeta", "host", "x-alpha", "trailer"},
		Trailers: []string{"x-trailer-b", "x-trailer-a"},
	}
	if !reflect.DeepEqual(gotRequest, wantRequest) {
		t.Fatalf("request order = %#v; want %#v", gotRequest, wantRequest)
	}
	gotRequest.Headers[0] = "mutated"
	if RequestWireHeaderOrder(req).Headers[0] != "x-zeta" {
		t.Fatal("request accessor returned shared state")
	}

	response := &http.Response{}
	source := http.HeaderOrder{Headers: []string{":status", "x-b", "x-a"}, Trailers: []string{"x-end"}}
	orderProvider := func() http.HeaderOrder {
		return http.HeaderOrder{
			Headers:  append([]string(nil), source.Headers...),
			Trailers: append([]string(nil), source.Trailers...),
		}
	}
	registerResponseWireProfile(response, orderProvider)
	defer unregisterResponseWireProfile(response)
	gotResponse := ResponseWireHeaderOrder(response)
	if !reflect.DeepEqual(gotResponse, source) {
		t.Fatalf("response order = %#v; want %#v", gotResponse, source)
	}
	gotResponse.Headers[0] = "mutated"
	if ResponseWireHeaderOrder(response).Headers[0] != ":status" {
		t.Fatal("response accessor returned shared state")
	}

	fingerprintRequest, err := http.NewRequest(http.MethodGet, "https://example.test/", nil)
	if err != nil {
		t.Fatal(err)
	}
	sourceFingerprint := http.Fingerprint{
		Settings:          []http.Setting{{ID: http.SettingHeaderTableSize, Val: 65536}},
		WindowUpdate:      15663105,
		PseudoHeaderOrder: []string{":method", ":authority", ":scheme", ":path"},
	}
	fingerprintRequest, err = http.WithRequestFingerprint(fingerprintRequest, sourceFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	fingerprintRequest = ensureRequestWireProfile(fingerprintRequest)
	gotFingerprint, ok := RequestHTTP2Fingerprint(fingerprintRequest.WithContext(fingerprintRequest.Context()))
	if !ok || !reflect.DeepEqual(gotFingerprint, sourceFingerprint) {
		t.Fatalf("fingerprint = %#v, %v; want %#v, true", gotFingerprint, ok, sourceFingerprint)
	}
	gotFingerprint.Settings[0].Val++
	secondFingerprint, _ := RequestHTTP2Fingerprint(fingerprintRequest)
	if secondFingerprint.Settings[0].Val != 65536 {
		t.Fatal("fingerprint accessor returned shared state")
	}

	clonedRequest := ensureRequestWireProfile(req)
	clonedRequest = clonedRequest.WithContext(clonedRequest.Context())
	requestBlocks := RequestWireHeaderBlocks(clonedRequest)
	if len(requestBlocks) != 1 || requestBlocks[0].Kind != http.HeaderBlockInitial {
		t.Fatalf("request blocks = %#v", requestBlocks)
	}
	requestBlocks[0].Fields[0].Name = "mutated"
	secondRequestBlocks := RequestWireHeaderBlocks(clonedRequest)
	if got := secondRequestBlocks[0].Fields[0].Name; got != "X-Zeta" {
		t.Fatalf("request blocks accessor first field = %q; want X-Zeta; blocks = %#v", got, secondRequestBlocks)
	}

	responseBlocksSource := []http.HeaderBlock{{
		Kind: http.HeaderBlockInitial,
		Fields: []http.HeaderField{
			{Name: ":status", Value: "200"},
			{Name: "x-b", Value: "two"},
		},
	}}
	registerResponseWireProfile(response, orderProvider, func() []http.HeaderBlock {
		return cloneHeaderBlocks(responseBlocksSource)
	})
	responseBlocks := ResponseWireHeaderBlocks(response)
	responseBlocks[0].Fields[0].Name = "mutated"
	if ResponseWireHeaderBlocks(response)[0].Fields[0].Name != ":status" {
		t.Fatal("response blocks accessor returned shared state")
	}
}

func TestRequestWireHeaderBlocksSurviveContextCloneAndTrackTrailers(t *testing.T) {
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(
		"POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\nTrailer: X-Trailer-B, X-Trailer-A\r\n\r\n" +
			"1\r\nx\r\n0\r\nX-Trailer-B: b\r\nX-Trailer-A: a\r\n\r\n",
	)))
	if err != nil {
		t.Fatal(err)
	}
	req = ensureRequestWireProfile(req)
	req = req.WithContext(req.Context())

	if got := RequestWireHeaderBlocks(req); len(got) != 1 || got[0].Kind != http.HeaderBlockInitial {
		t.Fatalf("initial blocks = %#v", got)
	}
	if _, err := io.ReadAll(req.Body); err != nil {
		t.Fatal(err)
	}
	blocks := RequestWireHeaderBlocks(req)
	if len(blocks) != 2 || blocks[1].Kind != http.HeaderBlockTrailer {
		t.Fatalf("completed blocks = %#v", blocks)
	}
	wantTrailers := []string{"x-trailer-b", "x-trailer-a"}
	if got := RequestWireHeaderOrder(req).Trailers; !reflect.DeepEqual(got, wantTrailers) {
		t.Fatalf("trailer order = %v; want %v", got, wantTrailers)
	}
}

func TestConvertHTTP2ResponseHeaderBlocks(t *testing.T) {
	source := []nethttp2.HeaderBlock{
		{
			Kind:      nethttp2.HeaderBlockInformational,
			Truncated: true,
			Fields: []nethttp2.HeaderField{
				{Name: ":status", Value: "103"},
				{Name: "link", Value: "</style.css>; rel=preload", Sensitive: true},
			},
		},
		{
			Kind: nethttp2.HeaderBlockInitial,
			Fields: []nethttp2.HeaderField{
				{Name: ":status", Value: "200"},
				{Name: "x-zeta", Value: "one"},
			},
		},
		{
			Kind:   nethttp2.HeaderBlockTrailer,
			Fields: []nethttp2.HeaderField{{Name: "x-end", Value: "done"}},
		},
	}
	want := []http.HeaderBlock{
		{
			Kind:       http.HeaderBlockInformational,
			ProtoMajor: 2,
			Truncated:  true,
			Fields: []http.HeaderField{
				{Name: ":status", Value: "103"},
				{Name: "link", Value: "</style.css>; rel=preload", Sensitive: true},
			},
		},
		{
			Kind:       http.HeaderBlockInitial,
			ProtoMajor: 2,
			Fields: []http.HeaderField{
				{Name: ":status", Value: "200"},
				{Name: "x-zeta", Value: "one"},
			},
		},
		{
			Kind:       http.HeaderBlockTrailer,
			ProtoMajor: 2,
			Fields:     []http.HeaderField{{Name: "x-end", Value: "done"}},
		},
	}
	if got := convertHTTP2ResponseHeaderBlocks(source); !reflect.DeepEqual(got, want) {
		t.Fatalf("converted blocks = %#v; want %#v", got, want)
	}
}

func TestResponseWireProfileRegistryDoesNotRetainResponse(t *testing.T) {
	collected := make(chan struct{}, 1)
	func() {
		response := &http.Response{Body: http.NoBody}
		runtime.AddCleanup(response, func(ch chan struct{}) {
			select {
			case ch <- struct{}{}:
			default:
			}
		}, collected)
		prepareHTTP2Response(response, nil)
		runtime.KeepAlive(response)
	}()

	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		runtime.GC()
		select {
		case <-collected:
			return
		case <-deadline.C:
			t.Fatal("registered response remained strongly reachable")
		case <-tick.C:
		}
	}
}

func TestResponseWireProfileSurvivesBodyClose(t *testing.T) {
	response := prepareHTTP2Response(&http.Response{
		Body: io.NopCloser(strings.NewReader("body")),
	}, nil)
	want := http.HeaderOrder{Headers: []string{":status", "x-test"}}
	registerResponseWireProfile(response, func() http.HeaderOrder {
		return http.HeaderOrder{Headers: append([]string(nil), want.Headers...)}
	})
	defer unregisterResponseWireProfile(response)

	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if got := ResponseWireHeaderOrder(response); !reflect.DeepEqual(got, want) {
		t.Fatalf("response order after Body.Close = %#v; want %#v", got, want)
	}
}
