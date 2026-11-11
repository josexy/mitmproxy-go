package mitmproxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	http "github.com/josexy/xhttp"
	"github.com/josexy/xhttp/httptest"
)

const overrideTestRequest = "GET http://example.test/ HTTP/1.1\r\nX-Zeta: z\r\nHost: example.test\r\nX-Mid: m\r\nX-Alpha: a\r\nAccept: */*\r\nUser-Agent: ua\r\n\r\n"

func readOverrideTestRequest(t *testing.T, raw string) *http.Request {
	t.Helper()
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatal(err)
	}
	req = ensureRequestWireProfile(req)
	req.RequestURI = ""
	return req
}

// writeOverrideTestHTTP1 prepares req like the HTTP/1 transport and returns its
// header lines.
func writeOverrideTestHTTP1(t *testing.T, req *http.Request) []string {
	t.Helper()
	prepared, err := withRequestHeaderOrder(req)
	if err != nil {
		t.Fatalf("prepare HTTP/1 request: %v", err)
	}
	var wire bytes.Buffer
	if err := prepared.Write(&wire); err != nil {
		t.Fatal(err)
	}
	head, _, _ := strings.Cut(wire.String(), "\r\n\r\n")
	return strings.Split(head, "\r\n")[1:]
}

func TestPartialRequestHeaderOrderKeepsReceivedOrder(t *testing.T) {
	req := readOverrideTestRequest(t, overrideTestRequest)
	req.Header.Set("X-Mid", "edited")
	req.Header.Set("X-New", "n")
	if got, want := writeOverrideTestHTTP1(t, req), []string{
		"X-Zeta: z", "Host: example.test", "X-Mid: edited", "X-Alpha: a", "Accept: */*", "User-Agent: ua", "X-New: n",
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("default order = %q; want %q", got, want)
	}
	req, err := WithRequestHeaderOrder(req, http.HeaderOrder{Headers: []string{"Accept", "x-alpha"}})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := writeOverrideTestHTTP1(t, req), []string{
		"Accept: */*", "X-Alpha: a", "X-Zeta: z", "Host: example.test", "X-Mid: edited", "User-Agent: ua", "X-New: n",
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("partial override = %q; want %q", got, want)
	}
}

func TestRequestHeaderOrderEmptyClearsOverride(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "http://example.test/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-B", "b")
	req.Header.Set("X-A", "a")
	if req, err = WithRequestHeaderOrder(req, http.HeaderOrder{Headers: []string{"x-b", "x-a"}}); err != nil {
		t.Fatal(err)
	}
	if req, err = WithRequestHeaderOrder(req, http.HeaderOrder{}); err != nil {
		t.Fatal(err)
	}
	req = ensureRequestWireProfile(req)
	if got, want := writeOverrideTestHTTP1(t, req), []string{"Host: example.test", "User-Agent: Go-http-client/1.1", "X-A: a", "X-B: b"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("after clearing = %q; want %q", got, want)
	}
}

func TestRequestHeaderOrderValidation(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "http://example.test/", nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, order := range map[string]http.HeaderOrder{
		"response pseudo":   {Headers: []string{":status"}},
		"late pseudo":       {Headers: []string{"x-a", ":method"}},
		"duplicate":         {Headers: []string{"X-A", "x-a"}},
		"forbidden trailer": {Trailers: []string{"Content-Length"}},
		"trailer pseudo":    {Trailers: []string{":path"}},
	} {
		if _, err := WithRequestHeaderOrder(req, order); err == nil || !strings.HasPrefix(err.Error(), "mitmproxy: invalid request ") {
			t.Errorf("%s: error = %v", name, err)
		}
	}
	if _, err := WithRequestHeaderOrder(req, http.HeaderOrder{Headers: []string{":method", ":path", "x-a"}, Trailers: []string{"x-end"}}); err != nil {
		t.Errorf("valid order rejected: %v", err)
	}
}

// Name order and an occurrence layout combine on both protocols: layout
// positions first, then the override, then the received order.
func TestRequestHeaderOrderCombinesWithHeaderBlock(t *testing.T) {
	req := readOverrideTestRequest(t, overrideTestRequest)
	req, err := WithRequestHeaderOrder(req, http.HeaderOrder{Headers: []string{"x-alpha", "accept"}})
	if err != nil {
		t.Fatal(err)
	}
	req, err = WithRequestHeaderBlock(req, http.HeaderBlock{Kind: http.HeaderBlockInitial, Fields: []http.HeaderField{{Name: "x-mid", Value: "m"}}})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := writeOverrideTestHTTP1(t, req), []string{
		"x-mid: m", "X-Alpha: a", "Accept: */*", "X-Zeta: z", "Host: example.test", "User-Agent: ua",
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("combined HTTP/1 order = %q; want %q", got, want)
	}
	if _, err := prepareHTTP2Request(req); err != nil {
		t.Fatalf("combined HTTP/2 preparation: %v", err)
	}
}

func TestRequestHeaderBlockEditedValueKeepsPosition(t *testing.T) {
	req := readOverrideTestRequest(t, "GET http://example.test/ HTTP/1.1\r\nx-zeta: z\r\nHost: example.test\r\nX-D: 1\r\nX-Mid: m\r\nX-D: 2\r\n\r\n")
	var initial http.HeaderBlock
	for _, block := range RequestWireHeaderBlocks(req) {
		if block.Kind == http.HeaderBlockInitial {
			initial = block
		}
	}
	req.Header.Set("X-Zeta", "edited")
	req.Header["X-D"] = []string{"2", "3"} // remove 1, keep 2, add 3
	req, err := WithRequestHeaderBlock(req, initial)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := writeOverrideTestHTTP1(t, req), []string{
		"x-zeta: edited", "Host: example.test", "X-D: 3", "X-Mid: m", "X-D: 2", "User-Agent: Go-http-client/1.1",
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("layout after edits = %q; want %q", got, want)
	}
}

func TestResponseHeaderBlockRemainderMatchesAcrossProtocols(t *testing.T) {
	resp := &http.Response{
		StatusCode: 200, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: http.Header{"X-A": {"a"}, "X-Y": {"y"}, "X-Z": {"z"}},
		Body:   http.NoBody, Request: &http.Request{Method: http.MethodGet},
	}
	if err := SetResponseHeaderOrder(resp, http.HeaderOrder{Headers: []string{"x-z", "x-y", "x-a"}}); err != nil {
		t.Fatal(err)
	}
	if err := SetResponseHeaderBlock(resp, http.HeaderBlock{Kind: http.HeaderBlockInitial, Fields: []http.HeaderField{{Name: "x-y", Value: "y"}}}); err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	if err := writeHTTP1Response(&wire, resp); err != nil {
		t.Fatal(err)
	}
	var http1 []string
	for _, line := range strings.Split(wire.String(), "\r\n")[1:] {
		if name, _, ok := strings.Cut(line, ":"); ok && strings.HasPrefix(strings.ToLower(name), "x-") {
			http1 = append(http1, strings.ToLower(name))
		}
	}
	block, _ := responseSendingBlock(resp, 2)
	var http2 []string
	for _, field := range block.Fields {
		if strings.HasPrefix(field.Name, "x-") {
			http2 = append(http2, field.Name)
		}
	}
	want := []string{"x-y", "x-z", "x-a"}
	if !reflect.DeepEqual(http1, want) || !reflect.DeepEqual(http2, want) {
		t.Fatalf("HTTP/1 = %v, HTTP/2 = %v; want %v for both", http1, http2, want)
	}
}

func TestHTTP1RequestTrailerOrderOverride(t *testing.T) {
	for _, override := range []bool{false, true} {
		t.Run(fmt.Sprintf("override_%t", override), func(t *testing.T) {
			observed := make(chan []string, 1)
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				var names []string
				for _, block := range http.RequestHeaderBlocks(r) {
					if block.Kind == http.HeaderBlockTrailer {
						for _, field := range block.Fields {
							names = append(names, field.Name)
						}
					}
				}
				observed <- names
			}))
			t.Cleanup(origin.Close)
			interceptor := func(ctx context.Context, req *http.Request, next HTTPDelegatedInvoker) (*http.Response, error) {
				if override {
					var err error
					if req, err = WithRequestHeaderOrder(req, http.HeaderOrder{Trailers: []string{"x-t-b", "x-t-a"}}); err != nil {
						return nil, err
					}
				}
				return next.Invoke(req)
			}
			listener := startKeepAliveProxy(t, WithHTTPInterceptor(interceptor))
			conn, reader := dialProxy(t, listener)
			host := strings.TrimPrefix(origin.URL, "http://")
			if _, err := fmt.Fprintf(conn, "POST %s/ HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: chunked\r\nTrailer: X-T-A, X-T-B\r\n\r\n4\r\nbody\r\n0\r\nX-T-A: a\r\nX-T-B: b\r\n\r\n", origin.URL, host); err != nil {
				t.Fatal(err)
			}
			resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodPost})
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			want := []string{"X-T-A", "X-T-B"}
			if override {
				want = []string{"X-T-B", "X-T-A"}
			}
			if got := receiveRegressionValue(t, observed); !reflect.DeepEqual(got, want) {
				t.Fatalf("origin trailers = %v; want %v", got, want)
			}
		})
	}
}

func TestHTTP2RequestTrailersWithHeaderOrderOverride(t *testing.T) {
	type observation struct{ initial, trailers []string }
	observed := make(chan observation, 1)
	originAddr := startH2CWireOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		var got observation
		for _, block := range http.RequestHeaderBlocks(r) {
			for _, field := range block.Fields {
				if !strings.HasPrefix(field.Name, "x-") {
					continue
				}
				if block.Kind == http.HeaderBlockTrailer {
					got.trailers = append(got.trailers, field.Name)
				} else {
					got.initial = append(got.initial, field.Name)
				}
			}
		}
		observed <- got
		_, _ = io.WriteString(w, "ok")
	}))
	ca, key, root, _ := writeTestCertificates(t, t.TempDir())
	proxyAddr, _ := startHTTP2E2EProxy(t, ca, key, root, func(ctx context.Context, req *http.Request, next HTTPDelegatedInvoker) (*http.Response, error) {
		req, err := WithRequestHeaderOrder(req, http.HeaderOrder{
			Headers:  []string{"x-second", "x-first"},
			Trailers: []string{"x-b", "x-a"},
		})
		if err != nil {
			return nil, err
		}
		return next.Invoke(req)
	})
	transport := newSingleUseHTTP2Transport(t, connectProxyTunnel(t, proxyAddr, originAddr))
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+originAddr+"/", strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-First", "1")
	req.Header.Set("X-Second", "2")
	req.Trailer = http.Header{"X-A": {"a"}, "X-B": {"b"}}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("response = %d %q, %v", resp.StatusCode, body, err)
	}
	got := receiveRegressionValue(t, observed)
	if want := []string{"x-second", "x-first"}; !reflect.DeepEqual(got.initial, want) {
		t.Errorf("initial order = %v; want %v", got.initial, want)
	}
	if want := []string{"x-b", "x-a"}; !reflect.DeepEqual(got.trailers, want) {
		t.Errorf("trailer order = %v; want %v", got.trailers, want)
	}
}

func TestInterceptorRejectsXHTTPRequestHeaderBlocks(t *testing.T) {
	var originCalls atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { originCalls.Add(1) }))
	t.Cleanup(origin.Close)
	invokeErr := make(chan error, 1)
	interceptor := func(ctx context.Context, req *http.Request, next HTTPDelegatedInvoker) (*http.Response, error) {
		req, err := http.WithRequestHeaderBlocks(req, http.HeaderBlock{Kind: http.HeaderBlockInitial, ProtoMajor: 1, Fields: []http.HeaderField{
			{Name: "Host", Value: req.Host}, {Name: "Proxy-Authorization", Value: "Basic leaked"},
		}}, nil)
		if err != nil {
			return nil, err
		}
		resp, err := next.Invoke(req)
		invokeErr <- err
		return resp, err
	}
	listener := startKeepAliveProxy(t, WithHTTPInterceptor(interceptor))
	conn, reader := dialProxy(t, listener)
	if _, err := fmt.Fprintf(conn, "GET %s/ HTTP/1.1\r\nHost: %s\r\n\r\n", origin.URL, strings.TrimPrefix(origin.URL, "http://")); err != nil {
		t.Fatal(err)
	}
	if resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet}); err == nil {
		_ = resp.Body.Close()
	}
	if err := receiveRegressionValue(t, invokeErr); !errors.Is(err, errXHTTPRequestHeaderBlocks) {
		t.Fatalf("invoke error = %v; want errXHTTPRequestHeaderBlocks", err)
	}
	if got := originCalls.Load(); got != 0 {
		t.Fatalf("origin calls = %d; want 0", got)
	}
}

// The observer reports the block actually written, with or without overrides.
func TestHTTPRequestSendHeaderObserverReportsWrittenBlock(t *testing.T) {
	for _, protocol := range []string{"http1", "http2"} {
		for _, layout := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/layout_%t", protocol, layout), func(t *testing.T) {
				received := make(chan []http.HeaderField, 1)
				handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					for _, block := range http.RequestHeaderBlocks(r) {
						if block.Kind == http.HeaderBlockInitial {
							received <- block.Fields
						}
					}
				})
				reports := make(chan http.HeaderBlock, 4)
				interceptor := func(ctx context.Context, req *http.Request, next HTTPDelegatedInvoker) (*http.Response, error) {
					req.Header.Set("X-Added", "1")
					if layout {
						var err error
						req, err = WithRequestHeaderBlock(req, http.HeaderBlock{Kind: http.HeaderBlockInitial, Fields: []http.HeaderField{
							{Name: "x-added", Value: "1", Sensitive: protocol == "http2"},
						}})
						if err != nil {
							return nil, err
						}
					}
					req = WithHTTPRequestSendHeaderObserver(req, func(block http.HeaderBlock) { reports <- block })
					return next.Invoke(req)
				}
				var resp *http.Response
				var err error
				wantProto := 1
				if protocol == "http2" {
					wantProto = 2
					originAddr := startH2CWireOrigin(t, handler)
					ca, key, root, _ := writeTestCertificates(t, t.TempDir())
					proxyAddr, _ := startHTTP2E2EProxy(t, ca, key, root, interceptor)
					transport := newSingleUseHTTP2Transport(t, connectProxyTunnel(t, proxyAddr, originAddr))
					req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+originAddr+"/", nil)
					req.Header.Set("X-Client", "c")
					resp, err = transport.RoundTrip(req)
				} else {
					origin := httptest.NewServer(handler)
					t.Cleanup(origin.Close)
					listener := startKeepAliveProxy(t, WithHTTPInterceptor(interceptor))
					conn, reader := dialProxy(t, listener)
					_, _ = fmt.Fprintf(conn, "GET %s/ HTTP/1.1\r\nX-Client: c\r\nHost: %s\r\n\r\n", origin.URL, strings.TrimPrefix(origin.URL, "http://"))
					resp, err = http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
				}
				if err != nil {
					t.Fatal(err)
				}
				_ = resp.Body.Close()
				wire := receiveRegressionValue(t, received)
				report := receiveRegressionValue(t, reports)
				if report.Kind != http.HeaderBlockInitial || report.ProtoMajor != wantProto {
					t.Fatalf("report kind/proto = %d/%d", report.Kind, report.ProtoMajor)
				}
				if len(report.Fields) != len(wire) {
					t.Fatalf("report = %+v; origin received %+v", report.Fields, wire)
				}
				for i := range wire {
					got, want := report.Fields[i], wire[i]
					if got.Name != want.Name || got.Value != want.Value {
						t.Fatalf("report = %+v; origin received %+v", report.Fields, wire)
					}
					if got.Name == "x-added" && got.Sensitive != (layout && protocol == "http2") {
						t.Fatalf("x-added Sensitive = %t", got.Sensitive)
					}
				}
				select {
				case extra := <-reports:
					t.Fatalf("unexpected extra report: %+v", extra)
				default:
				}
			})
		}
	}
}
