package mitmproxy

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	http "github.com/josexy/xhttp"
	"github.com/josexy/xhttp/httptest"
)

func TestInterceptorResponseHeaderOrder(t *testing.T) {
	for _, protocol := range []string{"http1_depth_1", "http1_depth_2", "http2"} {
		for _, local := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/local_%t", protocol, local), func(t *testing.T) {
				gate := make(chan struct{})
				var releaseOnce sync.Once
				release := func() { releaseOnce.Do(func() { close(gate) }) }
				defer release() // Unblock the origin even if an assertion fails.
				newHeader := func() http.Header {
					return http.Header{
						"X-A": {"original"}, "X-B": {"first", "second"},
						"X-Unlisted-Z": {"z"}, "X-Unlisted-A": {"a"},
						"Trailer": {"X-End-A, X-End-B"},
					}
				}
				originHandler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					if local {
						t.Error("short-circuit response contacted the origin handler")
					}
					for name, values := range newHeader() {
						w.Header()[name] = values
					}
					if err := http.SetResponseHeaderOrder(w, http.HeaderOrder{
						Headers: []string{"x-a", "x-b"}, Trailers: []string{"x-end-a", "x-end-b"},
					}); err != nil {
						t.Error(err)
						return
					}
					_, _ = io.WriteString(w, "prefix")
					w.(http.Flusher).Flush()
					select {
					case <-gate:
					case <-req.Context().Done():
						return
					}
					w.Header().Set("X-End-A", "a")
					w.Header().Set("X-End-B", "b")
					_, _ = io.WriteString(w, "suffix")
				})
				var originURL string
				if protocol == "http2" {
					originURL = "http://" + startH2CWireOrigin(t, originHandler)
				} else {
					origin := httptest.NewServer(originHandler)
					t.Cleanup(origin.Close)
					originURL = origin.URL
				}
				interceptor := func(ctx context.Context, req *http.Request, next HTTPDelegatedInvoker) (*http.Response, error) {
					var resp *http.Response
					if local {
						reader, writer := io.Pipe()
						resp = &http.Response{
							StatusCode: 200, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
							Header: newHeader(), Body: reader, ContentLength: -1,
							TransferEncoding: []string{"chunked"},
							Trailer:          http.Header{"X-End-A": nil, "X-End-B": nil},
						}
						finished := make(chan struct{})
						t.Cleanup(func() {
							_ = reader.Close()
							receiveRegressionValue(t, finished)
						})
						go func() {
							defer close(finished)
							defer writer.Close()
							if _, err := io.WriteString(writer, "prefix"); err != nil {
								return
							}
							select {
							case <-gate:
							case <-ctx.Done():
								return
							}
							resp.Trailer.Set("X-End-A", "a")
							resp.Trailer.Set("X-End-B", "b")
							_, _ = io.WriteString(writer, "suffix")
						}()
					} else {
						var err error
						resp, err = next.Invoke(req)
						if err != nil {
							return nil, err
						}
						if order := ResponseWireHeaderOrder(resp).Headers; slices.Index(order, "x-a") < 0 || slices.Index(order, "x-b") <= slices.Index(order, "x-a") {
							t.Errorf("origin order = %v; want x-a before x-b", order)
						}
					}
					resp.Header.Set("X-A", "modified")
					resp.Header.Set("X-Interceptor", "added")
					resp.Header.Set("Connection", "X-Hop")
					resp.Header.Set("X-Hop", "removed")
					if err := SetResponseHeaderOrder(resp, http.HeaderOrder{
						Headers:  []string{":status", "X-B", "x-missing", "x-hop", "X-A", "X-Interceptor"},
						Trailers: []string{"X-End-B", "X-End-A"},
					}); err != nil {
						_ = resp.Body.Close()
						return nil, err
					}
					return resp, nil
				}

				var response *http.Response
				var err error
				if protocol == "http2" {
					ca, key, root, _ := writeTestCertificates(t, t.TempDir())
					proxyAddr, _ := startHTTP2E2EProxy(t, ca, key, root, interceptor)
					transport := newSingleUseHTTP2Transport(t, connectProxyTunnel(t, proxyAddr, strings.TrimPrefix(originURL, "http://")))
					ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
					defer cancel()
					req, reqErr := http.NewRequestWithContext(ctx, "GET", originURL+"/", nil)
					if reqErr != nil {
						t.Fatal(reqErr)
					}
					response, err = transport.RoundTrip(req)
				} else {
					depth := 1
					if protocol == "http1_depth_2" {
						depth = 2
					}
					listener := startKeepAliveProxy(t, WithHTTP1PipelineDepth(depth), WithHTTPInterceptor(interceptor))
					conn, reader := dialProxy(t, listener)
					if _, err := fmt.Fprintf(conn, "GET %s/ HTTP/1.1\r\nHost: %s\r\n\r\n", originURL, strings.TrimPrefix(originURL, "http://")); err != nil {
						t.Fatal(err)
					}
					response, err = http.ReadResponse(reader, &http.Request{Method: "GET"})
				}
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				prefix := make([]byte, len("prefix"))
				if _, err := io.ReadFull(response.Body, prefix); err != nil || string(prefix) != "prefix" {
					t.Fatalf("streaming prefix before EOF = %q, %v", prefix, err)
				}
				release()
				suffix, err := io.ReadAll(response.Body)
				if err != nil || string(suffix) != "suffix" {
					t.Fatalf("suffix = %q, %v", suffix, err)
				}
				if response.Header.Get("X-A") != "modified" || response.Header.Get("X-Hop") != "" {
					t.Fatalf("header edits/filtering lost: %v", response.Header)
				}
				if !slices.Equal(response.Header.Values("X-B"), []string{"first", "second"}) {
					t.Fatalf("repeated values = %v", response.Header.Values("X-B"))
				}
				blocks := http.ResponseHeaderBlocks(response)
				var fields []string
				for _, block := range blocks {
					if block.Kind != http.HeaderBlockInitial {
						continue
					}
					for _, field := range block.Fields {
						if name := strings.ToLower(field.Name); strings.HasPrefix(name, "x-") {
							fields = append(fields, name)
						}
					}
				}
				want := []string{"x-b", "x-b", "x-a", "x-interceptor", "x-unlisted-a", "x-unlisted-z"}
				if !slices.Equal(fields, want) {
					t.Fatalf("downstream header fields = %v; want %v", fields, want)
				}
				if trailers := headerBlockNames(blocks, http.HeaderBlockTrailer); !slices.Equal(trailers, []string{"x-end-b", "x-end-a"}) {
					t.Fatalf("downstream trailer order = %v", trailers)
				}
				if response.Trailer.Get("X-End-A") != "a" || response.Trailer.Get("X-End-B") != "b" {
					t.Fatalf("trailer values = %v", response.Trailer)
				}
			})
		}
	}
}
