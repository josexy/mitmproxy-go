package mitmproxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	http "github.com/josexy/xhttp"
	"github.com/josexy/xhttp/httptest"
)

func rewriteTestBlock() http.HeaderBlock {
	return http.HeaderBlock{Kind: http.HeaderBlockInitial, Fields: []http.HeaderField{
		{Name: "X-Mix", Value: "first"}, {Name: "x-Between", Value: ""}, {Name: "x-mix", Value: "last"}, {Name: "X-Hop", Value: "removed"},
	}}
}
func rewriteTestHeader() http.Header {
	return http.Header{"X-Mix": {"first", "last"}, "X-Between": {""}, "Connection": {"X-Hop"}, "X-Hop": {"removed"}}
}
func rewriteTestFields(blocks []http.HeaderBlock) []string {
	var fields []string
	for _, block := range blocks {
		if block.Kind == http.HeaderBlockInitial {
			for _, field := range block.Fields {
				if strings.HasPrefix(strings.ToLower(field.Name), "x-") {
					fields = append(fields, strings.ToLower(field.Name)+"="+field.Value)
				}
			}
		}
	}
	return fields
}
func TestHTTPRewriteTargetAndExactFields(t *testing.T) {
	for _, protocol := range []string{"http1", "pipeline", "http2"} {
		t.Run(protocol, func(t *testing.T) {
			var originalRequests atomic.Int32
			originalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { originalRequests.Add(1); w.WriteHeader(500) })
			observed := make(chan *http.Request, 1)
			fields := make(chan []string, 1)
			targetHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				observed <- r
				fields <- rewriteTestFields(http.RequestHeaderBlocks(r))
				w.Header().Set("X-Origin", "actual")
				_, _ = io.WriteString(w, "rewritten target")
			})
			var originalURL, targetURL string
			if protocol == "http2" {
				originalURL = "http://" + startH2CWireOrigin(t, originalHandler)
				targetURL = "http://" + startH2CWireOrigin(t, targetHandler)
			} else {
				a, b := httptest.NewServer(originalHandler), httptest.NewServer(targetHandler)
				t.Cleanup(a.Close)
				t.Cleanup(b.Close)
				originalURL, targetURL = a.URL, b.URL
			}
			target, _ := url.Parse(targetURL)
			sends := make(chan HTTPResponseSendResult, 1)
			interceptor := func(ctx context.Context, req *http.Request, next HTTPDelegatedInvoker) (*http.Response, error) {
				before := RequestWireHeaderBlocks(req)
				req.Header = rewriteTestHeader()
				req.Host = "preserved.example:321"
				var err error
				req, err = WithRequestHeaderBlock(req, rewriteTestBlock())
				if err != nil {
					return nil, err
				}
				req, err = WithHTTPUpstreamTarget(req, target)
				if err != nil {
					return nil, err
				}
				if !reflect.DeepEqual(before, RequestWireHeaderBlocks(req)) {
					t.Error("received request metadata changed")
				}
				resp, err := next.Invoke(req)
				if err != nil {
					t.Errorf("rewrite invoke: %v", err)
					return nil, err
				}
				raw := ResponseWireHeaderBlocks(resp)
				resp.Header = rewriteTestHeader()
				if err = SetResponseHeaderBlock(resp, rewriteTestBlock()); err != nil {
					return nil, err
				}
				if !reflect.DeepEqual(raw, ResponseWireHeaderBlocks(resp)) {
					t.Error("received response metadata changed")
				}
				_ = SetHTTPResponseSendObserver(resp, func(result HTTPResponseSendResult) {
					if result.Err != nil {
						t.Errorf("send failed: %v", result.Err)
					}
					sends <- result
				})
				return resp, nil
			}
			var resp *http.Response
			var err error
			if protocol == "http2" {
				ca, key, root, _ := writeTestCertificates(t, t.TempDir())
				addr, _ := startHTTP2E2EProxy(t, ca, key, root, interceptor)
				client := newSingleUseHTTP2Transport(t, connectProxyTunnel(t, addr, strings.TrimPrefix(originalURL, "http://")))
				req, _ := http.NewRequestWithContext(t.Context(), "GET", originalURL+"/path?q=kept", nil)
				resp, err = client.RoundTrip(req)
			} else {
				depth := 1
				if protocol == "pipeline" {
					depth = 2
				}
				listener := startKeepAliveProxy(t, WithHTTP1PipelineDepth(depth), WithHTTPInterceptor(interceptor))
				conn, reader := dialProxy(t, listener)
				_, _ = fmt.Fprintf(conn, "GET %s/path?q=kept HTTP/1.1\r\nHost: %s\r\n\r\n", originalURL, strings.TrimPrefix(originalURL, "http://"))
				resp, err = http.ReadResponse(reader, &http.Request{Method: "GET"})
			}
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil || string(body) != "rewritten target" {
				t.Fatalf("body = %q, %v", body, err)
			}
			got := receiveRegressionValue(t, observed)
			if got.Host != "preserved.example:321" || got.URL.RequestURI() != "/path?q=kept" {
				t.Fatalf("request host/path = %q %q", got.Host, got.URL.RequestURI())
			}
			want := []string{"x-mix=first", "x-between=", "x-mix=last"}
			if got := receiveRegressionValue(t, fields); !reflect.DeepEqual(got, want) {
				t.Fatalf("request fields = %v", got)
			}
			if got := rewriteTestFields(http.ResponseHeaderBlocks(resp)); !reflect.DeepEqual(got, want) {
				t.Fatalf("response fields = %v", got)
			}
			if originalRequests.Load() != 0 {
				t.Fatal("original origin received rewritten request")
			}
			sent := receiveRegressionValue(t, sends)
			if sent.Err != nil || sent.Canceled || sent.BodyBytes != int64(len(body)) || sent.StartedAt.IsZero() || sent.EndedAt.Before(sent.StartedAt) {
				t.Fatalf("send result = %+v", sent)
			}
		})
	}
}

func TestHTTPDropNoFinalResponse(t *testing.T) {
	for _, depth := range []int{1, 2} {
		t.Run(fmt.Sprint(depth), func(t *testing.T) {
			var requests atomic.Int32
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(204) }))
			defer origin.Close()
			listener := startKeepAliveProxy(t, WithHTTP1PipelineDepth(depth), WithHTTPInterceptor(func(context.Context, *http.Request, HTTPDelegatedInvoker) (*http.Response, error) {
				return nil, fmt.Errorf("rule dropped: %w", ErrDropHTTP)
			}))
			conn, reader := dialProxy(t, listener)
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			_, _ = fmt.Fprintf(conn, "GET %s/ HTTP/1.1\r\nHost: %s\r\n\r\n", origin.URL, strings.TrimPrefix(origin.URL, "http://"))
			response, err := http.ReadResponse(reader, nil)
			if response != nil || err == nil {
				t.Fatalf("drop returned final response: %#v, %v", response, err)
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				t.Fatal("drop did not close connection")
			}
			if requests.Load() != 0 {
				t.Fatal("dropped request reached origin")
			}
		})
	}
}

func TestHTTPAbortRequestReadStopsPipeline(t *testing.T) {
	for _, depth := range []int{1, 2} {
		t.Run(fmt.Sprint(depth), func(t *testing.T) {
			origin := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Error("aborted request reached upstream")
			}))
			defer origin.Close()
			readExited := make(chan struct{})
			listener := startKeepAliveProxy(t, WithHTTP1PipelineDepth(depth), WithHTTPInterceptor(func(ctx context.Context, req *http.Request, _ HTTPDelegatedInvoker) (*http.Response, error) {
				ctx, cancel := context.WithTimeout(ctx, 25*time.Millisecond)
				defer cancel()
				abortDone := make(chan struct{})
				stop := context.AfterFunc(ctx, func() {
					defer close(abortDone)
					_ = AbortHTTPRequestRead(req, ctx.Err())
					_ = req.Body.Close()
				})
				defer func() {
					if !stop() {
						<-abortDone
					}
				}()
				_, err := io.Copy(io.Discard, req.Body)
				close(readExited)
				if err == nil {
					t.Error("incomplete upload unexpectedly reached EOF")
				}
				return nil, ErrDropHTTP
			}))
			conn, reader := dialProxy(t, listener)
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			_, _ = fmt.Fprintf(conn, "POST %s/ HTTP/1.1\r\nHost: %s\r\nContent-Length: 100\r\n\r\nx", origin.URL, strings.TrimPrefix(origin.URL, "http://"))
			data, err := io.ReadAll(reader)
			if len(data) != 0 {
				t.Fatalf("aborted request returned a response: %q", data)
			}
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				t.Fatal("body abort did not release the connection")
			}
			receiveRegressionValue(t, readExited)
		})
	}
}

func TestHTTP2DropPreservesSiblingStream(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	var dropped atomic.Int32
	origin := startH2CWireOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/drop" {
			dropped.Add(1)
		}
		if r.URL.Path == "/slow" {
			close(started)
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		_, _ = io.WriteString(w, "alive")
	}))
	ca, key, root, _ := writeTestCertificates(t, t.TempDir())
	proxy, _ := startHTTP2E2EProxy(t, ca, key, root, func(ctx context.Context, req *http.Request, next HTTPDelegatedInvoker) (*http.Response, error) {
		if req.URL.Path == "/drop" {
			return nil, fmt.Errorf("drop: %w", ErrDropHTTP)
		}
		return next.Invoke(req)
	})
	client := newSingleUseHTTP2Transport(t, connectProxyTunnel(t, proxy, origin))
	done := make(chan error, 1)
	go func() {
		req, _ := http.NewRequestWithContext(t.Context(), "GET", "http://"+origin+"/slow", nil)
		resp, err := client.RoundTrip(req)
		if err == nil {
			_, err = io.ReadAll(resp.Body)
			_ = resp.Body.Close()
		}
		done <- err
	}()
	receiveRegressionValue(t, started)
	req, _ := http.NewRequestWithContext(t.Context(), "GET", "http://"+origin+"/drop", nil)
	resp, err := client.RoundTrip(req)
	if resp != nil || err == nil {
		t.Fatalf("dropped stream returned response: %v, %v", resp, err)
	}
	// A third request verifies reuse while the original sibling is still active.
	req, _ = http.NewRequestWithContext(t.Context(), "GET", "http://"+origin+"/alive", nil)
	resp, err = client.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil || string(body) != "alive" || dropped.Load() != 0 {
		t.Fatalf("sibling/drop = %q %v %d", body, err, dropped.Load())
	}
	// Canceling the slow request during test cleanup is also stream-local.
	client.Close()
	_ = receiveRegressionValue(t, done)
}

func TestHTTP1SendObserverCountsPartialEntityWrites(t *testing.T) {
	for _, chunked := range []bool{false, true} {
		t.Run(fmt.Sprint(chunked), func(t *testing.T) {
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			response := &http.Response{StatusCode: 200, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("abcdefgh")), ContentLength: 8}
			if chunked {
				response.ContentLength = -1
				response.TransferEncoding = []string{"chunked"}
			}
			observed := make(chan HTTPResponseSendResult, 1)
			_ = SetHTTPResponseSendObserver(response, func(result HTTPResponseSendResult) { observed <- result })
			done := make(chan error, 1)
			go func() { done <- writeHTTP1Response(left, response) }()
			// Read the head then exactly three entity bytes before closing the peer.
			var prefix []byte
			one := make([]byte, 1)
			for !strings.HasSuffix(string(prefix), "\r\n\r\n") {
				if _, err := io.ReadFull(right, one); err != nil {
					t.Fatal(err)
				}
				prefix = append(prefix, one[0])
			}
			if chunked {
				for {
					if _, err := io.ReadFull(right, one); err != nil {
						t.Fatal(err)
					}
					if one[0] == '\n' {
						break
					}
				}
			}
			if _, err := io.ReadFull(right, make([]byte, 3)); err != nil {
				t.Fatal(err)
			}
			_ = right.Close()
			if err := receiveRegressionValue(t, done); err == nil {
				t.Fatal("expected downstream write failure")
			}
			got := receiveRegressionValue(t, observed)
			if got.Err == nil || got.BodyBytes != 3 || got.StartedAt.IsZero() || got.EndedAt.IsZero() {
				t.Fatalf("send = %+v", got)
			}
		})
	}
}

func TestHTTP1PipelineBodyCancellation(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	pipeline := newHTTP1PipelineConn(left, 1, time.Minute)
	defer pipeline.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	req := newPipelineTestRequest("/").WithContext(ctx)
	go func() {
		buffer := make([]byte, 1024)
		_, _ = right.Read(buffer)
		_, _ = io.WriteString(right, "HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n")
	}()
	response, err := pipeline.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := io.ReadAll(response.Body); done <- err }()
	cancel()
	if err := receiveRegressionValue(t, done); err == nil {
		t.Fatal("canceled body read unexpectedly completed")
	}
	if err := pipeline.Err(); !errors.Is(err, context.Canceled) {
		t.Fatalf("pipeline error = %v", err)
	}
	_ = response.Body.Close()
}

func TestHTTP2ResponseSendObserverCancellation(t *testing.T) {
	origin := startH2CWireOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	ca, key, root, _ := writeTestCertificates(t, t.TempDir())
	observed := make(chan HTTPResponseSendResult, 1)
	proxy, _ := startHTTP2E2EProxy(t, ca, key, root, func(ctx context.Context, req *http.Request, next HTTPDelegatedInvoker) (*http.Response, error) {
		body := "alive"
		if req.URL.Path == "/large" {
			body = strings.Repeat("x", 8<<20)
		}
		response := &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body))}
		if req.URL.Path == "/large" {
			_ = SetHTTPResponseSendObserver(response, func(result HTTPResponseSendResult) { observed <- result })
		}
		return response, nil
	})
	client := newSingleUseHTTP2Transport(t, connectProxyTunnel(t, proxy, origin))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://"+origin+"/large", nil)
	response, err := client.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(response.Body, make([]byte, 512)); err != nil {
		t.Fatal(err)
	}
	cancel()
	_ = response.Body.Close()
	got := receiveRegressionValue(t, observed)
	if got.Err == nil || !got.Canceled || got.BodyBytes >= 8<<20 || got.StartedAt.IsZero() || got.EndedAt.IsZero() {
		t.Fatalf("canceled send = %+v", got)
	}
	req, _ = http.NewRequestWithContext(t.Context(), "GET", "http://"+origin+"/alive", nil)
	response, err = client.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || string(body) != "alive" {
		t.Fatalf("sibling = %q %v", body, err)
	}
}

func TestHTTPRewriteTLSUsesConfiguredProxyAndTrust(t *testing.T) {
	_, _, root, key := writeTestCertificates(t, t.TempDir())
	certificate, err := tls.LoadX509KeyPair(root, key)
	if err != nil {
		t.Fatal(err)
	}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("original origin received request") }))
	t.Cleanup(origin.Close)
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "kept.example" {
			t.Errorf("Host = %q", r.Host)
		}
		_, _ = io.WriteString(w, "secure")
	}))
	target.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}}
	target.StartTLS()
	t.Cleanup(target.Close)
	connections := make(chan string, 4)
	upstreamProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodConnect {
			t.Errorf("upstream proxy method = %s", req.Method)
			w.WriteHeader(400)
			return
		}
		remote, err := net.Dial("tcp", req.Host)
		if err != nil {
			w.WriteHeader(502)
			return
		}
		defer remote.Close()
		local, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer local.Close()
		connections <- req.Host
		_, _ = io.WriteString(local, "HTTP/1.1 200 Connection Established\r\n\r\n")
		go func() { _, _ = io.Copy(remote, local) }()
		_, _ = io.Copy(local, remote)
	}))
	t.Cleanup(upstreamProxy.Close)
	targetURL, _ := url.Parse(target.URL)
	listener := startKeepAliveProxy(t, WithRootCAs(root), WithProxy(upstreamProxy.URL), WithHTTPInterceptor(func(ctx context.Context, req *http.Request, next HTTPDelegatedInvoker) (*http.Response, error) {
		req.Host = "kept.example"
		req, err := WithHTTPUpstreamTarget(req, targetURL)
		if err != nil {
			return nil, err
		}
		return next.Invoke(req)
	}))
	conn, reader := dialProxy(t, listener)
	_, _ = fmt.Fprintf(conn, "GET %s/ HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", origin.URL, strings.TrimPrefix(origin.URL, "http://"))
	response, body := readProxyResponse(t, reader, "GET")
	if response.StatusCode != 200 || body != "secure" {
		t.Fatalf("TLS rewrite = %d %q", response.StatusCode, body)
	}
	seen := map[string]bool{}
	seen[receiveRegressionValue(t, connections)] = true
	seen[receiveRegressionValue(t, connections)] = true
	if !seen[strings.TrimPrefix(origin.URL, "http://")] || !seen[strings.TrimPrefix(target.URL, "https://")] {
		t.Fatalf("CONNECT destinations = %v", seen)
	}
}

func TestHTTPDropAfterInvokeClosesUpstreamBody(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan struct{})
	origin := startH2CWireOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = io.WriteString(w, "prefix")
		w.(http.Flusher).Flush()
		close(started)
		<-req.Context().Done()
		close(canceled)
	}))
	ca, key, root, _ := writeTestCertificates(t, t.TempDir())
	proxy, _ := startHTTP2E2EProxy(t, ca, key, root, func(ctx context.Context, req *http.Request, next HTTPDelegatedInvoker) (*http.Response, error) {
		_, err := next.Invoke(req)
		if err != nil {
			return nil, err
		}
		return nil, ErrDropHTTP
	})
	client := newSingleUseHTTP2Transport(t, connectProxyTunnel(t, proxy, origin))
	req, _ := http.NewRequestWithContext(t.Context(), "GET", "http://"+origin+"/", nil)
	response, err := client.RoundTrip(req)
	if response != nil || err == nil {
		t.Fatalf("response drop = %v %v", response, err)
	}
	receiveRegressionValue(t, started)
	receiveRegressionValue(t, canceled)
}

func TestHTTPExactResponseHeaderBoundFailsBeforeSending(t *testing.T) {
	response := &http.Response{StatusCode: 200, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1, Header: http.Header{"X-Large": {strings.Repeat("x", maxBufferedResponseHeaderBytes)}}, Body: http.NoBody, ContentLength: 0}
	if err := SetResponseHeaderBlock(response, http.HeaderBlock{Kind: http.HeaderBlockInitial}); err != nil {
		t.Fatal(err)
	}
	var output strings.Builder
	if err := writeHTTP1Response(&output, response); err == nil {
		t.Fatal("expected oversized exact head to fail")
	}
	if output.Len() != 0 {
		t.Fatalf("wrote %d bytes before failure", output.Len())
	}
}

func TestExactSendingBlockSanitizesNoncanonicalHeaderKeys(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://localhost/", nil)
	req.Header = http.Header{"connection": {"x-hop"}, "x-hop": {"secret"}, "user-agent": {""}, "X-A": {"one", "two"}, "Content-Length": {"999"}}
	block := http.HeaderBlock{Kind: http.HeaderBlockInitial, Fields: []http.HeaderField{{Name: "x-hop", Value: "secret"}, {Name: "User-Agent", Value: ""}}}
	req, err := WithRequestHeaderBlock(req, block)
	if err != nil {
		t.Fatal(err)
	}
	removeHopByHopRequestHeaders(req.Header)
	req, err = withExactRequestHeaderBlock(req, 1)
	if err != nil {
		t.Fatal(err)
	}
	var output strings.Builder
	if err := req.Write(&output); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "secret") || strings.Contains(output.String(), "999") || strings.Contains(output.String(), "Go-http-client") {
		t.Fatalf("unsanitized output: %q", output.String())
	}
}

func TestRewriteHTTP2ToTLSWithoutALPN(t *testing.T) {
	ca, caKey, root, key := writeTestCertificates(t, t.TempDir())
	certificate, err := tls.LoadX509KeyPair(root, key)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { _, _ = io.WriteString(w, "ok") })}
	go server.Serve(tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{certificate}}))
	t.Cleanup(func() { _ = server.Close() })
	original := startH2CWireOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { t.Error("reached original") }))
	target, _ := url.Parse("https://" + listener.Addr().String())
	proxy, _ := startHTTP2E2EProxy(t, ca, caKey, root, func(ctx context.Context, req *http.Request, next HTTPDelegatedInvoker) (*http.Response, error) {
		req, err := WithHTTPUpstreamTarget(req, target)
		if err != nil {
			return nil, err
		}
		return next.Invoke(req)
	})
	client := newSingleUseHTTP2Transport(t, connectProxyTunnel(t, proxy, original))
	req, _ := http.NewRequestWithContext(t.Context(), "GET", "http://"+original+"/", nil)
	resp, err := client.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil || resp.StatusCode != 200 || string(body) != "ok" {
		t.Fatalf("response = %d %q %v", resp.StatusCode, body, err)
	}
}

func TestExactRequestChunkedKnownLength(t *testing.T) {
	req, _ := http.NewRequest("POST", "http://localhost/", strings.NewReader("body"))
	req.TransferEncoding = []string{"chunked"}
	req.Trailer = http.Header{"X-Trailer": {"done"}}
	var before strings.Builder
	if err := req.Write(&before); err != nil {
		t.Fatal("baseline:", err)
	}
	req, _ = http.NewRequest("POST", "http://localhost/", strings.NewReader("body"))
	req.TransferEncoding = []string{"chunked"}
	req.Trailer = http.Header{"X-Trailer": {"done"}}
	req, err := WithRequestHeaderBlock(req, http.HeaderBlock{Kind: http.HeaderBlockInitial})
	if err != nil {
		t.Fatal(err)
	}
	req, err = withExactRequestHeaderBlock(req, 1)
	if err != nil {
		t.Fatal(err)
	}
	var after strings.Builder
	if err := req.Write(&after); err != nil {
		t.Fatal("with exact override:", err)
	}
}
