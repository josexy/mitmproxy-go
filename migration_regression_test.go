package mitmproxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/josexy/websocket"
	http "github.com/josexy/xhttp"
	"github.com/josexy/xhttp/httptest"
)

func TestWebsocketProxyWritesSanitizedHandshakeBlocks(t *testing.T) {
	originErrors := make(chan error, 1)
	upgrader := websocket.Upgrader{ResponseHeaderOrder: http.HeaderOrder{
		Headers: []string{"x-b", "connection", "upgrade", "x-hop", "x-a", "sec-websocket-accept"},
	}}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		conn, err := upgrader.Upgrade(w, req, http.Header{
			"Connection": {"Upgrade, X-Hop"}, "X-Hop": {"secret"},
			"Proxy-Authenticate": {"secret"}, "Proxy-Agent": {"secret"},
			"Keep-Alive": {"timeout=60"}, "X-B": {"b"}, "X-A": {"a"},
		})
		if err != nil {
			originErrors <- err
			return
		}
		defer conn.Close()
		kind, data, err := conn.ReadMessage()
		if err == nil {
			err = conn.WriteMessage(kind, data)
		}
		originErrors <- err
	}))
	defer origin.Close()
	listener := startKeepAliveProxy(t)
	proxyURL, _ := url.Parse("http://" + listener.Addr().String())
	dialer := websocket.Dialer{Proxy: http.ProxyURL(proxyURL), HandshakeTimeout: 3 * time.Second}
	client, response, err := dialer.Dial("ws"+strings.TrimPrefix(origin.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	for _, name := range []string{"X-Hop", "Proxy-Authenticate", "Proxy-Agent", "Keep-Alive"} {
		if response.Header.Get(name) != "" {
			t.Errorf("unsanitized response header %s = %q", name, response.Header.Get(name))
		}
	}
	if got := response.Header.Get("Connection"); got != "Upgrade" {
		t.Errorf("Connection = %q; want Upgrade", got)
	}
	names := headerBlockNames(http.ResponseHeaderBlocks(response), http.HeaderBlockInitial)
	if slices.Index(names, "x-b") < 0 || slices.Index(names, "x-b") >= slices.Index(names, "x-a") {
		t.Errorf("handshake order = %v; want x-b before x-a", names)
	}
	if err := client.WriteMessage(websocket.TextMessage, []byte("echo")); err != nil {
		t.Fatal(err)
	}
	_, data, err := client.ReadMessage()
	if err != nil || string(data) != "echo" {
		t.Fatalf("upgraded echo = %q, %v", data, err)
	}
	if err := receiveRegressionValue(t, originErrors); err != nil {
		t.Fatal(err)
	}
}

func headerBlockNames(blocks []http.HeaderBlock, kind http.HeaderBlockKind) []string {
	for _, block := range blocks {
		if block.Kind == kind {
			return uniqueHeaderNames(block.Fields, true)
		}
	}
	return nil
}

func receiveRegressionValue[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for regression test observation")
		var zero T
		return zero
	}
}

func TestHTTP1ProxyForwardsLateTrailerOrder(t *testing.T) {
	for _, depth := range []int{1, 2} {
		t.Run(fmt.Sprintf("pipeline_depth_%d", depth), func(t *testing.T) {
			bodyStarted := make(chan struct{}, 1)
			originObserved := make(chan []http.HeaderBlock, 1)
			interceptorObserved := make(chan []http.HeaderBlock, 1)
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				prefix := make([]byte, 7)
				_, err := io.ReadFull(req.Body, prefix)
				bodyStarted <- struct{}{}
				if err == nil {
					_, err = io.Copy(io.Discard, req.Body)
				}
				if err != nil || string(prefix) != "payload" {
					t.Errorf("upstream body = %q, %v", prefix, err)
				}
				if req.Header.Get("X-Remove") != "" || req.Header.Get("X-Edit") != "modified" {
					t.Errorf("outgoing headers = %v", req.Header)
				}
				originObserved <- http.RequestHeaderBlocks(req)
				_, _ = io.WriteString(w, "ok")
			}))
			defer origin.Close()
			listener := startKeepAliveProxy(t, WithHTTP1PipelineDepth(depth), WithHTTPInterceptor(
				func(ctx context.Context, req *http.Request, next HTTPDelegatedInvoker) (*http.Response, error) {
					req = req.WithContext(ctx)
					req.Header.Set("X-Edit", "modified")
					resp, err := next.Invoke(req)
					interceptorObserved <- RequestWireHeaderBlocks(req)
					return resp, err
				},
			))
			conn, reader := dialProxy(t, listener)
			// Exercise the initial Hijack parser and subsequent keep-alive parser,
			// including valid partial/absent trailers (not all declarations must occur).
			for index, trailers := range []string{"X-B: b\r\nX-A: a\r\n", "X-B: b\r\n", ""} {
				_, err := fmt.Fprintf(conn, "POST %s/%d HTTP/1.1\r\nHost: %s\r\nConnection: X-Remove\r\nX-Remove: secret\r\nX-Edit: original\r\nTransfer-Encoding: chunked\r\nTrailer: X-A, X-B\r\n\r\n7\r\npayload\r\n", origin.URL, index, strings.TrimPrefix(origin.URL, "http://"))
				if err != nil {
					t.Fatal(err)
				}
				receiveRegressionValue(t, bodyStarted) // Must arrive before client EOF.
				if _, err := io.WriteString(conn, "0\r\n"+trailers+"\r\n"); err != nil {
					t.Fatal(err)
				}
				response, body := readProxyResponse(t, reader, http.MethodPost)
				if response.StatusCode != 200 || body != "ok" {
					t.Fatalf("response = %d, %q", response.StatusCode, body)
				}
				var want []string
				if index < 2 {
					want = append(want, "x-b")
				}
				if index == 0 {
					want = append(want, "x-a")
				}
				for name, blocks := range map[string][]http.HeaderBlock{
					"origin":      receiveRegressionValue(t, originObserved),
					"interceptor": receiveRegressionValue(t, interceptorObserved),
				} {
					if got := headerBlockNames(blocks, http.HeaderBlockTrailer); !slices.Equal(got, want) {
						t.Errorf("request %d %s trailer order = %v; want %v", index, name, got, want)
					}
					if name == "interceptor" && !slices.Contains(headerBlockNames(blocks, http.HeaderBlockInitial), "x-remove") {
						t.Error("interceptor lost original inbound initial headers")
					}
				}
			}
		})
	}
}

func TestHTTP2ProxyForwardsLateTrailerOrder(t *testing.T) {
	for _, length := range []int64{-1, 8} {
		t.Run(fmt.Sprintf("content_length_%d", length), func(t *testing.T) {
			caCert, caKey, serverCert, _ := writeTestCertificates(t, t.TempDir())
			bodyStarted := make(chan struct{}, 1)
			originObserved := make(chan []http.HeaderBlock, 1)
			interceptorObserved := make(chan []http.HeaderBlock, 1)
			fingerprint := testHTTP2E2EFingerprint(t)
			originAddr := startH2CWireOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				prefix := make([]byte, 7)
				_, err := io.ReadFull(req.Body, prefix)
				bodyStarted <- struct{}{}
				if err == nil {
					_, err = io.Copy(io.Discard, req.Body)
				}
				if err != nil || string(prefix) != "payload" {
					t.Errorf("body = %q, %v", prefix, err)
				}
				if req.Header.Get("X-Edit") != "modified" || req.Header.Get("X-Remove") != "" {
					t.Errorf("outgoing headers = %v", req.Header)
				}
				if req.Trailer.Get("X-B") != "b" || req.Trailer.Get("X-A") != "a" {
					t.Errorf("trailers = %v", req.Trailer)
				}
				if fp, ok := RequestHTTP2Fingerprint(req); !ok || !reflect.DeepEqual(fp, fingerprint) {
					t.Errorf("fingerprint = %#v, %t", fp, ok)
				}
				originObserved <- http.RequestHeaderBlocks(req)
				_, _ = io.WriteString(w, "ok")
			}))
			proxyAddr, proxyErrors := startHTTP2E2EProxy(t, caCert, caKey, serverCert,
				func(ctx context.Context, req *http.Request, next HTTPDelegatedInvoker) (*http.Response, error) {
					req = req.WithContext(ctx)
					req.Header.Set("X-Edit", "modified")
					req.Header.Del("X-Remove")
					resp, err := next.Invoke(req)
					interceptorObserved <- RequestWireHeaderBlocks(req)
					return resp, err
				})
			transport := newSingleUseHTTP2Transport(t, connectProxyTunnel(t, proxyAddr, originAddr))
			bodyReader, bodyWriter := io.Pipe()
			defer bodyReader.Close()
			defer bodyWriter.Close()
			req, _ := http.NewRequest(http.MethodPost, "http://"+originAddr+"/trailers", bodyReader)
			req.ContentLength = length
			req.Trailer = http.Header{"X-A": nil, "X-B": nil}
			initial := http.HeaderBlock{Kind: http.HeaderBlockInitial, ProtoMajor: 2, Fields: []http.HeaderField{
				{Name: ":scheme", Value: "http"}, {Name: ":method", Value: "POST"},
				{Name: ":authority", Value: originAddr}, {Name: ":path", Value: "/trailers"},
				{Name: "trailer", Value: "X-A, X-B"}, {Name: "x-edit", Value: "original"}, {Name: "x-remove", Value: "secret"},
			}}
			if length > 0 {
				initial.Fields = append(initial.Fields, http.HeaderField{Name: "content-length", Value: "8"})
			}
			var err error
			req, err = http.WithRequestHeaderBlocks(req, initial, func() (http.HeaderBlock, error) {
				return http.HeaderBlock{Kind: http.HeaderBlockTrailer, ProtoMajor: 2, Fields: []http.HeaderField{{Name: "x-b", Value: "b"}, {Name: "x-a", Value: "a"}}}, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			req, err = http.WithRequestFingerprint(req, fingerprint)
			if err != nil {
				t.Fatal(err)
			}
			completed := make(chan error, 1)
			go func() {
				response, err := transport.RoundTrip(req)
				if err == nil {
					defer response.Body.Close()
					var data []byte
					data, err = io.ReadAll(response.Body)
					if err == nil && (response.StatusCode != 200 || string(data) != "ok") {
						err = fmt.Errorf("response = %d, %q", response.StatusCode, data)
					}
				}
				completed <- err
			}()
			if _, err := io.WriteString(bodyWriter, "payload"); err != nil {
				t.Fatal(err)
			}
			receiveRegressionValue(t, bodyStarted)
			if length > 0 {
				if _, err := io.WriteString(bodyWriter, "!"); err != nil {
					t.Fatal(err)
				}
			}
			_ = bodyWriter.Close()
			if err := receiveRegressionValue(t, completed); err != nil {
				t.Fatal(err)
			}
			for name, blocks := range map[string][]http.HeaderBlock{"origin": receiveRegressionValue(t, originObserved), "interceptor": receiveRegressionValue(t, interceptorObserved)} {
				if got := headerBlockNames(blocks, http.HeaderBlockTrailer); !slices.Equal(got, []string{"x-b", "x-a"}) {
					t.Errorf("%s trailer order = %v", name, got)
				}
			}
			assertNoHTTP2E2EError(t, proxyErrors)
		})
	}
}

func TestTransportRetryTimingIncludesRedialFailure(t *testing.T) {
	for _, protocol := range []string{"http1", "http1_pipeline", "http2"} {
		t.Run(protocol, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			serverDone := make(chan error, 1)
			retryStarted := make(chan struct{})
			testDone := make(chan struct{})
			defer close(testDone)
			go func() {
				conn, err := listener.Accept()
				if err == nil {
					defer conn.Close()
					_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
					if protocol == "http2" {
						err = refuseHTTP2Request(conn)
						// Keep the socket alive until REFUSED_STREAM is observed.
						// Closing with unread SETTINGS ACKs can race it with a TCP reset.
						select {
						case <-retryStarted:
						case <-testDone:
						}
					} else {
						var req *http.Request
						req, err = http.ReadRequest(bufio.NewReader(conn))
						if err == nil {
							_, err = io.Copy(io.Discard, req.Body)
							_ = req.Body.Close()
						}
					}
				}
				serverDone <- err
			}()
			timing := newHTTPExchangeTiming(systemTimingClock{})
			var mu sync.Mutex
			var events []HTTPExchangeTimingEvent
			ObserveHTTPExchangeTiming(withHTTPExchangeTiming(context.Background(), timing), func(event HTTPExchangeTimingEvent) {
				mu.Lock()
				defer mu.Unlock()
				events = append(events, event)
			})
			redialErr := errors.New("retry redial failed")
			var dialCount atomic.Int32
			depth := 0
			if protocol == "http1_pipeline" {
				depth = 2
			}
			transport := newTransport(listener.Addr().String(), func(ctx context.Context, network, addr string) (net.Conn, error) {
				if dialCount.Add(1) == 2 {
					close(retryStarted)
					mu.Lock()
					last := events[len(events)-1]
					mu.Unlock()
					if last.Phase != HTTPExchangeRequestStarted || last.Attempt != 2 {
						t.Errorf("event at redial = %#v", last)
					}
					return nil, redialErr
				}
				return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, addr)
			}, time.Second, false, depth)
			defer transport.Close()
			req, _ := http.NewRequest(http.MethodGet, "http://"+listener.Addr().String()+"/", nil)
			if protocol == "http2" {
				req.Proto = "HTTP/2.0"
				req.ProtoMajor = 2
				req.ProtoMinor = 0
			}
			req, attempt := timing.traceRequest(req)
			response, err := transport.RoundTrip(req)
			timing.observeResult(req, response, err, attempt)
			if !errors.Is(err, redialErr) || dialCount.Load() != 2 {
				t.Fatalf("RoundTrip = %v, dials = %d", err, dialCount.Load())
			}
			mu.Lock()
			last := events[len(events)-1]
			mu.Unlock()
			if last.Attempt != 2 || last.Phase != HTTPExchangeRequestEnded || !errors.Is(last.Error, redialErr) {
				t.Errorf("last retry event = %#v", last)
			}
			if err := receiveRegressionValue(t, serverDone); err != nil {
				t.Fatal(err)
			}
		})
	}
}
