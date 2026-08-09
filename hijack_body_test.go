package mitmproxy

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"github.com/josexy/xhttp"
	"github.com/josexy/xhttp/httptest"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestHTTPProxyPreservesMethodAfterHijackedRequestBody(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = io.Copy(io.Discard, req.Body)
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	var methodsMu sync.Mutex
	var methods []string
	certPath, keyPath := writeTestCA(t)
	handler, err := NewMitmProxyHandler(
		WithCACertPath(certPath),
		WithCAKeyPath(keyPath),
		WithDisableHTTP2(),
		WithHTTPInterceptor(func(ctx context.Context, req *http.Request, next HTTPDelegatedInvoker) (*http.Response, error) {
			methodsMu.Lock()
			methods = append(methods, req.Method)
			methodsMu.Unlock()
			return next.Invoke(req)
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Cleanup()

	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxyServer := &http.Server{Handler: handler}
	defer proxyServer.Close()
	go func() {
		if err := proxyServer.Serve(proxyListener); err != nil && err != http.ErrServerClosed {
			t.Errorf("proxy server failed: %v", err)
		}
	}()

	conn, err := net.DialTimeout("tcp", proxyListener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}

	target := upstream.URL + "/api"
	host := strings.TrimPrefix(upstream.URL, "http://")
	responseReader := bufio.NewReader(conn)
	for _, body := range []string{"x", "y"} {
		request := fmt.Sprintf(
			"POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n\r\n%s",
			target, host, len(body), body,
		)
		if _, err := io.WriteString(conn, request); err != nil {
			t.Fatal(err)
		}
		response, err := http.ReadResponse(responseReader, &http.Request{Method: http.MethodPost})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, response.Body); err != nil {
			_ = response.Body.Close()
			t.Fatal(err)
		}
		if err := response.Body.Close(); err != nil {
			t.Fatal(err)
		}
	}

	expectRequest := fmt.Sprintf(
		"POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: 1\r\nExpect: 100-continue\r\n\r\n",
		target, host,
	)
	if _, err := io.WriteString(conn, expectRequest); err != nil {
		t.Fatal(err)
	}
	continueResponse, err := http.ReadResponse(responseReader, &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := continueResponse.StatusCode, http.StatusContinue; got != want {
		t.Fatalf("interim status = %d; want %d", got, want)
	}
	_ = continueResponse.Body.Close()
	if _, err := io.WriteString(conn, "z"); err != nil {
		t.Fatal(err)
	}
	finalResponse, err := http.ReadResponse(responseReader, &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, finalResponse.Body); err != nil {
		_ = finalResponse.Body.Close()
		t.Fatal(err)
	}
	if err := finalResponse.Body.Close(); err != nil {
		t.Fatal(err)
	}

	methodsMu.Lock()
	defer methodsMu.Unlock()
	if got, want := fmt.Sprint(methods), "[POST POST POST]"; got != want {
		t.Fatalf("methods = %s; want %s", got, want)
	}
}

func TestRebindHijackedRequestBodyPreservesContentLengthBoundary(t *testing.T) {
	raw := &bytesConn{Reader: bytes.NewReader([]byte(
		"dataPOST /two HTTP/1.1\r\nHost: example.test\r\n\r\n",
	))}
	rw := bufio.NewReadWriter(bufio.NewReader(raw), bufio.NewWriter(raw))
	originalBody := &countingReadCloser{Reader: strings.NewReader("wrong")}
	request := &http.Request{
		Method:        http.MethodPost,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          originalBody,
		ContentLength: 4,
	}

	request, conn, err := rebindRequestBodyAfterHijack(request, raw, rw)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(body), "data"; got != want {
		t.Fatalf("body = %q; want %q", got, want)
	}
	if originalBody.reads != 0 {
		t.Fatalf("original body was read %d times after Hijack", originalBody.reads)
	}

	next, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := next.Method, http.MethodPost; got != want {
		t.Fatalf("next method = %q; want %q", got, want)
	}
}

func TestRebindHijackedRequestBodyPreservesChunkedTrailersAndNextRequest(t *testing.T) {
	raw := &bytesConn{Reader: bytes.NewReader([]byte(
		"4\r\ndata\r\n0\r\nX-Checksum: valid\r\n\r\n" +
			"POST /two HTTP/1.1\r\nHost: example.test\r\nContent-Length: 0\r\n\r\n",
	))}
	rw := bufio.NewReadWriter(bufio.NewReader(raw), bufio.NewWriter(raw))
	request := &http.Request{
		Method:           http.MethodPost,
		Proto:            "HTTP/1.1",
		ProtoMajor:       1,
		ProtoMinor:       1,
		Header:           make(http.Header),
		Body:             io.NopCloser(strings.NewReader("wrong")),
		ContentLength:    -1,
		TransferEncoding: []string{"chunked"},
		Trailer:          http.Header{"X-Checksum": nil},
	}

	request, conn, err := rebindRequestBodyAfterHijack(request, raw, rw)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(body), "data"; got != want {
		t.Fatalf("body = %q; want %q", got, want)
	}
	if got, want := request.Trailer.Get("X-Checksum"), "valid"; got != want {
		t.Fatalf("trailer = %q; want %q", got, want)
	}

	next, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := next.Method, http.MethodPost; got != want {
		t.Fatalf("next method = %q; want %q", got, want)
	}
}

func TestRebindHijackedRequestBodyCopiesUndeclaredTrailer(t *testing.T) {
	raw := &bytesConn{Reader: bytes.NewReader([]byte(
		"4\r\ndata\r\n0\r\nX-Checksum: valid\r\n\r\n",
	))}
	rw := bufio.NewReadWriter(bufio.NewReader(raw), bufio.NewWriter(raw))
	request := &http.Request{
		Method:           http.MethodPost,
		Proto:            "HTTP/1.1",
		ProtoMajor:       1,
		ProtoMinor:       1,
		Header:           make(http.Header),
		Body:             io.NopCloser(strings.NewReader("wrong")),
		ContentLength:    -1,
		TransferEncoding: []string{"chunked"},
	}

	request, _, err := rebindRequestBodyAfterHijack(request, raw, rw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(request.Body); err != nil {
		t.Fatal(err)
	}
	if got, want := request.Trailer.Get("X-Checksum"), "valid"; got != want {
		t.Fatalf("trailer = %q; want %q", got, want)
	}
}

func TestRebindHijackedRequestBodyRejectsUnsafeFramingMetadata(t *testing.T) {
	tests := []struct {
		name     string
		transfer []string
		trailer  http.Header
	}{
		{
			name:     "unsupported transfer encoding",
			transfer: []string{"chunked\r\nContent-Length: 1"},
		},
		{
			name:     "forbidden trailer",
			transfer: []string{"chunked"},
			trailer:  http.Header{"Content-Length": nil},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw := &bytesConn{Reader: bytes.NewReader(nil)}
			rw := bufio.NewReadWriter(bufio.NewReader(raw), bufio.NewWriter(raw))
			request := &http.Request{
				Method:           http.MethodPost,
				Proto:            "HTTP/1.1",
				ProtoMajor:       1,
				ProtoMinor:       1,
				Header:           make(http.Header),
				Body:             io.NopCloser(strings.NewReader("wrong")),
				ContentLength:    -1,
				TransferEncoding: test.transfer,
				Trailer:          test.trailer,
			}

			if _, _, err := rebindRequestBodyAfterHijack(request, raw, rw); err == nil {
				t.Fatal("unsafe framing metadata was accepted")
			}
		})
	}
}

func TestRebindHijackedRequestBodySendsContinueBeforeReading(t *testing.T) {
	raw := &bytesConn{Reader: bytes.NewReader([]byte("data"))}
	rw := bufio.NewReadWriter(bufio.NewReader(raw), bufio.NewWriter(raw))
	request := &http.Request{
		Method:        http.MethodPost,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Expect": {"100-continue"}},
		Body:          io.NopCloser(strings.NewReader("wrong")),
		ContentLength: 4,
	}

	request, _, err := rebindRequestBodyAfterHijack(request, raw, rw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(request.Body); err != nil {
		t.Fatal(err)
	}
	if got, want := raw.Buffer.String(), "HTTP/1.1 100 Continue\r\n\r\n"; got != want {
		t.Fatalf("continue response = %q; want %q", got, want)
	}
}

func TestIncompleteHijackedRequestBodyCloseUnblocksRead(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	rw := bufio.NewReadWriter(bufio.NewReader(server), bufio.NewWriter(server))
	request := &http.Request{
		Method:        http.MethodPost,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader("wrong")),
		ContentLength: 1,
	}

	request, _, err := rebindRequestBodyAfterHijack(request, server, rw)
	if err != nil {
		t.Fatal(err)
	}
	readDone := make(chan error, 1)
	go func() {
		var data [1]byte
		_, err := request.Body.Read(data[:])
		readDone <- err
	}()
	if err := request.Body.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("blocked body read returned without an error")
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock the request body read")
	}
}

func TestPassthroughRemovesLocallyHandledExpectContinue(t *testing.T) {
	raw := &bytesConn{Reader: bytes.NewReader([]byte("data"))}
	request := &http.Request{
		Method:        http.MethodPost,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Expect": {"100-continue"}},
		Body:          io.NopCloser(strings.NewReader("data")),
		ContentLength: 4,
	}
	request = prepareHijackedRequestBody(request, request, raw)

	forwarded := withoutForwardedExpectContinue(request)
	if got := forwarded.Header.Get("Expect"); got != "" {
		t.Fatalf("forwarded Expect = %q; want empty", got)
	}
	if got, want := request.Header.Get("Expect"), "100-continue"; got != want {
		t.Fatalf("original Expect = %q; want %q", got, want)
	}
	if forwarded.Body != request.Body {
		t.Fatal("passthrough request body was replaced")
	}
}

type countingReadCloser struct {
	io.Reader
	reads int
}

func (r *countingReadCloser) Read(data []byte) (int, error) {
	r.reads++
	return r.Reader.Read(data)
}

func (r *countingReadCloser) Close() error { return nil }
