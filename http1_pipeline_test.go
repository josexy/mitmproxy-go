package mitmproxy

import (
	"bufio"
	"context"
	"github.com/josexy/xhttp"
	"github.com/josexy/xhttp/httptrace"
	"io"
	"net"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTP1PipelineConnTracesFirstResponseByte(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = server.Close() })
	pipeline := newHTTP1PipelineConn(client, 1, time.Second)
	t.Cleanup(func() { _ = pipeline.Close() })

	requestRead := make(chan struct{})
	writeResponse := make(chan struct{})
	serverErr := make(chan error, 1)
	go func() {
		request, err := http.ReadRequest(bufio.NewReader(server))
		if err != nil {
			serverErr <- err
			return
		}
		_ = request.Body.Close()
		close(requestRead)
		<-writeResponse
		_, err = io.WriteString(server, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
		serverErr <- err
	}()

	var calls atomic.Int32
	req := newPipelineTestRequest("/trace")
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
		GotFirstResponseByte: func() {
			calls.Add(1)
		},
	}))
	type pipelineTraceResult struct {
		response *http.Response
		err      error
	}
	resultCh := make(chan pipelineTraceResult, 1)
	go func() {
		response, err := pipeline.RoundTrip(req)
		resultCh <- pipelineTraceResult{response: response, err: err}
	}()

	select {
	case <-requestRead:
	case <-time.After(time.Second):
		t.Fatal("upstream did not receive request")
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("GotFirstResponseByte calls before response = %d; want 0", got)
	}
	close(writeResponse)

	gotResult := <-resultCh
	if gotResult.err != nil {
		t.Fatal(gotResult.err)
	}
	_ = gotResult.response.Body.Close()
	if got := calls.Load(); got != 1 {
		t.Fatalf("GotFirstResponseByte calls = %d; want 1", got)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestHTTP1PipelineConnTracesEarlyResponseBeforeRequestBodyCompletes(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = server.Close() })
	pipeline := newHTTP1PipelineConn(client, 1, time.Second)
	t.Cleanup(func() { _ = pipeline.Close() })

	bodyReader, bodyWriter := io.Pipe()
	request := newPipelineTestRequest("/early-response")
	request.Method = http.MethodPost
	request.Body = bodyReader
	request.ContentLength = 2

	events := make(chan string, 2)
	request = request.WithContext(httptrace.WithClientTrace(request.Context(), &httptrace.ClientTrace{
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			if info.Err != nil {
				t.Errorf("WroteRequest error = %v", info.Err)
			}
			events <- "wrote-request"
		},
		GotFirstResponseByte: func() {
			events <- "got-first-response-byte"
		},
	}))

	headersRead := make(chan struct{})
	serverErr := make(chan error, 1)
	go func() {
		reader := bufio.NewReader(server)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				serverErr <- err
				return
			}
			if line == "\r\n" {
				break
			}
		}
		close(headersRead)
		if _, err := io.WriteString(server, "HTTP/1.1 413 Content Too Large\r\nContent-Length: 0\r\n\r\n"); err != nil {
			serverErr <- err
			return
		}
		_, err := io.CopyN(io.Discard, reader, 2)
		serverErr <- err
	}()

	type result struct {
		response *http.Response
		err      error
	}
	resultCh := make(chan result, 1)
	go func() {
		response, err := pipeline.RoundTrip(request)
		resultCh <- result{response: response, err: err}
	}()

	select {
	case <-headersRead:
	case <-time.After(time.Second):
		t.Fatal("upstream did not receive request headers")
	}
	select {
	case got := <-events:
		if got != "got-first-response-byte" {
			t.Fatalf("first trace event = %q, want got-first-response-byte", got)
		}
	case <-time.After(time.Second):
		t.Fatal("GotFirstResponseByte did not fire while request body was blocked")
	}

	if _, err := bodyWriter.Write([]byte("ok")); err != nil {
		t.Fatalf("write request body: %v", err)
	}
	_ = bodyWriter.Close()

	gotResult := <-resultCh
	if gotResult.err != nil {
		t.Fatal(gotResult.err)
	}
	_ = gotResult.response.Body.Close()
	if got := <-events; got != "wrote-request" {
		t.Fatalf("second trace event = %q, want wrote-request", got)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
	if got, want := gotResult.response.StatusCode, http.StatusRequestEntityTooLarge; got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}
}

func TestHTTP1PipelineConnSendsSecondRequestBeforeFirstResponse(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = server.Close() })
	pipeline := newHTTP1PipelineConn(client, 8, time.Second)
	t.Cleanup(func() { _ = pipeline.Close() })

	requestsRead := make(chan string, 2)
	serverDone := make(chan error, 1)
	go func() {
		reader := bufio.NewReader(server)
		for range 2 {
			req, err := http.ReadRequest(reader)
			if err != nil {
				serverDone <- err
				return
			}
			_, _ = io.Copy(io.Discard, req.Body)
			_ = req.Body.Close()
			requestsRead <- req.URL.Path
		}
		_, err := io.WriteString(server,
			"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\na"+
				"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nb")
		serverDone <- err
	}()

	type result struct {
		response *http.Response
		err      error
	}
	firstResult := make(chan result, 1)
	secondResult := make(chan result, 1)
	go func() {
		response, err := pipeline.RoundTrip(newPipelineTestRequest("/a"))
		firstResult <- result{response, err}
	}()

	select {
	case got := <-requestsRead:
		if got != "/a" {
			t.Fatalf("first upstream request = %q; want /a", got)
		}
	case <-time.After(time.Second):
		t.Fatal("upstream did not receive first request")
	}

	go func() {
		response, err := pipeline.RoundTrip(newPipelineTestRequest("/b"))
		secondResult <- result{response, err}
	}()
	select {
	case got := <-requestsRead:
		if got != "/b" {
			t.Fatalf("second upstream request = %q; want /b", got)
		}
	case <-time.After(time.Second):
		t.Fatal("second request was not pipelined before the first response")
	}

	first := <-firstResult
	if first.err != nil {
		t.Fatal(first.err)
	}
	if body := readPipelineTestBody(t, first.response); body != "a" {
		t.Fatalf("first response body = %q; want a", body)
	}
	second := <-secondResult
	if second.err != nil {
		t.Fatal(second.err)
	}
	if body := readPipelineTestBody(t, second.response); body != "b" {
		t.Fatalf("second response body = %q; want b", body)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestHTTP1PipelineConnWaitsForResponseBodyBoundary(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = server.Close() })
	pipeline := newHTTP1PipelineConn(client, 8, time.Second)
	t.Cleanup(func() { _ = pipeline.Close() })

	requestRead := make(chan string, 2)
	go func() {
		reader := bufio.NewReader(server)
		for range 2 {
			req, _ := http.ReadRequest(reader)
			if req != nil {
				requestRead <- req.URL.Path
				_ = req.Body.Close()
			}
		}
		_, _ = io.WriteString(server,
			"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\none"+
				"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\ntwo")
	}()

	firstCh := make(chan *http.Response, 1)
	secondCh := make(chan *http.Response, 1)
	go func() {
		response, _ := pipeline.RoundTrip(newPipelineTestRequest("/one"))
		firstCh <- response
	}()
	select {
	case path := <-requestRead:
		if path != "/one" {
			t.Fatalf("first upstream request = %q; want /one", path)
		}
	case <-time.After(time.Second):
		t.Fatal("upstream did not receive first request")
	}
	go func() {
		response, _ := pipeline.RoundTrip(newPipelineTestRequest("/two"))
		secondCh <- response
	}()

	first := <-firstCh
	select {
	case <-secondCh:
		t.Fatal("second response was parsed before the first body reached its boundary")
	case <-time.After(50 * time.Millisecond):
	}
	if body := readPipelineTestBody(t, first); body != "one" {
		t.Fatalf("first response body = %q; want one", body)
	}
	select {
	case second := <-secondCh:
		if body := readPipelineTestBody(t, second); body != "two" {
			t.Fatalf("second response body = %q; want two", body)
		}
	case <-time.After(time.Second):
		t.Fatal("second response was not released after the first body completed")
	}
}

func TestHTTP1PipelineConnAppliesDepthBackpressure(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = server.Close() })
	pipeline := newHTTP1PipelineConn(client, 2, time.Second)
	t.Cleanup(func() { _ = pipeline.Close() })

	requests := make(chan string, 3)
	release := make(chan struct{})
	go func() {
		reader := bufio.NewReader(server)
		for range 2 {
			request, err := http.ReadRequest(reader)
			if err != nil {
				return
			}
			requests <- request.URL.Path
			_ = request.Body.Close()
		}
		<-release
		_, _ = io.WriteString(server,
			"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"+
				"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
		request, err := http.ReadRequest(reader)
		if err == nil {
			requests <- request.URL.Path
			_ = request.Body.Close()
			_, _ = io.WriteString(server, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
		}
	}()

	results := make([]chan *http.Response, 3)
	for i, path := range []string{"/one", "/two", "/three"} {
		results[i] = make(chan *http.Response, 1)
		go func(result chan<- *http.Response, path string) {
			response, _ := pipeline.RoundTrip(newPipelineTestRequest(path))
			result <- response
		}(results[i], path)
		if i < 2 {
			select {
			case <-requests:
			case <-time.After(time.Second):
				t.Fatalf("request %d did not reach upstream", i+1)
			}
		}
	}
	select {
	case path := <-requests:
		t.Fatalf("request %s exceeded pipeline depth before a slot was released", path)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	for i, result := range results {
		select {
		case response := <-result:
			if response == nil {
				t.Fatalf("request %d returned nil response", i+1)
			}
			_ = response.Body.Close()
		case <-time.After(time.Second):
			t.Fatalf("request %d did not complete", i+1)
		}
	}
}

func newPipelineTestRequest(path string) *http.Request {
	req := &http.Request{
		Method: http.MethodGet,
		URL:    &url.URL{Scheme: "http", Host: "example.test", Path: path},
		Host:   "example.test",
		Header: make(http.Header),
		Body:   http.NoBody,
	}
	return req.WithContext(context.Background())
}

func readPipelineTestBody(t *testing.T, response *http.Response) string {
	t.Helper()
	if response == nil {
		t.Fatal("nil response")
	}
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	return string(data)
}
