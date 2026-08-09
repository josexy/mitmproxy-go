package mitmproxy

import (
	"bufio"
	"context"
	"github.com/josexy/xhttp"
	"io"
	"net"
	"net/url"
	"testing"
	"time"
)

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
