package mitmproxy

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"github.com/josexy/xhttp"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http/httpguts"
)

type hijackedRequestBodyContextKey struct{}

const (
	hijackedBodyActive int32 = iota
	hijackedBodyComplete
	hijackedBodyAborted
)

type hijackedRequestBodyState struct {
	lifecycle atomic.Int32
	closed    atomic.Bool
	done      chan struct{}
	doneOnce  sync.Once

	writeMu              sync.Mutex
	continueConn         net.Conn
	sendContinue         bool
	continueSent         bool
	continueWriteErr     error
	finalResponseStarted bool
}

type hijackedRequestBody struct {
	body          io.ReadCloser
	parsedRequest *http.Request
	request       *http.Request
	state         *hijackedRequestBodyState
}

// rebindRequestBodyAfterHijack replaces the server-owned request body with one
// that reads from the bufio.Reader returned by Hijack. The xhttp contract
// forbids using the original Request.Body after Hijack. This requires the proxy
// handler to receive the request before middleware consumes or replaces Body.
func rebindRequestBodyAfterHijack(req *http.Request, conn net.Conn, rw *bufio.ReadWriter) (*http.Request, net.Conn, error) {
	if rw == nil {
		return nil, nil, fmt.Errorf("hijacked connection reader unavailable")
	}
	if err := rw.Flush(); err != nil {
		return nil, nil, fmt.Errorf("flush hijacked connection: %w", err)
	}

	framingHeader, err := buildRequestBodyFramingHeader(req)
	if err != nil {
		return nil, nil, err
	}
	reader := bufio.NewReader(io.MultiReader(bytes.NewReader(framingHeader), rw.Reader))
	parsed, err := http.ReadRequest(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("rebind hijacked request body: %w", err)
	}

	req.Body = parsed.Body
	req.ContentLength = parsed.ContentLength
	req.TransferEncoding = append([]string(nil), parsed.TransferEncoding...)
	req.Trailer = parsed.Trailer
	req.GetBody = nil
	req = prepareHijackedRequestBody(req, parsed, conn)

	return req, &bufConnExt{Conn: conn, Reader: reader}, nil
}

func prepareHijackedRequestBody(req, parsedRequest *http.Request, conn net.Conn) *http.Request {
	if req == nil {
		return nil
	}
	if state, _ := req.Context().Value(hijackedRequestBodyContextKey{}).(*hijackedRequestBodyState); state != nil {
		return req
	}

	state := &hijackedRequestBodyState{
		continueConn: conn,
		done:         make(chan struct{}),
		sendContinue: req.ProtoAtLeast(1, 1) &&
			req.ContentLength != 0 &&
			httpguts.HeaderValuesContainsToken(req.Header.Values("Expect"), "100-continue"),
	}
	body := req.Body
	req = req.WithContext(contextWithHijackedRequestBodyState(req, state))
	if body == nil || body == http.NoBody {
		state.lifecycle.Store(hijackedBodyComplete)
		state.signalDone()
		req.Body = http.NoBody
		return req
	}

	req.Body = &hijackedRequestBody{
		body:          body,
		parsedRequest: parsedRequest,
		request:       req,
		state:         state,
	}
	return req
}

func contextWithHijackedRequestBodyState(req *http.Request, state *hijackedRequestBodyState) context.Context {
	return context.WithValue(req.Context(), hijackedRequestBodyContextKey{}, state)
}

func buildRequestBodyFramingHeader(req *http.Request) ([]byte, error) {
	var header bytes.Buffer
	_, _ = io.WriteString(&header, "POST / HTTP/1.1\r\nHost: mitmproxy.invalid\r\n")

	if len(req.TransferEncoding) > 0 {
		if len(req.TransferEncoding) != 1 || !strings.EqualFold(req.TransferEncoding[0], "chunked") {
			return nil, fmt.Errorf("unsupported request transfer encoding %q", req.TransferEncoding)
		}
		_, _ = io.WriteString(&header, "Transfer-Encoding: chunked\r\n")
		if len(req.Trailer) > 0 {
			keys := make([]string, 0, len(req.Trailer))
			for key := range req.Trailer {
				if !httpguts.ValidTrailerHeader(key) {
					return nil, fmt.Errorf("invalid request trailer %q", key)
				}
				keys = append(keys, key)
			}
			sort.Strings(keys)
			_, _ = fmt.Fprintf(&header, "Trailer: %s\r\n", strings.Join(keys, ", "))
		}
	} else if req.ContentLength < -1 {
		return nil, fmt.Errorf("invalid request content length %d", req.ContentLength)
	} else if req.ContentLength >= 0 {
		_, _ = fmt.Fprintf(&header, "Content-Length: %d\r\n", req.ContentLength)
	}
	_, _ = io.WriteString(&header, "\r\n")
	return header.Bytes(), nil
}

func (b *hijackedRequestBody) Read(data []byte) (int, error) {
	if b.state.closed.Load() {
		return 0, http.ErrBodyReadAfterClose
	}
	if err := b.state.send100Continue(); err != nil {
		return 0, err
	}

	n, err := b.body.Read(data)
	if err == io.EOF {
		b.finish()
	}
	return n, err
}

func (b *hijackedRequestBody) Close() error {
	if !b.state.closed.CompareAndSwap(false, true) {
		return nil
	}
	if b.state.lifecycle.CompareAndSwap(hijackedBodyActive, hijackedBodyAborted) {
		// Do not drain an incomplete body here. A client using Expect:
		// 100-continue may still be waiting for a response, and this connection
		// will be closed instead of being reused.
		_ = b.state.continueConn.SetReadDeadline(time.Now())
		b.state.signalDone()
		return nil
	}
	if b.state.lifecycle.Load() != hijackedBodyComplete {
		return nil
	}
	err := b.body.Close()
	b.copyTrailers()
	return err
}

func (b *hijackedRequestBody) finish() {
	b.copyTrailers()
	if b.state.lifecycle.CompareAndSwap(hijackedBodyActive, hijackedBodyComplete) {
		b.state.signalDone()
	}
}

func (s *hijackedRequestBodyState) signalDone() {
	s.doneOnce.Do(func() { close(s.done) })
}

func hijackedRequestBodyDone(req *http.Request) <-chan struct{} {
	if req != nil {
		if state, _ := req.Context().Value(hijackedRequestBodyContextKey{}).(*hijackedRequestBodyState); state != nil {
			return state.done
		}
	}
	done := make(chan struct{})
	close(done)
	return done
}

func hijackedRequestNeedsContinue(req *http.Request) bool {
	if req == nil {
		return false
	}
	state, _ := req.Context().Value(hijackedRequestBodyContextKey{}).(*hijackedRequestBodyState)
	return state != nil && state.sendContinue
}

func (b *hijackedRequestBody) copyTrailers() {
	b.request.Trailer = b.parsedRequest.Trailer
}

func (s *hijackedRequestBodyState) send100Continue() error {
	if !s.sendContinue {
		return nil
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.finalResponseStarted {
		return io.ErrClosedPipe
	}
	if !s.continueSent {
		s.continueSent = true
		_, s.continueWriteErr = io.Copy(s.continueConn, strings.NewReader("HTTP/1.1 100 Continue\r\n\r\n"))
	}
	return s.continueWriteErr
}

func beginHijackedFinalResponse(req *http.Request) bool {
	if req == nil {
		return true
	}
	state, _ := req.Context().Value(hijackedRequestBodyContextKey{}).(*hijackedRequestBodyState)
	if state == nil {
		return true
	}

	state.writeMu.Lock()
	state.finalResponseStarted = true
	complete := state.lifecycle.Load() == hijackedBodyComplete
	state.writeMu.Unlock()
	return complete
}

func withoutForwardedExpectContinue(req *http.Request) *http.Request {
	if req == nil {
		return nil
	}
	state, _ := req.Context().Value(hijackedRequestBodyContextKey{}).(*hijackedRequestBodyState)
	if state == nil || !state.sendContinue {
		return req
	}

	cloned := new(http.Request)
	*cloned = *req
	cloned.Header = req.Header.Clone()
	cloned.Header.Del("Expect")
	return cloned
}
