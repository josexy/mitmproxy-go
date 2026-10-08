package mitmproxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	http "github.com/josexy/xhttp"
)

// SetHTTPResponseSendObserver installs a single terminal downstream callback.
// Calling again replaces it. The callback runs synchronously after a send ends
// (including failure) and must not block. Different streams may call it in
// parallel. HTTP/1 bytes count successful connection writes; HTTP/2 bytes count
// ResponseWriter acceptance and success additionally requires FinishResponse,
// including flushing the final END_STREAM and trailer frames to the connection.
// Neither protocol claims acknowledgment by the peer. Body pre-reading does
// not start or complete the downstream send. The observer is tied to response.
func SetHTTPResponseSendObserver(response *http.Response, observer func(HTTPResponseSendResult)) error {
	if response == nil {
		return errors.New("mitmproxy: nil response")
	}
	var callback func(HTTPResponseSendResult)
	if observer != nil {
		var once sync.Once
		callback = func(result HTTPResponseSendResult) { once.Do(func() { observer(result) }) }
	}
	updateResponseProfile(response, func(profile *responseWireProfile) { profile.sendObserver = callback })
	return nil
}

type httpResponseSend struct {
	completed bool
	result    HTTPResponseSendResult
	observer  func(HTTPResponseSendResult)
	ctx       context.Context
}

func newHTTPResponseSend(response *http.Response) *httpResponseSend {
	s := &httpResponseSend{ctx: context.Background()}
	if profile, ok := responseWireProfileFor(response); ok {
		s.observer = profile.sendObserver
		if profile.sendContext != nil {
			s.ctx = profile.sendContext
		}
	}
	if s.ctx == context.Background() && response != nil && response.Request != nil {
		s.ctx = response.Request.Context()
	}
	return s
}

func (s *httpResponseSend) start() {
	if s.result.StartedAt.IsZero() {
		s.result.StartedAt = time.Now()
	}
}

func (s *httpResponseSend) finish(err error) {
	if s.observer == nil {
		return
	}
	if err == nil && !s.completed {
		err = s.ctx.Err()
	}
	s.result.EndedAt = time.Now()
	s.result.Err = err
	s.result.Canceled = (!s.completed && s.ctx.Err() != nil) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
	s.observer(s.result)
}

func finishUnsentHTTPResponse(response *http.Response, err error) {
	newHTTPResponseSend(response).finish(err)
}

type http1ObservedWriter struct {
	dst         io.Writer
	send        *httpResponseSend
	header      []byte
	headerDone  bool
	bodyAllowed bool
	chunked     bool
	line        []byte
	remaining   int64
	state       uint8
}

func (w *http1ObservedWriter) Write(data []byte) (int, error) {
	w.send.start()
	n, err := w.dst.Write(data)
	w.count(data[:n])
	return n, err
}

func (w *http1ObservedWriter) count(data []byte) {
	if !w.headerDone {
		w.header = append(w.header, data...)
		index := bytes.Index(w.header, []byte("\r\n\r\n"))
		if index < 0 {
			return
		}
		w.send.result.HeaderBlock = http.HeaderBlock{Kind: http.HeaderBlockInitial, ProtoMajor: 1}
		lines := bytes.Split(w.header[:index], []byte("\r\n"))
		if status := bytes.Fields(lines[0]); len(status) > 1 {
			w.send.result.HeaderBlock.StatusCode, _ = strconv.Atoi(string(status[1]))
		}
		for _, line := range lines[1:] {
			name, value, ok := bytes.Cut(line, []byte(":"))
			if ok {
				w.send.result.HeaderBlock.Fields = append(w.send.result.HeaderBlock.Fields, http.HeaderField{Name: string(name), Value: strings.TrimSpace(string(value))})
			}
		}
		w.headerDone = true
		w.chunked = bytes.Contains(bytes.ToLower(w.header[:index]), []byte("\r\ntransfer-encoding: chunked"))
		data = w.header[index+4:]
		defer func() { w.header = nil }()
	}
	if !w.bodyAllowed {
		return
	}
	if !w.chunked {
		w.send.result.BodyBytes += int64(len(data))
		return
	}
	for len(data) > 0 {
		switch w.state {
		case 0: // chunk size line
			index := bytes.IndexByte(data, '\n')
			if index < 0 {
				w.line = append(w.line, data...)
				return
			}
			w.line = append(w.line, data[:index+1]...)
			size, err := parseHTTP1ChunkSize(bytes.TrimSpace(w.line))
			w.line = nil
			data = data[index+1:]
			if err != nil || size == 0 {
				w.state = 3
				return
			}
			w.remaining = size
			w.state = 1
		case 1:
			n := min(int64(len(data)), w.remaining)
			w.send.result.BodyBytes += n
			w.remaining -= n
			data = data[n:]
			if w.remaining == 0 {
				w.remaining = 2
				w.state = 2
			}
		case 2:
			n := min(int64(len(data)), w.remaining)
			w.remaining -= n
			data = data[n:]
			if w.remaining == 0 {
				w.state = 0
			}
		default:
			return // zero chunk/trailers are not entity bytes
		}
	}
}

type http2ObservedWriter struct {
	http.ResponseWriter
	send        *httpResponseSend
	bodyAllowed bool
}

func (w *http2ObservedWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *http2ObservedWriter) Write(data []byte) (int, error) {
	w.send.start()
	n, err := w.ResponseWriter.Write(data)
	if w.bodyAllowed {
		w.send.result.BodyBytes += int64(n)
	}
	return n, err
}
func (w *http2ObservedWriter) WriteHeader(status int) {
	w.send.start()
	w.ResponseWriter.WriteHeader(status)
}
func (w *http2ObservedWriter) Flush() { _ = w.FlushError() }
func (w *http2ObservedWriter) FlushError() error {
	return http.NewResponseController(w.ResponseWriter).Flush()
}

// AbortHTTPRequestRead interrupts an in-flight interceptor request-body read.
// HTTP/1 aborts the entire connection; the interceptor must return ErrDropHTTP.
// HTTP/2 closes only this stream's request body. It is safe to call from a
// timeout/cancellation goroutine, and does not wait for a HTTP/1 Body.Read lock.
func AbortHTTPRequestRead(req *http.Request, cause error) error {
	if req == nil {
		return errors.New("mitmproxy: nil request")
	}
	if req.ProtoMajor == 2 {
		if req.Body == nil {
			return nil
		}
		return req.Body.Close()
	}
	connCtx, ok := req.Context().Value(connContextKey).(*biConnContext)
	if !ok || connCtx.local == nil {
		return errors.New("mitmproxy: missing downstream connection")
	}
	return connCtx.local.SetReadDeadline(time.Now())
}
