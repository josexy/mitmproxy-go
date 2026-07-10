package mitmproxy

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/josexy/mitmproxy-go/buf"
	"github.com/josexy/websocket"
)

var ErrHTTPHeaderTooLarge = errors.New("HTTP header too large")

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func newBufConn(c net.Conn) *bufConn { return &bufConn{Conn: c, r: bufio.NewReader(c)} }

func (c *bufConn) Peek(n int) ([]byte, error) { return c.r.Peek(n) }

func (c *bufConn) Read(p []byte) (int, error) { return c.r.Read(p) }

type boundedHTTPHeaderConn struct {
	net.Conn
	maxBytes int
	read     int
	done     bool
	window   [4]byte
	seen     int
}

func newBoundedHTTPHeaderConn(conn net.Conn, maxBytes int) net.Conn {
	if maxBytes <= 0 {
		return conn
	}
	return &boundedHTTPHeaderConn{Conn: conn, maxBytes: maxBytes}
}

func (c *boundedHTTPHeaderConn) Read(data []byte) (int, error) {
	n, err := c.Conn.Read(data)
	if c.done || n == 0 {
		return n, err
	}
	for i, value := range data[:n] {
		c.read++
		c.window[c.seen%len(c.window)] = value
		c.seen++
		if c.headerComplete() {
			c.done = true
			return n, err
		}
		if c.read >= c.maxBytes {
			return i + 1, fmt.Errorf("%w: limit is %d bytes", ErrHTTPHeaderTooLarge, c.maxBytes)
		}
	}
	return n, err
}

func (c *boundedHTTPHeaderConn) headerComplete() bool {
	if c.seen >= 2 && c.window[(c.seen-1)%4] == '\n' && c.window[(c.seen-2)%4] == '\n' {
		return true
	}
	return c.seen >= 4 &&
		c.window[(c.seen-1)%4] == '\n' &&
		c.window[(c.seen-2)%4] == '\r' &&
		c.window[(c.seen-3)%4] == '\n' &&
		c.window[(c.seen-4)%4] == '\r'
}

type replayReader struct {
	src    io.Reader
	prefix []byte
}

func (r *replayReader) Read(p []byte) (int, error) {
	if len(r.prefix) > 0 {
		n := copy(p, r.prefix)
		r.prefix = r.prefix[n:]
		return n, nil
	}
	return r.src.Read(p)
}

func (r *replayReader) prepend(data []byte) {
	if len(data) == 0 {
		return
	}
	prefix := make([]byte, 0, len(data)+len(r.prefix))
	prefix = append(prefix, data...)
	prefix = append(prefix, r.prefix...)
	r.prefix = prefix
}

type boundedHTTPRequestReader struct {
	replay *replayReader
	reader *bufio.Reader
}

func newBoundedHTTPRequestReader(src io.Reader) *boundedHTTPRequestReader {
	replay := &replayReader{src: src}
	return &boundedHTTPRequestReader{
		replay: replay,
		reader: bufio.NewReader(replay),
	}
}

func (r *boundedHTTPRequestReader) ReadRequest(maxHeaderBytes int) (*http.Request, error) {
	if maxHeaderBytes <= 0 {
		return nil, ErrInvalidHTTPHeaderSize
	}

	header, err := readBoundedHTTPHeader(r.reader, maxHeaderBytes)
	if err != nil {
		return nil, err
	}

	buffered := r.reader.Buffered()
	replay := make([]byte, 0, len(header)+buffered)
	replay = append(replay, header...)
	if buffered > 0 {
		data, err := r.reader.Peek(buffered)
		if err != nil {
			return nil, err
		}
		replay = append(replay, data...)
		_, _ = r.reader.Discard(buffered)
	}
	r.replay.prepend(replay)
	r.reader.Reset(r.replay)
	return http.ReadRequest(r.reader)
}

func readBoundedHTTPHeader(reader *bufio.Reader, maxHeaderBytes int) ([]byte, error) {
	if maxHeaderBytes <= 0 {
		return nil, ErrInvalidHTTPHeaderSize
	}
	header := make([]byte, 0, min(maxHeaderBytes, 4096))
	lineBytes := 0
	for len(header) < maxHeaderBytes {
		value, err := reader.ReadByte()
		if err != nil {
			return nil, err
		}
		header = append(header, value)
		if value != '\n' {
			lineBytes++
			continue
		}
		if lineBytes == 0 || (lineBytes == 1 && len(header) >= 2 && header[len(header)-2] == '\r') {
			return header, nil
		}
		lineBytes = 0
	}
	return nil, fmt.Errorf("%w: limit is %d bytes", ErrHTTPHeaderTooLarge, maxHeaderBytes)
}

func readBoundedHTTPResponse(reader *bufio.Reader, request *http.Request, maxHeaderBytes int) (*http.Response, *bufio.Reader, error) {
	header, err := readBoundedHTTPHeader(reader, maxHeaderBytes)
	if err != nil {
		return nil, nil, err
	}
	buffered := reader.Buffered()
	prefix := make([]byte, 0, len(header)+buffered)
	prefix = append(prefix, header...)
	if buffered > 0 {
		data, err := reader.Peek(buffered)
		if err != nil {
			return nil, nil, err
		}
		prefix = append(prefix, data...)
		_, _ = reader.Discard(buffered)
	}
	replay := &replayReader{src: reader, prefix: prefix}
	responseReader := bufio.NewReader(replay)
	response, err := http.ReadResponse(responseReader, request)
	if err != nil {
		return nil, nil, err
	}
	return response, responseReader, nil
}

var (
	wsBufferPool        = buf.New(512)
	socksBufferPool     = buf.New(515)
	http2BodyBufferPool = buf.NewV1(32 * 1024)
)

func acquireBuffer() *buf.Buffer            { return wsBufferPool.Get() }
func releaseBuffer(buffer *buf.Buffer)      { wsBufferPool.Put(buffer) }
func acquireHTTP2BodyBuffer() []byte        { return http2BodyBufferPool.Get() }
func releaseHTTP2BodyBuffer(buffer []byte)  { http2BodyBufferPool.Put(buffer) }
func acquireSocksBuffer() *buf.Buffer       { return socksBufferPool.Get() }
func releaseSocksBuffer(buffer *buf.Buffer) { socksBufferPool.Put(buffer) }

func readBufferFromWSConn(conn *websocket.Conn, maxMessageBytes int64) (msgType int, buffer *buf.Buffer, err error) {
	var reader io.Reader
	msgType, reader, err = conn.NextReader()
	if err != nil {
		return
	}
	buffer = acquireBuffer()
	if _, err = buffer.ReadFrom(io.LimitReader(reader, maxMessageBytes+1)); err != nil {
		wsBufferPool.Put(buffer)
		buffer = nil
		return
	}
	if int64(buffer.Len()) > maxMessageBytes {
		wsBufferPool.Put(buffer)
		buffer = nil
		return msgType, nil, ErrWebsocketMessageTooLarge
	}
	return msgType, buffer, nil
}
