package mitmproxy

import (
	"bufio"
	"io"
	"net"

	"github.com/josexy/mitmproxy-go/buf"
	"github.com/josexy/websocket"
)

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func newBufConn(c net.Conn) *bufConn { return &bufConn{Conn: c, r: bufio.NewReader(c)} }

func (c *bufConn) Peek(n int) ([]byte, error) { return c.r.Peek(n) }

func (c *bufConn) Read(p []byte) (int, error) { return c.r.Read(p) }

var (
	wsBufferPool        = buf.New(512)
	socksBufferPool     = buf.New(515)
	http2BodyBufferPool = buf.NewV1(1024 * 4)
)

func acquireBuffer() *buf.Buffer            { return wsBufferPool.Get() }
func releaseBuffer(buffer *buf.Buffer)      { wsBufferPool.Put(buffer) }
func acquireHTTP2BodyBuffer() *[]byte       { return http2BodyBufferPool.Get() }
func releaseHTTP2BodyBuffer(buffer *[]byte) { http2BodyBufferPool.Put(buffer) }
func acquireSocksBuffer() *buf.Buffer       { return socksBufferPool.Get() }
func releaseSocksBuffer(buffer *buf.Buffer) { socksBufferPool.Put(buffer) }

func readBufferFromWSConn(conn *websocket.Conn) (msgType int, buffer *buf.Buffer, err error) {
	var reader io.Reader
	msgType, reader, err = conn.NextReader()
	if err != nil {
		return
	}
	buffer = acquireBuffer()
	if _, err = buffer.ReadFrom(reader); err != nil {
		wsBufferPool.Put(buffer)
		buffer = nil
		return
	}
	return msgType, buffer, nil
}
