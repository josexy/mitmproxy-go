package iocopy

import (
	"io"
	"sync"
	"sync/atomic"
	"time"
)

const maxTcpBufferSize = 16 * 1024

// Pooling slice pointers keeps Put from allocating a slice header each time.
var tcpPool = sync.Pool{New: func() any {
	buffer := make([]byte, maxTcpBufferSize)
	return &buffer
}}

// CloseWriter is implemented by connections that can shut down only their
// sending side, such as *net.TCPConn and *tls.Conn.
type CloseWriter interface {
	CloseWrite() error
}

type readDeadliner interface {
	SetReadDeadline(time.Time) error
}

// IoCopyBidirectional relays upstream and client without bounding the client
// direction after upstream half-closes. See IoCopyBidirectionalHalfClose.
func IoCopyBidirectional(upstream, client io.ReadWriteCloser) error {
	return IoCopyBidirectionalHalfClose(upstream, client, 0)
}

// IoCopyBidirectionalHalfClose relays data between upstream and client.
//
// When the client's stream ends, both connections close at once. A client that
// closes and one that only shuts down its sending side look the same, and the
// upstream connection is not kept open for a client that may be gone.
//
// When upstream's stream ends, only the client's write side is shut down, so
// the client reads every byte before EOF while its own data keeps flowing; if
// the client connection cannot half-close, both close instead. A positive
// idleTimeout then bounds how long the client direction may wait for data.
//
// Both connections are closed before returning, and the result of the
// direction that finished first is returned.
func IoCopyBidirectionalHalfClose(upstream, client io.ReadWriteCloser, idleTimeout time.Duration) error {
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			_ = upstream.Close()
			_ = client.Close()
		})
	}
	defer closeBoth()

	var upstreamEnded atomic.Bool
	errCh := make(chan error, 2)
	go func() {
		var reader io.Reader = client
		if idleTimeout > 0 {
			reader = &halfClosedIdleReader{reader: client, ended: &upstreamEnded, timeout: idleTimeout}
		}
		err := IoCopy(upstream, reader)
		closeBoth()
		errCh <- err
	}()
	go func() {
		err := IoCopy(client, upstream)
		if err == nil && closeWrite(client) {
			upstreamEnded.Store(true)
			// The client direction may already be blocked in Read. It observes
			// a deadline set concurrently, and later reads rearm it.
			if conn, ok := client.(readDeadliner); ok && idleTimeout > 0 {
				_ = conn.SetReadDeadline(time.Now().Add(idleTimeout))
			}
			errCh <- nil
			return
		}
		closeBoth()
		errCh <- err
	}()
	first := <-errCh
	<-errCh
	return first
}

func closeWrite(w io.Writer) bool {
	conn, ok := w.(CloseWriter)
	return ok && conn.CloseWrite() == nil
}

// halfClosedIdleReader rearms an idle read deadline before every Read once
// upstream has ended.
type halfClosedIdleReader struct {
	reader  io.Reader
	ended   *atomic.Bool
	timeout time.Duration
}

func (r *halfClosedIdleReader) Read(p []byte) (int, error) {
	if r.ended.Load() {
		if conn, ok := r.reader.(readDeadliner); ok {
			_ = conn.SetReadDeadline(time.Now().Add(r.timeout))
		}
	}
	return r.reader.Read(p)
}

func IoCopy(dst io.Writer, src io.Reader) error {
	_, srcWriterTo := src.(io.WriterTo)
	_, dstReaderFrom := dst.(io.ReaderFrom)
	if srcWriterTo || dstReaderFrom {
		_, err := io.Copy(dst, src)
		return err
	}
	buffer := tcpPool.Get().(*[]byte)
	defer tcpPool.Put(buffer)
	_, err := io.CopyBuffer(dst, src, *buffer)
	return err
}
