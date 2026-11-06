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

// IoCopyBidirectional relays dst and src without bounding a half-closed
// direction. See IoCopyBidirectionalHalfClose.
func IoCopyBidirectional(dst, src io.ReadWriteCloser) error {
	return IoCopyBidirectionalHalfClose(dst, src, 0)
}

// IoCopyBidirectionalHalfClose relays data in both directions. When one
// direction reaches EOF, the write side of its destination is shut down, so
// that peer observes EOF while the opposite direction keeps flowing; when the
// destination cannot half-close, both connections are closed instead. After
// one direction has ended, a positive idleTimeout bounds how long the remaining
// direction may wait for data. Both connections are closed before returning,
// and the result of the direction that finished first is returned.
func IoCopyBidirectionalHalfClose(dst, src io.ReadWriteCloser, idleTimeout time.Duration) error {
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			_ = dst.Close()
			_ = src.Close()
		})
	}
	defer closeBoth()

	var ended atomic.Bool
	errCh := make(chan error, 2)
	relay := func(to, from io.ReadWriteCloser) {
		var reader io.Reader = from
		if idleTimeout > 0 {
			reader = &halfClosedIdleReader{reader: from, ended: &ended, timeout: idleTimeout}
		}
		err := IoCopy(to, reader)
		if err == nil && closeWrite(to) {
			// The opposite direction reads from to. A pending Read observes a
			// deadline set concurrently, and later reads rearm it.
			if ended.CompareAndSwap(false, true) && idleTimeout > 0 {
				if conn, ok := to.(readDeadliner); ok {
					_ = conn.SetReadDeadline(time.Now().Add(idleTimeout))
				}
			}
			errCh <- nil
			return
		}
		closeBoth()
		errCh <- err
	}
	go relay(dst, src)
	go relay(src, dst)
	first := <-errCh
	<-errCh
	return first
}

func closeWrite(w io.Writer) bool {
	conn, ok := w.(CloseWriter)
	return ok && conn.CloseWrite() == nil
}

// halfClosedIdleReader rearms an idle read deadline before every Read once the
// opposite direction has ended.
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
