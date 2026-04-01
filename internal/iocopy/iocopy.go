package iocopy

import (
	"io"

	"github.com/josexy/mitmproxy-go/buf"
)

const maxTcpBufferSize = 16 * 1024

var tcpPool = buf.NewV1(maxTcpBufferSize)

func IoCopyBidirectional(dst, src io.ReadWriteCloser) error {
	defer dst.Close()
	defer src.Close()
	errCh := make(chan error, 2)
	copyFn := func(dest, src io.ReadWriteCloser) {
		err := IoCopy(dest, src)
		errCh <- err
	}
	go copyFn(dst, src)
	go copyFn(src, dst)
	return <-errCh
}

func IoCopy(dst io.Writer, src io.Reader) error {
	var b []byte
	if _, ok := src.(io.WriterTo); ok {
		b = nil
	} else if _, ok := dst.(io.ReaderFrom); ok {
		b = nil
	} else {
		buf := tcpPool.Get()
		defer tcpPool.Put(buf)
		b = *buf
	}
	_, err := io.CopyBuffer(dst, src, b)
	return err
}
