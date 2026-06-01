package iocopy

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestIoCopy(t *testing.T) {
	var dst bytes.Buffer
	if err := IoCopy(&dst, bytes.NewBufferString("hello")); err != nil {
		t.Fatalf("IoCopy: %v", err)
	}
	if dst.String() != "hello" {
		t.Fatalf("dst = %q; want hello", dst.String())
	}
}

func TestIoCopyReturnsReaderError(t *testing.T) {
	wantErr := errors.New("read failed")
	if err := IoCopy(io.Discard, errReader{err: wantErr}); !errors.Is(err, wantErr) {
		t.Fatalf("IoCopy err = %v; want %v", err, wantErr)
	}
}

func TestIoCopyBidirectional(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- IoCopyBidirectional(left, right)
	}()

	if _, err := left.Write([]byte("ping")); err != nil {
		t.Fatalf("left write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(right, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("right read = %q, %v; want ping", buf, err)
	}
	_ = right.Close()
	select {
	case <-errCh:
	case <-time.After(time.Second):
		t.Fatalf("IoCopyBidirectional did not return after one side closed")
	}
}

type errReader struct {
	err error
}

func (r errReader) Read([]byte) (int, error) { return 0, r.err }
