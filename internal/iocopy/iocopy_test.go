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

// tcpPair returns the two ends of a loopback TCP connection.
func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, _ := listener.Accept()
		accepted <- conn
	}()
	dialed, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	peer := <-accepted
	if peer == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() {
		_ = dialed.Close()
		_ = peer.Close()
	})
	return dialed.(*net.TCPConn), peer.(*net.TCPConn)
}

// A client that shuts down its sending side must still receive the reply.
func TestIoCopyBidirectionalPropagatesHalfClose(t *testing.T) {
	client, proxyDown := tcpPair(t)
	proxyUp, server := tcpPair(t)
	errCh := make(chan error, 1)
	go func() { errCh <- IoCopyBidirectionalHalfClose(proxyUp, proxyDown, time.Second) }()

	go func() {
		data, _ := io.ReadAll(server)
		_, _ = server.Write(append([]byte("reply:"), data...))
		_ = server.Close()
	}()
	if _, err := client.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	reply, err := io.ReadAll(client)
	if err != nil || string(reply) != "reply:request" {
		t.Fatalf("reply = %q, %v; want reply:request", reply, err)
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("IoCopyBidirectionalHalfClose = %v; want nil", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not return after both directions ended")
	}
}

// After one side half-closes, an idle remaining direction must not pin the relay.
func TestIoCopyBidirectionalBoundsHalfClosedIdleDirection(t *testing.T) {
	client, proxyDown := tcpPair(t)
	proxyUp, server := tcpPair(t)
	errCh := make(chan error, 1)
	go func() { errCh <- IoCopyBidirectionalHalfClose(proxyUp, proxyDown, 100*time.Millisecond) }()

	serverSawEOF := make(chan struct{})
	go func() {
		_, _ = io.ReadAll(server) // never replies and never closes
		close(serverSawEOF)
	}()
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-serverSawEOF:
	case <-time.After(3 * time.Second):
		t.Fatal("server did not observe the propagated EOF")
	}
	select {
	case <-errCh:
	case <-time.After(3 * time.Second):
		t.Fatal("idle half-closed relay was not bounded")
	}
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadAll(client); err != nil {
		t.Fatalf("client read after relay ended = %v; want EOF", err)
	}
}

type errReader struct {
	err error
}

func (r errReader) Read([]byte) (int, error) { return 0, r.err }
