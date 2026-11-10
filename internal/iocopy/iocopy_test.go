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

// A client that closes or half-closes ends the relay: its data reaches
// upstream, and then both connections close at once rather than waiting for
// upstream, which here never replies and never closes.
func TestIoCopyBidirectionalClientEndClosesUpstream(t *testing.T) {
	for _, mode := range []struct {
		name string
		end  func(*net.TCPConn) error
	}{
		{"close", (*net.TCPConn).Close},
		{"half-close", (*net.TCPConn).CloseWrite},
	} {
		t.Run(mode.name, func(t *testing.T) {
			client, proxyDown := tcpPair(t)
			proxyUp, server := tcpPair(t)
			errCh := make(chan error, 1)
			// No idle timeout: only the client's end may stop the relay.
			go func() { errCh <- IoCopyBidirectionalHalfClose(proxyUp, proxyDown, 0) }()

			serverGot := make(chan string, 1)
			go func() {
				data, _ := io.ReadAll(server)
				serverGot <- string(data)
			}()
			if _, err := client.Write([]byte("request")); err != nil {
				t.Fatal(err)
			}
			if err := mode.end(client); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-errCh:
				if err != nil {
					t.Fatalf("IoCopyBidirectionalHalfClose = %v; want nil", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("relay kept upstream open after the client ended")
			}
			select {
			case got := <-serverGot:
				if got != "request" {
					t.Fatalf("upstream received %q; want request", got)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("upstream connection was not closed")
			}
		})
	}
}

// When upstream shuts down its sending side, the client reads every byte and
// then EOF, while its own data keeps reaching upstream until it closes.
func TestIoCopyBidirectionalForwardsUpstreamHalfClose(t *testing.T) {
	client, proxyDown := tcpPair(t)
	proxyUp, server := tcpPair(t)
	errCh := make(chan error, 1)
	go func() { errCh <- IoCopyBidirectionalHalfClose(proxyUp, proxyDown, time.Second) }()

	serverGot := make(chan string, 1)
	go func() {
		request := make([]byte, len("request"))
		if _, err := io.ReadFull(server, request); err != nil {
			serverGot <- "read request: " + err.Error()
			return
		}
		_, _ = server.Write([]byte("reply"))
		_ = server.CloseWrite()
		rest, _ := io.ReadAll(server)
		serverGot <- string(rest)
	}()
	if _, err := client.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	reply, err := io.ReadAll(client)
	if err != nil || string(reply) != "reply" {
		t.Fatalf("reply = %q, %v; want reply then EOF", reply, err)
	}
	if _, err := client.Write([]byte("more")); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-serverGot:
		if got != "more" {
			t.Fatalf("upstream received %q after its half-close; want more", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("upstream did not receive the client's data after its half-close")
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("IoCopyBidirectionalHalfClose = %v; want nil", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not return after the client closed")
	}
}

// After upstream half-closes, a client that stays silent must not pin the relay.
func TestIoCopyBidirectionalBoundsHalfClosedIdleDirection(t *testing.T) {
	client, proxyDown := tcpPair(t)
	proxyUp, server := tcpPair(t)
	errCh := make(chan error, 1)
	go func() { errCh <- IoCopyBidirectionalHalfClose(proxyUp, proxyDown, 100*time.Millisecond) }()

	if err := server.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = io.ReadAll(server) }()
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	if data, err := io.ReadAll(client); err != nil || len(data) != 0 {
		t.Fatalf("client read = %q, %v; want the forwarded EOF", data, err)
	}
	select {
	case <-errCh:
	case <-time.After(3 * time.Second):
		t.Fatal("idle client after the upstream half-close was not bounded")
	}
}

type errReader struct {
	err error
}

func (r errReader) Read([]byte) (int, error) { return 0, r.err }
