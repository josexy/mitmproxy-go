package mitmproxy

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/josexy/mitmproxy-go/buf"
)

func TestParseAddressForSocks5(t *testing.T) {
	tests := []struct {
		name     string
		packet   []byte
		host     string
		port     uint16
		wantErr  error
		baseSize int
		offset   int
	}{
		{
			name:     "domain",
			packet:   []byte{0x03, 0x0b, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0x01, 0xbb},
			host:     "example.com",
			port:     443,
			baseSize: 32,
			offset:   0,
		},
		{
			name:     "ipv4",
			packet:   []byte{0x01, 127, 0, 0, 1, 0x1f, 0x90},
			host:     "127.0.0.1",
			port:     8080,
			baseSize: 8,
			offset:   0,
		},
		{
			name:     "ipv6",
			packet:   []byte{0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x00, 0x50},
			host:     "::1",
			port:     80,
			baseSize: 32,
			offset:   0,
		},
		{
			name:     "invalid address type",
			packet:   []byte{0x09},
			wantErr:  ErrInvalidSocks5Address,
			baseSize: 8,
			offset:   0,
		},
		{
			name:     "short read",
			packet:   []byte{},
			wantErr:  bytes.ErrTooLarge,
			baseSize: 8,
			offset:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := buf.NewSize(tt.baseSize)
			host, port, err := parseAddressForSocks5(bytes.NewReader(tt.packet), b, tt.offset)
			if tt.name == "short read" {
				if err == nil {
					t.Fatalf("expected short read error")
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v; want %v", err, tt.wantErr)
			}
			if host != tt.host || port != tt.port {
				t.Fatalf("host, port = %q, %d; want %q, %d", host, port, tt.host, tt.port)
			}
		})
	}
}

func TestSocks5HandshakeAndRequest(t *testing.T) {
	handler := &mitmProxyHandler{}

	t.Run("handshake success", func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()

		errCh := make(chan error, 1)
		go func() { errCh <- handler.handleSocks5Handshake(context.Background(), server) }()

		if _, err := client.Write([]byte{5, 1, 0}); err != nil {
			t.Fatalf("write handshake: %v", err)
		}
		reply := make([]byte, 2)
		if _, err := client.Read(reply); err != nil {
			t.Fatalf("read handshake reply: %v", err)
		}
		if !bytes.Equal(reply, []byte{5, 0}) {
			t.Fatalf("handshake reply = %v; want [5 0]", reply)
		}
		if err := <-errCh; err != nil {
			t.Fatalf("handshake err = %v", err)
		}
	})

	t.Run("invalid handshake version", func(t *testing.T) {
		if err := handler.handleSocks5Handshake(context.Background(), bytesConn{Reader: bytes.NewReader([]byte{4})}); !errors.Is(err, ErrInvalidSocks5Version) {
			t.Fatalf("err = %v; want ErrInvalidSocks5Version", err)
		}
	})

	t.Run("request success", func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()

		errCh := make(chan error, 1)
		hostCh := make(chan string, 1)
		go func() {
			host, err := handler.handleSocks5Request(context.Background(), server)
			hostCh <- host
			errCh <- err
		}()

		packet := []byte{5, 1, 0, 3, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0x01, 0xbb}
		if _, err := client.Write(packet); err != nil {
			t.Fatalf("write request: %v", err)
		}
		reply := make([]byte, 10)
		if _, err := client.Read(reply); err != nil {
			t.Fatalf("read request reply: %v", err)
		}
		if !bytes.Equal(reply, []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}) {
			t.Fatalf("request reply = %v", reply)
		}
		if err := <-errCh; err != nil {
			t.Fatalf("request err = %v", err)
		}
		if host := <-hostCh; host != "example.com:443" {
			t.Fatalf("hostport = %q; want example.com:443", host)
		}
	})

	t.Run("unsupported command", func(t *testing.T) {
		packet := []byte{5, 2, 0, 1, 127, 0, 0, 1, 0, 80}
		conn := bytesConn{Reader: bytes.NewReader(packet)}
		if _, err := handler.handleSocks5Request(context.Background(), conn); !errors.Is(err, ErrUnsupportedSocks5Command) {
			t.Fatalf("err = %v; want ErrUnsupportedSocks5Command", err)
		}
	})
}

type bytesConn struct {
	*bytes.Reader
	bytes.Buffer
}

func (c bytesConn) Read(p []byte) (int, error)       { return c.Reader.Read(p) }
func (c bytesConn) Write(p []byte) (int, error)      { return c.Buffer.Write(p) }
func (c bytesConn) Close() error                     { return nil }
func (c bytesConn) LocalAddr() net.Addr              { return dummyAddr("local") }
func (c bytesConn) RemoteAddr() net.Addr             { return dummyAddr("remote") }
func (c bytesConn) SetDeadline(time.Time) error      { return nil }
func (c bytesConn) SetReadDeadline(time.Time) error  { return nil }
func (c bytesConn) SetWriteDeadline(time.Time) error { return nil }

type dummyAddr string

func (a dummyAddr) Network() string { return string(a) }
func (a dummyAddr) String() string  { return string(a) }
