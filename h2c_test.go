package mitmproxy

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestIsH2CUpgrade(t *testing.T) {
	tests := []struct {
		name string
		h    http.Header
		want bool
	}{
		{
			name: "valid",
			h: http.Header{
				"Upgrade":    {"h2c"},
				"Connection": {"keep-alive, HTTP2-Settings"},
			},
			want: true,
		},
		{
			name: "missing settings token",
			h: http.Header{
				"Upgrade":    {"h2c"},
				"Connection": {"Upgrade"},
			},
			want: false,
		},
		{
			name: "wrong upgrade token",
			h: http.Header{
				"Upgrade":    {"websocket"},
				"Connection": {"HTTP2-Settings"},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isH2CUpgrade(tt.h); got != tt.want {
				t.Fatalf("isH2CUpgrade = %v; want %v", got, tt.want)
			}
		})
	}
}

func TestGetH2Settings(t *testing.T) {
	settings := []byte{0, 1, 2, 3}
	encoded := base64.RawURLEncoding.EncodeToString(settings)
	header := make(http.Header)
	header.Set("HTTP2-Settings", encoded)
	got, err := getH2Settings(header)
	if err != nil || !bytes.Equal(got, settings) {
		t.Fatalf("getH2Settings = %v, %v; want %v, nil", got, err, settings)
	}

	if _, err := getH2Settings(http.Header{}); err == nil {
		t.Fatalf("missing settings header should fail")
	}
	if _, err := getH2Settings(http.Header{"HTTP2-Settings": {"a", "b"}}); err == nil {
		t.Fatalf("multiple settings headers should fail")
	}
	if _, err := getH2Settings(http.Header{"HTTP2-Settings": {"!!!"}}); err == nil {
		t.Fatalf("invalid settings header should fail")
	}
}

func TestBufConnExtReadsBufferedBytesBeforeConn(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	reader := bufio.NewReader(bytes.NewBufferString("abc"))
	if _, err := reader.Peek(1); err != nil {
		t.Fatalf("prime buffered reader: %v", err)
	}
	rw := bufio.NewReadWriter(reader, bufio.NewWriter(ioDiscard{}))
	conn := newBufConnExt(client, rw)

	buf := make([]byte, 5)
	n, err := conn.Read(buf)
	if err != nil || string(buf[:n]) != "abc" {
		t.Fatalf("first Read = %d, %v, %q; want abc", n, err, buf[:n])
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = server.Write([]byte("de"))
	}()

	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	n, err = conn.Read(buf)
	if err != nil || string(buf[:n]) != "de" {
		t.Fatalf("second Read = %d, %v, %q; want de from underlying conn", n, err, buf[:n])
	}
	<-done
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) { return len(p), nil }
