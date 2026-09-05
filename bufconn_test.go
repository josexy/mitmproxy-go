package mitmproxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	mitmbuf "github.com/josexy/mitmproxy-go/v2/buf"
)

func TestBoundedHTTPRequestReaderRejectsOversizedHeader(t *testing.T) {
	reader := newBoundedHTTPRequestReader(strings.NewReader(
		"GET / HTTP/1.1\r\nHost: example.test\r\nX-Large: " + strings.Repeat("x", 64) + "\r\n\r\n",
	))
	_, err := reader.ReadRequest(48)
	if !errors.Is(err, ErrHTTPHeaderTooLarge) {
		t.Fatalf("err = %v; want ErrHTTPHeaderTooLarge", err)
	}
}

func TestBoundedHTTPRequestReaderPreservesBodyAndNextRequest(t *testing.T) {
	raw := "POST /one HTTP/1.1\r\nHost: example.test\r\nContent-Length: 4\r\n\r\ndata" +
		"GET /two HTTP/1.1\r\nHost: example.test\r\n\r\n"
	reader := newBoundedHTTPRequestReader(strings.NewReader(raw))

	first, err := reader.ReadRequest(1024)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(first.Body)
	if err != nil || string(body) != "data" {
		t.Fatalf("body = %q, err = %v; want data", body, err)
	}
	second, err := reader.ReadRequest(1024)
	if err != nil {
		t.Fatal(err)
	}
	if second.URL.Path != "/two" {
		t.Fatalf("path = %q; want /two", second.URL.Path)
	}
}

func TestBoundedHTTPHeaderConnStopsLimitingAfterHeader(t *testing.T) {
	raw := &bytesConn{Reader: bytes.NewReader([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n" + strings.Repeat("x", 128)))}
	data, err := io.ReadAll(newBoundedHTTPHeaderConn(raw, 64))
	if err != nil {
		t.Fatal(err)
	}
	if len(data) <= 64 {
		t.Fatalf("read %d bytes; payload after header was still limited", len(data))
	}
}

func TestBoundedHTTPHeaderConnRejectsOversizedHeader(t *testing.T) {
	raw := &bytesConn{Reader: bytes.NewReader([]byte("HTTP/1.1 101 Switching Protocols\r\nX-Large: " + strings.Repeat("x", 128)))}
	_, err := io.ReadAll(newBoundedHTTPHeaderConn(raw, 64))
	if !errors.Is(err, ErrHTTPHeaderTooLarge) {
		t.Fatalf("err = %v; want ErrHTTPHeaderTooLarge", err)
	}
}

func TestWebsocketWatcherEnforcesBufferedByteBudget(t *testing.T) {
	watcher := &wsFramesWatcherImpl{
		framesCh:       make(chan WsFrame, 2),
		maxBuffered:    4,
		budgetReleased: make(chan struct{}, 1),
	}
	first := &wsFrameImpl{dataBuf: mitmbuf.As([]byte("1234"))}
	if !watcher.send(context.Background(), first) {
		t.Fatal("first frame was not queued")
	}

	second := &wsFrameImpl{dataBuf: mitmbuf.As([]byte("5"))}
	sent := make(chan bool, 1)
	go func() { sent <- watcher.send(context.Background(), second) }()
	select {
	case <-sent:
		t.Fatal("second frame bypassed the byte budget")
	case <-time.After(20 * time.Millisecond):
	}

	(<-watcher.Receive()).Release()
	select {
	case ok := <-sent:
		if !ok {
			t.Fatal("second frame was not queued after budget release")
		}
	case <-time.After(time.Second):
		t.Fatal("second frame remained blocked")
	}
	watcher.close()
	if got := watcher.bufferedBytes.Load(); got != 0 {
		t.Fatalf("buffered bytes = %d; want 0", got)
	}
}

func TestWebsocketWatcherReleasesOriginalReservedSizeAfterMutation(t *testing.T) {
	watcher := &wsFramesWatcherImpl{
		framesCh:       make(chan WsFrame, 1),
		maxBuffered:    8,
		budgetReleased: make(chan struct{}, 1),
	}
	frame := &wsFrameImpl{dataBuf: mitmbuf.As([]byte("1234"))}
	if !watcher.send(context.Background(), frame) {
		t.Fatal("frame was not queued")
	}
	received := (<-watcher.Receive()).(*wsFrameImpl)
	received.dataBuf.Truncate(1)
	received.Release()
	if got := watcher.bufferedBytes.Load(); got != 0 {
		t.Fatalf("buffered bytes = %d; want 0", got)
	}
}

func TestReleasedWebsocketFrameCannotBeInvoked(t *testing.T) {
	frame := &wsFrameImpl{dataBuf: mitmbuf.As([]byte("data"))}
	frame.Release()
	if err := frame.Invoke(); !errors.Is(err, ErrWebsocketFrameReleased) {
		t.Fatalf("Invoke err = %v; want ErrWebsocketFrameReleased", err)
	}
}
