package mitmproxy

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"golang.org/x/net/http2"
	h2cserver "golang.org/x/net/http2/h2c"
	"golang.org/x/net/http2/hpack"
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

func TestH2CUpgradeProxyUpgradesClientAndUpstream(t *testing.T) {
	caCertPath, caKeyPath := writeTestCA(t)
	originErrCh := make(chan error, 1)
	originLn := listenLocalhostForH2C(t)
	settingsHeader := encodeHTTP2SettingsForUpgrade(t, http2.Setting{
		ID:  http2.SettingMaxConcurrentStreams,
		Val: 100,
	})

	origin := &http.Server{
		Handler: h2cserver.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ProtoMajor != 1 {
				reportOriginH2CTestError(w, originErrCh, fmt.Errorf("origin request proto = %s, want HTTP/1.1 upgrade", r.Proto))
				return
			}
			if !isH2CUpgrade(r.Header) ||
				r.Header.Get(HttpHeaderUpgrade) != "h2c" ||
				r.Header.Get(HttpHeaderHttp2Settings) != settingsHeader {
				reportOriginH2CTestError(w, originErrCh, fmt.Errorf("origin did not receive h2c upgrade headers: %v", r.Header))
				return
			}
			w.Header().Set("Trailer", "X-Origin-Trailer")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
			w.Header().Set("X-Origin-Trailer", "done")
		}), &http2.Server{}),
	}
	go func() {
		if err := origin.Serve(originLn); err != nil && err != http.ErrServerClosed {
			originErrCh <- err
		}
	}()
	defer origin.Close()

	handler, err := NewMitmProxyHandler(
		WithCACertPath(caCertPath),
		WithCAKeyPath(caKeyPath),
	)
	if err != nil {
		t.Fatal(err)
	}
	proxyLn := listenLocalhostForH2C(t)
	proxy := &http.Server{Handler: handler}
	go func() {
		if err := proxy.Serve(proxyLn); err != nil && err != http.ErrServerClosed {
			originErrCh <- err
		}
	}()
	defer proxy.Close()

	conn, err := net.DialTimeout("tcp", proxyLn.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	_, err = fmt.Fprintf(conn,
		"GET http://%s/trailers HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: h2c-upgrade-test\r\n"+
			"Accept: */*\r\n"+
			"Connection: Upgrade, HTTP2-Settings\r\n"+
			"Upgrade: h2c\r\n"+
			"HTTP2-Settings: %s\r\n\r\n",
		originLn.Addr().String(), originLn.Addr().String(), settingsHeader,
	)
	if err != nil {
		t.Fatal(err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade status = %s, want 101 Switching Protocols", resp.Status)
	}
	_ = resp.Body.Close()

	rw := bufio.NewReadWriter(br, bufio.NewWriter(conn))
	h2Conn := newBufConnExt(conn, rw)
	fr := http2.NewFramer(h2Conn, h2Conn)
	if _, err := h2Conn.Write([]byte(http2.ClientPreface)); err != nil {
		t.Fatal(err)
	}
	if err := fr.WriteSettings(); err != nil {
		t.Fatal(err)
	}

	_ = h2Conn.SetReadDeadline(time.Now().Add(time.Second))
	status, body, trailers := readH2Stream1Response(t, fr)
	select {
	case err := <-originErrCh:
		t.Fatalf("origin rejected upstream request: %v; h2 status=%q body=%q", err, status, body)
	default:
	}
	if status != "200" {
		t.Fatalf("h2 stream status = %q, want 200", status)
	}
	if string(body) != "ok" {
		t.Fatalf("h2 stream body = %q, want ok", body)
	}
	if trailers.Get("X-Origin-Trailer") != "done" {
		t.Fatalf("h2 stream trailer = %q, want done", trailers.Get("X-Origin-Trailer"))
	}

	assertNoOriginH2CTestError(t, originErrCh)
}

func encodeHTTP2SettingsForUpgrade(t *testing.T, settings ...http2.Setting) string {
	t.Helper()
	buf := make([]byte, 6*len(settings))
	for i, setting := range settings {
		off := i * 6
		binary.BigEndian.PutUint16(buf[off:], uint16(setting.ID))
		binary.BigEndian.PutUint32(buf[off+2:], setting.Val)
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

func readH2Stream1Response(t *testing.T, fr *http2.Framer) (string, []byte, http.Header) {
	t.Helper()
	decoder := hpack.NewDecoder(4096, nil)
	var status string
	var body bytes.Buffer
	trailers := make(http.Header)
	sawRegularHeaders := false

	for {
		frame, err := fr.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		switch f := frame.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				if err := fr.WriteSettingsAck(); err != nil {
					t.Fatal(err)
				}
			}
		case *http2.HeadersFrame:
			if f.Header().StreamID != 1 {
				continue
			}
			fields := decodeHeaderBlock(t, fr, decoder, f.HeaderBlockFragment(), f.HeadersEnded())
			if !sawRegularHeaders {
				sawRegularHeaders = true
				for _, hf := range fields {
					if hf.Name == ":status" {
						status = hf.Value
					}
				}
			} else {
				for _, hf := range fields {
					trailers.Add(http.CanonicalHeaderKey(hf.Name), hf.Value)
				}
			}
			if f.StreamEnded() {
				return status, body.Bytes(), trailers
			}
		case *http2.DataFrame:
			if f.Header().StreamID != 1 {
				continue
			}
			_, _ = body.Write(f.Data())
			if f.StreamEnded() {
				return status, body.Bytes(), trailers
			}
		case *http2.RSTStreamFrame:
			if f.Header().StreamID == 1 {
				t.Fatalf("stream 1 reset: %v", f.ErrCode)
			}
		case *http2.GoAwayFrame:
			t.Fatalf("connection goaway: %v %q", f.ErrCode, f.DebugData())
		}
	}
}

func decodeHeaderBlock(t *testing.T, fr *http2.Framer, decoder *hpack.Decoder, first []byte, endHeaders bool) []hpack.HeaderField {
	t.Helper()
	block := append([]byte(nil), first...)
	for !endHeaders {
		frame, err := fr.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		cont, ok := frame.(*http2.ContinuationFrame)
		if !ok || cont.Header().StreamID != 1 {
			t.Fatalf("frame = %T on stream %d, want continuation on stream 1", frame, frame.Header().StreamID)
		}
		block = append(block, cont.HeaderBlockFragment()...)
		endHeaders = cont.HeadersEnded()
	}
	fields, err := decoder.DecodeFull(block)
	if err != nil {
		t.Fatal(err)
	}
	return fields
}

func listenLocalhostForH2C(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

func reportOriginH2CTestError(w http.ResponseWriter, errCh chan<- error, err error) {
	select {
	case errCh <- err:
	default:
	}
	http.Error(w, err.Error(), http.StatusBadGateway)
}

func assertNoOriginH2CTestError(t *testing.T, errCh <-chan error) {
	t.Helper()
	select {
	case err := <-errCh:
		t.Fatal(err)
	default:
	}
}
