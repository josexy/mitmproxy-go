package mitmproxy

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"

	"golang.org/x/net/http/httpguts"
)

func isH2CUpgrade(h http.Header) bool {
	return httpguts.HeaderValuesContainsToken(h[textproto.CanonicalMIMEHeaderKey("Upgrade")], "h2c") &&
		httpguts.HeaderValuesContainsToken(h[textproto.CanonicalMIMEHeaderKey("Connection")], "HTTP2-Settings")
}

func initH2CWithPriorKnowledge(w http.ResponseWriter) (net.Conn, error) {
	rc := http.NewResponseController(w)
	conn, rw, err := rc.Hijack()
	if err != nil {
		return nil, err
	}

	const expectedBody = "SM\r\n\r\n"

	buf := make([]byte, len(expectedBody))
	n, err := io.ReadFull(rw, buf)
	if err != nil {
		return nil, fmt.Errorf("h2c: error reading client preface: %s", err)
	}

	if string(buf[:n]) == expectedBody {
		return newBufConnExt(conn, rw), nil
	}

	conn.Close()
	return nil, errors.New("h2c: invalid client preface")
}

// getH2Settings returns the settings in the HTTP2-Settings header.
func getH2Settings(h http.Header) ([]byte, error) {
	vals, ok := h[textproto.CanonicalMIMEHeaderKey("HTTP2-Settings")]
	if !ok {
		return nil, errors.New("missing HTTP2-Settings header")
	}
	if len(vals) != 1 {
		return nil, fmt.Errorf("expected 1 HTTP2-Settings. Got: %v", vals)
	}
	settings, err := base64.RawURLEncoding.DecodeString(vals[0])
	if err != nil {
		return nil, err
	}
	return settings, nil
}

func upgradeH2C(w http.ResponseWriter, r *http.Request) (_ net.Conn, settings []byte, err error) {
	settings, err = getH2Settings(r.Header)
	if err != nil {
		return nil, nil, err
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, nil, err
	}
	r.Body = io.NopCloser(bytes.NewBuffer(body))

	rc := http.NewResponseController(w)
	conn, rw, err := rc.Hijack()
	if err != nil {
		return nil, nil, err
	}

	rw.Write(H2CUpgradeResponseSwitchingProtocols)
	return newBufConnExt(conn, rw), settings, nil
}

func newBufConnExt(conn net.Conn, rw *bufio.ReadWriter) net.Conn {
	rw.Flush()
	if rw.Reader.Buffered() == 0 {
		// If there's no buffered data to be read,
		// we can just discard the bufio.ReadWriter.
		return conn
	}
	return &bufConnExt{conn, rw.Reader}
}

type bufConnExt struct {
	net.Conn
	*bufio.Reader
}

func (c *bufConnExt) Read(p []byte) (int, error) {
	if c.Reader == nil {
		return c.Conn.Read(p)
	}
	n := c.Reader.Buffered()
	if n == 0 {
		c.Reader = nil
		return c.Conn.Read(p)
	}
	if n < len(p) {
		p = p[:n]
	}
	return c.Reader.Read(p)
}
