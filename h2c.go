package mitmproxy

import (
	"bufio"
	"errors"
	"fmt"
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

	var buf [len(expectedBody)]byte
	for n := 0; n < len(buf); {
		read, err := rw.Read(buf[n:])
		if err != nil {
			return nil, fmt.Errorf("h2c: error reading client preface: %s", err)
		}
		n += read
	}

	if string(buf[:]) == expectedBody {
		return newBufConnExt(conn, rw), nil
	}

	conn.Close()
	return nil, errors.New("h2c: invalid client preface")
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
