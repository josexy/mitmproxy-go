package mitmproxy

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"time"

	http "github.com/josexy/xhttp"
	"golang.org/x/net/http/httpguts"
)

func isH2CUpgrade(h http.Header) bool {
	return httpguts.HeaderValuesContainsToken(h[textproto.CanonicalMIMEHeaderKey("Upgrade")], "h2c") &&
		httpguts.HeaderValuesContainsToken(h[textproto.CanonicalMIMEHeaderKey("Connection")], "HTTP2-Settings")
}

// initH2CWithPriorKnowledge reads the remainder of the client preface. The
// caller clears the request read deadline before handing the connection to the
// HTTP/2 server, so prefaceTimeout bounds these few bytes on their own.
func initH2CWithPriorKnowledge(w http.ResponseWriter, prefaceTimeout time.Duration) (net.Conn, error) {
	rc := http.NewResponseController(w)
	conn, rw, err := rc.Hijack()
	if err != nil {
		return nil, err
	}

	const expectedBody = "SM\r\n\r\n"

	clearDeadline := setReadDeadlineForTimeout(conn, prefaceTimeout)
	var buf [len(expectedBody)]byte
	for n := 0; n < len(buf); {
		read, err := rw.Read(buf[n:])
		if err != nil {
			clearDeadline()
			return nil, fmt.Errorf("h2c: error reading client preface: %s", err)
		}
		n += read
	}
	clearDeadline()

	if string(buf[:]) == expectedBody {
		conn = newBufConnExt(conn, rw)
		return &bufConnExt{
			Conn:   conn,
			Reader: bufio.NewReader(io.MultiReader(bytes.NewBufferString(http2ClientPreface), conn)),
		}, nil
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

// Read always goes through Reader once one is attached. Reader is layered on
// top of Conn, and it may itself sit on top of another buffered reader that
// still holds bytes (a pipelined request, the first bytes of a tunnelled TLS
// handshake). Falling back to Conn once Reader looks empty would strand those
// bytes in a buffer nobody reads again.
func (c *bufConnExt) Read(p []byte) (int, error) {
	if c.Reader == nil {
		return c.Conn.Read(p)
	}
	return c.Reader.Read(p)
}
