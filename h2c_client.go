package mitmproxy

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"strconv"
	"sync"

	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const h2cUpgradeStreamID = 1

func shouldUseUpstreamH2CUpgrade(req *http.Request, disableHTTP2 bool) bool {
	return !disableHTTP2 &&
		req != nil &&
		req.URL != nil &&
		req.URL.Scheme == "http" &&
		req.ProtoMajor == 1 &&
		isH2CUpgrade(req.Header)
}

func (t *singleConnTransport) roundTripH2CUpgrade(req *http.Request) (_ *http.Response, retErr error) {
	conn, err := t.dialSingleUseConn(req.Context())
	if err != nil {
		return nil, err
	}
	owned := true
	defer func() {
		if owned {
			t.untrackSingleUseConn(conn)
			_ = conn.Close()
		}
	}()

	br := bufio.NewReader(conn)
	bw := bufio.NewWriter(conn)
	if err := req.Write(bw); err != nil {
		return nil, fmt.Errorf("write h2c upgrade request failed: %w", err)
	}
	if err := bw.Flush(); err != nil {
		return nil, fmt.Errorf("flush h2c upgrade request failed: %w", err)
	}

	upgradeResp, err := http.ReadResponse(br, req)
	if err != nil {
		return nil, fmt.Errorf("read h2c upgrade response failed: %w", err)
	}
	if upgradeResp.StatusCode != http.StatusSwitchingProtocols {
		upgradeResp.Body = &singleUseResponseBody{
			ReadCloser: upgradeResp.Body,
			closeFn: func() {
				t.untrackSingleUseConn(conn)
				_ = conn.Close()
			},
		}
		upgradeResp.Close = true
		owned = false
		return upgradeResp, nil
	}
	_ = upgradeResp.Body.Close()
	if !isH2CUpgradeResponse(upgradeResp.Header) {
		return nil, fmt.Errorf("upstream returned non-h2c switching protocols response: %s", upgradeResp.Status)
	}

	rw := bufio.NewReadWriter(br, bufio.NewWriter(conn))
	h2Conn := newBufConnExt(conn, rw)
	fr := http2.NewFramer(h2Conn, h2Conn)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)

	if _, err := h2Conn.Write([]byte(http2.ClientPreface)); err != nil {
		return nil, fmt.Errorf("write h2c client preface failed: %w", err)
	}
	if err := fr.WriteSettings(); err != nil {
		return nil, fmt.Errorf("write h2c client settings failed: %w", err)
	}

	headers, err := readH2CUpgradeResponseHeaders(fr)
	if err != nil {
		return nil, err
	}
	body := &h2cUpgradeResponseBody{
		fr:       fr,
		streamID: h2cUpgradeStreamID,
		trailer:  make(http.Header),
		done:     headers.StreamEnded(),
		closeFn: func() {
			t.untrackSingleUseConn(conn)
			_ = h2Conn.Close()
		},
	}
	resp, err := responseFromH2CUpgradeHeaders(req, headers, body)
	if err != nil {
		_ = body.Close()
		return nil, err
	}
	resp.Body = body
	resp.Trailer = body.trailer
	owned = false
	return resp, nil
}

func isH2CUpgradeResponse(h http.Header) bool {
	return httpguts.HeaderValuesContainsToken(h[textproto.CanonicalMIMEHeaderKey(HttpHeaderUpgrade)], "h2c") &&
		httpguts.HeaderValuesContainsToken(h[textproto.CanonicalMIMEHeaderKey(HttpHeaderConnection)], "Upgrade")
}

func readH2CUpgradeResponseHeaders(fr *http2.Framer) (*http2.MetaHeadersFrame, error) {
	for {
		frame, err := fr.ReadFrame()
		if err != nil {
			return nil, fmt.Errorf("read h2c response headers failed: %w", err)
		}
		switch f := frame.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				if err := fr.WriteSettingsAck(); err != nil {
					return nil, fmt.Errorf("ack h2c server settings failed: %w", err)
				}
			}
		case *http2.MetaHeadersFrame:
			if f.Header().StreamID == h2cUpgradeStreamID {
				return f, nil
			}
		case *http2.RSTStreamFrame:
			if f.Header().StreamID == h2cUpgradeStreamID {
				return nil, fmt.Errorf("h2c stream reset before response headers: %s", f.ErrCode)
			}
		case *http2.GoAwayFrame:
			return nil, fmt.Errorf("h2c connection closed before response headers: %s", f.ErrCode)
		case *http2.DataFrame:
			if f.Header().StreamID == h2cUpgradeStreamID {
				return nil, fmt.Errorf("h2c data frame received before response headers")
			}
		}
	}
}

func responseFromH2CUpgradeHeaders(req *http.Request, mh *http2.MetaHeadersFrame, body io.ReadCloser) (*http.Response, error) {
	if mh.Truncated {
		return nil, fmt.Errorf("h2c response headers exceeded decoder limit")
	}
	statusText := mh.PseudoValue("status")
	statusCode, err := strconv.Atoi(statusText)
	if err != nil {
		return nil, fmt.Errorf("invalid h2c response status %q: %w", statusText, err)
	}

	header := make(http.Header)
	for _, hf := range mh.RegularFields() {
		header.Add(http.CanonicalHeaderKey(hf.Name), hf.Value)
	}
	contentLength := int64(-1)
	if value := header.Get(HttpHeaderContentLength); value != "" {
		if n, err := strconv.ParseInt(value, 10, 64); err == nil {
			contentLength = n
		}
	}

	status := fmt.Sprintf("%d %s", statusCode, http.StatusText(statusCode))
	if http.StatusText(statusCode) == "" {
		status = statusText
	}
	return &http.Response{
		Status:        status,
		StatusCode:    statusCode,
		Proto:         "HTTP/2.0",
		ProtoMajor:    2,
		ProtoMinor:    0,
		Header:        header,
		Body:          body,
		ContentLength: contentLength,
		Request:       req,
	}, nil
}

type singleUseResponseBody struct {
	io.ReadCloser
	closeOnce sync.Once
	closeFn   func()
}

func (b *singleUseResponseBody) Close() error {
	var err error
	b.closeOnce.Do(func() {
		err = b.ReadCloser.Close()
		if b.closeFn != nil {
			b.closeFn()
		}
	})
	return err
}

type h2cUpgradeResponseBody struct {
	fr        *http2.Framer
	streamID  uint32
	trailer   http.Header
	buf       bytes.Buffer
	done      bool
	closeOnce sync.Once
	closeFn   func()
}

func (b *h2cUpgradeResponseBody) Read(p []byte) (int, error) {
	if b.buf.Len() > 0 {
		return b.buf.Read(p)
	}
	if b.done {
		return 0, io.EOF
	}

	for {
		frame, err := b.fr.ReadFrame()
		if err != nil {
			return 0, fmt.Errorf("read h2c response body failed: %w", err)
		}
		switch f := frame.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				if err := b.fr.WriteSettingsAck(); err != nil {
					return 0, fmt.Errorf("ack h2c server settings failed: %w", err)
				}
			}
		case *http2.PingFrame:
			if !f.IsAck() {
				if err := b.fr.WritePing(true, f.Data); err != nil {
					return 0, fmt.Errorf("ack h2c ping failed: %w", err)
				}
			}
		case *http2.DataFrame:
			if f.Header().StreamID != b.streamID {
				continue
			}
			data := f.Data()
			if len(data) > 0 {
				if err := b.fr.WriteWindowUpdate(0, uint32(len(data))); err != nil {
					return 0, fmt.Errorf("write h2c connection window update failed: %w", err)
				}
				if err := b.fr.WriteWindowUpdate(b.streamID, uint32(len(data))); err != nil {
					return 0, fmt.Errorf("write h2c stream window update failed: %w", err)
				}
				_, _ = b.buf.Write(data)
			}
			if f.StreamEnded() {
				b.done = true
			}
			if b.buf.Len() > 0 {
				return b.buf.Read(p)
			}
			if b.done {
				return 0, io.EOF
			}
		case *http2.MetaHeadersFrame:
			if f.Header().StreamID != b.streamID {
				continue
			}
			for _, hf := range f.RegularFields() {
				b.trailer.Add(http.CanonicalHeaderKey(hf.Name), hf.Value)
			}
			if f.StreamEnded() {
				b.done = true
				return 0, io.EOF
			}
		case *http2.RSTStreamFrame:
			if f.Header().StreamID == b.streamID {
				return 0, fmt.Errorf("h2c stream reset while reading body: %s", f.ErrCode)
			}
		case *http2.GoAwayFrame:
			return 0, fmt.Errorf("h2c connection closed while reading body: %s", f.ErrCode)
		}
	}
}

func (b *h2cUpgradeResponseBody) Close() error {
	b.closeOnce.Do(func() {
		if b.closeFn != nil {
			b.closeFn()
		}
	})
	return nil
}
