package mitmproxy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

const tlsRecordHeaderLen = 5

var errClientHelloRecordNotCaptured = errors.New("client hello record not captured")

type tlsRecordCapture struct {
	mu   sync.Mutex
	raw  []byte
	want int
}

func (c *tlsRecordCapture) Record(data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for len(data) > 0 {
		if c.want > 0 && len(c.raw) >= c.want {
			return
		}

		if len(c.raw) < tlsRecordHeaderLen {
			n := min(tlsRecordHeaderLen-len(c.raw), len(data))
			c.raw = append(c.raw, data[:n]...)
			data = data[n:]
			if len(c.raw) < tlsRecordHeaderLen {
				return
			}
			c.want = tlsRecordHeaderLen + int(binary.BigEndian.Uint16(c.raw[3:5]))
		}

		n := min(c.want-len(c.raw), len(data))
		if n <= 0 {
			return
		}
		c.raw = append(c.raw, data[:n]...)
		data = data[n:]
	}
}

func (c *tlsRecordCapture) RawClientHello() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.raw) < tlsRecordHeaderLen {
		return nil, fmt.Errorf("%w: header has %d bytes", errClientHelloRecordNotCaptured, len(c.raw))
	}
	if c.raw[0] != 0x16 {
		return nil, fmt.Errorf("%w: first record type is %#x", errClientHelloRecordNotCaptured, c.raw[0])
	}
	if c.want == 0 {
		return nil, errClientHelloRecordNotCaptured
	}
	if len(c.raw) < c.want {
		return nil, fmt.Errorf("%w: got %d bytes, want %d", errClientHelloRecordNotCaptured, len(c.raw), c.want)
	}
	raw := make([]byte, c.want)
	copy(raw, c.raw[:c.want])
	return raw, nil
}

type clientHelloCaptureConn struct {
	net.Conn
	capture tlsRecordCapture
}

func newClientHelloCaptureConn(conn net.Conn) *clientHelloCaptureConn {
	return &clientHelloCaptureConn{Conn: conn}
}

func (c *clientHelloCaptureConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.capture.Record(p[:n])
	}
	return n, err
}

func (c *clientHelloCaptureConn) RawClientHello() ([]byte, error) {
	return c.capture.RawClientHello()
}

func filteredClientHelloProtos(protos []string, disableHTTP2 bool) []string {
	filtered := slices.Clone(protos)
	if disableHTTP2 {
		filtered = slices.DeleteFunc(filtered, func(proto string) bool {
			return proto == http2.NextProtoTLS
		})
	}
	return filtered
}

func patchClientHelloSpec(spec *utls.ClientHelloSpec, serverName string, protos []string) {
	if spec == nil {
		return
	}
	filteredExtensions := spec.Extensions[:0]
	for _, ext := range spec.Extensions {
		switch e := ext.(type) {
		case *utls.SNIExtension:
			e.ServerName = serverName
		case *utls.ALPNExtension:
			if len(protos) == 0 {
				continue
			}
			e.AlpnProtocols = slices.Clone(protos)
		}
		filteredExtensions = append(filteredExtensions, ext)
	}
	spec.Extensions = filteredExtensions
}

var tlsFingerprinter = &utls.Fingerprinter{
	AllowBluntMimicry: true,
	RealPSKResumption: false,
}

func clientHelloSpecFromRaw(raw []byte, serverName string, protos []string) (*utls.ClientHelloSpec, error) {
	spec, err := tlsFingerprinter.FingerprintClientHello(raw)
	if err != nil {
		return nil, fmt.Errorf("fingerprint client hello: %w", err)
	}
	patchClientHelloSpec(spec, serverName, protos)
	return spec, nil
}
