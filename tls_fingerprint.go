package mitmproxy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/josexy/net/http2"
	utls "github.com/refraction-networking/utls"
)

const tlsRecordHeaderLen = 5
const tlsHandshakeHeaderLen = 4

var errClientHelloRecordNotCaptured = errors.New("client hello record not captured")

type tlsRecordCapture struct {
	mu               sync.Mutex
	done             atomic.Bool
	buf              []byte
	handshake        []byte
	wantHandshake    int
	recordVersion    [2]byte
	haveRecordHeader bool
	firstRecordType  byte
}

func (c *tlsRecordCapture) Done() bool {
	return c.done.Load()
}

func (c *tlsRecordCapture) Record(data []byte) {
	if c.done.Load() {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.done.Load() {
		return
	}
	c.buf = append(c.buf, data...)
	for {
		if c.wantHandshake > 0 && len(c.handshake) >= c.wantHandshake {
			c.handshake = c.handshake[:c.wantHandshake]
			c.done.Store(true)
			return
		}
		if len(c.buf) < tlsRecordHeaderLen {
			return
		}
		c.captureRecordHeader(c.buf[:tlsRecordHeaderLen])
		if c.firstRecordType != 0x16 {
			return
		}
		recordLen := int(binary.BigEndian.Uint16(c.buf[3:5]))
		if len(c.buf) < tlsRecordHeaderLen+recordLen {
			return
		}
		payload := c.buf[tlsRecordHeaderLen : tlsRecordHeaderLen+recordLen]
		c.buf = c.buf[tlsRecordHeaderLen+recordLen:]
		c.recordHandshakePayload(payload)
	}
}

func (c *tlsRecordCapture) RawClientHello() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.haveRecordHeader {
		return nil, fmt.Errorf("%w: header has %d bytes", errClientHelloRecordNotCaptured, len(c.buf))
	}
	if c.firstRecordType != 0x16 {
		return nil, fmt.Errorf("%w: first record type is %#x", errClientHelloRecordNotCaptured, c.firstRecordType)
	}
	if len(c.handshake) < tlsHandshakeHeaderLen {
		return nil, fmt.Errorf("%w: handshake header has %d bytes", errClientHelloRecordNotCaptured, len(c.handshake))
	}
	if c.handshake[0] != 0x01 {
		return nil, fmt.Errorf("%w: handshake type is %#x", errClientHelloRecordNotCaptured, c.handshake[0])
	}
	if c.wantHandshake == 0 {
		return nil, errClientHelloRecordNotCaptured
	}
	if len(c.handshake) < c.wantHandshake {
		return nil, fmt.Errorf("%w: got %d handshake bytes, want %d", errClientHelloRecordNotCaptured, len(c.handshake), c.wantHandshake)
	}
	raw := make([]byte, tlsRecordHeaderLen+c.wantHandshake)
	raw[0] = 0x16
	copy(raw[1:3], c.recordVersion[:])
	recordLen := min(c.wantHandshake, 0xffff)
	binary.BigEndian.PutUint16(raw[3:5], uint16(recordLen))
	copy(raw[tlsRecordHeaderLen:], c.handshake[:c.wantHandshake])
	c.done.Store(true)
	return raw, nil
}

func (c *tlsRecordCapture) captureRecordHeader(header []byte) {
	if c.haveRecordHeader {
		return
	}
	c.haveRecordHeader = true
	c.firstRecordType = header[0]
	copy(c.recordVersion[:], header[1:3])
}

func (c *tlsRecordCapture) recordHandshakePayload(payload []byte) {
	if len(payload) == 0 {
		return
	}
	if c.wantHandshake > 0 {
		remaining := c.wantHandshake - len(c.handshake)
		if remaining <= 0 {
			return
		}
		payload = payload[:min(remaining, len(payload))]
	}
	c.handshake = append(c.handshake, payload...)
	if c.wantHandshake == 0 && len(c.handshake) >= tlsHandshakeHeaderLen {
		c.wantHandshake = tlsHandshakeHeaderLen + int(c.handshake[1])<<16 + int(c.handshake[2])<<8 + int(c.handshake[3])
		if len(c.handshake) > c.wantHandshake {
			c.handshake = c.handshake[:c.wantHandshake]
		}
	}
	if c.wantHandshake > 0 && len(c.handshake) >= c.wantHandshake {
		c.done.Store(true)
	}
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
	if n > 0 && !c.capture.Done() {
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
