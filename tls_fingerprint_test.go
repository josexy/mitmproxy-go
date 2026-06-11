package mitmproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/josexy/mitmproxy-go/internal/cert"
	utls "github.com/refraction-networking/utls"
)

type readChunkConn struct {
	*bytes.Reader
	maxChunk int
}

func (c *readChunkConn) Read(p []byte) (int, error) {
	if c.maxChunk > 0 && len(p) > c.maxChunk {
		p = p[:c.maxChunk]
	}
	return c.Reader.Read(p)
}

func (c *readChunkConn) Write([]byte) (int, error)       { return 0, io.ErrClosedPipe }
func (c *readChunkConn) Close() error                    { return nil }
func (c *readChunkConn) LocalAddr() net.Addr             { return fingerprintDummyAddr("local") }
func (c *readChunkConn) RemoteAddr() net.Addr            { return fingerprintDummyAddr("remote") }
func (c *readChunkConn) SetDeadline(time.Time) error     { return nil }
func (c *readChunkConn) SetReadDeadline(time.Time) error { return nil }
func (c *readChunkConn) SetWriteDeadline(time.Time) error {
	return nil
}

type fingerprintDummyAddr string

func (a fingerprintDummyAddr) Network() string { return string(a) }
func (a fingerprintDummyAddr) String() string  { return string(a) }

func TestClientHelloCaptureConnCapturesExactlyFirstRecord(t *testing.T) {
	record := []byte{0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04}
	extra := []byte{0x17, 0x03, 0x03, 0x00, 0x01, 0xff}
	input := append(append([]byte{}, record...), extra...)
	conn := newClientHelloCaptureConn(&readChunkConn{Reader: bytes.NewReader(input)})

	buf := make([]byte, len(input))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if n != len(input) {
		t.Fatalf("Read n = %d, want %d", n, len(input))
	}
	if !bytes.Equal(buf[:n], input) {
		t.Fatalf("read data changed: got %x want %x", buf[:n], input)
	}

	raw, err := conn.RawClientHello()
	if err != nil {
		t.Fatalf("RawClientHello: %v", err)
	}
	if !bytes.Equal(raw, record) {
		t.Fatalf("raw = %x, want %x", raw, record)
	}
}

func TestTLSRecordCaptureStopsRecordingAfterDone(t *testing.T) {
	record := []byte{0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04}
	extra := []byte{0x17, 0x03, 0x03, 0x00, 0x01, 0xff}

	var capture tlsRecordCapture
	capture.Record(record)
	if !capture.Done() {
		t.Fatal("capture was not marked done after a complete record")
	}
	capture.Record(extra)

	raw, err := capture.RawClientHello()
	if err != nil {
		t.Fatalf("RawClientHello: %v", err)
	}
	if !bytes.Equal(raw, record) {
		t.Fatalf("raw = %x, want %x", raw, record)
	}
}

func TestClientHelloCaptureConnHandlesSplitReads(t *testing.T) {
	record := []byte{0x16, 0x03, 0x03, 0x00, 0x06, 0x01, 0x00, 0x00, 0x02, 0xab, 0xcd}
	conn := newClientHelloCaptureConn(&readChunkConn{
		Reader:   bytes.NewReader(record),
		maxChunk: 2,
	})

	buf := make([]byte, 16)
	for {
		_, err := conn.Read(buf)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		if raw, err := conn.RawClientHello(); err == nil {
			if !bytes.Equal(raw, record) {
				t.Fatalf("raw = %x, want %x", raw, record)
			}
			return
		}
	}
	t.Fatal("record was not captured")
}

func TestFilteredClientHelloProtos(t *testing.T) {
	protos := []string{"h2", "http/1.1"}
	got := filteredClientHelloProtos(protos, true)
	if !reflect.DeepEqual(got, []string{"http/1.1"}) {
		t.Fatalf("filtered protos = %v, want [http/1.1]", got)
	}
	if !reflect.DeepEqual(protos, []string{"h2", "http/1.1"}) {
		t.Fatalf("input protos mutated: %v", protos)
	}
}

func TestPatchClientHelloSpecUpdatesExistingSNIAndALPN(t *testing.T) {
	spec := &utls.ClientHelloSpec{
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{ServerName: "old.example"},
			&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
		},
	}

	patchClientHelloSpec(spec, "new.example", []string{"http/1.1"})

	sni, ok := spec.Extensions[0].(*utls.SNIExtension)
	if !ok || sni.ServerName != "new.example" {
		t.Fatalf("SNI extension = %#v, want new.example", spec.Extensions[0])
	}
	alpn, ok := spec.Extensions[1].(*utls.ALPNExtension)
	if !ok || !reflect.DeepEqual(alpn.AlpnProtocols, []string{"http/1.1"}) {
		t.Fatalf("ALPN extension = %#v, want [http/1.1]", spec.Extensions[1])
	}
}

func TestPatchClientHelloSpecDoesNotAddMissingExtensions(t *testing.T) {
	spec := &utls.ClientHelloSpec{
		Extensions: []utls.TLSExtension{
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{utls.X25519}},
		},
	}

	patchClientHelloSpec(spec, "new.example", []string{"http/1.1"})

	for _, ext := range spec.Extensions {
		switch ext.(type) {
		case *utls.SNIExtension:
			t.Fatal("patchClientHelloSpec added SNI extension")
		case *utls.ALPNExtension:
			t.Fatal("patchClientHelloSpec added ALPN extension")
		}
	}
}

func TestPatchClientHelloSpecRemovesEmptyALPN(t *testing.T) {
	spec := &utls.ClientHelloSpec{
		Extensions: []utls.TLSExtension{
			&utls.ALPNExtension{AlpnProtocols: []string{"h2"}},
			&utls.SNIExtension{ServerName: "old.example"},
		},
	}

	patchClientHelloSpec(spec, "new.example", nil)

	if len(spec.Extensions) != 1 {
		t.Fatalf("extensions len = %d, want 1", len(spec.Extensions))
	}
	if _, ok := spec.Extensions[0].(*utls.SNIExtension); !ok {
		t.Fatalf("remaining extension = %#v, want SNI", spec.Extensions[0])
	}
}

type writeCaptureConn struct {
	net.Conn
	capture tlsRecordCapture
}

func (c *writeCaptureConn) Write(p []byte) (int, error) {
	if len(p) > 0 {
		c.capture.Record(p)
	}
	return c.Conn.Write(p)
}

func (c *writeCaptureConn) RawClientHello() ([]byte, error) {
	return c.capture.RawClientHello()
}

func TestStrictUTLSMirroringThroughProxy(t *testing.T) {
	dir := t.TempDir()
	caCertPath, caKeyPath, serverCertPath, serverKeyPath := writeTestCertificates(t, dir)
	originAddr, originRawCh, closeOrigin := startRawClientHelloOrigin(t, serverCertPath, serverKeyPath)
	defer closeOrigin()

	errCh := make(chan error, 4)
	handler, err := NewMitmProxyHandler(
		WithCACertPath(caCertPath),
		WithCAKeyPath(caKeyPath),
		WithRootCAs(serverCertPath),
		WithErrorHandler(func(ec ErrorContext) {
			select {
			case errCh <- ec.Error:
			default:
			}
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Cleanup()

	proxyLn := listenLocalhostForFingerprintTest(t)
	proxyServer := &http.Server{Handler: handler}
	go func() {
		if err := proxyServer.Serve(proxyLn); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()
	defer proxyServer.Close()

	clientRaw := sendUTLSHTTPThroughProxy(t, proxyLn.Addr().String(), originAddr, nil)
	originRaw := receiveRawClientHello(t, originRawCh)

	clientSpec := fingerprintRawClientHello(t, clientRaw)
	originSpec := fingerprintRawClientHello(t, originRaw)

	if !reflect.DeepEqual(originSpec.CipherSuites, clientSpec.CipherSuites) {
		t.Fatalf("upstream cipher suites = %v, want %v", originSpec.CipherSuites, clientSpec.CipherSuites)
	}
	gotExtIDs := clientHelloExtensionIDsFromRaw(t, originRaw)
	wantExtIDs := clientHelloExtensionIDsFromRaw(t, clientRaw)
	if !reflect.DeepEqual(gotExtIDs, wantExtIDs) {
		t.Fatalf("upstream extension IDs = %v, want %v", gotExtIDs, wantExtIDs)
	}
	select {
	case err := <-errCh:
		t.Fatalf("unexpected proxy error: %v", err)
	default:
	}
}

func TestStrictUTLSMirroringFailsWithoutFallback(t *testing.T) {
	raw := []byte{0x16, 0x03, 0x03, 0x00, 0x01, 0x01}
	_, err := clientHelloSpecFromRaw(raw, "localhost", []string{"http/1.1"})
	if err == nil {
		t.Fatal("malformed ClientHello unexpectedly succeeded")
	}
	if !strings.Contains(err.Error(), "fingerprint client hello") {
		t.Fatalf("err = %v, want fingerprint client hello error", err)
	}
}

func writeTestCertificates(t *testing.T, dir string) (caCertPath, caKeyPath, serverCertPath, serverKeyPath string) {
	t.Helper()

	caCertPath = filepath.Join(dir, "ca.crt")
	caKeyPath = filepath.Join(dir, "ca.key")
	serverCertPath = filepath.Join(dir, "server.crt")
	serverKeyPath = filepath.Join(dir, "server.key")

	caCert, err := cert.NewCaBuilder().
		Subject(pkix.Name{CommonName: "example.ca.com"}).
		ValidateDays(3650).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	keyPem, certPem := caCert.Pem()
	if err := os.WriteFile(caCertPath, certPem, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caKeyPath, keyPem, 0644); err != nil {
		t.Fatal(err)
	}

	serverCert, err := cert.NewCertificateBuilder().
		Subject(pkix.Name{CommonName: "localhost"}).
		IPAddresses([]net.IP{net.ParseIP("127.0.0.1")}).
		DNSNames([]string{"localhost"}).
		ValidateDays(365).
		ServerAuth().
		BuildFromCA(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyPem, certPem = serverCert.Pem()
	if err := os.WriteFile(serverCertPath, certPem, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(serverKeyPath, keyPem, 0644); err != nil {
		t.Fatal(err)
	}
	return
}

func startRawClientHelloOrigin(t *testing.T, certPath, keyPath string) (string, <-chan []byte, func()) {
	t.Helper()
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	ln := listenLocalhostForFingerprintTest(t)
	rawCh := make(chan []byte, 2)
	done := make(chan struct{})

	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				captureConn := newClientHelloCaptureConn(conn)
				tlsConn := tls.Server(captureConn, &tls.Config{
					Certificates: []tls.Certificate{certificate},
					NextProtos:   []string{"http/1.1"},
				})
				defer tlsConn.Close()
				if err := tlsConn.Handshake(); err != nil {
					return
				}
				raw, err := captureConn.RawClientHello()
				if err == nil {
					rawCh <- raw
				}
				req, err := http.ReadRequest(bufio.NewReader(tlsConn))
				if err != nil {
					return
				}
				_, _ = io.Copy(io.Discard, req.Body)
				_ = req.Body.Close()
				_, _ = tlsConn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"))
			}(conn)
		}
	}()

	return ln.Addr().String(), rawCh, func() {
		_ = ln.Close()
		<-done
	}
}

func listenLocalhostForFingerprintTest(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

func sendUTLSHTTPThroughProxy(t *testing.T, proxyAddr, originAddr string, spec *utls.ClientHelloSpec) []byte {
	t.Helper()
	if spec == nil {
		baseSpec, err := utls.UTLSIdToSpec(utls.HelloFirefox_120)
		if err != nil {
			t.Fatal(err)
		}
		spec = &baseSpec
	}
	conn := connectProxyTunnel(t, proxyAddr, originAddr)
	captureConn := &writeCaptureConn{Conn: conn}
	uconn := utls.UClient(captureConn, &utls.Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	}, utls.HelloCustom)
	if err := uconn.ApplyPreset(spec); err != nil {
		t.Fatalf("ApplyPreset: %v", err)
	}
	if err := uconn.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	raw, err := captureConn.RawClientHello()
	if err != nil {
		t.Fatalf("client raw hello: %v", err)
	}
	_, err = fmt.Fprintf(uconn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", originAddr)
	if err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(uconn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	_ = uconn.Close()
	return raw
}

func connectProxyTunnel(t *testing.T, proxyAddr, originAddr string) net.Conn {
	t.Helper()
	conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(context.Background(), "tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	connectReq := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: originAddr},
		Host:   originAddr,
	}
	if err := connectReq.Write(conn); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), connectReq)
	if err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		t.Fatalf("CONNECT status = %s, want 200", resp.Status)
	}
	return conn
}

func receiveRawClientHello(t *testing.T, rawCh <-chan []byte) []byte {
	t.Helper()
	select {
	case raw := <-rawCh:
		return raw
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for upstream ClientHello")
	}
	return nil
}

func fingerprintRawClientHello(t *testing.T, raw []byte) *utls.ClientHelloSpec {
	t.Helper()
	spec, err := (&utls.Fingerprinter{}).RawClientHello(raw)
	if err != nil {
		t.Fatalf("fingerprint raw ClientHello: %v", err)
	}
	return spec
}

func clientHelloExtensionIDsFromRaw(t *testing.T, raw []byte) []uint16 {
	t.Helper()
	extensions := rawClientHelloExtensions(t, raw)
	ids := make([]uint16, 0)
	for len(extensions) > 0 {
		if len(extensions) < 4 {
			t.Fatalf("truncated extension header: %x", extensions)
		}
		id := binary.BigEndian.Uint16(extensions[:2])
		extLen := int(binary.BigEndian.Uint16(extensions[2:4]))
		extensions = extensions[4:]
		if len(extensions) < extLen {
			t.Fatalf("truncated extension %d: got %d bytes, want %d", id, len(extensions), extLen)
		}
		ids = append(ids, id)
		extensions = extensions[extLen:]
	}
	return ids
}

func rawClientHelloExtensions(t *testing.T, raw []byte) []byte {
	t.Helper()
	if len(raw) < tlsRecordHeaderLen+4+2+32 {
		t.Fatalf("raw ClientHello too short: %d", len(raw))
	}
	if raw[0] != 0x16 || raw[5] != 0x01 {
		t.Fatalf("raw data is not a ClientHello record: %x", raw[:min(len(raw), 6)])
	}
	pos := tlsRecordHeaderLen + 4 + 2 + 32
	if len(raw) < pos+1 {
		t.Fatalf("missing session id length")
	}
	sessionIDLen := int(raw[pos])
	pos++
	pos += sessionIDLen
	if len(raw) < pos+2 {
		t.Fatalf("missing cipher suite length")
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(raw[pos : pos+2]))
	pos += 2 + cipherSuitesLen
	if len(raw) < pos+1 {
		t.Fatalf("missing compression methods length")
	}
	compressionMethodsLen := int(raw[pos])
	pos++
	pos += compressionMethodsLen
	if len(raw) == pos {
		return nil
	}
	if len(raw) < pos+2 {
		t.Fatalf("missing extensions length")
	}
	extensionsLen := int(binary.BigEndian.Uint16(raw[pos : pos+2]))
	pos += 2
	if len(raw) < pos+extensionsLen {
		t.Fatalf("truncated extensions: got %d bytes, want %d", len(raw)-pos, extensionsLen)
	}
	return raw[pos : pos+extensionsLen]
}
