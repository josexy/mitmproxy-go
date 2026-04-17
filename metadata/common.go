package metadata

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"time"
)

const (
	// StreamBody indicates whether the request/response body should be streamed when HTTP/2
	StreamBody = "stream_body"
	// LocalConnectionEstablishedTs is the timestamp when the client's connection was established
	LocalConnectionEstablishedTs = "local_connection_established_ts"
	// RemoteConnectionEstablishedTs is the timestamp when the connection to the remote server was established
	RemoteConnectionEstablishedTs = "remote_connection_established_ts"
	// RequestReceivedTs is the timestamp when the request was received and processed
	RequestReceivedTs = "request_received_ts"
	// SSLHandshakeCompletedTs is the timestamp when the SSL/TLS handshake completed
	SSLHandshakeCompletedTs = "ssl_handshake_completed_ts"
	// RequestHostport is the target host:port from the request
	RequestHostport = "request_hostport"
	// LocalConnectionAddrInfo is the client's source address and port
	LocalConnectionAddrInfo = "local_connection_addrinfo"
	// RemoteConnectionAddrInfo is the destination server's address and port
	RemoteConnectionAddrInfo = "remote_connection_addrinfo"
	// ConnectionTLSState contains TLS negotiation details (cipher suite, version, ALPN)
	ConnectionTLSState = "connection_tls_state"
	// ConnectionServerCertificate is the server's certificate from the TLS handshake
	ConnectionServerCertificate = "connection_server_certificate"
)

type ConnectionAddrInfo struct {
	// SourceAddr is the source address and port (e.g., client's local address for incoming connection, or proxy's local address for outgoing connection)
	SourceAddr netip.AddrPort
	// DestinationAddr is the destination address and port (e.g., proxy's local address for incoming connection, or target server's address for outgoing connection)
	DestinationAddr netip.AddrPort
}

// TLSState captures TLS negotiation parameters from both client and server
type TLSState struct {
	// Client-side TLS parameters from ClientHello
	ServerName   string   // SNI (Server Name Indication) from client
	CipherSuites []uint16 // Cipher suites offered by client
	TLSVersions  []uint16 // TLS versions supported by client
	ALPN         []string // Application-Layer Protocol Negotiation protocols offered by client

	// Server-side TLS parameters from ServerHello
	SelectedCipherSuite uint16 // Cipher suite chosen by server
	SelectedTLSVersion  uint16 // TLS version chosen by server
	SelectedALPN        string // ALPN protocol chosen by server
}

// ServerCertificate contains parsed fields from the destination server's X.509 certificate
type ServerCertificate struct {
	Version            int                     // X.509 version number
	SerialNumber       *big.Int                // Certificate serial number
	SignatureAlgorithm x509.SignatureAlgorithm // Signature algorithm used (e.g., SHA256-RSA)
	Subject            pkix.Name               // Certificate subject (CN, O, OU, etc.)
	Issuer             pkix.Name               // Certificate issuer (CA information)
	NotBefore          time.Time               // Certificate validity start time
	NotAfter           time.Time               // Certificate validity end time
	DNSNames           []string                // Subject Alternative Names (DNS entries)
	IPAddresses        []net.IP                // Subject Alternative Names (IP addresses)
	RawContent         []byte                  // Raw DER-encoded certificate data
}

func (sc *ServerCertificate) SerialNumberHex() string {
	if sc == nil {
		return ""
	}
	return hex.EncodeToString(sc.SerialNumber.Bytes())
}

func (sc *ServerCertificate) Sha1FingerprintHex() string {
	if sc == nil {
		return ""
	}
	fingerprint := sha1.Sum(sc.RawContent)
	hexFingerprint := make([]string, 0, len(fingerprint))
	for _, b := range fingerprint {
		hexFingerprint = append(hexFingerprint, fmt.Sprintf("%02X", b))
	}
	return strings.Join(hexFingerprint, ":")
}

func (sc *ServerCertificate) Sha256FingerprintHex() string {
	if sc == nil {
		return ""
	}
	fingerprint := sha256.Sum256(sc.RawContent)
	hexFingerprint := make([]string, 0, len(fingerprint))
	for _, b := range fingerprint {
		hexFingerprint = append(hexFingerprint, fmt.Sprintf("%02X", b))
	}
	return strings.Join(hexFingerprint, ":")
}

// MD contains metadata collected during proxy connection and request processing
type MD struct {
	StreamBody                    bool               // Whether body should be streamed (not buffered)
	LocalConnectionEstablishedTs  time.Time          // When the client's connection was established
	RemoteConnectionEstablishedTs time.Time          // When the connection to the remote server was established
	RequestProcessedTs            time.Time          // When the request was received and started processing
	SSLHandshakeCompletedTs       time.Time          // When TLS handshake completed (zero if non-TLS)
	RequestHostport               string             // Target host:port (e.g., "example.com:443")
	LocalAddrInfo                 ConnectionAddrInfo // Client's source address and port
	RemoteAddrInfo                ConnectionAddrInfo // Destination server's address and port
	TLSState                      *TLSState          // TLS negotiation details (nil if non-TLS)
	ServerCertificate             *ServerCertificate // Server's certificate (nil if non-TLS)
}
