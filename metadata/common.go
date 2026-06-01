package metadata

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net"
	"net/netip"
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
	// DNSLookupStartTs is the timestamp when DNS lookup started
	DNSLookupStartTs = "dns_lookup_start_ts"
	// DNSLookupDoneTs is the timestamp when DNS lookup completed
	DNSLookupDoneTs = "dns_lookup_done_ts"
	// SocketConnectStartTs is the timestamp when socket connection started
	SocketConnectStartTs = "socket_connect_start_ts"
	// SocketConnectDoneTs is the timestamp when socket connection completed
	SocketConnectDoneTs = "socket_connect_done_ts"
	// SSLHandshakeStartTs is the timestamp when the SSL/TLS handshake started
	SSLHandshakeStartTs = "ssl_handshake_start_ts"
	// SSLHandshakeCompletedTs is the timestamp when the SSL/TLS handshake completed
	SSLHandshakeCompletedTs = "ssl_handshake_completed_ts"
	// RequestUploadStartTs is the timestamp when request upload started
	RequestUploadStartTs = "request_upload_start_ts"
	// RequestUploadDoneTs is the timestamp when request upload completed
	RequestUploadDoneTs = "request_upload_done_ts"
	// ResponseStartTs is the timestamp when the first response byte was received
	ResponseStartTs = "response_start_ts"
	// ResponseDoneTs is the timestamp when response body download completed
	ResponseDoneTs = "response_done_ts"
	// ConnectionReused indicates whether the request reused an existing upstream connection
	ConnectionReused = "connection_reused"
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
	return colonHex(fingerprint[:])
}

func (sc *ServerCertificate) Sha256FingerprintHex() string {
	if sc == nil {
		return ""
	}
	fingerprint := sha256.Sum256(sc.RawContent)
	return colonHex(fingerprint[:])
}

func colonHex(src []byte) string {
	if len(src) == 0 {
		return ""
	}
	const upperHex = "0123456789ABCDEF"
	dst := make([]byte, len(src)*3-1)
	for i, b := range src {
		j := i * 3
		if i > 0 {
			dst[j-1] = ':'
		}
		dst[j] = upperHex[b>>4]
		dst[j+1] = upperHex[b&0x0f]
	}
	return string(dst)
}

// MD contains metadata collected during proxy connection and request processing
type MD struct {
	StreamBody                    bool               // Whether body should be streamed (not buffered)
	LocalConnectionEstablishedTs  time.Time          // When the client's connection was established
	RemoteConnectionEstablishedTs time.Time          // When the connection to the remote server was established
	RequestProcessedTs            time.Time          // When the request was received and started processing
	SSLHandshakeStartTs           time.Time          // When TLS handshake started (zero if non-TLS)
	SSLHandshakeCompletedTs       time.Time          // When TLS handshake completed (zero if non-TLS)
	RequestHostport               string             // Target host:port (e.g., "example.com:443")
	LocalAddrInfo                 ConnectionAddrInfo // Client's source address and port
	RemoteAddrInfo                ConnectionAddrInfo // Destination server's address and port
	TLSState                      *TLSState          // TLS negotiation details (nil if non-TLS)
	ServerCertificate             *ServerCertificate // Server's certificate (nil if non-TLS)
	Timing                        Timing             // Request timing phases suitable for waterfall charts
}
