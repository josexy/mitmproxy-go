package cert

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGeneratePrivateKey(t *testing.T) {
	key, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	if key.N.BitLen() != defaultKeySize {
		t.Fatalf("key size = %d; want %d", key.N.BitLen(), defaultKeySize)
	}
	if err := key.Validate(); err != nil {
		t.Fatalf("generated key is invalid: %v", err)
	}
}

func TestCaBuilderBuildPemCertificateAndLoad(t *testing.T) {
	ca, err := NewCaBuilder().
		Subject(pkix.Name{CommonName: "test ca"}).
		ValidateDays(30).
		Build()
	if err != nil {
		t.Fatalf("Build CA: %v", err)
	}
	if !ca.Cert().IsCA {
		t.Fatalf("CA certificate IsCA = false")
	}
	if ca.Cert().Subject.CommonName != "test ca" {
		t.Fatalf("CA common name = %q; want test ca", ca.Cert().Subject.CommonName)
	}
	if time.Until(ca.Cert().NotAfter) <= 0 {
		t.Fatalf("CA NotAfter is not in the future")
	}
	keyPem, certPem := ca.Pem()
	if len(keyPem) == 0 || len(certPem) == 0 {
		t.Fatalf("Pem returned empty key or cert")
	}
	tlsCert := ca.Certificate()
	if len(tlsCert.Certificate) != 1 || tlsCert.PrivateKey != ca.PrivateKey() {
		t.Fatalf("Certificate() did not expose cert bytes and private key")
	}

	certPath, keyPath := writeCertFiles(t, certPem, keyPem)
	loaded, err := LoadCACertificate(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadCACertificate PKCS1: %v", err)
	}
	if loaded.Cert().Subject.CommonName != "test ca" {
		t.Fatalf("loaded CA common name = %q", loaded.Cert().Subject.CommonName)
	}

	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(ca.PrivateKey())
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	pkcs8KeyPem := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Bytes})
	certPath, keyPath = writeCertFiles(t, certPem, pkcs8KeyPem)
	if _, err := LoadCACertificate(certPath, keyPath); err != nil {
		t.Fatalf("LoadCACertificate PKCS8: %v", err)
	}
}

func TestLoadCACertificateErrors(t *testing.T) {
	if _, err := LoadCACertificate("missing.crt", "missing.key"); err == nil {
		t.Fatalf("missing cert should fail")
	}

	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	if err := os.WriteFile(certPath, []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCACertificate(certPath, keyPath); err == nil {
		t.Fatalf("invalid PEM should fail")
	}

	ca, err := NewCaBuilder().Subject(pkix.Name{CommonName: "test ca"}).ValidateDays(1).Build()
	if err != nil {
		t.Fatal(err)
	}
	_, certPem := ca.Pem()
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edBytes, err := x509.MarshalPKCS8PrivateKey(edKey)
	if err != nil {
		t.Fatal(err)
	}
	edKeyPem := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: edBytes})
	certPath, keyPath = writeCertFiles(t, certPem, edKeyPem)
	if _, err := LoadCACertificate(certPath, keyPath); err == nil {
		t.Fatalf("non-RSA PKCS8 key should fail")
	}
}

func TestCertificateBuilderBuildFromCA(t *testing.T) {
	ca, err := NewCaBuilder().
		Subject(pkix.Name{CommonName: "root ca"}).
		ValidateDays(365).
		Build()
	if err != nil {
		t.Fatalf("Build CA: %v", err)
	}

	uri, err := url.Parse("spiffe://example/service")
	if err != nil {
		t.Fatal(err)
	}
	serverCert, err := NewCertificateBuilder().
		Subject(pkix.Name{CommonName: "server"}).
		DNSNames([]string{"example.com"}).
		IPAddresses([]net.IP{net.ParseIP("127.0.0.1")}).
		URIs([]*url.URL{uri}).
		EmailAddresses([]string{"admin@example.com"}).
		ServerAuth().
		ServerAuth().
		ClientAuth().
		ClientAuth().
		ValidateDays(10).
		BuildFromCA(ca)
	if err != nil {
		t.Fatalf("BuildFromCA: %v", err)
	}

	parsed, err := x509.ParseCertificate(serverCert.certBytes)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if parsed.Subject.CommonName != "server" ||
		parsed.Issuer.CommonName != "root ca" ||
		len(parsed.DNSNames) != 1 ||
		parsed.DNSNames[0] != "example.com" ||
		len(parsed.IPAddresses) != 1 ||
		!parsed.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) ||
		len(parsed.URIs) != 1 ||
		parsed.URIs[0].String() != uri.String() ||
		len(parsed.EmailAddresses) != 1 ||
		parsed.EmailAddresses[0] != "admin@example.com" {
		t.Fatalf("parsed certificate mismatch: %#v", parsed)
	}
	if len(parsed.ExtKeyUsage) != 2 {
		t.Fatalf("ExtKeyUsage = %#v; want server and client auth without duplicates", parsed.ExtKeyUsage)
	}
}

func TestCertificateBuilderBuildSelfSignedWhenCANil(t *testing.T) {
	cert, err := NewCertificateBuilder().
		Subject(pkix.Name{CommonName: "self"}).
		ValidateDays(1).
		BuildFromCA(nil)
	if err != nil {
		t.Fatalf("BuildFromCA(nil): %v", err)
	}
	parsed, err := x509.ParseCertificate(cert.certBytes)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if parsed.Subject.CommonName != parsed.Issuer.CommonName {
		t.Fatalf("self-signed subject=%q issuer=%q", parsed.Subject.CommonName, parsed.Issuer.CommonName)
	}
}

func writeCertFiles(t *testing.T, certPem, keyPem []byte) (string, string) {
	t.Helper()
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, certPem, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPem, 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}
