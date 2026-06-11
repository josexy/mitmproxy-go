package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"os"
	"slices"
	"time"

	tls "github.com/refraction-networking/utls"
)

const defaultKeySize = 2048

func GeneratePrivateKey() (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, defaultKeySize)
	if err != nil {
		return nil, err
	}
	err = privateKey.Validate()
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

func LoadCACertificate(certPath, keyPath string) (cert *Cert, err error) {
	certPem, err := os.ReadFile(certPath)
	if err != nil {
		return
	}
	keyPem, err := os.ReadFile(keyPath)
	if err != nil {
		return
	}
	certBlock, _ := pem.Decode(certPem)
	keyBlock, _ := pem.Decode(keyPem)
	if certBlock == nil {
		return nil, errors.New("failed to decode certificate PEM")
	}
	if keyBlock == nil {
		return nil, errors.New("failed to decode private key PEM")
	}
	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}
	caPriKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err == nil {
		return &Cert{
			cert:       caCert,
			privateKey: caPriKey,
			certBytes:  certBlock.Bytes,
		}, nil
	}
	priKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err == nil {
		var ok bool
		if caPriKey, ok = priKey.(*rsa.PrivateKey); !ok {
			err = errors.New("private key is not of RSA type")
		} else {
			return &Cert{
				cert:       caCert,
				privateKey: caPriKey,
				certBytes:  certBlock.Bytes,
			}, nil
		}
	}
	return
}

type Cert struct {
	cert       *x509.Certificate
	privateKey *rsa.PrivateKey
	certBytes  []byte
}

func (c *Cert) Cert() *x509.Certificate {
	return c.cert
}

func (c *Cert) PrivateKey() *rsa.PrivateKey {
	return c.privateKey
}

func (c *Cert) Pem() (keyPem []byte, certPem []byte) {
	keyPem = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(c.privateKey)})
	certPem = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.certBytes})
	return
}

func (c *Cert) Certificate() tls.Certificate {
	return tls.Certificate{
		Certificate: [][]byte{c.certBytes},
		PrivateKey:  c.privateKey,
	}
}

type CaBuilder struct {
	priKey *rsa.PrivateKey
	params *x509.Certificate
}

type CertificateBuilder struct {
	priKey *rsa.PrivateKey
	params *x509.Certificate
}

func NewCaBuilder() *CaBuilder {
	params := &x509.Certificate{
		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature |
			x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	return &CaBuilder{
		params: params,
	}
}
func (b *CaBuilder) Subject(subject pkix.Name) *CaBuilder {
	b.params.Subject = subject
	return b
}

func (b *CaBuilder) ValidateDays(days int) *CaBuilder {
	b.params.NotBefore = time.Now()
	b.params.NotAfter = b.params.NotBefore.AddDate(0, 0, days)
	return b
}

func (b *CaBuilder) PrivateKey(privateKey *rsa.PrivateKey) *CaBuilder {
	b.priKey = privateKey
	return b
}

func (b *CaBuilder) Build() (*Cert, error) {
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	b.params.SerialNumber = serialNumber
	if b.priKey == nil {
		if b.priKey, err = GeneratePrivateKey(); err != nil {
			return nil, err
		}
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, b.params, b.params, &b.priKey.PublicKey, b.priKey)
	if err != nil {
		return nil, err
	}
	return &Cert{
		cert:       b.params,
		privateKey: b.priKey,
		certBytes:  certBytes,
	}, nil
}

func NewCertificateBuilder() *CertificateBuilder {
	params := &x509.Certificate{
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	return &CertificateBuilder{
		params: params,
	}
}
func (b *CertificateBuilder) Subject(subject pkix.Name) *CertificateBuilder {
	b.params.Subject = subject
	return b
}

func (b *CertificateBuilder) DNSNames(dnsNames []string) *CertificateBuilder {
	b.params.DNSNames = dnsNames
	return b
}

func (b *CertificateBuilder) IPAddresses(ipAddresses []net.IP) *CertificateBuilder {
	b.params.IPAddresses = ipAddresses
	return b
}

func (b *CertificateBuilder) URIs(uris []*url.URL) *CertificateBuilder {
	b.params.URIs = uris
	return b
}

func (b *CertificateBuilder) EmailAddresses(emailAddresses []string) *CertificateBuilder {
	b.params.EmailAddresses = emailAddresses
	return b
}

func (b *CertificateBuilder) ServerAuth() *CertificateBuilder {
	usage := x509.ExtKeyUsageServerAuth
	if !slices.Contains(b.params.ExtKeyUsage, usage) {
		b.params.ExtKeyUsage = append(b.params.ExtKeyUsage, usage)
	}
	return b
}

func (b *CertificateBuilder) ClientAuth() *CertificateBuilder {
	usage := x509.ExtKeyUsageClientAuth
	if !slices.Contains(b.params.ExtKeyUsage, usage) {
		b.params.ExtKeyUsage = append(b.params.ExtKeyUsage, usage)
	}
	return b
}

func (b *CertificateBuilder) ValidateDays(days int) *CertificateBuilder {
	b.params.NotBefore = time.Now()
	b.params.NotAfter = b.params.NotBefore.AddDate(0, 0, days)
	return b
}

func (b *CertificateBuilder) PrivateKey(privateKey *rsa.PrivateKey) *CertificateBuilder {
	b.priKey = privateKey
	return b
}

func (b *CertificateBuilder) BuildFromCA(caCert *Cert) (*Cert, error) {
	if caCert == nil {
		return b.BuildFromCACertAndKey(nil, nil)
	}
	return b.BuildFromCACertAndKey(caCert.Cert(), caCert.PrivateKey())
}

func (b *CertificateBuilder) BuildFromCACertAndKey(caCert *x509.Certificate, caPriKey *rsa.PrivateKey) (*Cert, error) {
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	b.params.SerialNumber = serialNumber

	if b.priKey == nil {
		if b.priKey, err = GeneratePrivateKey(); err != nil {
			return nil, err
		}
	}

	parentCert := b.params
	caPrivateKey := b.priKey
	if caPriKey != nil && caCert != nil {
		parentCert = caCert
		caPrivateKey = caPriKey
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, b.params, parentCert, &b.priKey.PublicKey, caPrivateKey)
	if err != nil {
		return nil, err
	}
	return &Cert{
		privateKey: b.priKey,
		certBytes:  certBytes,
	}, nil
}
