// Package ca is windevvm's local certificate authority. VMs trust it, which
// lets the proxy open TLS to hosts that have secrets bound and inject them.
package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"windevvm/internal/hostmatch"
	"windevvm/internal/protect"
)

const (
	certFile     = "ca.crt"
	keyFile      = "ca.key.sealed"
	leafLifetime = 7 * 24 * time.Hour
)

// CA signs short-lived leaf certificates on demand.
type CA struct {
	Cert    *x509.Certificate
	CertPEM []byte

	key     *ecdsa.PrivateKey
	leafKey *ecdsa.PrivateKey

	mu    sync.Mutex
	cache map[string]*tls.Certificate
}

// New creates a CA with a fresh key, valid for 10 years.
func New() (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "windevvm local CA", Organization: []string{"windevvm"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return fromParts(der, key)
}

func fromParts(der []byte, key *ecdsa.PrivateKey) (*CA, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &CA{
		Cert:    cert,
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		key:     key,
		leafKey: leafKey,
		cache:   map[string]*tls.Certificate{},
	}, nil
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		panic(err)
	}
	return n
}

// CertPath is where the CA certificate lives in dir.
func CertPath(dir string) string { return filepath.Join(dir, certFile) }

// Save writes the certificate in PEM and the key sealed by p.
func (c *CA) Save(dir string, p protect.Protector) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(c.key)
	if err != nil {
		return err
	}
	sealed, err := p.Protect(keyDER)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, keyFile), sealed, 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, certFile), c.CertPEM, 0o644)
}

// Load reads a CA saved by Save.
func Load(dir string, p protect.Protector) (*CA, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, certFile))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%s: not a PEM certificate", certFile)
	}
	sealed, err := os.ReadFile(filepath.Join(dir, keyFile))
	if err != nil {
		return nil, err
	}
	keyDER, err := p.Unprotect(sealed)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParseECPrivateKey(keyDER)
	if err != nil {
		return nil, err
	}
	return fromParts(block.Bytes, key)
}

// LoadOrCreate loads the CA in dir, creating it on first use. created reports
// whether a new CA was made.
func LoadOrCreate(dir string, p protect.Protector) (c *CA, created bool, err error) {
	c, err = Load(dir, p)
	if err == nil {
		return c, false, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, false, err
	}
	if c, err = New(); err != nil {
		return nil, false, err
	}
	return c, true, c.Save(dir, p)
}

// Pool returns a cert pool containing only this CA.
func (c *CA) Pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(c.Cert)
	return pool
}

// Leaf returns a certificate for host signed by the CA, cached until it is
// within a day of expiring.
func (c *CA) Leaf(host string) (*tls.Certificate, error) {
	host = hostmatch.Normalize(host)
	c.mu.Lock()
	defer c.mu.Unlock()
	if lc, ok := c.cache[host]; ok && time.Until(lc.Leaf.NotAfter) > 24*time.Hour {
		return lc, nil
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(leafLifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		tmpl.IPAddresses = []net.IP{ip.AsSlice()}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.Cert, &c.leafKey.PublicKey, c.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	tc := &tls.Certificate{Certificate: [][]byte{der, c.Cert.Raw}, PrivateKey: c.leafKey, Leaf: leaf}
	c.cache[host] = tc
	return tc, nil
}
