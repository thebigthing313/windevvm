package ca

import (
	"crypto/x509"
	"testing"

	"windevvm/internal/protect"
)

func TestLeafVerifies(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"api.github.com", "127.0.0.1", "::1"} {
		lc, err := c.Leaf(host)
		if err != nil {
			t.Fatal(err)
		}
		_, err = lc.Leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: c.Pool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
		if err != nil {
			t.Errorf("%s: %v", host, err)
		}
	}
	a, _ := c.Leaf("API.github.com.")
	b, _ := c.Leaf("api.github.com")
	if a != b {
		t.Error("leaf certificates should be cached per normalized host")
	}
}

func TestSaveLoad(t *testing.T) {
	dir := t.TempDir()
	c, created, err := LoadOrCreate(dir, protect.Default())
	if err != nil || !created {
		t.Fatalf("LoadOrCreate: created=%v err=%v", created, err)
	}
	c2, created, err := LoadOrCreate(dir, protect.Default())
	if err != nil || created {
		t.Fatalf("second LoadOrCreate: created=%v err=%v", created, err)
	}
	if !c.Cert.Equal(c2.Cert) {
		t.Fatal("reloaded CA differs")
	}
	lc, err := c2.Leaf("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lc.Leaf.Verify(x509.VerifyOptions{DNSName: "example.com", Roots: c.Pool()}); err != nil {
		t.Fatalf("leaf from reloaded CA doesn't verify against the original: %v", err)
	}
}
