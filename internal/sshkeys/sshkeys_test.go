package sshkeys

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestClientKeyStable(t *testing.T) {
	d := &Dir{Path: t.TempDir()}
	a, err := d.AuthorizedKey()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := d.AuthorizedKey()
	if a != b || !strings.HasPrefix(a, "ssh-ed25519 ") {
		t.Fatalf("keys %q / %q", a, b)
	}
}

func TestNewKeyPairParses(t *testing.T) {
	priv, pub, err := NewKeyPair("test")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.ParsePrivateKey([]byte(priv))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))) != pub {
		t.Fatal("public key doesn't match the private key")
	}
}

func TestSync(t *testing.T) {
	d := &Dir{Path: t.TempDir()}
	_, pub, _ := NewKeyPair("vm")
	if err := d.Sync([]Host{{Alias: "wdvm-app-abc123", IP: "10.77.0.10", HostKey: pub}}); err != nil {
		t.Fatal(err)
	}
	cfg, _ := os.ReadFile(d.ConfigPath())
	for _, want := range []string{"Host wdvm-app-abc123", "HostName 10.77.0.10", "User dev", "StrictHostKeyChecking yes", "HostKeyAlias wdvm-app-abc123"} {
		if !strings.Contains(string(cfg), want) {
			t.Errorf("config lacks %q:\n%s", want, cfg)
		}
	}
	kh, _ := ReadAuthorizedKeyFile(d.KnownHostsPath())
	if len(kh) != 1 || !strings.HasPrefix(kh[0], "wdvm-app-abc123 ssh-ed25519 ") {
		t.Fatalf("known_hosts = %v", kh)
	}
	if err := d.Sync(nil); err != nil {
		t.Fatal(err)
	}
	kh, _ = ReadAuthorizedKeyFile(d.KnownHostsPath())
	if len(kh) != 0 {
		t.Fatalf("known_hosts not cleared: %v", kh)
	}
}

func ReadAuthorizedKeyFile(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out, nil
}

func TestConfigRef(t *testing.T) {
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)
	t.Setenv("HOME", home)
	if got := ConfigRef(filepath.Join(home, "AppData", "x", "config")); got != "~/AppData/x/config" {
		t.Errorf("under home: %q", got)
	}
	other := filepath.Join(filepath.Dir(home), "elsewhere", "config")
	if got := ConfigRef(other); got != filepath.ToSlash(other) {
		t.Errorf("outside home: %q", got)
	}
}
