package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureSSHInclude(t *testing.T) {
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)
	t.Setenv("HOME", home)
	cfg := filepath.Join(home, ".ssh", "config")
	os.MkdirAll(filepath.Dir(cfg), 0o700)
	os.WriteFile(cfg, []byte("Host work\n  HostName example.com\n"), 0o600)

	gen := filepath.Join(home, "AppData", "Local", "windevvm", "ssh", "config")
	if err := ensureSSHInclude(gen, true); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(cfg)
	if !strings.HasPrefix(string(b), "# Added by windevvm") || !strings.Contains(string(b), `Include "~/AppData/Local/windevvm/ssh/config"`) || !strings.HasSuffix(string(b), "Host work\n  HostName example.com\n") {
		t.Fatalf("config:\n%s", b)
	}
	// Idempotent.
	if err := ensureSSHInclude(gen, true); err != nil {
		t.Fatal(err)
	}
	b2, _ := os.ReadFile(cfg)
	if string(b2) != string(b) {
		t.Fatal("added the Include twice")
	}
}

// An absolute Include from an older version is rewritten in place, without
// asking (yes=false would otherwise read stdin).
func TestEnsureSSHIncludeMigrates(t *testing.T) {
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)
	t.Setenv("HOME", home)
	cfg := filepath.Join(home, ".ssh", "config")
	os.MkdirAll(filepath.Dir(cfg), 0o700)
	gen := filepath.Join(home, "AppData", "Local", "windevvm", "ssh", "config")
	os.WriteFile(cfg, []byte("# Added by windevvm: its VMs, by name.\nInclude \""+filepath.ToSlash(gen)+"\"\n\nHost work\n"), 0o600)
	if err := ensureSSHInclude(gen, false); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(cfg)
	want := "# Added by windevvm: its VMs, by name.\nInclude \"~/AppData/Local/windevvm/ssh/config\"\n\nHost work\n"
	if string(b) != want {
		t.Fatalf("config:\n%s", b)
	}
}
