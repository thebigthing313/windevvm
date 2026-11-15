package seed

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteISO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "seed.iso")
	err := WriteISO(path, Files{
		"user-data": []byte("#cloud-config\nhostname: test\n"),
		"meta-data": []byte("instance-id: test-1\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Primary volume descriptor at sector 16 carries the label.
	pvd := b[16*2048:]
	if pvd[0] != 1 || string(pvd[1:6]) != "CD001" {
		t.Fatal("no primary volume descriptor")
	}
	if label := strings.TrimRight(string(pvd[40:72]), " "+string(rune(0))); label != "cidata" {
		t.Fatalf("volume label %q, want cidata", label)
	}
	if !bytes.Contains(b, []byte("hostname: test")) || !bytes.Contains(b, []byte("instance-id: test-1")) {
		t.Fatal("file contents missing")
	}
	// Rock Ridge name entries ("NM") carry the real file names.
	if !bytes.Contains(b, []byte("user-data")) || !bytes.Contains(b, []byte("meta-data")) {
		t.Fatal("long file names missing")
	}
}
