package diskimg

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// writerAt is an in-memory io.WriterAt.
type writerAt struct{ b []byte }

func (w *writerAt) WriteAt(p []byte, off int64) (int, error) {
	if need := int(off) + len(p); need > len(w.b) {
		w.b = append(w.b, make([]byte, need-len(w.b))...)
	}
	copy(w.b[off:], p)
	return len(p), nil
}

func TestVHDFooterChecksum(t *testing.T) {
	f := vhdFooter(3 << 30)
	if string(f[:8]) != "conectix" {
		t.Fatal("bad cookie")
	}
	stored := binary.BigEndian.Uint32(f[64:])
	binary.BigEndian.PutUint32(f[64:], 0)
	var sum uint32
	for _, b := range f {
		sum += uint32(b)
	}
	if ^sum != stored {
		t.Fatalf("checksum %#x, want %#x", stored, ^sum)
	}
	if got := binary.BigEndian.Uint64(f[48:]); got != 3<<30 {
		t.Fatalf("current size %d", got)
	}
}

func TestRejectsNonQcow(t *testing.T) {
	if _, err := QcowToRaw(bytes.NewReader(make([]byte, 512)), &writerAt{}); err == nil {
		t.Fatal("expected an error for a non-qcow2 input")
	}
}

// TestUbuntuImage converts the real cloud image when it's present locally:
// set WINDEVVM_TEST_QCOW2 to its path.
func TestUbuntuImage(t *testing.T) {
	src := os.Getenv("WINDEVVM_TEST_QCOW2")
	if src == "" {
		t.Skip("WINDEVVM_TEST_QCOW2 not set")
	}
	dst := filepath.Join(t.TempDir(), "out.vhd")
	if err := QcowToVHD(src, dst); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	// The guest disk starts with a protective MBR and a GPT header.
	mbr := make([]byte, 1024)
	if _, err := f.ReadAt(mbr, 0); err != nil {
		t.Fatal(err)
	}
	if mbr[510] != 0x55 || mbr[511] != 0xaa {
		t.Fatal("no MBR signature at the start of the disk")
	}
	if string(mbr[512:520]) != "EFI PART" {
		t.Fatal("no GPT header at LBA 1")
	}
}
