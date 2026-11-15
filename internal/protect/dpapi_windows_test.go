//go:build windows

package protect

import (
	"bytes"
	"testing"
)

func TestDPAPIRoundTrip(t *testing.T) {
	plain := []byte("ghp_example_token_value")
	sealed, err := DPAPI{}.Protect(plain)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, plain) {
		t.Fatal("sealed blob contains the plaintext")
	}
	got, err := DPAPI{}.Unprotect(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("got %q, want %q", got, plain)
	}
}

func TestDPAPIRejectsTampering(t *testing.T) {
	sealed, err := DPAPI{}.Protect([]byte("value"))
	if err != nil {
		t.Fatal(err)
	}
	sealed[len(sealed)-1] ^= 0xff
	if _, err := (DPAPI{}).Unprotect(sealed); err == nil {
		t.Fatal("expected an error for a tampered blob")
	}
}
