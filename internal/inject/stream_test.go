package inject

import (
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

func replaceAll(t *testing.T, src io.Reader, pats, reps []string) (string, error) {
	t.Helper()
	bp := make([][]byte, len(pats))
	for i, p := range pats {
		bp[i] = []byte(p)
	}
	r := newReplacer(src, bp, func(i int) ([]byte, error) { return []byte(reps[i]), nil })
	b, err := io.ReadAll(r)
	return string(b), err
}

func TestReplacerAcrossBoundaries(t *testing.T) {
	src := "aaSECRETbbSECRETSECRETcc SECRE"
	for _, rd := range []io.Reader{strings.NewReader(src), iotest.OneByteReader(strings.NewReader(src)), iotest.HalfReader(strings.NewReader(src))} {
		got, err := replaceAll(t, rd, []string{"SECRET"}, []string{"X"})
		if err != nil {
			t.Fatal(err)
		}
		if got != "aaXbbXXcc SECRE" {
			t.Fatalf("got %q", got)
		}
	}
}

func TestReplacerOverlappingPatterns(t *testing.T) {
	got, err := replaceAll(t, iotest.OneByteReader(strings.NewReader("abcd abc ab")), []string{"ab", "abcd"}, []string{"1", "2"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "2 1c 1" {
		t.Fatalf("got %q", got)
	}
}

// A streamed response must not be held back unless its tail could start a pattern.
func TestReplacerMinimalHoldback(t *testing.T) {
	pr, pw := io.Pipe()
	r := newReplacer(pr, [][]byte{[]byte("SECRET")}, func(int) ([]byte, error) { return []byte("X"), nil })
	go pw.Write([]byte("data: hello\n\n"))
	buf := make([]byte, 64)
	n, err := r.Read(buf)
	if err != nil || string(buf[:n]) != "data: hello\n\n" {
		t.Fatalf("Read = %q, %v", buf[:n], err)
	}
	go pw.Write([]byte("data: SEC"))
	n, _ = r.Read(buf)
	if string(buf[:n]) != "data: " {
		t.Fatalf("Read = %q, want only the part that can't start a pattern", buf[:n])
	}
	pw.Close()
	rest, _ := io.ReadAll(r)
	if string(rest) != "SEC" {
		t.Fatalf("rest = %q", rest)
	}
}

func TestReplacerAbort(t *testing.T) {
	boom := errors.New("violation")
	r := newReplacer(strings.NewReader("ok BAD more"), [][]byte{[]byte("BAD")}, func(int) ([]byte, error) { return nil, boom })
	b, err := io.ReadAll(r)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(string(b), "BAD") || strings.Contains(string(b), "more") {
		t.Fatalf("leaked %q past the violation", b)
	}
}
