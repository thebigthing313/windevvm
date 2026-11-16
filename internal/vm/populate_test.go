package vm

import (
	"strings"
	"testing"
)

func TestMiseWriterDropsProgress(t *testing.T) {
	in := "mise by @jdx – installing 1 tool\n" +
		"mise ███████████░░░░░ 0/1 · 3.0s\n" +
		"  node@18.20.0  downloading  3.0s  44.3/44.3 MB · 40.5 MB/s\n" +
		"mise ███████████░░░░░ 0/1 · 7.9s\n" +
		"  node@18.20.0  downloading  7.9s  44.3/44.3 MB · 7.3 MB/s\n" +
		"  node@18.20.0  extracting  13.9s\n" +
		"  node@18.20.0  extracting  16.9s\n" +
		"mise node@18.20.0 v18.20.0\n" +
		"mise ✓ node@18.20.0  30.1s  node-v18.20.0-linux-x64.tar.gz\n" +
		"mise ████████████████ 1/1 · installed 1 tool in 30.1s\n" +
		"no newline at the end"
	var out strings.Builder
	w := &miseWriter{w: &out, prefix: "  "}
	// Feed it in awkward pieces, as a stream would arrive.
	for i := 0; i < len(in); i += 7 {
		w.Write([]byte(in[i:min(i+7, len(in))]))
	}
	w.Flush()
	want := "  mise by @jdx – installing 1 tool\n" +
		"    node@18.20.0  downloading  3.0s  44.3/44.3 MB · 40.5 MB/s\n" +
		"    node@18.20.0  extracting  13.9s\n" +
		"  mise node@18.20.0 v18.20.0\n" +
		"  mise ✓ node@18.20.0  30.1s  node-v18.20.0-linux-x64.tar.gz\n" +
		"  mise ████████████████ 1/1 · installed 1 tool in 30.1s\n" +
		"  no newline at the end\n"
	if out.String() != want {
		t.Fatalf("got:\n%s\nwant:\n%s", out.String(), want)
	}
}

func TestMiseWriterCarriageReturns(t *testing.T) {
	var out strings.Builder
	w := &miseWriter{w: &out}
	w.Write([]byte("10%\r20%\r"))
	w.Write([]byte("\n"))
	w.Write([]byte("a\r\nb\r"))
	w.Write([]byte("100%\r"))
	w.Write([]byte("done\n"))
	if got := out.String(); got != "20%\na\ndone\n" {
		t.Fatalf("got %q", got)
	}
	out.Reset()
	w.Write([]byte(strings.Repeat("x", 5000)))
	if out.Len() == 0 || len(w.buf) != 0 {
		t.Fatal("a long line without a newline should be passed on")
	}
}
