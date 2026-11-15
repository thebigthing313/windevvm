package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

func TestParseSize(t *testing.T) {
	cases := map[string]Size{"4GB": 4 << 30, "512MB": 512 << 20, "1.5G": 3 << 29, "2 GiB": 2 << 30, "1024": 1024, "64gb": 64 << 30}
	for in, want := range cases {
		got, err := ParseSize(in)
		if err != nil || got != want {
			t.Errorf("ParseSize(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "abc", "-1GB", "4XB"} {
		if _, err := ParseSize(bad); err == nil {
			t.Errorf("ParseSize(%q): expected an error", bad)
		}
	}
	if s := Size(4 << 30).String(); s != "4GB" {
		t.Errorf("String = %q", s)
	}
	if s := Size(1536 << 20).String(); s != "1.5GB" {
		t.Errorf("String = %q", s)
	}
}

func TestDefaultsValid(t *testing.T) {
	if err := Defaults().Resources.Validate(12); err != nil {
		t.Fatal(err)
	}
}

func TestValidate(t *testing.T) {
	r := Defaults().Resources
	r.CPUs = 32
	r.MemoryMax = 768 << 20 // below startup
	r.MemoryMin = 100 << 20
	err := r.Validate(12)
	if err == nil {
		t.Fatal("expected errors")
	}
	for _, want := range []string{"cpus", "memory_min must be at least", "memory must satisfy"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
}

func TestMergeAndProjectFile(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ProjectFile), []byte(`
[resources]
cpus = 6
memory_max = "8GB"
`), 0o644)
	p, err := LoadProject(dir)
	if err != nil {
		t.Fatal(err)
	}
	r := Defaults().Resources.Merge(p.Resources)
	if r.CPUs != 6 || r.MemoryMax != 8<<30 || r.CPUMaxPercent != 50 {
		t.Fatalf("merged = %+v", r)
	}

	os.WriteFile(filepath.Join(dir, ProjectFile), []byte("[resources]\ncpu = 6\n"), 0o644)
	if _, err := LoadProject(dir); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("expected an unknown-setting error, got %v", err)
	}
}

func TestBudgetResolve(t *testing.T) {
	b := Budget{}.Resolve(16<<30, 12)
	if b.Memory != 10<<30 || b.CPUs != 6 || b.MaxRunning != 3 {
		t.Fatalf("resolved = %+v", b)
	}
	var g Global
	if _, err := toml.Decode("[budget]\nmemory = \"12GB\"\ncpus = 8\n", &g); err != nil {
		t.Fatal(err)
	}
	b = g.Budget.Resolve(16<<30, 12)
	if b.Memory != 12<<30 || b.CPUs != 8 {
		t.Fatalf("resolved = %+v", b)
	}
}

func TestFindProjectRoot(t *testing.T) {
	root := t.TempDir()
	os.Mkdir(filepath.Join(root, ".git"), 0o755)
	sub := filepath.Join(root, "a", "b")
	os.MkdirAll(sub, 0o755)
	got, err := FindProjectRoot(sub)
	if err != nil || got != root {
		t.Fatalf("FindProjectRoot = %q, %v; want %q", got, err, root)
	}
}
