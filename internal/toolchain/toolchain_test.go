package toolchain

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func project(t *testing.T, files map[string]string) string {
	dir := t.TempDir()
	for name, content := range files {
		p := filepath.Join(dir, name)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(content), 0o644)
	}
	return dir
}

func TestDetect(t *testing.T) {
	cases := []struct {
		files map[string]string
		want  string
	}{
		{map[string]string{"package.json": "{}"}, "node@lts"},
		{map[string]string{"package.json": "{}", ".nvmrc": "v20.11.1\n"}, "node@20.11.1"},
		{map[string]string{".nvmrc": "lts/iron"}, "node@lts"},
		{map[string]string{"requirements.txt": ""}, "python@3.12"},
		{map[string]string{"pyproject.toml": "", ".python-version": "3.11\n"}, "python@3.11"},
		{map[string]string{"go.mod": "module x\n\ngo 1.23.4\n"}, "go@1.23.4"},
		{map[string]string{"go.mod": "module x\n"}, "go@latest"},
		{map[string]string{"Cargo.toml": ""}, "rust@stable"},
		{map[string]string{"Cargo.toml": "", "rust-toolchain.toml": "[toolchain]\nchannel = \"1.80.0\"\n"}, "rust@1.80.0"},
		{map[string]string{"package.json": "", "go.mod": "go 1.22\n"}, "go@1.22,node@lts"},
		{map[string]string{".nvmrc": "$(rm -rf /)"}, "node@lts"},
		{map[string]string{"README.md": ""}, ""},
	}
	for _, c := range cases {
		got := strings.Join(Detect(project(t, c.files)).Tools, ",")
		if got != c.want {
			t.Errorf("%v: got %q want %q", c.files, got, c.want)
		}
	}
}

func TestMiseFileWins(t *testing.T) {
	p := Detect(project(t, map[string]string{"package.json": "", ".tool-versions": "nodejs 18\n"}))
	if p.MiseConfig != ".tool-versions" || len(p.Tools) != 0 {
		t.Fatalf("%+v", p)
	}
}

func TestMiseConfigText(t *testing.T) {
	p := Plan{Tools: []string{"go@1.22", "node@lts"}}
	if s := p.MiseConfigText(); !strings.Contains(s, "go = \"1.22\"\nnode = \"lts\"\n") {
		t.Fatal(s)
	}
}
