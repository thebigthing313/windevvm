// Package toolchain works out which language toolchains a project needs, so
// mise can install them in the project's VM.
package toolchain

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Plan is what a project needs.
type Plan struct {
	// MiseConfig is the project's own mise or asdf file, if it has one. mise
	// then installs exactly what that file lists and Tools is empty.
	MiseConfig string
	// Tools are mise specs detected from the project's files, e.g. "node@20".
	Tools []string
	// Reasons say which file each tool came from, for display.
	Reasons map[string]string
}

var miseFiles = []string{"mise.toml", ".mise.toml", "mise/config.toml", ".mise/config.toml", ".config/mise.toml", ".config/mise/config.toml", ".tool-versions"}

var versionRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,40}$`)

func exists(dir, name string) bool {
	_, err := os.Stat(filepath.Join(dir, name))
	return err == nil
}

// firstLine returns the first non-empty, non-comment line of a file.
func firstLine(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l != "" && !strings.HasPrefix(l, "#") {
			return l
		}
	}
	return ""
}

func clean(v, def string) string {
	v = strings.Trim(strings.TrimSpace(v), `"'`)
	if versionRE.MatchString(v) {
		return v
	}
	return def
}

var goLineRE = regexp.MustCompile(`(?m)^go\s+([0-9][0-9.]*)\s*$`)
var channelRE = regexp.MustCompile(`(?m)^\s*channel\s*=\s*"([^"]+)"`)

// Detect inspects a project folder.
func Detect(dir string) Plan {
	p := Plan{Reasons: map[string]string{}}
	for _, f := range miseFiles {
		if exists(dir, f) {
			p.MiseConfig = f
			return p
		}
	}
	add := func(tool, version, why string) {
		spec := tool + "@" + version
		p.Tools = append(p.Tools, spec)
		p.Reasons[spec] = why
	}

	switch {
	case exists(dir, ".nvmrc"):
		v := strings.TrimPrefix(firstLine(filepath.Join(dir, ".nvmrc")), "v")
		if strings.HasPrefix(v, "lts/") || v == "node" {
			v = "lts"
		}
		add("node", clean(v, "lts"), ".nvmrc")
	case exists(dir, ".node-version"):
		add("node", clean(strings.TrimPrefix(firstLine(filepath.Join(dir, ".node-version")), "v"), "lts"), ".node-version")
	case exists(dir, "package.json"):
		add("node", "lts", "package.json")
	}

	if exists(dir, ".python-version") {
		add("python", clean(firstLine(filepath.Join(dir, ".python-version")), "3.12"), ".python-version")
	} else {
		for _, f := range []string{"pyproject.toml", "requirements.txt", "setup.py", "Pipfile", "uv.lock"} {
			if exists(dir, f) {
				add("python", "3.12", f)
				break
			}
		}
	}

	if b, err := os.ReadFile(filepath.Join(dir, "go.mod")); err == nil {
		v := "latest"
		if m := goLineRE.FindSubmatch(b); m != nil {
			v = string(m[1])
		}
		add("go", clean(v, "latest"), "go.mod")
	}

	if exists(dir, "Cargo.toml") {
		v, why := "stable", "Cargo.toml"
		if b, err := os.ReadFile(filepath.Join(dir, "rust-toolchain.toml")); err == nil {
			if m := channelRE.FindSubmatch(b); m != nil {
				v, why = string(m[1]), "rust-toolchain.toml"
			}
		} else if l := firstLine(filepath.Join(dir, "rust-toolchain")); l != "" {
			v, why = l, "rust-toolchain"
		}
		add("rust", clean(v, "stable"), why)
	}
	sort.Strings(p.Tools)
	return p
}

// MiseConfigText renders Tools as a mise config file.
func (p Plan) MiseConfigText() string {
	var b strings.Builder
	b.WriteString("# Detected by windevvm from the project's files.\n[tools]\n")
	for _, t := range p.Tools {
		name, ver, _ := strings.Cut(t, "@")
		fmt.Fprintf(&b, "%s = %q\n", name, ver)
	}
	return b.String()
}
