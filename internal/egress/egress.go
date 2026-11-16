// Package egress assembles a VM's effective network policy from its sources
// (global policy file, .windevvm.toml, the VM's own policy file, presets and
// bound secrets) and renders the VM-side proxy configuration.
package egress

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"windevvm/internal/policy"
	"windevvm/internal/secrets"
)

// PortBase plus the last octet of a VM's address is the port its proxy
// listens on. VMs use .10-.250, so ports fall in 18010-18250.
const PortBase = 18000

// Port is the proxy port for a VM address.
func Port(ip netip.Addr) int {
	b := ip.As4()
	return PortBase + int(b[3])
}

// Presets are named sets of rules, written @name in a policy file or on the
// command line.
var Presets = map[string][]string{
	"apt": {
		"archive.ubuntu.com", "*.archive.ubuntu.com", "security.ubuntu.com",
		"ports.ubuntu.com", "ppa.launchpadcontent.net",
	},
	"npm":  {"registry.npmjs.org", "registry.yarnpkg.com", "repo.yarnpkg.com"},
	"pypi": {"pypi.org", "files.pythonhosted.org"},
	"github": {
		"github.com", "api.github.com", "codeload.github.com", "uploads.github.com",
		"*.githubusercontent.com", "ghcr.io", "pkg-containers.githubusercontent.com",
	},
	// mise and the toolchains it installs (node, go, rust; python comes from
	// GitHub releases, so it needs @github too).
	"mise": {
		"mise.run", "mise.jdx.dev", "mise-versions.jdx.dev", "nodejs.org",
		"go.dev", "dl.google.com", "static.rust-lang.org", "sh.rustup.rs",
	},
	// VS Code Remote-SSH: its server download and the extension marketplace.
	"vscode": {
		"update.code.visualstudio.com", "vscode.download.prss.microsoft.com", "*.vo.msecnd.net",
		"marketplace.visualstudio.com", "*.gallery.vsassets.io", "*.gallerycdn.vsassets.io",
		"*.vscode-unpkg.net", "*.vscode-cdn.net", "open-vsx.org",
	},
	"go":     {"proxy.golang.org", "sum.golang.org", "storage.googleapis.com"},
	"crates": {"crates.io", "index.crates.io", "static.crates.io"},
}

// AgentHosts are the coding agents' API and sign-in hosts. They are allowed
// on every tier, like the hosts bound secrets are injected into.
var AgentHosts = []string{
	"api.anthropic.com", "statsig.anthropic.com", "console.anthropic.com", "claude.ai",
	"api.openai.com", "auth.openai.com", "chatgpt.com",
}

// DefaultGlobalPolicy is written to the global policy file the first time
// it is needed.
const DefaultGlobalPolicy = `# windevvm global network policy: applies to every VM.
# One rule per line: example.com, *.example.com, host:port, 10.0.0.0/8:5432,
# @preset, and !rule to deny (denies always win). Edit freely, or use
# windevvm network allow|deny|rm --global.
#
# Presets: apt, npm, pypi, github, mise, go, crates, vscode.
@apt
@npm
@pypi
@github
@mise
@go
@crates
@vscode
`

// PresetNames lists the presets, sorted.
func PresetNames() []string {
	names := make([]string, 0, len(Presets))
	for n := range Presets {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// ExpandRule parses one rule, expanding @preset (or !@preset) into its rules.
func ExpandRule(s string) ([]policy.Rule, error) {
	s = strings.TrimSpace(s)
	deny := strings.HasPrefix(s, "!")
	body := strings.TrimSpace(strings.TrimPrefix(s, "!"))
	if name, ok := strings.CutPrefix(body, "@"); ok {
		hosts, ok := Presets[strings.ToLower(name)]
		if !ok {
			return nil, fmt.Errorf("unknown preset @%s (have %s)", name, strings.Join(PresetNames(), ", "))
		}
		out := make([]policy.Rule, 0, len(hosts))
		for _, h := range hosts {
			if deny {
				h = "!" + h
			}
			r, err := policy.ParseRule(h)
			if err != nil {
				return nil, err
			}
			out = append(out, r)
		}
		return out, nil
	}
	r, err := policy.ParseRule(s)
	if err != nil {
		return nil, err
	}
	return []policy.Rule{r}, nil
}

// ParseLines returns the rule lines in a policy file, without comments or
// blank lines.
func ParseLines(text string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}

// Source is one named list of rules, e.g. the global policy file.
type Source struct {
	Name  string
	Rules []string
}

// Inputs are everything a VM's policy is made from.
type Inputs struct {
	// TierOverride is set with `windevvm network TIER`; it beats the project file.
	TierOverride string
	ProjectTier  string
	Sources      []Source
	// Secrets are the secrets in use by the VM; their hosts become built-in.
	Secrets []secrets.Secret
}

// ResolveTier picks the tier and says where it came from.
func ResolveTier(override, project string) (policy.Tier, string, error) {
	switch {
	case override != "":
		t, err := policy.ParseTier(override)
		return t, "set with windevvm network", err
	case project != "":
		t, err := policy.ParseTier(project)
		if err != nil {
			return "", "", fmt.Errorf(".windevvm.toml: %w", err)
		}
		return t, ".windevvm.toml", nil
	}
	return policy.Allowlist, "default", nil
}

// Builtin returns the rules allowed on every tier: agent hosts and the
// hosts the given secrets are bound to.
func Builtin(in []secrets.Secret) []policy.Rule {
	var out []policy.Rule
	seen := map[string]bool{}
	add := func(h string) {
		if seen[h] {
			return
		}
		seen[h] = true
		if r, err := policy.ParseRule(h); err == nil && !r.Deny {
			out = append(out, r)
		}
	}
	for _, h := range AgentHosts {
		add(h)
	}
	for _, s := range in {
		for _, h := range s.Hosts {
			add(h)
		}
	}
	return out
}

// Assemble builds the effective policy.
func Assemble(in Inputs) (*policy.Policy, error) {
	tier, _, err := ResolveTier(in.TierOverride, in.ProjectTier)
	if err != nil {
		return nil, err
	}
	p := &policy.Policy{Tier: tier, Builtin: Builtin(in.Secrets)}
	for _, src := range in.Sources {
		for _, line := range src.Rules {
			rs, err := ExpandRule(line)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", src.Name, err)
			}
			p.Rules = append(p.Rules, rs...)
		}
	}
	return p, nil
}

// SecretsInUse merges the project file's [secrets] use with the secrets
// enabled with `windevvm secret use`, sorted and without duplicates.
func SecretsInUse(project, vm []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range append(append([]string(nil), project...), vm...) {
		if n = strings.TrimSpace(n); n != "" && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// EditRules adds or removes one rule in a policy file's text, keeping
// comments and the order of the other lines.
//
//	add=true, rule "x"   removes "!x" and appends "x" (if not present)
//	add=true, rule "!x"  removes "x" and appends "!x"
//	add=false            removes "x" and "!x"
//
// changed reports whether the text changed.
func EditRules(text, rule string, add bool) (out string, changed bool, err error) {
	rule = strings.TrimSpace(rule)
	if _, err := ExpandRule(rule); err != nil {
		return text, false, err
	}
	bare := strings.TrimSpace(strings.TrimPrefix(rule, "!"))
	norm := func(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

	var lines []string
	present := false
	var existing []string
	if t := strings.TrimRight(text, "\r\n"); t != "" {
		existing = strings.Split(t, "\n")
	}
	for _, line := range existing {
		line = strings.TrimRight(line, "\r")
		content := line
		if i := strings.Index(content, "#"); i >= 0 {
			content = content[:i]
		}
		content = strings.TrimSpace(content)
		if content != "" {
			if add && norm(content) == norm(rule) {
				present = true
			} else if norm(strings.TrimPrefix(content, "!")) == norm(bare) {
				changed = true
				continue
			}
		}
		lines = append(lines, line)
	}
	if add && !present {
		lines = append(lines, rule)
		changed = true
	}
	out = strings.Join(lines, "\n")
	if strings.TrimSpace(out) == "" {
		out = ""
	} else {
		out += "\n"
	}
	return out, changed, nil
}
