package egress

import (
	"net/netip"
	"strings"
	"testing"

	"windevvm/internal/policy"
	"windevvm/internal/secrets"
)

func TestPort(t *testing.T) {
	if p := Port(netip.MustParseAddr("10.77.0.10")); p != 18010 {
		t.Fatalf("port = %d", p)
	}
	if p := Port(netip.MustParseAddr("10.77.0.250")); p != 18250 {
		t.Fatalf("port = %d", p)
	}
}

func TestPresetsParse(t *testing.T) {
	for name := range Presets {
		if _, err := ExpandRule("@" + name); err != nil {
			t.Errorf("@%s: %v", name, err)
		}
	}
	if _, err := ExpandRule("@nope"); err == nil {
		t.Fatal("unknown preset accepted")
	}
	for _, line := range ParseLines(DefaultGlobalPolicy) {
		if _, err := ExpandRule(line); err != nil {
			t.Errorf("default policy %q: %v", line, err)
		}
	}
	rs, _ := ExpandRule("!@pypi")
	if len(rs) != 2 || !rs[0].Deny {
		t.Fatalf("!@pypi = %v", rs)
	}
}

func TestAssemble(t *testing.T) {
	gh := secrets.Secret{Name: "GITHUB_TOKEN", Hosts: []string{"github.com", "api.github.com"}}
	p, err := Assemble(Inputs{
		Sources: []Source{
			{Name: "global", Rules: []string{"@npm", "!evil.com"}},
			{Name: "project", Rules: []string{"*.supabase.co"}},
			{Name: "vm", Rules: []string{"db.internal:5432"}},
		},
		Secrets: []secrets.Secret{gh},
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.Tier != policy.Allowlist {
		t.Fatalf("tier = %s", p.Tier)
	}
	for _, c := range []struct {
		host  string
		port  int
		allow bool
	}{
		{"registry.npmjs.org", 443, true},
		{"x.supabase.co", 443, true},
		{"db.internal", 5432, true},
		{"evil.com", 443, false},
		{"api.github.com", 443, true}, // bound secret host
		{"api.anthropic.com", 443, true},
		{"pypi.org", 443, false},
	} {
		if d := p.Decide(c.host, c.port); d.Allow != c.allow {
			t.Errorf("%s:%d allow=%v want %v (%s)", c.host, c.port, d.Allow, c.allow, d.Reason)
		}
	}

	none, _ := Assemble(Inputs{TierOverride: "none", ProjectTier: "internet", Sources: []Source{{Name: "g", Rules: []string{"@npm"}}}, Secrets: []secrets.Secret{gh}})
	if none.Tier != policy.None || none.Decide("registry.npmjs.org", 443).Allow || !none.Decide("github.com", 443).Allow {
		t.Fatalf("tier none policy wrong: %+v", none)
	}
	if _, err := Assemble(Inputs{Sources: []Source{{Name: "vm policy", Rules: []string{"bad host!"}}}}); err == nil || !strings.Contains(err.Error(), "vm policy") {
		t.Fatalf("bad rule error = %v", err)
	}
}

func TestResolveTier(t *testing.T) {
	if tier, src, _ := ResolveTier("", ""); tier != policy.Allowlist || src != "default" {
		t.Fatal(tier, src)
	}
	if tier, _, _ := ResolveTier("", "internet"); tier != policy.Internet {
		t.Fatal(tier)
	}
	if tier, _, _ := ResolveTier("none", "internet"); tier != policy.None {
		t.Fatal(tier)
	}
	if _, _, err := ResolveTier("", "open"); err == nil {
		t.Fatal("bad project tier accepted")
	}
}

func TestSecretsInUse(t *testing.T) {
	got := SecretsInUse([]string{"B", "A"}, []string{"A", "C", ""})
	if strings.Join(got, ",") != "A,B,C" {
		t.Fatal(got)
	}
}

func TestEditRules(t *testing.T) {
	text := "# comment\n@npm\nfoo.com # trailing\n\n!bar.com\n"
	out, changed, err := EditRules(text, "bar.com", true)
	if err != nil || !changed {
		t.Fatal(err, changed)
	}
	if out != "# comment\n@npm\nfoo.com # trailing\n\nbar.com\n" {
		t.Fatalf("allow bar.com:\n%s", out)
	}
	out2, changed, _ := EditRules(out, "bar.com", true)
	if changed || out2 != out {
		t.Fatal("adding an existing rule changed the text")
	}
	out, _, _ = EditRules(out, "!FOO.com", true)
	if !strings.Contains(out, "!FOO.com") || strings.Contains(out, "foo.com # trailing") {
		t.Fatalf("deny foo.com:\n%s", out)
	}
	out, changed, _ = EditRules(out, "foo.com", false)
	if !changed || strings.Contains(strings.ToLower(out), "foo.com") {
		t.Fatalf("rm foo.com:\n%s", out)
	}
	if out, _, _ := EditRules("", "x.com", true); out != "x.com\n" {
		t.Fatalf("empty file: %q", out)
	}
	if _, _, err := EditRules("", "@nope", true); err == nil {
		t.Fatal("bad rule accepted")
	}
}

const testCert = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"

func TestGuestScript(t *testing.T) {
	ph := "wdvm_ph_GITHUB_TOKEN_0123456789abcdef0123456789abcdef"
	g := Guest{
		ProxyURL:     "http://10.77.0.1:18010",
		CACert:       []byte(testCert),
		Placeholders: map[string]string{"GITHUB_TOKEN": ph},
		Secrets:      []secrets.Secret{{Name: "GITHUB_TOKEN", Hosts: []string{"github.com", "api.github.com"}}},
	}
	s, err := g.Script()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`https_proxy="http://10.77.0.1:18010"`,
		`HTTPS_PROXY="http://10.77.0.1:18010"`,
		`NODE_EXTRA_CA_CERTS="/usr/local/share/ca-certificates/windevvm.crt"`,
		`SSL_CERT_FILE="/etc/ssl/certs/ca-certificates.crt"`,
		`REQUESTS_CA_BUNDLE="/etc/ssl/certs/ca-certificates.crt"`,
		`GITHUB_TOKEN="` + ph + `"`,
		`export GITHUB_TOKEN="` + ph + `"`,
		`Acquire::https::Proxy "http://10.77.0.1:18010/";`,
		`[credential "https://github.com"]`,
		"password=" + ph,
		testCert + "WDVM_EOF",
		GuestDone,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script lacks %q", want)
		}
	}

	bad := g
	bad.Placeholders = map[string]string{"HTTPS_PROXY": ph}
	if _, err := bad.Script(); err == nil {
		t.Fatal("reserved secret name accepted")
	}
	bad = g
	bad.Placeholders = map[string]string{"X": "a\"; rm -rf /"}
	if _, err := bad.Script(); err == nil {
		t.Fatal("unsafe placeholder accepted")
	}
	bad = g
	bad.CACert = []byte("junk")
	if _, err := bad.Script(); err == nil {
		t.Fatal("bad cert accepted")
	}
}
