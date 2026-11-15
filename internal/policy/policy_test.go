package policy

import (
	"net/netip"
	"testing"
)

func mustRules(t *testing.T, text string) []Rule {
	t.Helper()
	r, err := ParseRules(text)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestDecide(t *testing.T) {
	rules := mustRules(t, `
# comment
registry.npmjs.org
*.example.com   # trailing comment
!evil.example.com
db.internal:5432
`)
	builtin := mustRules(t, "api.github.com\napi.anthropic.com")

	cases := []struct {
		tier  Tier
		host  string
		port  int
		allow bool
	}{
		{Allowlist, "registry.npmjs.org", 443, true},
		{Allowlist, "a.example.com", 443, true},
		{Allowlist, "evil.example.com", 443, false},
		{Allowlist, "db.internal", 5432, true},
		{Allowlist, "db.internal", 443, false},
		{Allowlist, "pypi.org", 443, false},
		{Allowlist, "api.github.com", 443, true},
		{None, "registry.npmjs.org", 443, false},
		{None, "api.anthropic.com", 443, true},
		{Internet, "pypi.org", 443, true},
		{Internet, "evil.example.com", 443, false},
	}
	for _, c := range cases {
		p := &Policy{Tier: c.tier, Rules: rules, Builtin: builtin}
		if d := p.Decide(c.host, c.port); d.Allow != c.allow {
			t.Errorf("%s: Decide(%s, %d) = %+v, want allow=%v", c.tier, c.host, c.port, d, c.allow)
		}
	}
}

func TestDecideSuggests(t *testing.T) {
	p := &Policy{Tier: Allowlist}
	if d := p.Decide("pypi.org", 443); d.Suggest != "pypi.org" {
		t.Errorf("Suggest = %q", d.Suggest)
	}
	if d := p.Decide("db.local", 5432); d.Suggest != "db.local:5432" {
		t.Errorf("Suggest = %q", d.Suggest)
	}
}

func TestDenyBeatsBuiltin(t *testing.T) {
	p := &Policy{Tier: Internet, Rules: mustRules(t, "!api.github.com"), Builtin: mustRules(t, "api.github.com")}
	if p.Decide("api.github.com", 443).Allow {
		t.Error("a deny rule must beat a built-in allow")
	}
}

func TestCheckIP(t *testing.T) {
	ip := netip.MustParseAddr
	p := &Policy{Tier: Internet}
	for _, bad := range []string{"127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.1", "169.254.169.254", "100.64.0.1", "::1", "fe80::1", "fd00::1", "::ffff:10.0.0.1", "0.0.0.0"} {
		if err := p.CheckIP(ip(bad), 443); err == nil {
			t.Errorf("CheckIP(%s): expected refusal", bad)
		}
	}
	for _, good := range []string{"140.82.112.3", "2606:4700::6810:84e5"} {
		if err := p.CheckIP(ip(good), 443); err != nil {
			t.Errorf("CheckIP(%s): %v", good, err)
		}
	}

	p.Rules = mustRules(t, "192.168.1.0/24:*\n!140.82.112.0/24")
	if err := p.CheckIP(ip("192.168.1.20"), 8080); err != nil {
		t.Errorf("explicit range rule should allow: %v", err)
	}
	if err := p.CheckIP(ip("140.82.112.3"), 443); err == nil {
		t.Error("deny range should refuse a public address")
	}

	p.Tier = None
	if err := p.CheckIP(ip("192.168.1.20"), 8080); err == nil {
		t.Error("tier none must ignore user allow rules")
	}
}

func TestParseTier(t *testing.T) {
	if _, err := ParseTier("open"); err == nil {
		t.Error("open is not a tier in v1")
	}
	if tr, err := ParseTier(" Allowlist "); err != nil || tr != Allowlist {
		t.Errorf("ParseTier = %v, %v", tr, err)
	}
}
