package hostmatch

import (
	"net/netip"
	"testing"
)

func TestMatch(t *testing.T) {
	cases := []struct {
		pattern string
		host    string
		port    int
		want    bool
	}{
		{"example.com", "example.com", 443, true},
		{"example.com", "EXAMPLE.com.", 80, true},
		{"example.com", "example.com", 22, false},
		{"example.com", "api.example.com", 443, false},
		{"*.example.com", "api.example.com", 443, true},
		{"*.example.com", "a.b.example.com", 443, true},
		{"*.example.com", "example.com", 443, false},
		{"*.example.com", "badexample.com", 443, false},
		{"example.com:22", "example.com", 22, true},
		{"example.com:22", "example.com", 443, false},
		{"example.com:*", "example.com", 5432, true},
		{"**", "anything.test", 443, true},
		{"**", "anything.test", 8080, false},
		{"**:*", "anything.test", 8080, true},
		{"10.0.0.0/8", "10.1.2.3", 443, true},
		{"10.0.0.0/8", "11.1.2.3", 443, false},
		{"10.0.0.0/8:*", "10.1.2.3", 5432, true},
		{"192.168.1.5", "192.168.1.5", 80, true},
		{"[fd00::/8]:22", "fd12::1", 22, true},
		{"fd00::/8", "[fd12::1]", 443, true},
		{"10.0.0.0/8", "example.com", 443, false},
	}
	for _, c := range cases {
		p, err := Parse(c.pattern)
		if err != nil {
			t.Fatalf("Parse(%q): %v", c.pattern, err)
		}
		if got := p.Match(c.host, c.port); got != c.want {
			t.Errorf("%q.Match(%q, %d) = %v, want %v", c.pattern, c.host, c.port, got, c.want)
		}
	}
}

func TestParseErrors(t *testing.T) {
	for _, s := range []string{"", "exa mple.com", "*example.com", "a.*.com", "example.com:0", "example.com:x", "10.0.0.0/99", "[::1", "foo..bar"} {
		if _, err := Parse(s); err == nil {
			t.Errorf("Parse(%q): expected an error", s)
		}
	}
}

func TestMatchIP(t *testing.T) {
	p := MustParse("127.0.0.0/8:*")
	if !p.MatchIP(netip.MustParseAddr("127.0.0.1"), 9999) {
		t.Error("expected 127.0.0.1 to match")
	}
	if !p.MatchIP(netip.MustParseAddr("::ffff:127.0.0.1"), 9999) {
		t.Error("expected the IPv4-mapped form to match")
	}
	if MustParse("example.com").MatchIP(netip.MustParseAddr("127.0.0.1"), 443) {
		t.Error("host patterns must not match IPs")
	}
}
