// Package policy decides which destinations a VM may reach.
package policy

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"windevvm/internal/hostmatch"
)

// Tier is the baseline network access level of a VM.
type Tier string

const (
	// None allows only built-in hosts: bound secret hosts and agent hosts.
	None Tier = "none"
	// Allowlist adds hosts named by allow rules. It is the default.
	Allowlist Tier = "allowlist"
	// Internet allows any public host. Non-public addresses still need a rule.
	Internet Tier = "internet"
)

// ParseTier parses a tier name.
func ParseTier(s string) (Tier, error) {
	switch t := Tier(strings.ToLower(strings.TrimSpace(s))); t {
	case None, Allowlist, Internet:
		return t, nil
	}
	return "", fmt.Errorf("unknown network tier %q (want none, allowlist or internet)", s)
}

// Rule allows or denies destinations matching a pattern.
type Rule struct {
	Deny    bool
	Pattern hostmatch.Pattern
}

func (r Rule) String() string {
	if r.Deny {
		return "!" + r.Pattern.String()
	}
	return r.Pattern.String()
}

// ParseRule parses "pattern" (allow) or "!pattern" (deny).
func ParseRule(s string) (Rule, error) {
	s = strings.TrimSpace(s)
	deny := strings.HasPrefix(s, "!")
	if deny {
		s = strings.TrimSpace(s[1:])
	}
	p, err := hostmatch.Parse(s)
	if err != nil {
		return Rule{}, err
	}
	return Rule{Deny: deny, Pattern: p}, nil
}

// ParseRules parses a policy file: one rule per line, # starts a comment.
func ParseRules(text string) ([]Rule, error) {
	var rules []Rule
	for i, line := range strings.Split(text, "\n") {
		if j := strings.Index(line, "#"); j >= 0 {
			line = line[:j]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		r, err := ParseRule(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		rules = append(rules, r)
	}
	return rules, nil
}

// Policy is the effective network policy of one VM.
type Policy struct {
	Tier Tier
	// Rules are the user's rules (global plus per-VM). Denies always win.
	Rules []Rule
	// Builtin rules are allowed on every tier: hosts that bound secrets are
	// injected into, and the coding agents' API hosts.
	Builtin []Rule
}

// Decision is the outcome of a policy check.
type Decision struct {
	Allow  bool
	Reason string
	// Rule is the rule that decided, if any.
	Rule string
	// Suggest is a rule that would allow a blocked destination.
	Suggest string
}

// Decide checks whether host:port may be reached.
func (p *Policy) Decide(host string, port int) Decision {
	host = hostmatch.Normalize(host)
	for _, r := range p.Rules {
		if r.Deny && r.Pattern.Match(host, port) {
			return Decision{Reason: "denied by rule " + r.String(), Rule: r.String()}
		}
	}
	for _, r := range p.Builtin {
		if !r.Deny && r.Pattern.Match(host, port) {
			return Decision{Allow: true, Reason: "built-in host", Rule: r.String()}
		}
	}
	switch p.Tier {
	case Internet, Allowlist:
		for _, r := range p.Rules {
			if !r.Deny && r.Pattern.Match(host, port) {
				return Decision{Allow: true, Reason: "allowed by rule " + r.String(), Rule: r.String()}
			}
		}
		if p.Tier == Internet {
			return Decision{Allow: true, Reason: "tier internet"}
		}
		return Decision{Reason: "not on the allowlist", Suggest: Suggest(host, port)}
	default:
		return Decision{Reason: "tier none allows only built-in hosts", Suggest: Suggest(host, port)}
	}
}

// Suggest returns the narrowest rule that would allow host:port.
func Suggest(host string, port int) string {
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port == 80 || port == 443 {
		return host
	}
	return host + ":" + strconv.Itoa(port)
}

// CheckIP vets an address just before the proxy dials it. Non-public
// addresses (loopback, private, link-local and so on) are refused unless an
// allow rule names them by address range, so a public hostname can't be
// pointed at the host machine or the LAN.
func (p *Policy) CheckIP(ip netip.Addr, port int) error {
	ip = ip.Unmap()
	for _, r := range p.Rules {
		if r.Deny && r.Pattern.MatchIP(ip, port) {
			return fmt.Errorf("%s is denied by rule %s", ip, r)
		}
	}
	if IsPublic(ip) {
		return nil
	}
	allowed := p.Builtin
	if p.Tier != None {
		allowed = append(append([]Rule(nil), p.Rules...), p.Builtin...)
	}
	for _, r := range allowed {
		if !r.Deny && r.Pattern.MatchIP(ip, port) {
			return nil
		}
	}
	return fmt.Errorf("%s is not a public address; to allow it add a rule such as %s", ip, Suggest(ip.String(), port))
}

var nonPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2001:db8::/32"),
}

// IsPublic reports whether ip is a globally routable unicast address.
func IsPublic(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, pfx := range nonPublic {
		if pfx.Contains(ip) {
			return false
		}
	}
	return true
}
