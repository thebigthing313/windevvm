// Package hostmatch parses and matches destination patterns used by network
// rules and secret bindings.
package hostmatch

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

type kind int

const (
	kindExact kind = iota
	kindSuffix
	kindAll
	kindCIDR
)

// Pattern matches a destination host and port.
//
//	example.com     exactly that host
//	*.example.com   any subdomain of example.com, at any depth (not example.com itself)
//	**              any host
//	10.0.0.0/8      addresses in a range; a bare IP means just that address
//
// A pattern may end in :PORT or :*. Without a port it matches 80 and 443.
// IPv6 addresses with a port are written in brackets: [fd00::/8]:22.
type Pattern struct {
	raw     string
	kind    kind
	host    string // exact host, or ".example.com" for suffix patterns
	prefix  netip.Prefix
	anyPort bool
	port    int // 0 means the default web ports
}

// Parse parses a single pattern.
func Parse(s string) (Pattern, error) {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return Pattern{}, fmt.Errorf("empty pattern")
	}
	p := Pattern{raw: raw}
	hostPart, portPart, err := splitPort(raw)
	if err != nil {
		return Pattern{}, err
	}
	switch portPart {
	case "":
	case "*":
		p.anyPort = true
	default:
		n, err := strconv.Atoi(portPart)
		if err != nil || n < 1 || n > 65535 {
			return Pattern{}, fmt.Errorf("%q: bad port %q", raw, portPart)
		}
		p.port = n
	}

	h := strings.ToLower(strings.TrimSuffix(hostPart, "."))
	switch {
	case h == "**":
		p.kind = kindAll
	case strings.Contains(h, "/"):
		pfx, err := netip.ParsePrefix(h)
		if err != nil {
			return Pattern{}, fmt.Errorf("%q: bad address range: %v", raw, err)
		}
		if pfx.Addr().Is4In6() {
			pfx = netip.PrefixFrom(pfx.Addr().Unmap(), pfx.Bits()-96)
		}
		p.kind, p.prefix = kindCIDR, pfx.Masked()
	case isIP(h):
		ip := netip.MustParseAddr(h).Unmap()
		p.kind, p.prefix = kindCIDR, netip.PrefixFrom(ip, ip.BitLen())
	case strings.HasPrefix(h, "*."):
		rest := h[2:]
		if err := validHost(rest); err != nil {
			return Pattern{}, fmt.Errorf("%q: %v", raw, err)
		}
		p.kind, p.host = kindSuffix, "."+rest
	default:
		if err := validHost(h); err != nil {
			return Pattern{}, fmt.Errorf("%q: %v", raw, err)
		}
		p.kind, p.host = kindExact, h
	}
	return p, nil
}

// MustParse is Parse for patterns known to be valid.
func MustParse(s string) Pattern {
	p, err := Parse(s)
	if err != nil {
		panic(err)
	}
	return p
}

func splitPort(s string) (host, port string, err error) {
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 {
			return "", "", fmt.Errorf("%q: missing ]", s)
		}
		host, rest := s[1:end], s[end+1:]
		if rest == "" {
			return host, "", nil
		}
		if !strings.HasPrefix(rest, ":") {
			return "", "", fmt.Errorf("%q: expected :port after ]", s)
		}
		return host, rest[1:], nil
	}
	if strings.Count(s, ":") == 1 {
		i := strings.Index(s, ":")
		return s[:i], s[i+1:], nil
	}
	return s, "", nil
}

func isIP(s string) bool {
	_, err := netip.ParseAddr(s)
	return err == nil
}

func validHost(h string) error {
	if h == "" {
		return fmt.Errorf("empty host")
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" {
			return fmt.Errorf("empty label in host %q", h)
		}
		for _, r := range label {
			ok := r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_'
			if !ok {
				return fmt.Errorf("invalid character %q in host %q", r, h)
			}
		}
	}
	return nil
}

// Normalize lowercases a host and strips IPv6 brackets and a trailing dot.
func Normalize(host string) string {
	return strings.ToLower(strings.TrimSuffix(strings.Trim(host, "[]"), "."))
}

// String returns the pattern as written.
func (p Pattern) String() string { return p.raw }

// IsRange reports whether the pattern names IP addresses rather than hosts.
func (p Pattern) IsRange() bool { return p.kind == kindCIDR }

func (p Pattern) portOK(port int) bool {
	switch {
	case p.anyPort:
		return true
	case p.port != 0:
		return port == p.port
	default:
		return port == 80 || port == 443
	}
}

// MatchHost reports whether host matches, ignoring the port.
func (p Pattern) MatchHost(host string) bool {
	h := Normalize(host)
	switch p.kind {
	case kindAll:
		return true
	case kindExact:
		return h == p.host
	case kindSuffix:
		return strings.HasSuffix(h, p.host)
	case kindCIDR:
		ip, err := netip.ParseAddr(h)
		return err == nil && p.prefix.Contains(ip.Unmap())
	}
	return false
}

// Match reports whether host and port match.
func (p Pattern) Match(host string, port int) bool {
	return p.portOK(port) && p.MatchHost(host)
}

// MatchIP reports whether an address range pattern contains ip and allows port.
// Host patterns never match an IP here.
func (p Pattern) MatchIP(ip netip.Addr, port int) bool {
	return p.kind == kindCIDR && p.portOK(port) && p.prefix.Contains(ip.Unmap())
}
