// Package secrets defines secrets, their host bindings and placeholders, and
// stores them encrypted on the host.
package secrets

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"

	"windevvm/internal/hostmatch"
)

// Location is a part of a request the proxy may inject a secret into.
type Location string

const (
	// InHeader covers every request header, including the user:password
	// inside a Basic Authorization header. It is the default.
	InHeader Location = "header"
	// InURL covers the request path and query string.
	InURL Location = "url"
	// InBody covers the request body.
	InBody Location = "body"
)

// ParseLocation parses a location name.
func ParseLocation(s string) (Location, error) {
	switch l := Location(s); l {
	case InHeader, InURL, InBody:
		return l, nil
	}
	return "", fmt.Errorf("unknown location %q (want header, url or body)", s)
}

// Secret is a value the proxy injects into requests to its bound hosts.
type Secret struct {
	Name string `json:"name"`
	// Hosts are hostmatch patterns (ports are ignored). The secret is only
	// ever injected into HTTPS requests to these hosts.
	Hosts []string `json:"hosts"`
	// In lists where in a request the secret may be injected. Empty means
	// headers only.
	In []Location `json:"in,omitempty"`
	// Value is the real secret. It is never serialized with the metadata.
	Value []byte `json:"-"`
}

var nameRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)

// ValidateName checks that name is usable as a secret and env var name.
func ValidateName(name string) error {
	if !nameRE.MatchString(name) {
		return fmt.Errorf("invalid secret name %q: use letters, digits and _, starting with a letter", name)
	}
	return nil
}

// Validate checks the metadata (not the value).
func (s Secret) Validate() error {
	if err := ValidateName(s.Name); err != nil {
		return err
	}
	if len(s.Hosts) == 0 {
		return fmt.Errorf("secret %s: at least one host is required", s.Name)
	}
	if _, err := s.Patterns(); err != nil {
		return fmt.Errorf("secret %s: %w", s.Name, err)
	}
	for _, l := range s.In {
		if _, err := ParseLocation(string(l)); err != nil {
			return fmt.Errorf("secret %s: %w", s.Name, err)
		}
	}
	return nil
}

// Patterns parses the bound hosts.
func (s Secret) Patterns() ([]hostmatch.Pattern, error) {
	ps := make([]hostmatch.Pattern, 0, len(s.Hosts))
	for _, h := range s.Hosts {
		p, err := hostmatch.Parse(h)
		if err != nil {
			return nil, err
		}
		ps = append(ps, p)
	}
	return ps, nil
}

// Allows reports whether the secret may be injected at loc.
func (s Secret) Allows(loc Location) bool {
	if len(s.In) == 0 {
		return loc == InHeader
	}
	for _, l := range s.In {
		if l == loc {
			return true
		}
	}
	return false
}

// PlaceholderPrefix starts every placeholder.
const PlaceholderPrefix = "wdvm_ph_"

// NewPlaceholder returns a fresh random placeholder for a secret. Each VM gets
// its own placeholder per secret, so a leaked placeholder is useless anywhere
// else and identifies the VM it came from.
func NewPlaceholder(name string) (string, error) {
	if err := ValidateName(name); err != nil {
		return "", err
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return PlaceholderPrefix + name + "_" + hex.EncodeToString(b), nil
}

// Preset is a ready-made binding for a common service.
type Preset struct {
	Hosts []string
	In    []Location
	Note  string
}

// Presets are the built-in bindings, selected with --preset.
var Presets = map[string]Preset{
	"github": {
		Hosts: []string{"github.com", "api.github.com", "uploads.github.com", "codeload.github.com", "raw.githubusercontent.com"},
		Note:  "For git over HTTPS, use any username (e.g. x-access-token) and the placeholder as the password.",
	},
	"anthropic": {
		Hosts: []string{"api.anthropic.com"},
		Note:  "Use as ANTHROPIC_API_KEY, or a `claude setup-token` token as CLAUDE_CODE_OAUTH_TOKEN.",
	},
	"openai": {Hosts: []string{"api.openai.com"}},
	"npm":    {Hosts: []string{"registry.npmjs.org"}, Note: "Put the placeholder in .npmrc as //registry.npmjs.org/:_authToken=<placeholder>."},
}
