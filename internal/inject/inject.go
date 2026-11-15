// Package inject swaps placeholders for real secrets in outgoing requests and
// real secrets back to placeholders in responses.
package inject

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"windevvm/internal/hostmatch"
	"windevvm/internal/secrets"
)

// Binding exposes a secret to one VM under a placeholder.
type Binding struct {
	Placeholder string
	Secret      secrets.Secret
}

// Violation reports a placeholder headed somewhere its secret isn't bound to:
// a likely exfiltration attempt. The request must be blocked.
type Violation struct {
	Secret string
	Host   string // empty for plain HTTP
	Where  secrets.Location
}

func (v *Violation) Error() string {
	if v.Host == "" {
		return fmt.Sprintf("placeholder for secret %s sent over plain HTTP (in the %s); secrets are only injected over HTTPS", v.Secret, v.Where)
	}
	return fmt.Sprintf("placeholder for secret %s sent to %s in the %s, where it is not bound", v.Secret, v.Host, v.Where)
}

// minScrubLen is the shortest secret value scrubbed from responses; shorter
// values would match innocent text.
const minScrubLen = 8

// maxBufferedBody is the largest request body rewritten in memory. Larger
// bodies are streamed without a Content-Length.
const maxBufferedBody = 16 << 20

type binding struct {
	Binding
	hosts []hostmatch.Pattern
	ph    []byte
}

func (b *binding) boundTo(host string) bool {
	for _, p := range b.hosts {
		if p.MatchHost(host) {
			return true
		}
	}
	return false
}

// Injector holds one VM's bindings. A nil *Injector has no bindings.
type Injector struct {
	b []*binding
}

// New validates bindings and builds an Injector.
func New(bindings []Binding) (*Injector, error) {
	in := &Injector{}
	seen := map[string]bool{}
	for _, bd := range bindings {
		if err := bd.Secret.Validate(); err != nil {
			return nil, err
		}
		if len(bd.Secret.Value) == 0 {
			return nil, fmt.Errorf("secret %s: empty value", bd.Secret.Name)
		}
		if !strings.HasPrefix(bd.Placeholder, secrets.PlaceholderPrefix) {
			return nil, fmt.Errorf("secret %s: malformed placeholder", bd.Secret.Name)
		}
		if seen[bd.Placeholder] {
			return nil, fmt.Errorf("secret %s: duplicate placeholder", bd.Secret.Name)
		}
		seen[bd.Placeholder] = true
		hosts, _ := bd.Secret.Patterns()
		in.b = append(in.b, &binding{Binding: bd, hosts: hosts, ph: []byte(bd.Placeholder)})
	}
	return in, nil
}

// Intercepts reports whether any secret is bound to host, meaning the proxy
// must open the TLS connection to host to inject into it.
func (in *Injector) Intercepts(host string) bool {
	if in == nil {
		return false
	}
	for _, b := range in.b {
		if b.boundTo(host) {
			return true
		}
	}
	return false
}

// BoundHosts returns every host pattern a secret is bound to.
func (in *Injector) BoundHosts() []string {
	if in == nil {
		return nil
	}
	var out []string
	for _, b := range in.b {
		out = append(out, b.Secret.Hosts...)
	}
	return out
}

func (in *Injector) resolve(b *binding, host string, secure bool, loc secrets.Location) ([]byte, error) {
	if !secure {
		return nil, &Violation{Secret: b.Secret.Name, Where: loc}
	}
	if !b.boundTo(host) || !b.Secret.Allows(loc) {
		return nil, &Violation{Secret: b.Secret.Name, Host: host, Where: loc}
	}
	return b.Secret.Value, nil
}

func (in *Injector) replaceString(s, host string, secure bool, loc secrets.Location, escape func(string) string, used map[string]bool) (string, error) {
	if !strings.Contains(s, secrets.PlaceholderPrefix) {
		return s, nil
	}
	for _, b := range in.b {
		if !strings.Contains(s, b.Placeholder) {
			continue
		}
		val, err := in.resolve(b, host, secure, loc)
		if err != nil {
			return "", err
		}
		v := string(val)
		if escape != nil {
			v = escape(v)
		}
		s = strings.ReplaceAll(s, b.Placeholder, v)
		used[b.Secret.Name] = true
	}
	return s, nil
}

// RewriteRequest replaces placeholders in r for a request to host. secure
// must be true only for requests that will travel over TLS; over plain HTTP
// any placeholder is a violation. It returns the names of injected secrets.
//
// Request bodies up to 16 MiB are rewritten in memory, so a violation there is
// caught before anything is sent upstream.
func (in *Injector) RewriteRequest(r *http.Request, host string, secure bool) ([]string, error) {
	if in == nil || len(in.b) == 0 {
		return nil, nil
	}
	used := map[string]bool{}

	for k, vals := range r.Header {
		basic := strings.EqualFold(k, "Authorization") || strings.EqualFold(k, "Proxy-Authorization")
		for i, v := range vals {
			nv, err := in.replaceString(v, host, secure, secrets.InHeader, nil, used)
			if err != nil {
				return nil, err
			}
			if basic {
				if nv, err = in.rewriteBasic(nv, host, secure, used); err != nil {
					return nil, err
				}
			}
			vals[i] = nv
		}
	}

	if r.URL != nil {
		q, err := in.replaceString(r.URL.RawQuery, host, secure, secrets.InURL, url.QueryEscape, used)
		if err != nil {
			return nil, err
		}
		r.URL.RawQuery = q
		ep := r.URL.EscapedPath()
		np, err := in.replaceString(ep, host, secure, secrets.InURL, url.PathEscape, used)
		if err != nil {
			return nil, err
		}
		if np != ep {
			if r.URL.Path, err = url.PathUnescape(np); err != nil {
				return nil, err
			}
			r.URL.RawPath = np
		}
	}

	if err := in.rewriteBody(r, host, secure, used); err != nil {
		return nil, err
	}

	names := make([]string, 0, len(used))
	for n := range used {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, nil
}

// rewriteBasic handles "Basic base64(user:password)", where git and many
// tools put a token.
func (in *Injector) rewriteBasic(v, host string, secure bool, used map[string]bool) (string, error) {
	if len(v) < 6 || !strings.EqualFold(v[:6], "basic ") {
		return v, nil
	}
	dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v[6:]))
	if err != nil {
		return v, nil
	}
	nd, err := in.replaceString(string(dec), host, secure, secrets.InHeader, nil, used)
	if err != nil {
		return "", err
	}
	if nd == string(dec) {
		return v, nil
	}
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(nd)), nil
}

func (in *Injector) placeholderPatterns() [][]byte {
	pats := make([][]byte, len(in.b))
	for i, b := range in.b {
		pats[i] = b.ph
	}
	return pats
}

func (in *Injector) rewriteBody(r *http.Request, host string, secure bool, used map[string]bool) error {
	if r.Body == nil || r.Body == http.NoBody {
		return nil
	}
	orig := r.Body
	rd := newReplacer(orig, in.placeholderPatterns(), func(i int) ([]byte, error) {
		b := in.b[i]
		v, err := in.resolve(b, host, secure, secrets.InBody)
		if err == nil {
			used[b.Secret.Name] = true
		}
		return v, err
	})
	data, err := io.ReadAll(io.LimitReader(rd, maxBufferedBody+1))
	if err != nil {
		orig.Close()
		return err
	}
	r.GetBody = nil
	if len(data) <= maxBufferedBody {
		orig.Close()
		r.Body = io.NopCloser(bytes.NewReader(data))
		r.ContentLength = int64(len(data))
		r.TransferEncoding = nil
		if len(data) == 0 {
			r.Body = http.NoBody
		}
		return nil
	}
	r.Body = readCloser{io.MultiReader(bytes.NewReader(data), rd), orig}
	r.ContentLength = -1
	return nil
}

type readCloser struct {
	io.Reader
	io.Closer
}

// HasScrub reports whether any secret is long enough to scrub from responses.
func (in *Injector) HasScrub() bool {
	if in == nil {
		return false
	}
	for _, b := range in.b {
		if len(b.Secret.Value) >= minScrubLen {
			return true
		}
	}
	return false
}

// ScrubHeaders replaces real secret values in response headers with their
// placeholders, so a server echoing a token doesn't leak it into the VM.
func (in *Injector) ScrubHeaders(h http.Header) {
	if in == nil {
		return
	}
	for _, vals := range h {
		for i, v := range vals {
			for _, b := range in.b {
				if len(b.Secret.Value) >= minScrubLen {
					v = strings.ReplaceAll(v, string(b.Secret.Value), b.Placeholder)
				}
			}
			vals[i] = v
		}
	}
}

// ScrubReader wraps a response body, replacing real secret values with their
// placeholders as it streams.
func (in *Injector) ScrubReader(r io.Reader) io.Reader {
	if in == nil {
		return r
	}
	var pats [][]byte
	var reps [][]byte
	for _, b := range in.b {
		if len(b.Secret.Value) >= minScrubLen {
			pats = append(pats, b.Secret.Value)
			reps = append(reps, b.ph)
		}
	}
	return newReplacer(r, pats, func(i int) ([]byte, error) { return reps[i], nil })
}
