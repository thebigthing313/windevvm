package proxy

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"

	"windevvm/internal/ca"
	"windevvm/internal/inject"
	"windevvm/internal/policy"
	"windevvm/internal/secrets"
)

const (
	ghPH    = "wdvm_ph_GITHUB_TOKEN_0123456789abcdef0123456789abcdef"
	ghVal   = "ghp_REAL_SECRET_VALUE_123"
	otherPH = "wdvm_ph_OTHER_0123456789abcdef0123456789abcdef"
	otherV  = "other-real-secret-value"
)

type seen struct {
	Auth string
	Body string
	Host string
}

type env struct {
	t        *testing.T
	upstream *httptest.Server
	port     string
	plain    *httptest.Server
	proxy    *Server
	client   *http.Client

	mu     sync.Mutex
	last   *seen
	events []Event
}

func echoHandler(e *env) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		e.mu.Lock()
		e.last = &seen{Auth: r.Header.Get("Authorization"), Body: string(body), Host: r.Host}
		e.mu.Unlock()
		w.Header().Set("X-Echo-Auth", r.Header.Get("Authorization"))
		fmt.Fprintf(w, "auth=%s body=%s", r.Header.Get("Authorization"), body)
	})
}

func newEnv(t *testing.T, rules string, bindings []inject.Binding) *env {
	t.Helper()
	e := &env{t: t}
	e.upstream = httptest.NewTLSServer(echoHandler(e))
	t.Cleanup(e.upstream.Close)
	e.plain = httptest.NewServer(echoHandler(e))
	t.Cleanup(e.plain.Close)
	_, e.port, _ = net.SplitHostPort(e.upstream.Listener.Addr().String())

	c, err := ca.New()
	if err != nil {
		t.Fatal(err)
	}
	inj, err := inject.New(bindings)
	if err != nil {
		t.Fatal(err)
	}
	userRules, err := policy.ParseRules(rules)
	if err != nil {
		t.Fatal(err)
	}
	var builtin []policy.Rule
	for _, h := range inj.BoundHosts() {
		r, err := policy.ParseRule(h + ":*")
		if err != nil {
			t.Fatal(err)
		}
		builtin = append(builtin, r)
	}

	upstreamRoots := x509.NewCertPool()
	upstreamRoots.AddCert(e.upstream.Certificate())

	e.proxy = New(c, &VM{
		Name:     "test",
		SourceIP: netip.MustParseAddr("127.0.0.1"),
		Policy:   &policy.Policy{Tier: policy.Allowlist, Rules: userRules, Builtin: builtin},
		Injector: inj,
	})
	e.proxy.UpstreamRoots = upstreamRoots
	e.proxy.Resolve = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	e.proxy.OnEvent = func(ev Event) {
		e.mu.Lock()
		e.events = append(e.events, ev)
		e.mu.Unlock()
	}
	ps := httptest.NewServer(e.proxy)
	t.Cleanup(ps.Close)
	proxyURL, _ := url.Parse(ps.URL)

	// The VM trusts the windevvm CA, plus (for the tunnel test) the upstream's
	// own certificate.
	vmRoots := c.Pool()
	vmRoots.AddCert(e.upstream.Certificate())
	tr := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	tr.TLSClientConfig = tlsConfig(vmRoots)
	t.Cleanup(tr.CloseIdleConnections)
	e.client = &http.Client{Transport: tr}
	return e
}

func ghBinding() inject.Binding {
	return inject.Binding{Placeholder: ghPH, Secret: secrets.Secret{Name: "GITHUB_TOKEN", Hosts: []string{"example.com"}, Value: []byte(ghVal)}}
}

func otherBinding() inject.Binding {
	return inject.Binding{Placeholder: otherPH, Secret: secrets.Secret{Name: "OTHER", Hosts: []string{"other.test"}, In: []secrets.Location{secrets.InHeader, secrets.InBody}, Value: []byte(otherV)}}
}

func (e *env) do(method, rawurl, body string, hdr map[string]string) (*http.Response, string, error) {
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, rawurl, rd)
	if err != nil {
		e.t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b), nil
}

func (e *env) lastSeen() *seen {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := e.last
	e.last = nil
	return s
}

func (e *env) hasEvent(kind string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, ev := range e.events {
		if ev.Kind == kind {
			return true
		}
	}
	return false
}

func (e *env) url(host string) string { return "https://" + host + ":" + e.port + "/echo" }

const loopback = "127.0.0.0/8:*\n"

func TestInjectsAndScrubs(t *testing.T) {
	e := newEnv(t, loopback, []inject.Binding{ghBinding()})
	resp, body, err := e.do("GET", e.url("example.com"), "", map[string]string{"Authorization": "Bearer " + ghPH})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	if got := e.lastSeen(); got == nil || got.Auth != "Bearer "+ghVal {
		t.Fatalf("upstream saw %+v, want the real token", got)
	}
	if strings.Contains(body, ghVal) || !strings.Contains(body, ghPH) {
		t.Fatalf("response body not scrubbed: %q", body)
	}
	if resp.Header.Get("X-Echo-Auth") != "Bearer "+ghPH {
		t.Fatalf("response header not scrubbed: %q", resp.Header.Get("X-Echo-Auth"))
	}
	if resp.TLS == nil || resp.TLS.PeerCertificates[0].Issuer.CommonName != "windevvm local CA" {
		t.Fatal("expected the windevvm CA to terminate TLS for an injected host")
	}
	if !e.hasEvent(KindInject) {
		t.Fatal("expected an inject event")
	}
}

func TestBasicAuthAndBody(t *testing.T) {
	e := newEnv(t, loopback, []inject.Binding{ghBinding(), otherBinding()})
	req, _ := http.NewRequest("POST", e.url("example.com"), strings.NewReader("payload"))
	req.SetBasicAuth("x-access-token", ghPH)
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	got := e.lastSeen()
	if got == nil {
		t.Fatal("upstream not reached")
	}
	r := &http.Request{Header: http.Header{"Authorization": {got.Auth}}}
	if _, pass, ok := r.BasicAuth(); !ok || pass != ghVal {
		t.Fatalf("upstream basic auth password = %q", pass)
	}
	if got.Body != "payload" {
		t.Fatalf("body = %q", got.Body)
	}
}

func TestBlocksPlaceholderToWrongHost(t *testing.T) {
	e := newEnv(t, loopback, []inject.Binding{ghBinding(), otherBinding()})
	resp, body, err := e.do("GET", e.url("example.com"), "", map[string]string{"X-Leak": otherPH})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d, want 403: %s", resp.StatusCode, body)
	}
	if e.lastSeen() != nil {
		t.Fatal("the request must not reach upstream")
	}
	if !e.hasEvent(KindExfil) {
		t.Fatal("expected an exfil event")
	}

	// In the body too, even though OTHER allows body injection (on other.test).
	resp, _, err = e.do("POST", e.url("example.com"), "data="+otherPH, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden || e.lastSeen() != nil {
		t.Fatalf("body leak: status %d", resp.StatusCode)
	}
}

func TestBlocksDisallowedHost(t *testing.T) {
	e := newEnv(t, loopback, []inject.Binding{ghBinding()})
	_, _, err := e.do("GET", e.url("blocked.test"), "", nil)
	if err == nil || !strings.Contains(err.Error(), "Forbidden") {
		t.Fatalf("expected CONNECT to be refused, got %v", err)
	}
	if !e.hasEvent(KindBlock) {
		t.Fatal("expected a block event")
	}
}

func TestTunnelsUninterceptedHosts(t *testing.T) {
	e := newEnv(t, loopback, []inject.Binding{ghBinding()})
	resp, body, err := e.do("GET", e.url("127.0.0.1"), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	if !resp.TLS.PeerCertificates[0].Equal(e.upstream.Certificate()) {
		t.Fatal("an unbound host must be tunneled with the upstream's own certificate")
	}
}

func TestPlainHTTP(t *testing.T) {
	e := newEnv(t, loopback, []inject.Binding{ghBinding()})
	resp, body, err := e.do("GET", e.plain.URL+"/echo", "", nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("plain request failed: %v %v %s", err, resp, body)
	}
	resp, _, err = e.do("GET", e.plain.URL+"/echo", "", map[string]string{"Authorization": "Bearer " + ghPH})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("placeholder over plain HTTP: status %d, want 403", resp.StatusCode)
	}
	if got := e.lastSeen(); got != nil && strings.Contains(got.Auth, "wdvm_ph") {
		t.Fatal("placeholder reached upstream")
	}
}

func TestRefusesNonPublicAddressWithoutRule(t *testing.T) {
	// example.com resolves to 127.0.0.1 here; without an explicit range rule
	// the proxy must refuse to dial it.
	e := newEnv(t, "", []inject.Binding{ghBinding()})
	resp, body, err := e.do("GET", e.url("example.com"), "", map[string]string{"Authorization": "Bearer " + ghPH})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "not a public address") {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	if e.lastSeen() != nil {
		t.Fatal("must not reach a non-public address")
	}
}

func TestSourceIPCheck(t *testing.T) {
	e := newEnv(t, loopback, []inject.Binding{ghBinding()})
	vm := *e.proxy.Config()
	vm.SourceIP = netip.MustParseAddr("10.77.0.5")
	e.proxy.SetVM(&vm)
	_, _, err := e.do("GET", e.url("example.com"), "", nil)
	if err == nil {
		t.Fatal("expected the proxy to refuse a request from the wrong address")
	}
}

func TestEventsNeverHoldInjectedSecrets(t *testing.T) {
	b := otherBinding()
	b.Secret.Hosts = []string{"example.com"}
	b.Secret.In = []secrets.Location{secrets.InURL}
	e := newEnv(t, loopback, []inject.Binding{b})
	resp, _, err := e.do("GET", "https://example.com:"+e.port+"/v1/"+otherPH+"/x", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	found := false
	for _, ev := range e.events {
		if strings.Contains(fmt.Sprintf("%+v", ev), otherV) {
			t.Fatalf("event holds the real secret: %+v", ev)
		}
		if ev.Kind == KindInject && strings.Contains(ev.Path, otherPH) {
			found = true
		}
	}
	if !found {
		t.Fatal("expected an inject event with the placeholder path")
	}
}
