package proxy

import (
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"windevvm/internal/inject"
	"windevvm/internal/policy"
)

// why fetches the why page through the proxy, the way windevvm-why's curl
// does when HTTP_PROXY is set.
func (e *env) why(query string) (int, string) {
	e.t.Helper()
	resp, body, err := e.do("GET", "http://"+WhyHost+"/why"+query, "", nil)
	if err != nil {
		e.t.Fatal(err)
	}
	return resp.StatusCode, body
}

func TestWhyListsBlockedRequests(t *testing.T) {
	e := newEnv(t, loopback, []inject.Binding{ghBinding()})
	e.do("GET", e.url("blocked.test"), "", nil)
	e.do("GET", e.url("blocked.test"), "", nil)
	e.do("GET", e.url("other-blocked.test"), "", nil)

	status, body := e.why("")
	if status != 200 {
		t.Fatalf("status %d: %s", status, body)
	}
	for _, want := range []string{"blocked.test:" + e.port, "other-blocked.test:" + e.port, "windevvm network allow blocked.test", "2 times"} {
		if !strings.Contains(body, want) {
			t.Errorf("why page lacks %q:\n%s", want, body)
		}
	}
	// Newest first.
	if strings.Index(body, "other-blocked.test") > strings.Index(body, " blocked.test") {
		t.Errorf("expected the newest block first:\n%s", body)
	}
	// Asking is not a request through the proxy: no block or allow event.
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, ev := range e.events {
		if ev.Host == WhyHost {
			t.Fatalf("the why page produced a proxy event: %+v", ev)
		}
	}
}

func TestWhyDirectRequest(t *testing.T) {
	e := newEnv(t, loopback, nil)
	e.do("GET", e.url("blocked.test"), "", nil)
	resp, err := (&http.Client{Transport: &http.Transport{Proxy: nil}}).Get(e.proxyURL + "/why")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(b), "blocked.test") {
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
}

func TestWhyEmpty(t *testing.T) {
	e := newEnv(t, loopback, nil)
	status, body := e.why("")
	if status != 200 || !strings.Contains(body, "No blocked requests") {
		t.Fatalf("status %d: %s", status, body)
	}
}

func TestWhyRefusesOtherSources(t *testing.T) {
	e := newEnv(t, loopback, nil)
	e.do("GET", e.url("blocked.test"), "", nil)
	vm := *e.proxy.Config()
	vm.SourceIP = netip.MustParseAddr("10.77.0.5")
	e.proxy.SetVM(&vm)
	status, body := e.why("")
	if status != http.StatusForbidden || strings.Contains(body, "blocked.test") {
		t.Fatalf("another address read the why page: status %d: %s", status, body)
	}
}

func TestWhyShowsAllowedNow(t *testing.T) {
	e := newEnv(t, loopback, nil)
	e.do("GET", e.url("blocked.test"), "", nil)
	vm := *e.proxy.Config()
	p := *vm.Policy
	p.Rules = append(p.Rules, mustRule(t, "blocked.test:*"))
	vm.Policy = &p
	e.proxy.SetVM(&vm)
	_, body := e.why("")
	if !strings.Contains(body, "allowed now") {
		t.Fatalf("expected the block to be marked as allowed now:\n%s", body)
	}
}

func TestWhyShowsExfil(t *testing.T) {
	e := newEnv(t, loopback, []inject.Binding{ghBinding()})
	e.do("GET", e.plain.URL+"/echo", "", map[string]string{"Authorization": "Bearer " + ghPH})
	_, body := e.why("")
	if !strings.Contains(body, "GITHUB_TOKEN") || strings.Contains(body, ghPH) {
		t.Fatalf("expected the exfil block, without the placeholder:\n%s", body)
	}
}

func TestWhyLimit(t *testing.T) {
	e := newEnv(t, loopback, nil)
	for _, h := range []string{"a.test", "b.test", "c.test"} {
		e.do("GET", e.url(h), "", nil)
	}
	_, body := e.why("?n=1")
	if !strings.Contains(body, "c.test") || strings.Contains(body, "a.test") {
		t.Fatalf("n=1 should show only the newest:\n%s", body)
	}
}

func TestWhyRingIsBounded(t *testing.T) {
	var r blockRing
	for i := 0; i < whyRingSize*2; i++ {
		r.add(Event{Kind: KindBlock, Host: "h.test", Port: i})
	}
	if got := len(r.snapshot()); got != whyRingSize {
		t.Fatalf("ring holds %d events, want %d", got, whyRingSize)
	}
	if last := r.snapshot()[whyRingSize-1]; last.Port != whyRingSize*2-1 {
		t.Fatalf("newest event is port %d", last.Port)
	}
}

func mustRule(t *testing.T, s string) policy.Rule {
	t.Helper()
	r, err := policy.ParseRule(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
