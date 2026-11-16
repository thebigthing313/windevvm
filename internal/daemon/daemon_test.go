package daemon

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"windevvm/internal/ca"
	"windevvm/internal/policy"
	"windevvm/internal/proxy"
)

type fakeConfig struct {
	mu      sync.Mutex
	targets []Target
	errs    map[string]error
}

func (f *fakeConfig) load() ([]Target, map[string]error, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Target(nil), f.targets...), f.errs, nil
}

func (f *fakeConfig) set(t []Target, errs map[string]error) {
	f.mu.Lock()
	f.targets, f.errs = t, errs
	f.mu.Unlock()
}

func vmWith(name string, rules ...string) *proxy.VM {
	var rs []policy.Rule
	for _, r := range rules {
		rs = append(rs, policy.Rule{Deny: false, Pattern: mustRule(r).Pattern})
	}
	return &proxy.VM{Name: name, Policy: &policy.Policy{Tier: policy.Allowlist, Rules: rs}}
}

func mustRule(s string) policy.Rule {
	r, err := policy.ParseRule(s)
	if err != nil {
		panic(err)
	}
	return r
}

// get sends a proxied plain-HTTP request through addr and returns the status.
func get(t *testing.T, addr, target string) int {
	t.Helper()
	pu, _ := url.Parse("http://" + addr)
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}, Timeout: 5 * time.Second}
	resp, err := c.Get(target)
	if err != nil {
		t.Fatalf("GET via %s: %v", addr, err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func newServer(t *testing.T, f *fakeConfig) *Server {
	c, err := ca.New()
	if err != nil {
		t.Fatal(err)
	}
	return &Server{Dir: t.TempDir(), CA: c, Load: f.load}
}

func addrOf(st Status, name string) (string, string) {
	for _, v := range st.VMs {
		if v.Name == name {
			return v.Addr, v.Error
		}
	}
	return "", "missing"
}

func TestReloadStartsUpdatesAndStopsListeners(t *testing.T) {
	f := &fakeConfig{}
	s := newServer(t, f)
	defer s.closeAll()

	f.set([]Target{{Name: "a", Addr: "127.0.0.1:0", VM: vmWith("a")}}, nil)
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	addr, e := addrOf(s.Status(), "a")
	if e != "" {
		t.Fatal(e)
	}
	// 192.0.2.1 is never reachable; a block answers 403 before any dial.
	if code := get(t, addr, "http://blocked.test/"); code != http.StatusForbidden {
		t.Fatalf("blocked host: status %d", code)
	}

	// Policy change keeps the same listener and applies immediately.
	f.set([]Target{{Name: "a", Addr: "127.0.0.1:0", VM: vmWith("a", "blocked.test")}}, nil)
	s.Reload()
	addr2, _ := addrOf(s.Status(), "a")
	if addr2 != addr {
		t.Fatalf("listener restarted on a policy change: %s -> %s", addr, addr2)
	}
	if code := get(t, addr, "http://blocked.test/"); code == http.StatusForbidden {
		t.Fatal("new policy not applied")
	}

	// A VM whose configuration fails to load loses its listener.
	f.set(nil, map[string]error{"a": errors.New("secret X is not set")})
	s.Reload()
	if _, e := addrOf(s.Status(), "a"); !strings.Contains(e, "secret X") {
		t.Fatalf("status error = %q", e)
	}
	if _, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		t.Fatal("listener still open after its config failed")
	}

	// Removed VMs are closed too.
	f.set([]Target{{Name: "b", Addr: "127.0.0.1:0", VM: vmWith("b")}}, nil)
	s.Reload()
	if _, e := addrOf(s.Status(), "a"); e != "missing" {
		t.Fatal("removed VM still reported")
	}
}

func TestEventsAreLogged(t *testing.T) {
	f := &fakeConfig{}
	s := newServer(t, f)
	defer s.closeAll()
	s.Log = OpenEventLog(EventsPath(s.Dir), 1<<20)
	f.set([]Target{{Name: "vm1", Addr: "127.0.0.1:0", VM: vmWith("vm1")}}, nil)
	s.Reload()
	addr, _ := addrOf(s.Status(), "vm1")
	get(t, addr, "http://blocked.test/x")
	s.Log.Close()

	evs, err := ReadEvents(EventsPath(s.Dir), "vm1", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 || evs[0].Kind != proxy.KindBlock || evs[0].Host != "blocked.test" || evs[0].Suggest != "blocked.test" {
		t.Fatalf("events = %+v", evs)
	}
	if evs, _ := ReadEvents(EventsPath(s.Dir), "other", 10); len(evs) != 0 {
		t.Fatal("filter by VM failed")
	}
}

func TestEventLogRotates(t *testing.T) {
	p := filepath.Join(t.TempDir(), "events.jsonl")
	l := OpenEventLog(p, 1000)
	for i := 0; i < 20; i++ {
		l.Write(proxy.Event{VM: "v", Kind: proxy.KindAllow, Host: "example.com"})
	}
	l.Close()
	if _, err := os.Stat(p + ".1"); err != nil {
		t.Fatal("no rotated file")
	}
	evs, _ := ReadEvents(p, "", 0)
	if len(evs) == 0 || len(evs) > 20 {
		t.Fatalf("read %d events", len(evs))
	}
	if evs, _ := ReadEvents(p, "", 3); len(evs) != 3 {
		t.Fatalf("tail returned %d", len(evs))
	}
}

func TestControlEndpoint(t *testing.T) {
	f := &fakeConfig{}
	f.set([]Target{{Name: "a", Addr: "127.0.0.1:0", VM: vmWith("a")}}, nil)
	s := newServer(t, f)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	c := &Client{Dir: s.Dir}
	if err := c.waitFor(ctx, true); err != nil {
		t.Fatal(err)
	}
	st, err := c.Reload(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if addr, e := addrOf(st, "a"); addr == "" || e != "" {
		t.Fatalf("status = %+v", st)
	}

	// A second daemon refuses to start.
	s2 := &Server{Dir: s.Dir, CA: s.CA, Load: f.load}
	if err := s2.Run(ctx); !errors.Is(err, ErrRunning) {
		t.Fatalf("second daemon: %v", err)
	}

	// A wrong token is refused.
	b, _ := os.ReadFile(StatePath(s.Dir))
	os.WriteFile(StatePath(s.Dir), []byte(strings.Replace(string(b), `"token":"`, `"token":"x`, 1)), 0o600)
	if _, err := c.Status(ctx); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("bad token: %v", err)
	}
	os.WriteFile(StatePath(s.Dir), b, 0o600)

	if err := c.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(StatePath(s.Dir)); err == nil {
		t.Fatal("state file left behind")
	}
}
