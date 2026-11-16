package proxy

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// WhyHost is the name the VM asks for its own recent blocks:
// http://windevvm.internal/why through the proxy. The page is also served at
// /why to requests sent straight to the proxy port. Either way only the
// proxy's own VM gets it, since the source address is checked first.
const WhyHost = "windevvm.internal"

// whyRingSize is how many recent blocks each proxy remembers.
const whyRingSize = 200

// blockRing keeps the most recent block and exfil events, in memory, for
// the why page. It starts empty whenever the daemon does; the host's event
// log (windevvm network log) keeps the longer history.
type blockRing struct {
	mu   sync.Mutex
	evs  []Event
	next int
	full bool
}

func (r *blockRing) add(e Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.evs == nil {
		r.evs = make([]Event, whyRingSize)
	}
	r.evs[r.next] = e
	r.next = (r.next + 1) % whyRingSize
	if r.next == 0 {
		r.full = true
	}
}

// snapshot returns the events, oldest first.
func (r *blockRing) snapshot() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.full {
		return append([]Event(nil), r.evs[:r.next]...)
	}
	return append(append([]Event(nil), r.evs[r.next:]...), r.evs[:r.next]...)
}

// isWhy reports whether r asks for the why page.
func isWhy(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	if !r.URL.IsAbs() {
		return r.URL.Path == "/why"
	}
	host, _, err := splitHostPort(r.URL.Host, 80)
	return err == nil && host == WhyHost && r.URL.Scheme == "http"
}

// whyEntry is one destination's blocks, merged.
type whyEntry struct {
	last    Event
	first   time.Time
	count   int
	allowed bool
}

func (s *Server) serveWhy(w http.ResponseWriter, r *http.Request, vm *VM) {
	n := 20
	if q := r.URL.Query().Get("n"); q != "" {
		if v, err := strconv.Atoi(q); err == nil && v > 0 {
			n = min(v, whyRingSize)
		}
	}
	evs := s.blocks.snapshot()
	var order []string
	byKey := map[string]*whyEntry{}
	for i := len(evs) - 1; i >= 0; i-- { // newest first
		e := evs[i]
		key := e.Kind + "|" + e.Method + "|" + hostPort(e.Host, e.Port) + "|" + e.Reason
		if we, ok := byKey[key]; ok {
			we.count++
			we.first = e.Time
			continue
		}
		if len(order) == n {
			continue
		}
		we := &whyEntry{last: e, first: e.Time, count: 1}
		if e.Kind == KindBlock && e.Suggest != "" && vm.Policy.Decide(e.Host, e.Port).Allow {
			we.allowed = true
		}
		byKey[key] = we
		order = append(order, key)
	}

	now := time.Now()
	var b strings.Builder
	if len(order) == 0 {
		b.WriteString("No blocked requests since the windevvm daemon started.\n")
	} else {
		fmt.Fprintf(&b, "Blocked requests from %s, newest first:\n", vm.Name)
	}
	for _, key := range order {
		we := byKey[key]
		e := we.last
		target := e.Host
		if e.Port > 0 {
			target = hostPort(e.Host, e.Port)
		}
		fmt.Fprintf(&b, "\n%8s  %s %s%s\n", ago(now, e.Time), e.Method, target, eventPath(e))
		if we.count > 1 {
			fmt.Fprintf(&b, "          %d times, first %s\n", we.count, ago(now, we.first))
		}
		reason := e.Reason
		if e.Kind == KindExfil {
			reason = "possible secret leak: " + reason
		}
		fmt.Fprintf(&b, "          %s\n", reason)
		switch {
		case we.allowed:
			b.WriteString("          allowed now; try again\n")
		case e.Suggest != "":
			fmt.Fprintf(&b, "          to allow it, run on the host: windevvm network allow %s\n", e.Suggest)
		case e.Kind == KindExfil && strings.Contains(e.Reason, "plain HTTP"):
			b.WriteString("          use https://; secrets are only injected over HTTPS\n")
		case e.Kind == KindExfil:
			b.WriteString("          if this host should get the secret, add it to the secret's hosts on the host (windevvm secret set NAME --hosts ...)\n")
		}
	}
	b.WriteString("\nThe host keeps a longer history: windevvm network log --blocked\n")
	b.WriteString("Programs that ignore HTTP_PROXY fail to resolve or connect and never reach the proxy, so they aren't listed.\n")

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write([]byte(b.String()))
}

func eventPath(e Event) string {
	if e.Path == "" || e.Path == "/" {
		return ""
	}
	return e.Path
}

// ago formats how long before now t was, coarsely.
func ago(now, t time.Time) string {
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return strconv.Itoa(int(d.Seconds())) + "s ago"
	case d < time.Hour:
		return strconv.Itoa(int(d.Minutes())) + "m ago"
	case d < 48*time.Hour:
		return strconv.Itoa(int(d.Hours())) + "h ago"
	}
	return strconv.Itoa(int(d.Hours()/24)) + "d ago"
}
