// Package daemon runs windevvm's background process: one egress proxy
// listener per VM, a local control endpoint the CLI uses to make it reload,
// and the proxy event log.
package daemon

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"windevvm/internal/ca"
	"windevvm/internal/proxy"
)

// Target is one VM the daemon serves a proxy for.
type Target struct {
	Name string
	Addr string // listen address, e.g. 10.77.0.1:18010
	VM   *proxy.VM
	// IP and HostKey reach the VM over SSH, for port forwards.
	IP      string
	HostKey string
	// Forwards are localhost ports forwarded into the VM while it runs.
	Forwards []Forward
	// IdleTimeout stops the VM after this long idle; 0 disables it.
	IdleTimeout time.Duration
}

// VMStatus reports one VM's listener.
type VMStatus struct {
	Name     string   `json:"name"`
	Addr     string   `json:"addr,omitempty"`
	Error    string   `json:"error,omitempty"`
	Forwards []string `json:"forwards,omitempty"`
	// IdleSince is when the VM was last seen busy, if it is idle now.
	IdleSince   time.Time     `json:"idle_since,omitempty"`
	IdleTimeout time.Duration `json:"idle_timeout,omitempty"`
}

// Status is what the control endpoint reports.
type Status struct {
	PID     int        `json:"pid"`
	Exe     string     `json:"exe"`
	ExeMod  time.Time  `json:"exe_mod"`
	Started time.Time  `json:"started"`
	Dropped int64      `json:"dropped_events"`
	VMs     []VMStatus `json:"vms"`
}

// Server is the daemon.
type Server struct {
	Dir string
	CA  *ca.CA
	// Load reads every VM's proxy configuration from disk. Errors for single
	// VMs are returned in errs; those VMs get no listener (fail closed).
	Load func() (targets []Target, errs map[string]error, err error)
	// Listen opens a TCP listener. Defaults to net.Listen.
	Listen func(addr string) (net.Listener, error)
	// Log receives proxy events. Optional.
	Log *EventLog
	// Host, if set, reports and stops VMs, for idle stop and for opening
	// port forwards only while a VM runs.
	Host Host
	// DialVM connects to a port inside a VM (over SSH), for port forwards.
	DialVM func(t Target, port int) (net.Conn, error)
	// Interval is how often the supervisor checks VMs. Default 1 minute.
	Interval time.Duration
	// Now is the clock, for tests. Defaults to time.Now.
	Now func() time.Time

	sup supervisor
	// activity is the time of each VM's latest proxy request.
	activity sync.Map

	reloadMu sync.Mutex // serializes whole reloads, so an older load never wins
	mu       sync.Mutex
	running  map[string]*listener
	errs     map[string]string
	started  time.Time
	stop     context.CancelFunc
}

type listener struct {
	addr   string // as configured
	actual string // as bound
	ps     *proxy.Server
	hs     *http.Server
}

// Paths in the daemon's directory.
func StatePath(dir string) string  { return filepath.Join(dir, "daemon.json") }
func LockPath(dir string) string   { return filepath.Join(dir, "daemon.lock") }
func EventsPath(dir string) string { return filepath.Join(dir, "events.jsonl") }
func LogPath(dir string) string    { return filepath.Join(dir, "daemon.log") }

// State is written to daemon.json so the CLI can find the control endpoint.
type State struct {
	PID   int    `json:"pid"`
	Addr  string `json:"addr"`
	Token string `json:"token"`
}

func (s *Server) listen(addr string) (net.Listener, error) {
	if s.Listen != nil {
		return s.Listen(addr)
	}
	return net.Listen("tcp", addr)
}

// Reload re-reads the configuration and starts, updates or stops listeners
// to match it.
func (s *Server) Reload() error {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	targets, errs, err := s.Load()
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running == nil {
		s.running = map[string]*listener{}
	}
	s.errs = map[string]string{}
	for name, e := range errs {
		s.errs[name] = e.Error()
	}
	want := map[string]Target{}
	for _, t := range targets {
		if _, bad := s.errs[t.Name]; !bad {
			want[t.Name] = t
		}
	}
	s.sup.targets = want
	for name, l := range s.running {
		if t, ok := want[name]; !ok || t.Addr != l.addr {
			l.hs.Close()
			delete(s.running, name)
		}
	}
	for name, t := range want {
		if l, ok := s.running[name]; ok {
			l.ps.SetVM(t.VM)
			continue
		}
		ln, err := s.listen(t.Addr)
		if err != nil {
			s.errs[name] = err.Error()
			continue
		}
		ps := proxy.New(s.CA, t.VM)
		ps.OnEvent = func(e proxy.Event) {
			s.markActive(e.VM, e.Time)
			if s.Log != nil {
				s.Log.Write(e)
			}
		}
		hs := &http.Server{Handler: ps, ReadHeaderTimeout: 30 * time.Second}
		go hs.Serve(ln)
		s.running[name] = &listener{addr: t.Addr, actual: ln.Addr().String(), ps: ps, hs: hs}
	}
	s.syncForwardsLocked()
	// Fresh VM states (a slow PowerShell call) are fetched in the background;
	// forwards of VMs that just started open as soon as they arrive.
	if s.Host != nil {
		go func() {
			s.refreshStates()
			s.mu.Lock()
			s.syncForwardsLocked()
			s.mu.Unlock()
		}()
	}
	return nil
}

// Status reports the listeners.
func (s *Server) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Status{PID: os.Getpid(), Started: s.started}
	st.Exe, st.ExeMod = startExe, startMod
	if s.Log != nil {
		st.Dropped = s.Log.Dropped()
	}
	for name, l := range s.running {
		st.VMs = append(st.VMs, s.vmStatusLocked(name, l.actual))
	}
	for name, e := range s.errs {
		st.VMs = append(st.VMs, VMStatus{Name: name, Error: e})
	}
	sort.Slice(st.VMs, func(i, j int) bool { return st.VMs[i].Name < st.VMs[j].Name })
	return st
}

func exeIdentity() (string, time.Time) {
	exe, err := os.Executable()
	if err != nil {
		return "", time.Time{}
	}
	if p, err := filepath.EvalSymlinks(exe); err == nil {
		exe = p
	}
	var mod time.Time
	if st, err := os.Stat(exe); err == nil {
		mod = st.ModTime().UTC()
	}
	return exe, mod
}

// startExe and startMod identify the binary this process was started from;
// the file on disk may since have been replaced by a rebuild.
var startExe, startMod = exeIdentity()

// ErrRunning means another daemon holds the lock.
var ErrRunning = errors.New("the windevvm daemon is already running")

// Run serves until ctx is cancelled or the CLI asks the daemon to stop.
func (s *Server) Run(ctx context.Context) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	unlock, err := lockFile(LockPath(s.Dir))
	if err != nil {
		return ErrRunning
	}
	defer unlock()

	ctx, s.stop = context.WithCancel(ctx)
	defer s.stop()
	s.started = time.Now()
	if err := s.Reload(); err != nil {
		return err
	}
	defer s.closeAll()
	go s.supervise(ctx)

	tok := make([]byte, 32)
	if _, err := rand.Read(tok); err != nil {
		return err
	}
	token := hex.EncodeToString(tok)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	ctl := &http.Server{Handler: s.controlHandler(token), ReadHeaderTimeout: 10 * time.Second}
	go ctl.Serve(ln)
	defer ctl.Close()

	state, _ := json.Marshal(State{PID: os.Getpid(), Addr: ln.Addr().String(), Token: token})
	if err := writeFileAtomic(StatePath(s.Dir), state); err != nil {
		return err
	}
	defer os.Remove(StatePath(s.Dir))

	<-ctx.Done()
	return nil
}

func (s *Server) closeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sup.closed = true
	for name, l := range s.running {
		l.hs.Close()
		delete(s.running, name)
	}
	for k, f := range s.sup.fwds {
		f.close()
		delete(s.sup.fwds, k)
	}
}

func (s *Server) controlHandler(token string) http.Handler {
	mux := http.NewServeMux()
	reply := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) { reply(w, s.Status()) })
	mux.HandleFunc("POST /reload", func(w http.ResponseWriter, r *http.Request) {
		if err := s.Reload(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		reply(w, s.Status())
	})
	mux.HandleFunc("POST /shutdown", func(w http.ResponseWriter, r *http.Request) {
		reply(w, map[string]bool{"ok": true})
		go func() {
			time.Sleep(100 * time.Millisecond)
			s.stop()
		}()
	})
	want := []byte("Bearer " + token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), want) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Client talks to a running daemon.
type Client struct {
	Dir string
	// Spawn starts a detached daemon process. Ensure uses it.
	Spawn func() error
}

func (c *Client) call(ctx context.Context, method, path string, out any) error {
	b, err := os.ReadFile(StatePath(c.Dir))
	if err != nil {
		return fmt.Errorf("daemon not running: %w", err)
	}
	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, "http://"+st.Addr+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+st.Token)
	resp, err := (&http.Client{Transport: &http.Transport{Proxy: nil}}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var msg [512]byte
		n, _ := resp.Body.Read(msg[:])
		return fmt.Errorf("daemon: %s: %s", resp.Status, msg[:n])
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// Status asks the daemon for its status.
func (c *Client) Status(ctx context.Context) (Status, error) {
	var st Status
	err := c.call(ctx, http.MethodGet, "/status", &st)
	return st, err
}

// Reload makes the daemon re-read all configuration.
func (c *Client) Reload(ctx context.Context) (Status, error) {
	var st Status
	err := c.call(ctx, http.MethodPost, "/reload", &st)
	return st, err
}

// Shutdown stops the daemon and waits for it to go away.
func (c *Client) Shutdown(ctx context.Context) error {
	if err := c.call(ctx, http.MethodPost, "/shutdown", nil); err != nil {
		return err
	}
	return c.waitFor(ctx, false)
}

func (c *Client) waitFor(ctx context.Context, up bool) error {
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		_, err := c.Status(ctx)
		if (err == nil) == up {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(150 * time.Millisecond):
		}
	}
	if up {
		return fmt.Errorf("the daemon didn't start; see %s", LogPath(c.Dir))
	}
	return errors.New("the daemon didn't stop")
}

// Ensure makes sure a daemon from this very executable is running, starting
// one (or replacing one from an older build) as needed, and has it reload.
func (c *Client) Ensure(ctx context.Context) (Status, error) {
	exe, mod := exeIdentity()
	st, err := c.Status(ctx)
	// Replace a daemon only when its own binary was rebuilt. A daemon from
	// another binary (say, go run) is left alone, so mixing them doesn't
	// restart it, and drop every VM's connections, on every command.
	if err == nil && st.Exe == exe && !st.ExeMod.Equal(mod) {
		if err := c.Shutdown(ctx); err != nil {
			return st, fmt.Errorf("stop the old daemon (pid %d): %w", st.PID, err)
		}
		err = errors.New("replaced")
	}
	if err != nil {
		if err := c.Spawn(); err != nil {
			return Status{}, fmt.Errorf("start the daemon: %w", err)
		}
		if err := c.waitFor(ctx, true); err != nil {
			return Status{}, err
		}
	}
	return c.Reload(ctx)
}
