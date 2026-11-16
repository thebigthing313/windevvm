package daemon

import (
	"context"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"time"

	"windevvm/internal/proxy"
)

// idleCPU is the CPU usage (percent of the VM's vCPUs) under which a VM
// counts as idle.
const idleCPU = 5

// KindStop is the event logged when the daemon stops an idle VM.
const KindStop = "stop"

// VMState is a VM's live state as the host reports it.
type VMState struct {
	Running bool
	CPU     int // percent
}

// Host reports and stops VMs. The daemon uses it for idle stop and to keep
// port forwards open only while their VM runs.
type Host interface {
	States(ctx context.Context) (map[string]VMState, error)
	// Connections counts established TCP connections between the host and
	// each VM, by VM IP address: shells, VS Code, port forwards, browsing,
	// and the VM's connections to its proxy.
	Connections(ctx context.Context) (map[string]int, error)
	Stop(ctx context.Context, name string) error
}

// Forward sends connections to 127.0.0.1:HostPort on the host to GuestPort
// inside the VM.
type Forward struct {
	HostPort  int `json:"host"`
	GuestPort int `json:"guest"`
}

func (f Forward) String() string {
	return "localhost:" + strconv.Itoa(f.HostPort) + " -> " + strconv.Itoa(f.GuestPort)
}

// supervisor is the part of the Server's state guarded by Server.mu that
// belongs to idle stop and port forwards.
type supervisor struct {
	targets   map[string]Target
	states    map[string]VMState // nil when there is no Host
	idleSince map[string]time.Time
	fwds      map[string]*forwardListener // by fwdKey
	fwdErrs   map[string]string
	// lastTick is when the previous tick ran; proxy activity after it
	// counts as busy.
	lastTick time.Time
	// closed is set at shutdown, so a late tick can't reopen forwards.
	closed bool
}

type forwardListener struct {
	vm  string
	f   Forward
	ln  net.Listener
	ln6 net.Listener // [::1], so "localhost" doesn't stall trying IPv6 first; may be nil
}

func (fl *forwardListener) close() {
	fl.ln.Close()
	if fl.ln6 != nil {
		fl.ln6.Close()
	}
}

func fwdKey(vm string, f Forward) string { return vm + "|" + strconv.Itoa(f.HostPort) }

// refreshStates asks the Host which VMs are running. Called without s.mu.
func (s *Server) refreshStates() {
	if s.Host == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	states, err := s.Host.States(ctx)
	if err != nil {
		return // keep the last known states
	}
	s.mu.Lock()
	s.sup.states = states
	s.mu.Unlock()
}

func (s *Server) runningLocked(name string) bool {
	if s.sup.states == nil {
		return s.Host == nil
	}
	return s.sup.states[name].Running
}

// syncForwardsLocked opens the forwards of running VMs and closes the rest.
func (s *Server) syncForwardsLocked() {
	if s.sup.closed {
		return
	}
	if s.sup.fwds == nil {
		s.sup.fwds = map[string]*forwardListener{}
	}
	s.sup.fwdErrs = map[string]string{}
	want := map[string]forwardListener{}
	for name, t := range s.sup.targets {
		if !s.runningLocked(name) {
			continue
		}
		for _, f := range t.Forwards {
			want[fwdKey(name, f)] = forwardListener{vm: name, f: f}
		}
	}
	for k, fl := range s.sup.fwds {
		if w, ok := want[k]; !ok || w.f != fl.f {
			fl.close()
			delete(s.sup.fwds, k)
		}
	}
	for k, w := range want {
		if _, ok := s.sup.fwds[k]; ok {
			continue
		}
		ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(w.f.HostPort)))
		if err != nil {
			s.sup.fwdErrs[k] = err.Error()
			continue
		}
		fl := &forwardListener{vm: w.vm, f: w.f, ln: ln}
		s.sup.fwds[k] = fl
		go s.serveForward(fl, ln)
		if ln6, err := net.Listen("tcp", net.JoinHostPort("::1", strconv.Itoa(w.f.HostPort))); err == nil {
			fl.ln6 = ln6
			go s.serveForward(fl, ln6)
		}
	}
}

func (s *Server) serveForward(fl *forwardListener, ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			s.mu.Lock()
			t, ok := s.sup.targets[fl.vm]
			s.mu.Unlock()
			if !ok || s.DialVM == nil {
				return
			}
			up, err := s.DialVM(t, fl.f.GuestPort)
			if err != nil {
				return
			}
			defer up.Close()
			pipeBoth(c, up)
		}()
	}
}

func (s *Server) vmStatusLocked(name, addr string) VMStatus {
	v := VMStatus{Name: name, Addr: addr}
	t := s.sup.targets[name]
	v.IdleTimeout = t.IdleTimeout
	v.IdleSince = s.sup.idleSince[name]
	for _, f := range t.Forwards {
		k := fwdKey(name, f)
		switch {
		case s.sup.fwds[k] != nil:
			v.Forwards = append(v.Forwards, f.String())
		case s.sup.fwdErrs[k] != "":
			v.Forwards = append(v.Forwards, f.String()+" (failed: "+s.sup.fwdErrs[k]+")")
		default:
			v.Forwards = append(v.Forwards, f.String()+" (when running)")
		}
	}
	sort.Strings(v.Forwards)
	return v
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// supervise runs the periodic checks until ctx ends.
func (s *Server) supervise(ctx context.Context) {
	if s.Host == nil {
		return
	}
	every := s.Interval
	if every == 0 {
		every = time.Minute
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.tick(ctx)
		}
	}
}

// tick refreshes VM states, reconciles port forwards and stops VMs that
// have been idle for their timeout: running, no SSH connection from the
// host (shells, VS Code and port forwards all use one) and CPU under 5%.
func (s *Server) tick(ctx context.Context) {
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	states, err := s.Host.States(cctx)
	cancel()
	if err != nil {
		return
	}
	cctx, cancel = context.WithTimeout(ctx, 30*time.Second)
	conns, err := s.Host.Connections(cctx)
	cancel()
	if err != nil {
		return // without session counts, idle can't be judged safely
	}

	now := s.now()
	var stop []Target
	s.mu.Lock()
	s.sup.states = states
	s.syncForwardsLocked()
	if s.sup.idleSince == nil {
		s.sup.idleSince = map[string]time.Time{}
	}
	for name, t := range s.sup.targets {
		st := states[name]
		active := s.lastActivity(name).After(s.sup.lastTick)
		if !st.Running || t.IdleTimeout <= 0 || conns[t.IP] > 0 || st.CPU >= idleCPU || active {
			delete(s.sup.idleSince, name)
			continue
		}
		since, ok := s.sup.idleSince[name]
		if !ok {
			s.sup.idleSince[name] = now
			continue
		}
		if now.Sub(since) >= t.IdleTimeout {
			stop = append(stop, t)
			delete(s.sup.idleSince, name)
		}
	}
	s.sup.lastTick = now
	s.mu.Unlock()

	for _, t := range stop {
		reason := fmt.Sprintf("idle for %s (no connections to or from the host, no proxy requests, CPU under %d%%)", t.IdleTimeout, idleCPU)
		if err := s.Host.Stop(ctx, t.Name); err != nil {
			reason = "idle stop failed: " + err.Error()
		}
		if s.Log != nil {
			s.Log.Write(proxy.Event{Time: now, VM: t.Name, Kind: KindStop, Reason: reason})
		}
	}
	if len(stop) > 0 {
		s.refreshStates()
		s.mu.Lock()
		s.syncForwardsLocked()
		s.mu.Unlock()
	}
}

// pipeBoth copies both ways. When one side finishes sending, the other side
// is told with a half-close, so a client that shuts down its write side still
// gets the reply. It returns when both directions are done, or a minute
// after the first one is.
func pipeBoth(a, b net.Conn) {
	done := make(chan struct{}, 2)
	copyHalf := func(dst, src net.Conn) {
		io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		} else {
			dst.Close()
		}
		done <- struct{}{}
	}
	go copyHalf(a, b)
	go copyHalf(b, a)
	<-done
	select {
	case <-done:
	case <-time.After(time.Minute):
	}
}

// markActive records proxy activity for a VM.
func (s *Server) markActive(vm string, at time.Time) { s.activity.Store(vm, at) }

func (s *Server) lastActivity(vm string) time.Time {
	if v, ok := s.activity.Load(vm); ok {
		return v.(time.Time)
	}
	return time.Time{}
}
