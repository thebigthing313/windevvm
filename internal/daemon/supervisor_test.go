package daemon

import (
	"bufio"
	"context"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"windevvm/internal/proxy"
)

type fakeHost struct {
	mu      sync.Mutex
	states  map[string]VMState
	conns   map[string]int
	stopped []string
}

func (h *fakeHost) States(context.Context) (map[string]VMState, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := map[string]VMState{}
	for k, v := range h.states {
		out[k] = v
	}
	return out, nil
}

func (h *fakeHost) Connections(context.Context) (map[string]int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := map[string]int{}
	for k, v := range h.conns {
		out[k] = v
	}
	return out, nil
}

func (h *fakeHost) Stop(_ context.Context, name string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.stopped = append(h.stopped, name)
	h.states[name] = VMState{}
	return nil
}

func TestIdleStop(t *testing.T) {
	f := &fakeConfig{}
	f.set([]Target{
		{Name: "idle", Addr: "127.0.0.1:0", VM: vmWith("idle"), IP: "10.77.0.10", IdleTimeout: 30 * time.Minute},
		{Name: "shell", Addr: "127.0.0.1:0", VM: vmWith("shell"), IP: "10.77.0.11", IdleTimeout: 30 * time.Minute},
		{Name: "busy", Addr: "127.0.0.1:0", VM: vmWith("busy"), IP: "10.77.0.12", IdleTimeout: 30 * time.Minute},
		{Name: "never", Addr: "127.0.0.1:0", VM: vmWith("never"), IP: "10.77.0.13"},
	}, nil)
	h := &fakeHost{
		states: map[string]VMState{"idle": {Running: true, CPU: 1}, "shell": {Running: true}, "busy": {Running: true, CPU: 40}, "never": {Running: true}},
		conns:  map[string]int{"10.77.0.11": 1},
	}
	s := newServer(t, f)
	defer s.closeAll()
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	s.Host, s.Now = h, func() time.Time { return now }
	s.Log = OpenEventLog(EventsPath(s.Dir), 1<<20)
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	s.tick(ctx) // starts the idle clock
	now = now.Add(29 * time.Minute)
	s.tick(ctx)
	if len(h.stopped) != 0 {
		t.Fatalf("stopped too early: %v", h.stopped)
	}
	now = now.Add(2 * time.Minute)
	s.tick(ctx)
	if len(h.stopped) != 1 || h.stopped[0] != "idle" {
		t.Fatalf("stopped = %v, want just idle", h.stopped)
	}

	// Activity resets the clock.
	h.states["idle"] = VMState{Running: true}
	s.tick(ctx)
	now = now.Add(20 * time.Minute)
	h.conns["10.77.0.10"] = 1
	s.tick(ctx)
	delete(h.conns, "10.77.0.10")
	s.tick(ctx)
	now = now.Add(20 * time.Minute)
	s.tick(ctx)
	if len(h.stopped) != 1 {
		t.Fatalf("an SSH connection didn't reset the idle clock: %v", h.stopped)
	}

	// Proxy requests count as activity too.
	h.states["idle"] = VMState{Running: true}
	s.tick(ctx)
	now = now.Add(20 * time.Minute)
	s.markActive("idle", now)
	s.tick(ctx)
	now = now.Add(20 * time.Minute)
	s.tick(ctx)
	if len(h.stopped) != 1 {
		t.Fatalf("proxy activity didn't reset the idle clock: %v", h.stopped)
	}

	s.Log.Close()
	evs, _ := ReadEvents(EventsPath(s.Dir), "idle", 0)
	if len(evs) != 1 || evs[0].Kind != KindStop {
		t.Fatalf("events = %+v", evs)
	}
}

func freePort(t *testing.T) int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestForwards(t *testing.T) {
	// A "guest" service: echoes one line.
	svc, _ := net.Listen("tcp", "127.0.0.1:0")
	defer svc.Close()
	go func() {
		for {
			c, err := svc.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				l, _ := bufio.NewReader(c).ReadString('\n')
				c.Write([]byte("echo " + l))
			}()
		}
	}()
	guestPort := svc.Addr().(*net.TCPAddr).Port
	hostPort := freePort(t)

	f := &fakeConfig{}
	f.set([]Target{{Name: "a", Addr: "127.0.0.1:0", VM: &proxy.VM{Name: "a", Policy: vmWith("a").Policy}, Forwards: []Forward{{HostPort: hostPort, GuestPort: guestPort}}}}, nil)
	h := &fakeHost{states: map[string]VMState{"a": {Running: true, CPU: 50}}}
	s := newServer(t, f)
	defer s.closeAll()
	s.Host = h
	s.DialVM = func(tg Target, port int) (net.Conn, error) {
		return net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(port))
	}
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	// The forward opens once the VM states arrive (in the background).
	var c net.Conn
	var err error
	for i := 0; i < 40; i++ {
		if c, err = net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(hostPort), time.Second); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	c.Write([]byte("hi\n"))
	c.(*net.TCPConn).CloseWrite() // a half-close must not lose the reply
	got, _ := bufio.NewReader(c).ReadString('\n')
	c.Close()
	if got != "echo hi\n" {
		t.Fatalf("got %q", got)
	}
	if fw := s.Status().VMs[0].Forwards; len(fw) != 1 || fw[0] != "localhost:"+strconv.Itoa(hostPort)+" -> "+strconv.Itoa(guestPort) {
		t.Fatalf("status forwards = %v", fw)
	}

	// The VM stops: the forward closes.
	h.states["a"] = VMState{}
	s.tick(context.Background())
	if c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(hostPort), time.Second); err == nil {
		c.Close()
		t.Fatal("forward still open while the VM is off")
	}
}
