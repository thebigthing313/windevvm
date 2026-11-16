package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"windevvm/internal/ca"
	"windevvm/internal/config"
	"windevvm/internal/daemon"
	"windevvm/internal/hyperv"
	"windevvm/internal/paths"
	"windevvm/internal/protect"
	"windevvm/internal/sshkeys"
	"windevvm/internal/vm"
)

func newNet(cfg config.Global) *vm.Net {
	return &vm.Net{
		Store:        &vm.Store{Root: filepath.Join(cfg.Storage(), "vms")},
		Secrets:      store(),
		GlobalPolicy: paths.PolicyPath(),
		IdleTimeout:  cfg.IdleTimeout,
	}
}

func daemonClient() *daemon.Client {
	return &daemon.Client{Dir: paths.DaemonDir(), Spawn: spawnDaemon}
}

// spawnDaemon starts `windevvm daemon` detached from this console, with its
// output going to daemon.log.
func spawnDaemon() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	dir := paths.DaemonDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	logf, err := os.OpenFile(daemon.LogPath(dir), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer logf.Close()
	cmd := exec.Command(exe, "daemon")
	cmd.Stdout, cmd.Stderr = logf, logf
	daemon.Detach(cmd)
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

// daemonNotifier starts the daemon if needed and makes it reload.
type daemonNotifier struct{ c *daemon.Client }

func (d daemonNotifier) Notify(ctx context.Context, name string) error {
	st, err := d.c.Ensure(ctx)
	if err != nil {
		return err
	}
	if name == "" {
		return nil
	}
	for _, v := range st.VMs {
		if v.Name == name {
			if v.Error != "" {
				return fmt.Errorf("the proxy for %s can't run: %s", name, v.Error)
			}
			return nil
		}
	}
	return fmt.Errorf("the daemon has no proxy for %s", name)
}

// reloadDaemonIfRunning tells a running daemon to re-read its configuration,
// e.g. after a secret's value changed. It doesn't start one.
func reloadDaemonIfRunning() {
	c := daemonClient()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := c.Status(ctx); err != nil {
		return
	}
	if _, err := c.Reload(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "windevvm: warning: the daemon didn't reload:", err)
	}
}

func cmdDaemon(args []string) error {
	if len(args) > 0 {
		c := daemonClient()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		switch args[0] {
		case "status":
			st, err := c.Status(ctx)
			if err != nil {
				fmt.Println("The daemon isn't running. It starts automatically with windevvm up.")
				return nil
			}
			printDaemonStatus(st)
			return nil
		case "stop":
			if err := c.Shutdown(ctx); err != nil {
				return err
			}
			fmt.Println("Daemon stopped.")
			return nil
		case "restart":
			if _, err := c.Status(ctx); err == nil {
				if err := c.Shutdown(ctx); err != nil {
					return err
				}
			}
			st, err := c.Ensure(ctx)
			if err != nil {
				return err
			}
			printDaemonStatus(st)
			return nil
		}
		return errors.New("usage: windevvm daemon [status|stop|restart]")
	}
	return runDaemon()
}

func printDaemonStatus(st daemon.Status) {
	fmt.Printf("Daemon pid %d, up since %s (%s)\n", st.PID, st.Started.Format(time.DateTime), st.Exe)
	if st.Dropped > 0 {
		fmt.Printf("Warning: %d proxy events were dropped from the log.\n", st.Dropped)
	}
	if len(st.VMs) == 0 {
		fmt.Println("No VMs.")
	}
	for _, v := range st.VMs {
		if v.Error != "" {
			fmt.Printf("  %-28s NOT SERVED: %s\n", v.Name, v.Error)
		} else {
			fmt.Printf("  %-28s proxy on %s\n", v.Name, v.Addr)
			for _, f := range v.Forwards {
				fmt.Printf("  %-28s forward %s\n", "", f)
			}
			if !v.IdleSince.IsZero() {
				fmt.Printf("  %-28s idle since %s (stops after %s)\n", "", v.IdleSince.Format("15:04"), v.IdleTimeout)
			}
		}
	}
	fmt.Printf("Events: %s\n", daemon.EventsPath(paths.DaemonDir()))
}

// runDaemon runs the daemon in the foreground.
func runDaemon() error {
	cfg, err := config.LoadGlobal()
	if err != nil {
		return err
	}
	authority, _, err := ca.LoadOrCreate(paths.CADir(), protect.Default())
	if err != nil {
		return err
	}
	dir := paths.DaemonDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	log := daemon.OpenEventLog(daemon.EventsPath(dir), 20<<20)
	defer log.Close()
	n := newNet(cfg)
	keys := &sshkeys.Dir{Path: filepath.Join(paths.DataDir(), "ssh")}
	s := &daemon.Server{
		Dir: dir, CA: authority, Load: n.Targets, Log: log,
		Host:   hvHost{&hyperv.Client{}},
		DialVM: (&vmDialer{keys: keys}).dial,
	}
	ctx, cancel := signalContext()
	defer cancel()
	fmt.Printf("%s windevvm daemon starting (pid %d)\n", time.Now().Format(time.DateTime), os.Getpid())
	err = s.Run(ctx)
	if errors.Is(err, daemon.ErrRunning) {
		fmt.Println("Another windevvm daemon is already running.")
		return nil
	}
	fmt.Printf("%s windevvm daemon stopped\n", time.Now().Format(time.DateTime))
	return err
}

// hvHost gives the daemon the VMs' live state from Hyper-V.
type hvHost struct{ hv *hyperv.Client }

func (h hvHost) States(ctx context.Context) (map[string]daemon.VMState, error) {
	vms, err := h.hv.ListVMs(ctx, "wdvm-")
	if err != nil {
		return nil, err
	}
	out := map[string]daemon.VMState{}
	for _, v := range vms {
		out[v.Name] = daemon.VMState{Running: v.Running(), CPU: v.CPUUsage}
	}
	return out, nil
}

func (h hvHost) Connections(ctx context.Context) (map[string]int, error) {
	return h.hv.Connections(ctx, vm.HostIP)
}

func (h hvHost) Stop(ctx context.Context, name string) error {
	return h.hv.Stop(ctx, name, 90*time.Second)
}

// vmDialer forwards connections into VMs over SSH (so services listening
// only on the VM's loopback work too). It shares one SSH connection per VM
// among the open forwarded streams and closes it shortly after the last one
// ends, so an unused forward doesn't keep the VM from idling.
type vmDialer struct {
	keys *sshkeys.Dir
	mu   sync.Mutex
	vms  map[string]*pooledSSH // by IP
}

type pooledSSH struct {
	client *ssh.Client
	refs   int
	idle   *time.Timer
}

const sshLinger = 15 * time.Second

func (d *vmDialer) dial(t daemon.Target, port int) (net.Conn, error) {
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	for attempt := 0; attempt < 2; attempt++ {
		p, err := d.get(t)
		if err != nil {
			return nil, err
		}
		conn, err := p.client.Dial("tcp", addr)
		if err == nil {
			return &pooledConn{Conn: conn, d: d, ip: t.IP, p: p}, nil
		}
		d.release(t.IP, p)
		if _, isOpen := err.(*ssh.OpenChannelError); isOpen {
			return nil, err // nothing listening on that port in the VM
		}
		d.drop(t.IP, p) // stale connection (e.g. the VM rebooted); retry once
	}
	return nil, fmt.Errorf("can't reach %s over SSH", t.Name)
}

func (d *vmDialer) get(t daemon.Target) (*pooledSSH, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.vms == nil {
		d.vms = map[string]*pooledSSH{}
	}
	if p, ok := d.vms[t.IP]; ok {
		if p.idle != nil {
			p.idle.Stop()
			p.idle = nil
		}
		p.refs++
		return p, nil
	}
	c, err := d.keys.Dial(t.IP, t.HostKey, 10*time.Second)
	if err != nil {
		return nil, err
	}
	p := &pooledSSH{client: c, refs: 1}
	d.vms[t.IP] = p
	return p, nil
}

func (d *vmDialer) release(ip string, p *pooledSSH) {
	d.mu.Lock()
	defer d.mu.Unlock()
	p.refs--
	if p.refs > 0 || d.vms[ip] != p {
		return
	}
	p.idle = time.AfterFunc(sshLinger, func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.vms[ip] == p && p.refs == 0 {
			delete(d.vms, ip)
			p.client.Close()
		}
	})
}

func (d *vmDialer) drop(ip string, p *pooledSSH) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.vms[ip] == p {
		delete(d.vms, ip)
		p.client.Close()
	}
}

// pooledConn is one forwarded stream; closing it releases the shared SSH
// connection.
type pooledConn struct {
	net.Conn
	d    *vmDialer
	ip   string
	p    *pooledSSH
	once sync.Once
}

func (c *pooledConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (c *pooledConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.d.release(c.ip, c.p) })
	return err
}
