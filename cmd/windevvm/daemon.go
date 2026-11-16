package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"windevvm/internal/ca"
	"windevvm/internal/config"
	"windevvm/internal/daemon"
	"windevvm/internal/paths"
	"windevvm/internal/protect"
	"windevvm/internal/vm"
)

func newNet(cfg config.Global) *vm.Net {
	return &vm.Net{
		Store:        &vm.Store{Root: filepath.Join(cfg.Storage(), "vms")},
		Secrets:      store(),
		GlobalPolicy: paths.PolicyPath(),
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
	s := &daemon.Server{Dir: dir, CA: authority, Load: n.Targets, Log: log}
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
