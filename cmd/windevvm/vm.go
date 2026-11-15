package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"windevvm/internal/config"
	"windevvm/internal/hostinfo"
	"windevvm/internal/hyperv"
	"windevvm/internal/image"
	"windevvm/internal/paths"
	"windevvm/internal/sshkeys"
	"windevvm/internal/vm"
)

func newManager() (*vm.Manager, error) {
	cfg, err := config.LoadGlobal()
	if err != nil {
		return nil, err
	}
	return &vm.Manager{
		Cfg:         cfg,
		HV:          &hyperv.Client{},
		Store:       &vm.Store{Root: filepath.Join(cfg.Storage(), "vms")},
		SSH:         &sshkeys.Dir{Path: filepath.Join(paths.DataDir(), "ssh")},
		Out:         os.Stdout,
		TotalMemory: hostinfo.TotalMemory(),
		LogicalCPUs: hostinfo.LogicalCPUs(),
	}, nil
}

func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt)
}

func currentProject() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return config.FindProjectRoot(wd)
}

func cmdUp(args []string, shell bool) error {
	fs := flag.NewFlagSet("up", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	m, err := newManager()
	if err != nil {
		return err
	}
	project, err := currentProject()
	if err != nil {
		return err
	}
	ctx, cancel := signalContext()
	defer cancel()
	rec, err := m.Up(ctx, project)
	if err != nil {
		return err
	}
	if !shell {
		fmt.Printf("%s is running at %s. Connect with: windevvm shell (or ssh -F \"%s\" %s)\n", rec.Name, rec.IP, m.SSH.ConfigPath(), rec.Name)
		return nil
	}
	return sshInto(m, rec.Name, fs.Args())
}

func sshExe() (string, error) {
	if p, err := exec.LookPath("ssh"); err == nil {
		return p, nil
	}
	p := filepath.Join(os.Getenv("SystemRoot"), "System32", "OpenSSH", "ssh.exe")
	if _, err := os.Stat(p); err == nil {
		return p, nil
	}
	return "", errors.New("ssh.exe not found; install the Windows OpenSSH client (Settings > System > Optional features)")
}

func sshInto(m *vm.Manager, name string, command []string) error {
	exe, err := sshExe()
	if err != nil {
		return err
	}
	args := []string{"-F", m.SSH.ConfigPath()}
	if len(command) == 0 {
		args = append(args, "-t")
	}
	args = append(args, name)
	args = append(args, command...)
	cmd := exec.Command(exe, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	// Ctrl-C belongs to the remote shell, not to us.
	signal.Ignore(os.Interrupt)
	err = cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		os.Exit(exit.ExitCode())
	}
	return err
}

func cmdStop(args []string) error {
	m, err := newManager()
	if err != nil {
		return err
	}
	wd, _ := os.Getwd()
	rec, err := m.Resolve(firstArg(args), wd)
	if err != nil {
		return err
	}
	ctx, cancel := signalContext()
	defer cancel()
	fmt.Printf("Stopping %s...\n", rec.Name)
	return m.Stop(ctx, rec.Name)
}

func cmdRm(args []string) error {
	fs := flag.NewFlagSet("rm", flag.ContinueOnError)
	yes := fs.Bool("y", false, "don't ask for confirmation")
	name, rest := splitName(args)
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if name == "" {
		name = fs.Arg(0)
	}
	m, err := newManager()
	if err != nil {
		return err
	}
	wd, _ := os.Getwd()
	rec, err := m.Resolve(name, wd)
	if err != nil {
		return err
	}
	if !*yes {
		fmt.Printf("Delete %s (%s) and everything inside it? This can't be undone. [y/N] ", rec.Name, rec.Project)
		var reply string
		fmt.Scanln(&reply)
		if !strings.HasPrefix(strings.ToLower(reply), "y") {
			return errors.New("cancelled")
		}
	}
	ctx, cancel := signalContext()
	defer cancel()
	if err := m.Remove(ctx, rec.Name); err != nil {
		return err
	}
	fmt.Printf("Removed %s.\n", rec.Name)
	return nil
}

func cmdLs(args []string) error {
	m, err := newManager()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	list, err := m.List(ctx)
	if err != nil {
		return err
	}
	if len(list) == 0 {
		fmt.Println("No VMs yet. Run windevvm in a project folder to create one.")
	} else {
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "NAME\tSTATE\tIP\tCPU\tMEMORY\tCAPS\tPROJECT")
		for _, s := range list {
			state, cpu, mem, caps := "missing", "-", "-", "-"
			if s.Exists {
				state = strings.ToLower(s.Info.State)
				caps = fmt.Sprintf("%d vCPU @%d%%, <=%s", s.Info.ProcessorCount, s.Info.ProcessorMaximum, config.Size(s.Info.MemoryCap()))
				if s.Info.Running() {
					cpu = fmt.Sprintf("%d%%", s.Info.CPUUsage)
					mem = config.Size(s.Info.MemoryAssigned).String()
				}
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", s.Record.Name, state, s.Record.IP, cpu, mem, caps, s.Record.Project)
		}
		tw.Flush()
	}
	vms, err := m.HV.ListVMs(ctx, "wdvm-")
	if err != nil {
		return err
	}
	u, b := vm.Sum(vms, ""), m.Budget()
	fmt.Printf("\nBudget: %d/%d running, memory %s/%s, CPU %.1f/%.1f\n", u.Running, b.MaxRunning, config.Size(u.Memory), b.Memory, u.CPUs, b.CPUs)
	return nil
}

func cmdShell(args []string) error {
	m, err := newManager()
	if err != nil {
		return err
	}
	name, rest := splitName(args)
	if name != "" && !strings.HasPrefix(name, "wdvm-") {
		// windevvm shell -- cmd...: no name given
		rest, name = args, ""
	}
	if name == "" {
		return cmdUp(rest, true)
	}
	return sshInto(m, name, rest)
}

func cmdImage(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: windevvm image build|ls")
	}
	cfg, err := config.LoadGlobal()
	if err != nil {
		return err
	}
	switch args[0] {
	case "build":
		ctx, cancel := signalContext()
		defer cancel()
		b := &image.Builder{Cfg: cfg, HV: &hyperv.Client{}, Out: os.Stdout}
		base, err := b.Build(ctx)
		if err != nil {
			return err
		}
		fmt.Printf("Base image ready: %s\nNew VMs will use it; existing VMs keep the image they were created from.\n", base.Path)
		return nil
	case "ls":
		files, err := image.List(cfg)
		if err != nil {
			return err
		}
		cur, _ := image.Current(cfg)
		for _, f := range files {
			mark := " "
			if f == cur.Path {
				mark = "*"
			}
			info, _ := os.Stat(f)
			size := ""
			if info != nil {
				size = config.Size(info.Size()).String()
			}
			fmt.Printf("%s %s  %s\n", mark, f, size)
		}
		if len(files) == 0 {
			fmt.Println("No base images yet. Build one with: windevvm image build")
		}
		return nil
	}
	return fmt.Errorf("unknown image command %q", args[0])
}

func firstArg(args []string) string {
	if len(args) > 0 {
		return args[0]
	}
	return ""
}
