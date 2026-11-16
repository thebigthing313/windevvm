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

	"windevvm/internal/ca"
	"windevvm/internal/config"
	"windevvm/internal/hostinfo"
	"windevvm/internal/hyperv"
	"windevvm/internal/image"
	"windevvm/internal/paths"
	"windevvm/internal/protect"
	"windevvm/internal/sshkeys"
	"windevvm/internal/vm"
)

func newManager() (*vm.Manager, error) {
	cfg, err := config.LoadGlobal()
	if err != nil {
		return nil, err
	}
	n := newNet(cfg)
	return &vm.Manager{
		Cfg:         cfg,
		HV:          &hyperv.Client{},
		Store:       n.Store,
		Net:         n,
		CACert:      caCert,
		Daemon:      daemonNotifier{daemonClient()},
		SSHExe:      sshPath(),
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
	return sshInto(m, rec, fs.Args())
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

func sshInto(m *vm.Manager, rec *vm.Record, command []string) error {
	exe, err := sshExe()
	if err != nil {
		return err
	}
	if len(command) > 0 && command[0] == "--" {
		command = command[1:]
	}
	// Start in the project folder (WorkDir is [a-z0-9/-], safe unquoted).
	remote := "cd " + rec.WorkDir() + " 2>/dev/null; exec bash -l"
	args := []string{"-F", m.SSH.ConfigPath()}
	if len(command) == 0 {
		args = append(args, "-t")
	} else {
		remote = "cd " + rec.WorkDir() + " 2>/dev/null; " + strings.Join(command, " ")
	}
	args = append(args, rec.Name, remote)
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
	rec, err := m.Store.Load(name)
	if err != nil {
		return fmt.Errorf("no VM named %s", name)
	}
	return sshInto(m, rec, rest)
}

const imageUsage = `usage:
  windevvm image build        build a new base image and make it current
  windevvm image ls           base images, and the VMs on each
  windevvm image prune [-y]   delete base images no VM uses, build leftovers and the download cache`

func cmdImage(args []string) error {
	if len(args) == 0 {
		return errors.New(imageUsage)
	}
	m, err := newManager()
	if err != nil {
		return err
	}
	cfg := m.Cfg
	switch args[0] {
	case "build":
		ctx, cancel := signalContext()
		defer cancel()
		b := &image.Builder{Cfg: cfg, HV: m.HV, Out: os.Stdout}
		base, err := b.Build(ctx)
		if err != nil {
			return err
		}
		fmt.Printf("Base image ready: %s\nNew VMs will use it.\n", base.Path)
		recs, err := m.Store.All()
		if err != nil {
			// The image is built and current; only the advice below is lost.
			fmt.Printf("(Couldn't read the VM records to say which VMs stay on older images: %v)\n", err)
		}
		var older []string
		for _, r := range recs {
			if image.PathKey(r.Base) != image.PathKey(base.Path) {
				older = append(older, r.Name)
			}
		}
		if len(older) > 0 {
			fmt.Printf("\n%d VM(s) keep the image they were created from: %s\n", len(older), strings.Join(older, ", "))
			fmt.Println("To move one onto the new image, recreate it. That discards everything inside the VM, so first")
			fmt.Println("bring its work out (windevvm pull, for clone mode), then: windevvm rm, windevvm up.")
		}
		fmt.Println("Once no VM uses an old image, windevvm image prune deletes it.")
		return nil
	case "ls":
		files, err := image.List(cfg)
		if err != nil {
			return err
		}
		cur, _ := image.CurrentPath(cfg)
		users, err := imageUsers(m)
		if err != nil {
			return err
		}
		for _, f := range files {
			mark := " "
			if image.PathKey(f) == image.PathKey(cur) {
				mark = "*"
			}
			info, _ := os.Stat(f)
			size := ""
			if info != nil {
				size = config.Size(info.Size()).String()
			}
			line := fmt.Sprintf("%s %s  %s", mark, f, size)
			if vms := users[image.PathKey(f)]; len(vms) > 0 {
				line += "  used by " + strings.Join(vms, ", ")
			}
			fmt.Println(line)
		}
		if len(files) == 0 {
			fmt.Println("No base images yet. Build one with: windevvm image build")
		} else {
			fmt.Println("* = current: new VMs use it")
		}
		return nil
	case "prune":
		fs := flag.NewFlagSet("image prune", flag.ContinueOnError)
		yes := fs.Bool("y", false, "don't ask for confirmation")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return imagePrune(m, *yes)
	}
	return fmt.Errorf("unknown image command %q\n%s", args[0], imageUsage)
}

// imageUsers maps each disk (by image.PathKey) to the VMs that depend on it,
// from the VM records and from Hyper-V itself, so a VM whose record is gone,
// or a build VM left registered, still counts.
func imageUsers(m *vm.Manager) (map[string][]string, error) {
	users := map[string][]string{}
	add := func(base, name string) {
		k := image.PathKey(base)
		for _, n := range users[k] {
			if n == name {
				return
			}
		}
		users[k] = append(users[k], name)
	}
	recs, err := m.Store.All()
	if err != nil {
		return nil, err
	}
	for _, r := range recs {
		if r.Base != "" {
			add(r.Base, r.Name)
		}
	}
	ctx, cancel := signalContext()
	defer cancel()
	disks, err := m.HV.VMDisks(ctx, "wdvm-")
	if err != nil {
		return nil, fmt.Errorf("ask Hyper-V which disks VMs use: %w", err)
	}
	for name, ds := range disks {
		for _, d := range ds {
			add(d, name)
		}
	}
	return users, nil
}

func imagePrune(m *vm.Manager, yes bool) error {
	cur, err := image.CurrentPath(m.Cfg)
	if err != nil && !errors.Is(err, image.ErrNoImage) {
		return err
	}
	users, err := imageUsers(m)
	if err != nil {
		return err
	}
	plan, err := image.PlanPrune(image.Dir(m.Cfg), cur, users, time.Now())
	if err != nil {
		return err
	}
	for _, k := range plan.Keep {
		fmt.Printf("keep    %s  (%s)\n", k.Path, k.Why)
	}
	if len(plan.Delete) == 0 {
		fmt.Println("Nothing to delete.")
		return nil
	}
	for _, it := range plan.Delete {
		fmt.Printf("delete  %s  %s  (%s)\n", it.Path, config.Size(it.Size), it.What)
	}
	fmt.Printf("This frees %s.\n", config.Size(plan.Bytes()))
	if !yes {
		fmt.Print("Delete these? [y/N] ")
		var reply string
		fmt.Scanln(&reply)
		if !strings.HasPrefix(strings.ToLower(reply), "y") {
			return errors.New("cancelled")
		}
	}
	if err := image.Prune(plan); err != nil {
		return err
	}
	fmt.Println("Done.")
	return nil
}

func firstArg(args []string) string {
	if len(args) > 0 {
		return args[0]
	}
	return ""
}

// caCert returns the local CA certificate, creating the CA on first use.
func caCert() ([]byte, error) {
	authority, _, err := ca.LoadOrCreate(paths.CADir(), protect.Default())
	if err != nil {
		return nil, err
	}
	return authority.CertPEM, nil
}

// sshPath is the OpenSSH client, or "" if it isn't installed.
func sshPath() string {
	p, _ := sshExe()
	return p
}
