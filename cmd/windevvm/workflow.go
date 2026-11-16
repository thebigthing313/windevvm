package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"windevvm/internal/config"
	"windevvm/internal/daemon"
	"windevvm/internal/hyperv"
	"windevvm/internal/sshkeys"
	"windevvm/internal/vm"
	"windevvm/internal/workspace"
)

// cmdPull fetches the VM clone's branches into windevvm/<branch>.
func cmdPull(args []string) error {
	args, vmName, _, err := networkFlags(args)
	if err != nil {
		return err
	}
	if len(args) > 0 {
		return errors.New("usage: windevvm pull [--vm NAME]")
	}
	m, err := newManager()
	if err != nil {
		return err
	}
	rec, err := resolveVM(m, vmName)
	if err != nil {
		return err
	}
	ctx, cancel := signalContext()
	defer cancel()
	if !workspace.IsRepo(ctx, rec.Project) {
		return workspace.ErrNotRepo
	}
	if !rec.Cloned {
		return fmt.Errorf("%s has no clone yet; start it with windevvm up", rec.Name)
	}
	changed, err := m.Git(rec).Pull(ctx)
	if err != nil {
		return err
	}
	if len(changed) == 0 {
		fmt.Println("Nothing new in the VM.")
		return nil
	}
	fmt.Printf("Updated %d branch(es) from %s:\n", len(changed), rec.Name)
	for _, b := range changed {
		fmt.Println("  " + b)
	}
	fmt.Printf("Nothing was checked out or merged. Look with: git log %s, then merge what you want.\n", changed[0])
	return nil
}

const portsUsage = `usage:
  windevvm ports                     forwarded ports, and what is listening in the VM
  windevvm ports add PORT            forward localhost:PORT to PORT in the VM
  windevvm ports add HOST:GUEST      forward localhost:HOST to GUEST in the VM
  windevvm ports rm HOST
Add --vm NAME for another project's VM.`

func parsePort(s string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("bad port %q", s)
	}
	return n, nil
}

func cmdPorts(args []string) error {
	args, vmName, _, err := networkFlags(args)
	if err != nil {
		return err
	}
	m, err := newManager()
	if err != nil {
		return err
	}
	rec, err := resolveVM(m, vmName)
	if err != nil {
		return err
	}
	ctx, cancel := signalContext()
	defer cancel()

	if len(args) == 0 {
		return showPorts(ctx, m, rec)
	}
	if len(args) != 2 {
		return errors.New(portsUsage)
	}
	switch args[0] {
	case "add":
		hostS, guestS, ok := strings.Cut(args[1], ":")
		if !ok {
			guestS = hostS
		}
		host, err := parsePort(hostS)
		if err != nil {
			return err
		}
		guest, err := parsePort(guestS)
		if err != nil {
			return err
		}
		if host < 1024 {
			return errors.New("pick a host port of 1024 or above")
		}
		others, err := m.Store.All()
		if err != nil {
			return err
		}
		for _, o := range others {
			for _, f := range o.Ports {
				if f.HostPort == host && o.Name != rec.Name {
					return fmt.Errorf("localhost:%d is already forwarded to %s", host, o.Name)
				}
			}
		}
		rec.Ports = append(withoutHostPort(rec.Ports, host), daemon.Forward{HostPort: host, GuestPort: guest})
		sort.Slice(rec.Ports, func(i, j int) bool { return rec.Ports[i].HostPort < rec.Ports[j].HostPort })
	case "rm":
		host, err := parsePort(args[1])
		if err != nil {
			return err
		}
		kept := withoutHostPort(rec.Ports, host)
		if len(kept) == len(rec.Ports) {
			return fmt.Errorf("localhost:%d isn't forwarded to %s", host, rec.Name)
		}
		rec.Ports = kept
	default:
		return errors.New(portsUsage)
	}
	if err := m.Store.Save(rec); err != nil {
		return err
	}
	if err := m.Daemon.Notify(ctx, rec.Name); err != nil {
		return err
	}
	return showPorts(ctx, m, rec)
}

func showPorts(ctx context.Context, m *vm.Manager, rec *vm.Record) error {
	fmt.Printf("%s (%s)\n", rec.Name, rec.IP)
	st, _ := daemonClient().Status(ctx)
	var status []string
	for _, v := range st.VMs {
		if v.Name == rec.Name {
			status = v.Forwards
		}
	}
	if len(rec.Ports) == 0 {
		fmt.Println("Forwards: none (windevvm ports add 3000)")
	} else {
		fmt.Println("Forwards:")
		if len(status) == 0 {
			for _, f := range rec.Ports {
				status = append(status, f.String())
			}
		}
		for _, s := range status {
			fmt.Println("  " + s)
		}
	}

	info, ok, err := m.HV.GetVM(ctx, rec.Name)
	if err != nil || !ok || !info.Running() {
		fmt.Println("The VM isn't running.")
		return err
	}
	c, err := m.SSH.Dial(rec.IP, rec.HostKey, 10*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	out, err := sshkeys.Run(c, "ss -Hltn")
	if err != nil {
		return fmt.Errorf("list listening ports: %v", err)
	}
	type listen struct {
		port     int
		loopback bool
	}
	seen := map[int]*listen{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		local := f[3]
		i := strings.LastIndex(local, ":")
		port, err := strconv.Atoi(local[i+1:])
		if err != nil || port == 22 || port == 53 || port == 54 {
			continue
		}
		addr := strings.Trim(local[:i], "[]")
		lo := strings.HasPrefix(addr, "127.") || addr == "::1"
		if l, ok := seen[port]; ok {
			l.loopback = l.loopback && lo
		} else {
			seen[port] = &listen{port, lo}
		}
	}
	if len(seen) == 0 {
		fmt.Println("Nothing is listening in the VM.")
		return nil
	}
	ports := make([]int, 0, len(seen))
	for p := range seen {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	fmt.Println("Listening in the VM:")
	for _, p := range ports {
		where := fmt.Sprintf("http://%s:%d from the host", rec.IP, p)
		if seen[p].loopback {
			where = "VM loopback only; forward it to reach it: windevvm ports add " + strconv.Itoa(p)
		}
		forwarded := ""
		for _, f := range rec.Ports {
			if f.GuestPort == p {
				forwarded = fmt.Sprintf(" (forwarded: http://localhost:%d)", f.HostPort)
			}
		}
		fmt.Printf("  %-6d %s%s\n", p, where, forwarded)
	}
	return nil
}

// cmdCode opens the project's VM in VS Code over Remote-SSH.
func cmdCode(args []string) error {
	fs := flag.NewFlagSet("code", flag.ContinueOnError)
	yes := fs.Bool("y", false, "add the ssh config Include without asking")
	if err := fs.Parse(args); err != nil {
		return err
	}
	codeExe, err := exec.LookPath("code")
	if err != nil {
		return errors.New("VS Code's `code` command isn't on PATH (install VS Code, with the Remote - SSH extension)")
	}
	m, err := newManager()
	if err != nil {
		return err
	}
	if err := ensureSSHInclude(m.SSH.ConfigPath(), *yes); err != nil {
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
	if pol, err := m.Net.Policy(rec); err == nil && !pol.Decide("update.code.visualstudio.com", 443).Allow {
		fmt.Println("Note: VS Code installs its server and extensions in the VM through the proxy, which doesn't allow them yet.")
		fmt.Println("      Allow them with: windevvm network allow @vscode --global")
	}
	fmt.Printf("Opening %s:%s in VS Code...\n", rec.Name, rec.WorkDir())
	cmd := exec.Command(codeExe, "--remote", "ssh-remote+"+rec.Name, rec.WorkDir())
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

// ensureSSHInclude makes ~/.ssh/config include windevvm's generated config,
// so VS Code (and plain ssh) know the VMs by name. It asks first.
func ensureSSHInclude(generated string, yes bool) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	path := filepath.Join(home, ".ssh", "config")
	line := `Include "` + filepath.ToSlash(generated) + `"`
	b, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if strings.Contains(strings.ToLower(string(b)), strings.ToLower(filepath.ToSlash(generated))) {
		return nil
	}
	if !yes {
		fmt.Printf("VS Code finds hosts through %s. Add this line at its top?\n  %s\n[y/N] ", path, line)
		reply, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(reply)), "y") {
			return errors.New("cancelled; add the line yourself, or connect with: windevvm shell")
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	// Include must come before any Host block to apply to every host.
	text := "# Added by windevvm: its VMs, by name.\n" + line + "\n\n" + string(b)
	if err := writeFile(path, text); err != nil {
		return err
	}
	fmt.Printf("Added the Include to %s.\n", path)
	return nil
}

// cmdTop shows live usage per VM against its caps and the host budget.
func cmdTop(args []string) error {
	fs := flag.NewFlagSet("top", flag.ContinueOnError)
	once := fs.Bool("once", false, "print once and exit")
	every := fs.Duration("every", 2*time.Second, "refresh interval")
	if err := fs.Parse(args); err != nil {
		return err
	}
	m, err := newManager()
	if err != nil {
		return err
	}
	ctx, cancel := signalContext()
	defer cancel()
	enableVT()
	for {
		frame, err := topFrame(ctx, m)
		if err != nil {
			return err
		}
		if !*once {
			fmt.Print("\033[H\033[2J")
		}
		fmt.Print(frame)
		if *once {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(*every):
		}
	}
}

func rate(bps float64) string {
	if bps < 1 {
		return "0"
	}
	return config.Size(int64(bps)).String() + "/s"
}

func topFrame(ctx context.Context, m *vm.Manager) (string, error) {
	recs, err := m.Store.All()
	if err != nil {
		return "", err
	}
	vms, err := m.HV.ListVMs(ctx, "wdvm-")
	if err != nil {
		return "", err
	}
	byName := map[string]hyperv.VMInfo{}
	var running []string
	for _, v := range vms {
		byName[v.Name] = v
		if v.Running() {
			running = append(running, v.Name)
		}
	}
	io := map[string]hyperv.IO{}
	if len(running) > 0 {
		io, _ = m.HV.IOUsage(ctx, running)
	}
	st, _ := daemonClient().Status(ctx)
	idle := map[string]daemon.VMStatus{}
	for _, v := range st.VMs {
		idle[v.Name] = v
	}

	var b strings.Builder
	fmt.Fprintf(&b, "windevvm top  %s  (Ctrl-C to quit)\n\n", time.Now().Format("15:04:05"))
	tw := tabwriter.NewWriter(&b, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tSTATE\tCPU\tMEMORY\tDISK\tDISK I/O (r/w)\tNET (in/out)\tIDLE STOP")
	for _, r := range recs {
		v, ok := byName[r.Name]
		state, cpu, mem, dio, nio, idl := "missing", "-", "-", "-", "-", "-"
		if ok {
			state = strings.ToLower(v.State)
			mem = "- / " + config.Size(v.MemoryCap()).String()
			if v.Running() {
				cpu = fmt.Sprintf("%d%% (cap %d%% of %d)", v.CPUUsage, v.ProcessorMaximum, v.ProcessorCount)
				mem = config.Size(v.MemoryAssigned).String() + " / " + config.Size(v.MemoryCap()).String()
				u := io[r.Name]
				dio = rate(u.DiskRead) + " / " + rate(u.DiskWrite)
				nio = rate(u.NetRx) + " / " + rate(u.NetTx)
				if d, ok := idle[r.Name]; ok {
					switch {
					case d.IdleTimeout == 0:
						idl = "off"
					case !d.IdleSince.IsZero():
						idl = fmt.Sprintf("idle %s of %s", time.Since(d.IdleSince).Round(time.Minute), d.IdleTimeout)
					default:
						idl = "busy (after " + d.IdleTimeout.String() + " idle)"
					}
				}
			}
		}
		used, _ := (&vm.Store{Root: m.Store.Dir(r.Name)}).DiskUsage()
		res, _ := m.Resources(r.Project)
		disk := config.Size(used).String() + " / " + res.Disk.String()
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", r.Name, state, cpu, mem, disk, dio, nio, idl)
	}
	tw.Flush()
	u, bud := vm.Sum(vms, ""), m.Budget()
	total, _ := m.Store.DiskUsage()
	fmt.Fprintf(&b, "\nBudget: %d/%d running, memory %s/%s, CPU %.1f/%.1f threads, disk %s/%s\n",
		u.Running, bud.MaxRunning, config.Size(u.Memory), bud.Memory, u.CPUs, bud.CPUs, config.Size(total), bud.Disk)
	if len(recs) == 0 {
		b.WriteString("No VMs yet.\n")
	}
	return b.String(), nil
}

func withoutHostPort(fs []daemon.Forward, host int) []daemon.Forward {
	var kept []daemon.Forward
	for _, f := range fs {
		if f.HostPort != host {
			kept = append(kept, f)
		}
	}
	return kept
}
