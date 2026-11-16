package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"windevvm/internal/daemon"
	"windevvm/internal/egress"
	"windevvm/internal/paths"
	"windevvm/internal/policy"
	"windevvm/internal/proxy"
	"windevvm/internal/vm"
)

const networkUsage = `usage:
  windevvm network                       show this VM's network policy
  windevvm network none|allowlist|internet  set this VM's tier
  windevvm network reset                 go back to the tier in .windevvm.toml (or allowlist)
  windevvm network allow RULE... [--global]
  windevvm network deny RULE... [--global]
  windevvm network rm RULE... [--global]
  windevvm network log [-n N] [-f] [--all]
Add --vm NAME to pick a VM other than this project's.
Rules: example.com, *.example.com, host:port, 10.0.0.0/8:5432, @preset (` + "%s" + `), !rule denies.`

// networkFlags pulls --vm NAME and --global out of args, anywhere.
func networkFlags(args []string) (rest []string, vmName string, global bool, err error) {
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "--global" || a == "-global":
			global = true
		case a == "--vm" || a == "-vm":
			if i+1 >= len(args) {
				return nil, "", false, errors.New("--vm needs a name")
			}
			vmName = args[i+1]
			i++
		case strings.HasPrefix(a, "--vm="):
			vmName = strings.TrimPrefix(a, "--vm=")
		default:
			rest = append(rest, a)
		}
	}
	return rest, vmName, global, nil
}

func cmdNetwork(args []string) error {
	usage := fmt.Sprintf(networkUsage, strings.Join(egress.PresetNames(), ", "))
	if len(args) > 0 && args[0] == "log" {
		return networkLog(args[1:])
	}
	args, vmName, global, err := networkFlags(args)
	if err != nil {
		return err
	}
	m, err := newManager()
	if err != nil {
		return err
	}
	ctx, cancel := signalContext()
	defer cancel()

	if len(args) == 0 {
		rec, err := resolveVM(m, vmName)
		if err != nil {
			return err
		}
		return showNetwork(m, rec)
	}

	switch cmd := args[0]; cmd {
	case "allow", "deny", "rm":
		rules := args[1:]
		if len(rules) == 0 {
			return errors.New(usage)
		}
		var rec *vm.Record
		path := paths.PolicyPath()
		if !global {
			if rec, err = resolveVM(m, vmName); err != nil {
				return err
			}
			path = m.Store.PolicyPath(rec.Name)
		} else if _, err := m.Net.ReadGlobalPolicy(); err != nil {
			return err
		}
		if err := editPolicyFile(path, cmd, rules); err != nil {
			return err
		}
		if rec != nil {
			if _, err := m.Net.Policy(rec); err != nil {
				return err
			}
		}
		name := ""
		if rec != nil {
			name = rec.Name
		}
		if err := m.Daemon.Notify(ctx, name); err != nil {
			return err
		}
		fmt.Printf("Updated %s. The proxy applies it now; no restart needed.\n", path)
		return nil

	case "reset", string(policy.None), string(policy.Allowlist), string(policy.Internet):
		rec, err := resolveVM(m, vmName)
		if err != nil {
			return err
		}
		if global {
			return errors.New("the tier is per VM; set a default for a project in .windevvm.toml")
		}
		if cmd == "reset" {
			rec.Tier = ""
		} else {
			rec.Tier = cmd
		}
		if err := m.Store.Save(rec); err != nil {
			return err
		}
		if err := m.Daemon.Notify(ctx, rec.Name); err != nil {
			return err
		}
		s, err := m.Net.Setup(rec)
		if err != nil {
			return err
		}
		tier, src, err := egress.ResolveTier(rec.Tier, s.Project.Network.Tier)
		if err != nil {
			return err
		}
		fmt.Printf("%s: tier %s (%s), effective now.\n", rec.Name, tier, src)
		return nil
	}
	return errors.New(usage)
}

func resolveVM(m *vm.Manager, name string) (*vm.Record, error) {
	wd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	return m.Resolve(name, wd)
}

func editPolicyFile(path, cmd string, rules []string) error {
	b, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	text := string(b)
	for _, r := range rules {
		r = strings.TrimSpace(r)
		bare := strings.TrimPrefix(r, "!")
		var changed bool
		switch cmd {
		case "allow":
			text, changed, err = egress.EditRules(text, bare, true)
		case "deny":
			text, changed, err = egress.EditRules(text, "!"+bare, true)
		case "rm":
			text, changed, err = egress.EditRules(text, bare, false)
			if err == nil && !changed {
				fmt.Printf("%s isn't in %s.\n", bare, path)
			}
		}
		if err != nil {
			return err
		}
	}
	return writeFile(path, text)
}

func writeFile(path, text string) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".policy-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(text); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func showNetwork(m *vm.Manager, rec *vm.Record) error {
	s, err := m.Net.Setup(rec)
	if err != nil {
		return err
	}
	tier, src, err := egress.ResolveTier(rec.Tier, s.Project.Network.Tier)
	if err != nil {
		return err
	}
	addr, _ := vm.ProxyAddr(rec)
	fmt.Printf("%s (%s)\n", rec.Name, rec.Project)
	fmt.Printf("Proxy: %s\n", addr)
	fmt.Printf("Tier:  %s (%s)\n", tier, src)
	switch tier {
	case policy.None:
		fmt.Println("       only the always-allowed hosts below; rules that allow are ignored")
	case policy.Internet:
		fmt.Println("       any public host; private and loopback addresses still need a rule")
	}
	fmt.Println("\nRules (denies win):")
	for _, source := range s.Inputs.Sources {
		if len(source.Rules) == 0 {
			fmt.Printf("  %s: (none)\n", source.Name)
			continue
		}
		fmt.Printf("  %s:\n", source.Name)
		for _, r := range source.Rules {
			line := "    " + r
			if name, ok := strings.CutPrefix(strings.TrimPrefix(r, "!"), "@"); ok {
				line += "  = " + strings.Join(egress.Presets[name], " ")
			}
			fmt.Println(line)
		}
	}
	fmt.Printf("\nAlways allowed (coding agents): %s\n", strings.Join(egress.AgentHosts, " "))
	if len(s.InUse) == 0 {
		fmt.Println("Secrets in use: none (windevvm secret use NAME)")
	} else {
		fmt.Println("Secrets in use (their hosts are always allowed):")
		for _, sec := range s.Inputs.Secrets {
			fmt.Printf("  %-22s %s\n", sec.Name, strings.Join(sec.Hosts, " "))
		}
	}
	return nil
}

func networkLog(args []string) error {
	fs := flag.NewFlagSet("network log", flag.ContinueOnError)
	n := fs.Int("n", 50, "how many recent events to show")
	follow := fs.Bool("f", false, "keep printing new events")
	all := fs.Bool("all", false, "show every VM's events")
	vmName := fs.String("vm", "", "VM name (default: this project's)")
	blocked := fs.Bool("blocked", false, "show only blocked requests")
	if err := fs.Parse(args); err != nil {
		return err
	}
	filter := ""
	if !*all {
		m, err := newManager()
		if err != nil {
			return err
		}
		rec, err := resolveVM(m, *vmName)
		if err != nil {
			return err
		}
		filter = rec.Name
	}
	path := daemon.EventsPath(paths.DaemonDir())
	show := func(evs []eventT) {
		for _, e := range evs {
			if *blocked && e.Kind != "block" && e.Kind != "exfil" {
				continue
			}
			if *all {
				fmt.Printf("[%s] ", e.VM)
			}
			printEvent(e)
		}
	}
	// Read the rotated file, then the live one once, remembering where it
	// ended so -f continues from exactly there.
	evs, _, err := daemon.ReadFrom(path+".1", 0, filter)
	if err != nil {
		return err
	}
	live, off, err := daemon.ReadFrom(path, 0, filter)
	if err != nil {
		return err
	}
	evs = append(evs, live...)
	if *blocked {
		var keep []eventT
		for _, e := range evs {
			if e.Kind == "block" || e.Kind == "exfil" {
				keep = append(keep, e)
			}
		}
		evs = keep
	}
	if *n > 0 && len(evs) > *n {
		evs = evs[len(evs)-*n:]
	}
	if len(evs) == 0 && !*follow {
		fmt.Println("No proxy events yet.")
	}
	show(evs)
	if !*follow {
		return nil
	}
	ctx, cancel := signalContext()
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(500 * time.Millisecond):
		}
		var more []eventT
		more, off, err = daemon.ReadFrom(path, off, filter)
		if err != nil {
			return err
		}
		show(more)
	}
}

type eventT = proxy.Event
