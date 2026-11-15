package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"windevvm/internal/hostinfo"
	"windevvm/internal/hyperv"
	"windevvm/internal/paths"
	"windevvm/internal/setup"
	"windevvm/internal/vm"
)

const (
	proxyPortFirst = 18000
	proxyPortLast  = 18250
)

// cmdSetup configures the host once. Without elevation it relaunches itself
// through a UAC prompt and shows the elevated run's output when it finishes.
func cmdSetup(args []string) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	elevated := fs.Bool("elevated", false, "internal: running in the elevated child")
	forUser := fs.String("user", "", "internal: the user to add to Hyper-V Administrators")
	logPath := fs.String("log", "", "internal: where the elevated child writes its output")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *elevated {
		out, err := os.Create(*logPath)
		if err != nil {
			return err
		}
		defer out.Close()
		res, err := runSetup(*forUser)
		for _, s := range res.Steps {
			fmt.Fprintln(out, "  "+s)
		}
		if err != nil {
			fmt.Fprintln(out, "ERROR: "+err.Error())
			return err
		}
		fmt.Fprintln(out, "OK")
		return nil
	}

	u, err := user.Current()
	if err != nil {
		return err
	}
	if hostinfo.IsElevated() {
		res, err := runSetup(u.Username)
		printSteps(res)
		return err
	}

	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(paths.DataDir(), 0o755); err != nil {
		return err
	}
	log := filepath.Join(paths.DataDir(), "setup.log")
	os.Remove(log)
	fmt.Println("windevvm setup needs administrator rights once. Approve the Windows prompt to continue...")
	ps := fmt.Sprintf(`$p = Start-Process -FilePath '%s' -ArgumentList @('setup','--elevated','--user','%s','--log','%s') -Verb RunAs -Wait -PassThru -WindowStyle Hidden; exit $p.ExitCode`,
		psQuote(exe), psQuote(u.Username), psQuote(log))
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps)
	runErr := cmd.Run()
	b, _ := os.ReadFile(log)
	text := strings.TrimSpace(string(b))
	if text == "" {
		if runErr != nil {
			return fmt.Errorf("setup didn't run (was the prompt declined?): %v", runErr)
		}
		return errors.New("setup produced no output")
	}
	lines := strings.Split(text, "\n")
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "OK" {
			continue
		}
		if msg, ok := strings.CutPrefix(l, "ERROR: "); ok {
			return errors.New(msg)
		}
		fmt.Println("  " + l)
	}
	fmt.Println("Setup complete.")
	return runErr
}

func psQuote(s string) string { return strings.ReplaceAll(s, "'", "''") }

func runSetup(username string) (setup.Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	return setup.Run(ctx, &hyperv.Runner{}, setup.Params{
		User:       username,
		Switch:     vm.Switch,
		HostIP:     vm.HostIP,
		PrefixLen:  vm.PrefixLen,
		Subnet:     "10.77.0.0/24",
		ProxyPorts: fmt.Sprintf("%d-%d", proxyPortFirst, proxyPortLast),
		BlockedTCP: []string{fmt.Sprintf("1-%d", proxyPortFirst-1), fmt.Sprintf("%d-65535", proxyPortLast+1)},
	})
}

func printSteps(res setup.Result) {
	if len(res.Steps) == 0 {
		fmt.Println("Everything was already set up.")
	}
	for _, s := range res.Steps {
		fmt.Println("  " + s)
	}
}
