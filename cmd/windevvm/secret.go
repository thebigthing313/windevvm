package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"golang.org/x/term"

	"windevvm/internal/paths"
	"windevvm/internal/protect"
	"windevvm/internal/secrets"
)

func store() *secrets.Store {
	return &secrets.Store{Dir: paths.SecretsDir(), P: protect.Default()}
}

// splitName lets the positional NAME come before or after the flags.
func splitName(args []string) (string, []string) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		return args[0], args[1:]
	}
	return "", args
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func cmdSecret(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: windevvm secret set|ls|rm")
	}
	switch args[0] {
	case "set":
		return secretSet(args[1:])
	case "ls", "list":
		return secretList()
	case "rm", "remove":
		if len(args) != 2 {
			return errors.New("usage: windevvm secret rm NAME")
		}
		if err := store().Remove(args[1]); err != nil {
			return err
		}
		fmt.Printf("Removed secret %s.\n", args[1])
		return nil
	}
	return fmt.Errorf("unknown secret command %q", args[0])
}

func presetNames() string {
	var names []string
	for n := range secrets.Presets {
		names = append(names, n)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

func secretSet(args []string) error {
	name, rest := splitName(args)
	fs := flag.NewFlagSet("secret set", flag.ContinueOnError)
	preset := fs.String("preset", "", "use a built-in binding: "+presetNames())
	hosts := fs.String("hosts", "", "comma-separated hosts the secret is injected into")
	in := fs.String("in", "", "comma-separated locations: header (default), url, body")
	fromEnv := fs.String("from-env", "", "read the value from this environment variable instead of prompting")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if name == "" {
		name = fs.Arg(0)
	}
	if name == "" {
		return errors.New("usage: windevvm secret set NAME [--preset P | --hosts h1,h2]")
	}

	sec := secrets.Secret{Name: name, Hosts: splitList(*hosts)}
	var note string
	if *preset != "" {
		p, ok := secrets.Presets[*preset]
		if !ok {
			return fmt.Errorf("unknown preset %q (have %s)", *preset, presetNames())
		}
		if len(sec.Hosts) == 0 {
			sec.Hosts = p.Hosts
		}
		sec.In = p.In
		note = p.Note
	}
	if *in != "" {
		sec.In = nil
		for _, l := range splitList(*in) {
			loc, err := secrets.ParseLocation(l)
			if err != nil {
				return err
			}
			sec.In = append(sec.In, loc)
		}
	}
	if len(sec.Hosts) == 0 {
		return errors.New("say where the secret may be sent with --preset or --hosts")
	}
	if err := sec.Validate(); err != nil {
		return err
	}

	value, err := readValue(name, *fromEnv)
	if err != nil {
		return err
	}
	sec.Value = value
	if err := store().Set(sec); err != nil {
		return err
	}
	fmt.Printf("Saved secret %s (encrypted for your Windows user). Injected only into HTTPS requests to: %s\n", name, strings.Join(sec.Hosts, ", "))
	if note != "" {
		fmt.Println(note)
	}
	return nil
}

func readValue(name, fromEnv string) ([]byte, error) {
	if fromEnv != "" {
		v := os.Getenv(fromEnv)
		if v == "" {
			return nil, fmt.Errorf("environment variable %s is empty", fromEnv)
		}
		return []byte(v), nil
	}
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		fmt.Fprintf(os.Stderr, "Value for %s (input hidden): ", name)
		v, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, err
		}
		if len(v) == 0 {
			return nil, errors.New("empty value")
		}
		return v, nil
	}
	v, err := io.ReadAll(bufio.NewReader(os.Stdin))
	if err != nil {
		return nil, err
	}
	v = []byte(strings.TrimRight(string(v), "\r\n"))
	if len(v) == 0 {
		return nil, errors.New("empty value on stdin")
	}
	return v, nil
}

func secretList() error {
	list, err := store().List()
	if err != nil {
		return err
	}
	if len(list) == 0 {
		fmt.Println("No secrets yet. Add one with: windevvm secret set NAME --preset github")
		return nil
	}
	for _, s := range list {
		in := "header"
		if len(s.In) > 0 {
			var parts []string
			for _, l := range s.In {
				parts = append(parts, string(l))
			}
			in = strings.Join(parts, ",")
		}
		fmt.Printf("%-24s hosts: %s   in: %s\n", s.Name, strings.Join(s.Hosts, ", "), in)
	}
	return nil
}
