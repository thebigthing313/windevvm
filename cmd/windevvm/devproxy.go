package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"windevvm/internal/ca"
	"windevvm/internal/inject"
	"windevvm/internal/paths"
	"windevvm/internal/policy"
	"windevvm/internal/protect"
	"windevvm/internal/proxy"
	"windevvm/internal/secrets"
)

func cmdCA(args []string) error {
	if len(args) != 1 || args[0] != "init" {
		return errors.New("usage: windevvm ca init")
	}
	_, created, err := ca.LoadOrCreate(paths.CADir(), protect.Default())
	if err != nil {
		return err
	}
	if created {
		fmt.Println("Created a new local CA.")
	}
	fmt.Println(ca.CertPath(paths.CADir()))
	return nil
}

// cmdDevProxy runs the proxy on this machine so injection and policy can be
// tried with curl before any VM exists.
func cmdDevProxy(args []string) error {
	fs := flag.NewFlagSet("dev-proxy", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:18080", "address to listen on")
	tierFlag := fs.String("tier", "allowlist", "network tier: none, allowlist or internet")
	allow := fs.String("allow", "", "comma-separated rules, e.g. pypi.org,*.npmjs.org,!evil.com")
	use := fs.String("use", "", "comma-separated secret names to expose")
	if err := fs.Parse(args); err != nil {
		return err
	}
	tier, err := policy.ParseTier(*tierFlag)
	if err != nil {
		return err
	}

	authority, _, err := ca.LoadOrCreate(paths.CADir(), protect.Default())
	if err != nil {
		return err
	}

	var rules []policy.Rule
	for _, s := range splitList(*allow) {
		r, err := policy.ParseRule(s)
		if err != nil {
			return err
		}
		rules = append(rules, r)
	}

	var bindings []inject.Binding
	var builtin []policy.Rule
	st := store()
	for _, name := range splitList(*use) {
		sec, err := st.Get(name)
		if err != nil {
			return err
		}
		ph, err := secrets.NewPlaceholder(name)
		if err != nil {
			return err
		}
		bindings = append(bindings, inject.Binding{Placeholder: ph, Secret: sec})
		for _, h := range sec.Hosts {
			r, err := policy.ParseRule(h)
			if err != nil {
				return err
			}
			builtin = append(builtin, r)
		}
	}
	inj, err := inject.New(bindings)
	if err != nil {
		return err
	}

	vm := &proxy.VM{
		Name:     "dev",
		Policy:   &policy.Policy{Tier: tier, Rules: rules, Builtin: builtin},
		Injector: inj,
	}
	if ap, err := netip.ParseAddrPort(*listen); err == nil && ap.Addr().IsLoopback() {
		vm.SourceIP = ap.Addr()
	}
	srv := proxy.New(authority, vm)
	srv.OnEvent = printEvent

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	fmt.Printf("windevvm dev proxy on http://%s (tier %s)\n", ln.Addr(), tier)
	fmt.Printf("CA certificate: %s\n\n", ca.CertPath(paths.CADir()))
	if len(bindings) > 0 {
		fmt.Println("Placeholders (use these where the real secrets would go):")
		for _, b := range bindings {
			fmt.Printf("  %s=%s\n", b.Secret.Name, b.Placeholder)
		}
		fmt.Println()
	}
	fmt.Println("Try it:")
	fmt.Printf("  curl --ssl-no-revoke --proxy http://%s --cacert \"%s\" https://api.github.com/user -H \"Authorization: Bearer <placeholder>\"\n", ln.Addr(), ca.CertPath(paths.CADir()))
	fmt.Println("  (Windows curl needs --ssl-no-revoke because the local CA publishes no revocation list; Linux VMs don't need it.)")
	fmt.Println()

	hs := &http.Server{Handler: srv, ReadHeaderTimeout: 30 * time.Second}
	return hs.Serve(ln)
}

func printEvent(e proxy.Event) {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %-6s", e.Time.Format("15:04:05"), e.Kind)
	if e.Host != "" {
		fmt.Fprintf(&b, " %s %s:%d", e.Method, e.Host, e.Port)
	}
	if e.Path != "" {
		b.WriteString(e.Path)
	}
	if e.Intercepted {
		b.WriteString(" [intercepted]")
	}
	if len(e.Secrets) > 0 {
		fmt.Fprintf(&b, " secrets=%s", strings.Join(e.Secrets, ","))
	}
	if e.Reason != "" {
		fmt.Fprintf(&b, " (%s)", e.Reason)
	}
	if e.Suggest != "" {
		fmt.Fprintf(&b, " allow with: windevvm network allow %s", e.Suggest)
	}
	fmt.Println(b.String())
}
