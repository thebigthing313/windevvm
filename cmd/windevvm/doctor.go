package main

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"windevvm/internal/daemon"
	"windevvm/internal/paths"
	"windevvm/internal/proxy"
	"windevvm/internal/secrets"
	"windevvm/internal/sshkeys"
	"windevvm/internal/vm"
)

// spoofIP is never assigned to a VM (they get .10-.250), so the doctor can
// add it inside the VM to test that the port ACL drops spoofed packets.
const spoofIP = "10.77.0.251"

type checkResult struct {
	ok     bool
	skip   bool
	name   string
	detail string
}

func (c checkResult) String() string {
	mark := "PASS"
	switch {
	case c.skip:
		mark = "skip"
	case !c.ok:
		mark = "FAIL"
	}
	return fmt.Sprintf("  %s  %-22s %s", mark, c.name, c.detail)
}

// doctorScript runs inside the VM as the dev user. Each check prints
// "PASS|FAIL|SKIP<TAB>name<TAB>detail".
const doctorScript = `P="$1"; HOSTPORT="${P#http://}"; SPOOF="$2"; MYIP="$3"
r() { printf '%s\t%s\t%s\n' "$1" "$2" "$3"; }

if timeout 5 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443' 2>/dev/null; then
  r FAIL direct "connected to 1.1.1.1:443 without the proxy"
else
  r PASS direct "a direct connection to 1.1.1.1:443 fails"
fi
if timeout 5 getent hosts example.com >/dev/null 2>&1; then
  r FAIL dns "the VM can resolve names itself"
else
  r PASS dns "no DNS inside the VM; the proxy resolves names"
fi

code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 --noproxy '*' "$P/")
if [ "$code" = 400 ]; then r PASS proxy "$P answers"; else r FAIL proxy "$P: got HTTP '$code', want 400"; fi

if [ "$(sh -lc 'echo $HTTPS_PROXY')" = "$P" ]; then
  r PASS env "HTTPS_PROXY and friends point at the proxy (login shells)"
else
  r FAIL env "HTTPS_PROXY in a login shell is '$(sh -lc 'echo $HTTPS_PROXY')', want $P"
fi

if openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt /usr/local/share/ca-certificates/windevvm.crt >/dev/null 2>&1; then
  r PASS ca "the windevvm CA is in the system trust store"
else
  r FAIL ca "the windevvm CA isn't trusted"
fi

code=$(curl -s -o /dev/null -w '%{http_connect}' --max-time 10 -x "$P" https://169.254.169.254/)
if [ "$code" = 403 ]; then r PASS blocked "a disallowed destination gets 403 from the proxy"; else r FAIL blocked "CONNECT 169.254.169.254:443 got '$code', want 403"; fi

code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 -x "$P" https://api.anthropic.com/)
case "$code" in
  000|403) r FAIL egress "https://api.anthropic.com/ through the proxy: got '$code'" ;;
  *) r PASS egress "an allowed host is reachable through the proxy (HTTP $code)" ;;
esac

shift 3
while [ $# -ge 3 ]; do
  name="$1"; host="$2"; ph="$3"; shift 3
  issuer=$(openssl s_client -proxy "$HOSTPORT" -connect "$host:443" -servername "$host" </dev/null 2>/dev/null | openssl x509 -noout -issuer 2>/dev/null)
  case "$issuer" in
    *"windevvm local CA"*) r PASS "intercept $name" "TLS to $host is opened by the proxy, and the VM trusts it" ;;
    *) r FAIL "intercept $name" "TLS to $host has issuer '$issuer', want the windevvm local CA" ;;
  esac
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 -x "$P" -H "Authorization: Bearer $ph" "https://$host/")
  r INFO "inject $name" "$code"
done

if sudo ip addr add "$SPOOF/32" dev eth0 2>/dev/null; then
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 --noproxy '*' --interface "$SPOOF" "$P/")
  sudo ip addr del "$SPOOF/32" dev eth0
  if [ "$code" = 000 ]; then r PASS spoof "packets from a spoofed address ($SPOOF) are dropped"; else r FAIL spoof "a spoofed address ($SPOOF) reached the proxy (HTTP $code)"; fi
else
  r SKIP spoof "couldn't add a test address"
fi
`

func cmdDoctor(args []string) error {
	args, vmName, _, err := networkFlags(args)
	if err != nil {
		return err
	}
	if len(args) > 0 {
		return errors.New("usage: windevvm doctor [--vm NAME]")
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
	fmt.Printf("Checking %s (%s)\n", rec.Name, rec.IP)

	var results []checkResult
	add := func(ok bool, name, format string, a ...any) {
		results = append(results, checkResult{ok: ok, name: name, detail: fmt.Sprintf(format, a...)})
	}
	addr, err := vm.ProxyAddr(rec)
	if err != nil {
		return err
	}

	// Host side.
	if err := m.Daemon.Notify(ctx, rec.Name); err != nil {
		add(false, "daemon", "%v", err)
	} else {
		add(true, "daemon", "running, proxy for this VM on %s", addr)
	}
	acl, err := m.HV.IPGuard(ctx, rec.Name)
	switch {
	case err != nil:
		add(false, "port ACL", "%v", err)
	case (slices.Contains(acl, "Allow "+rec.IP) || slices.Contains(acl, "Allow "+rec.IP+"/32")) && slices.Contains(acl, "Deny 0.0.0.0/0"):
		add(true, "port ACL", "the VM may only send from %s", rec.IP)
	default:
		add(false, "port ACL", "outbound ACLs are %v; run windevvm up to fix", acl)
	}

	info, ok, err := m.HV.GetVM(ctx, rec.Name)
	if err != nil {
		return err
	}
	if !ok || !info.Running() {
		printResults(results)
		return errors.New("the VM isn't running; start it with windevvm up, then run doctor again")
	}

	// Inside the VM.
	s, err := m.Net.Setup(rec)
	if err != nil {
		return err
	}
	scriptArgs := []string{"http://" + addr, spoofIP, rec.IP}
	type probe struct{ name, host string }
	var probes []probe
	for _, sec := range s.Inputs.Secrets {
		host := firstExactHost(sec)
		ph := rec.Placeholders[sec.Name]
		switch {
		case ph == "":
			results = append(results, checkResult{skip: true, name: "inject " + sec.Name, detail: "no placeholder yet; run windevvm up"})
		case host == "":
			results = append(results, checkResult{skip: true, name: "inject " + sec.Name, detail: "bound only to wildcard hosts"})
		case !sec.Allows(secrets.InHeader):
			results = append(results, checkResult{skip: true, name: "inject " + sec.Name, detail: "not injected into headers"})
		default:
			scriptArgs = append(scriptArgs, sec.Name, host, ph)
			probes = append(probes, probe{sec.Name, host})
		}
	}

	c, err := m.SSH.Dial(rec.IP, rec.HostKey, 10*time.Second)
	if err != nil {
		return fmt.Errorf("connect to %s: %w", rec.Name, err)
	}
	defer c.Close()
	started := time.Now().Add(-time.Second)
	quoted := make([]string, len(scriptArgs))
	for i, a := range scriptArgs {
		quoted[i] = "'" + a + "'" // all values are [A-Za-z0-9_.:/-]
	}
	out, err := sshkeys.RunInput(c, "bash -s -- "+strings.Join(quoted, " "), doctorScript)
	if err != nil && strings.TrimSpace(out) == "" {
		return fmt.Errorf("run checks in %s: %w", rec.Name, err)
	}
	injectCodes := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		f := strings.SplitN(strings.TrimRight(line, "\r"), "\t", 3)
		if len(f) != 3 {
			continue
		}
		switch f[0] {
		case "INFO":
			injectCodes[f[1]] = f[2]
		case "SKIP":
			results = append(results, checkResult{skip: true, name: f[1], detail: f[2]})
		default:
			results = append(results, checkResult{ok: f[0] == "PASS", name: f[1], detail: f[2]})
		}
	}

	// Injection is confirmed from the proxy's own log.
	if len(probes) > 0 {
		time.Sleep(500 * time.Millisecond) // let the event log flush
		evs, _ := daemon.ReadEvents(daemon.EventsPath(paths.DaemonDir()), rec.Name, 500)
		for _, p := range probes {
			name := "inject " + p.name
			if injected(evs, started, p.name) {
				add(true, name, "the proxy put the real value into a request to %s (it answered HTTP %s)", p.host, injectCodes[name])
			} else {
				add(false, name, "no injection logged for a request to %s (HTTP %s)", p.host, injectCodes[name])
			}
		}
	}
	printResults(results)
	for _, r := range results {
		if !r.ok && !r.skip {
			return errors.New("some checks failed")
		}
	}
	fmt.Println("All checks passed.")
	return nil
}

func firstExactHost(s secrets.Secret) string {
	for _, h := range s.Hosts {
		if strings.ContainsAny(h, "*/") {
			continue
		}
		if host, _, err := net.SplitHostPort(h); err == nil {
			h = host
		}
		return h
	}
	return ""
}

func injected(evs []proxy.Event, since time.Time, secret string) bool {
	for _, e := range evs {
		if e.Kind == proxy.KindInject && e.Time.After(since) && slices.Contains(e.Secrets, secret) {
			return true
		}
	}
	return false
}

func printResults(rs []checkResult) {
	for _, r := range rs {
		fmt.Println(r)
	}
}
