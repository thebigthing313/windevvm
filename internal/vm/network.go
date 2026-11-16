package vm

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"strconv"

	"windevvm/internal/config"
	"windevvm/internal/daemon"
	"windevvm/internal/egress"
	"windevvm/internal/inject"
	"windevvm/internal/policy"
	"windevvm/internal/proxy"
	"windevvm/internal/secrets"
)

// Net computes VMs' network configuration from the files on disk: the global
// policy, each project's .windevvm.toml, each VM's policy file and record,
// and the secret store.
type Net struct {
	Store        *Store
	Secrets      *secrets.Store
	GlobalPolicy string // path of the global policy file
}

// ProxyAddr is where a VM's proxy listens on the host.
func ProxyAddr(rec *Record) (string, error) {
	ip, err := netip.ParseAddr(rec.IP)
	if err != nil || !ip.Is4() {
		return "", fmt.Errorf("VM %s has a bad address %q", rec.Name, rec.IP)
	}
	return net.JoinHostPort(HostIP, strconv.Itoa(egress.Port(ip))), nil
}

// ReadGlobalPolicy returns the global policy file, creating it with the
// default presets the first time.
func (n *Net) ReadGlobalPolicy() (string, error) {
	b, err := os.ReadFile(n.GlobalPolicy)
	if errors.Is(err, fs.ErrNotExist) {
		if err := os.WriteFile(n.GlobalPolicy, []byte(egress.DefaultGlobalPolicy), 0o644); err != nil {
			return "", err
		}
		return egress.DefaultGlobalPolicy, nil
	}
	return string(b), err
}

// ReadVMPolicy returns a VM's own policy file (empty if it has none).
func (n *Net) ReadVMPolicy(name string) (string, error) {
	b, err := os.ReadFile(n.Store.PolicyPath(name))
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	return string(b), err
}

// Setup is everything about a VM's network that comes from its sources.
type Setup struct {
	Project config.Project
	Inputs  egress.Inputs
	// InUse are the names of the secrets the VM uses.
	InUse []string
}

// Setup gathers a VM's network sources. It fails if a secret in use isn't
// in the store.
func (n *Net) Setup(rec *Record) (*Setup, error) {
	proj, err := config.LoadProject(rec.Project)
	if err != nil {
		return nil, err
	}
	global, err := n.ReadGlobalPolicy()
	if err != nil {
		return nil, err
	}
	own, err := n.ReadVMPolicy(rec.Name)
	if err != nil {
		return nil, err
	}
	s := &Setup{Project: proj, InUse: egress.SecretsInUse(proj.Secrets.Use, rec.Secrets)}
	s.Inputs = egress.Inputs{
		TierOverride: rec.Tier,
		ProjectTier:  proj.Network.Tier,
		Sources: []egress.Source{
			{Name: "global policy (" + n.GlobalPolicy + ")", Rules: egress.ParseLines(global)},
			{Name: config.ProjectFile, Rules: proj.Network.Allow},
			{Name: "VM policy (" + n.Store.PolicyPath(rec.Name) + ")", Rules: egress.ParseLines(own)},
		},
	}
	for _, name := range s.InUse {
		meta, err := n.Secrets.Meta(name)
		if errors.Is(err, secrets.ErrNotFound) {
			return nil, fmt.Errorf("%s uses secret %s, which isn't set; set it with: windevvm secret set %s --preset ... (or stop using it)", rec.Name, name, name)
		}
		if err != nil {
			return nil, err
		}
		s.Inputs.Secrets = append(s.Inputs.Secrets, meta)
	}
	return s, nil
}

// Policy returns a VM's effective network policy.
func (n *Net) Policy(rec *Record) (*policy.Policy, error) {
	s, err := n.Setup(rec)
	if err != nil {
		return nil, err
	}
	return egress.Assemble(s.Inputs)
}

// ProxyVM builds the proxy configuration for a VM, decrypting the secrets
// it uses.
func (n *Net) ProxyVM(rec *Record) (*proxy.VM, error) {
	s, err := n.Setup(rec)
	if err != nil {
		return nil, err
	}
	pol, err := egress.Assemble(s.Inputs)
	if err != nil {
		return nil, err
	}
	ip, err := netip.ParseAddr(rec.IP)
	if err != nil {
		return nil, err
	}
	var bindings []inject.Binding
	for _, name := range s.InUse {
		ph, ok := rec.Placeholders[name]
		if !ok {
			continue // not pushed to the VM yet; it can't send what it doesn't have
		}
		sec, err := n.Secrets.Get(name)
		if err != nil {
			return nil, err
		}
		bindings = append(bindings, inject.Binding{Placeholder: ph, Secret: sec})
	}
	inj, err := inject.New(bindings)
	if err != nil {
		return nil, err
	}
	return &proxy.VM{Name: rec.Name, SourceIP: ip, Policy: pol, Injector: inj}, nil
}

// SyncPlaceholders gives rec a placeholder for every secret in inUse and
// drops the rest. It reports whether rec changed.
func SyncPlaceholders(rec *Record, inUse []string) (bool, error) {
	changed := false
	want := map[string]bool{}
	for _, name := range inUse {
		want[name] = true
		if _, ok := rec.Placeholders[name]; ok {
			continue
		}
		ph, err := secrets.NewPlaceholder(name)
		if err != nil {
			return false, err
		}
		if rec.Placeholders == nil {
			rec.Placeholders = map[string]string{}
		}
		rec.Placeholders[name] = ph
		changed = true
	}
	for name := range rec.Placeholders {
		if !want[name] {
			delete(rec.Placeholders, name)
			changed = true
		}
	}
	return changed, nil
}

// Targets returns every VM's proxy configuration, for the daemon. A VM whose
// configuration can't be built is reported in errs and gets no proxy.
func (n *Net) Targets() ([]daemon.Target, map[string]error, error) {
	recs, err := n.Store.All()
	if err != nil {
		return nil, nil, err
	}
	var out []daemon.Target
	errs := map[string]error{}
	for _, rec := range recs {
		addr, err := ProxyAddr(rec)
		if err != nil {
			errs[rec.Name] = err
			continue
		}
		v, err := n.ProxyVM(rec)
		if err != nil {
			errs[rec.Name] = err
			continue
		}
		out = append(out, daemon.Target{Name: rec.Name, Addr: addr, VM: v})
	}
	return out, errs, nil
}
