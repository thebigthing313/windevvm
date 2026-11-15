package vm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"windevvm/internal/cloudinit"
	"windevvm/internal/config"
	"windevvm/internal/hyperv"
	"windevvm/internal/image"
	"windevvm/internal/seed"
	"windevvm/internal/sshkeys"
)

// Manager runs the VM lifecycle.
type Manager struct {
	Cfg         config.Global
	HV          *hyperv.Client
	Store       *Store
	SSH         *sshkeys.Dir
	Out         io.Writer
	TotalMemory int64
	LogicalCPUs int
}

func (m *Manager) say(format string, a ...any) { fmt.Fprintf(m.Out, format+"\n", a...) }

// Budget is the resolved host budget.
func (m *Manager) Budget() config.Budget {
	return m.Cfg.Budget.Resolve(m.TotalMemory, m.LogicalCPUs)
}

// Resources returns the validated caps for a project.
func (m *Manager) Resources(project string) (config.Resources, error) {
	p, err := config.LoadProject(project)
	if err != nil {
		return config.Resources{}, err
	}
	res := m.Cfg.Resources.Merge(p.Resources)
	if err := res.Validate(m.LogicalCPUs); err != nil {
		return res, err
	}
	b := m.Budget()
	if int64(res.MemoryMax) > int64(b.Memory) {
		return res, fmt.Errorf("memory_max %s is larger than the whole memory budget (%s)", res.MemoryMax, b.Memory)
	}
	if res.CPUThreads() > b.CPUs {
		return res, fmt.Errorf("cpus x cpu_max_percent = %.1f CPUs is more than the whole CPU budget (%.1f)", res.CPUThreads(), b.CPUs)
	}
	return res, nil
}

func capsFor(r config.Resources) hyperv.Caps {
	return hyperv.Caps{
		CPUs:          r.CPUs,
		CPUMaxPercent: r.CPUMaxPercent,
		CPUWeight:     r.CPUWeight,
		MemoryStartup: int64(r.MemoryStartup),
		MemoryMin:     int64(r.MemoryMin),
		MemoryMax:     int64(r.MemoryMax),
		DiskIOPS:      r.DiskIOPS,
		NetBitsPerSec: int64(r.NetMbps) * 1_000_000,
		DiskBytes:     int64(r.Disk),
	}
}

// Up creates the project's VM if needed, applies its caps, checks the budget,
// starts it and waits until it accepts SSH.
func (m *Manager) Up(ctx context.Context, project string) (*Record, error) {
	res, err := m.Resources(project)
	if err != nil {
		return nil, err
	}
	rec, err := m.Store.FindByProject(project)
	if err != nil {
		return nil, err
	}
	if rec == nil {
		if rec, err = m.create(ctx, project, res); err != nil {
			return nil, err
		}
	}
	info, ok, err := m.HV.GetVM(ctx, rec.Name)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("VM %s is recorded but missing from Hyper-V; remove it with: windevvm rm %s", rec.Name, rec.Name)
	}

	if info.Running() {
		deferred, err := m.HV.ApplyCaps(ctx, rec.Name, capsFor(res))
		if err != nil {
			return nil, err
		}
		if deferred {
			m.say("Note: new vCPU or memory settings apply after a restart (windevvm stop, then windevvm).")
		}
	} else {
		vms, err := m.HV.ListVMs(ctx, "wdvm-")
		if err != nil {
			return nil, err
		}
		if err := CheckBudget(m.Budget(), vms, rec.Name, res); err != nil {
			return nil, err
		}
		if _, err := m.HV.ApplyCaps(ctx, rec.Name, capsFor(res)); err != nil {
			return nil, err
		}
		m.say("Starting %s (%d vCPUs capped at %d%%, memory %s-%s)...", rec.Name, res.CPUs, res.CPUMaxPercent, res.MemoryMin, res.MemoryMax)
		if err := m.HV.Start(ctx, rec.Name); err != nil {
			return nil, err
		}
	}

	if err := m.waitReady(ctx, rec); err != nil {
		return nil, err
	}
	if !rec.Provisioned {
		// Swap in the seed without the host private key; same instance-id, so
		// cloud-init doesn't provision again.
		if err := m.HV.SetDVD(ctx, rec.Name, m.seedPath(rec.Name)); err != nil {
			return nil, err
		}
		os.Remove(m.firstSeedPath(rec.Name))
		rec.Provisioned = true
		if err := m.Store.Save(rec); err != nil {
			return nil, err
		}
	}
	return rec, m.SyncSSH()
}

func (m *Manager) seedPath(name string) string { return filepath.Join(m.Store.Dir(name), "seed.iso") }
func (m *Manager) firstSeedPath(name string) string {
	return filepath.Join(m.Store.Dir(name), "seed-first.iso")
}
func (m *Manager) diskPath(name string) string { return filepath.Join(m.Store.Dir(name), "disk.vhdx") }

func (m *Manager) create(ctx context.Context, project string, res config.Resources) (*Record, error) {
	base, err := image.Current(m.Cfg)
	if err != nil {
		return nil, err
	}
	ok, err := m.HV.SwitchExists(ctx, Switch)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("the %q virtual switch doesn't exist yet; run once: windevvm setup", Switch)
	}
	if used, err := m.Store.DiskUsage(); err == nil && used >= int64(m.Budget().Disk) {
		return nil, fmt.Errorf("VM disks already use %s, at or above the %s disk budget; remove VMs with windevvm rm NAME", config.Size(used), m.Budget().Disk)
	}
	ip, err := m.Store.AllocateIP()
	if err != nil {
		return nil, err
	}
	name := NameFor(project)
	hostPriv, hostPub, err := sshkeys.NewKeyPair(name)
	if err != nil {
		return nil, err
	}
	authKey, err := m.SSH.AuthorizedKey()
	if err != nil {
		return nil, err
	}
	rec := &Record{
		Name:       name,
		Project:    project,
		IP:         ip.String(),
		MAC:        macFor(ip),
		InstanceID: name + "-" + strconv.FormatInt(time.Now().Unix(), 36),
		HostKey:    hostPub,
		Base:       base.Path,
		Created:    time.Now(),
	}
	if err := m.Store.Save(rec); err != nil {
		return nil, err
	}
	fail := func(err error) (*Record, error) {
		m.HV.Remove(context.Background(), name)
		os.RemoveAll(m.Store.Dir(name))
		return nil, err
	}

	spec := cloudinit.VMSpec{
		Name: name, InstanceID: rec.InstanceID, IP: rec.IP, PrefixLen: PrefixLen,
		AuthorizedKey: authKey, HostKeyPrivate: hostPriv, HostKeyPublic: hostPub,
	}
	if err := writeSeed(m.firstSeedPath(name), spec); err != nil {
		return fail(err)
	}
	spec.HostKeyPrivate = ""
	if err := writeSeed(m.seedPath(name), spec); err != nil {
		return fail(err)
	}

	m.say("Creating %s from the base image (%s)...", name, filepath.Base(base.Path))
	if err := m.HV.CreateVM(ctx, hyperv.CreateSpec{
		Name: name, Dir: m.Store.Dir(name), Disk: m.diskPath(name), Parent: base.Path,
		DiskBytes: int64(res.Disk), SeedISO: m.firstSeedPath(name), Switch: Switch,
		MAC: rec.MAC, ComPipe: `\\.\pipe\` + name, Memory: int64(res.MemoryStartup),
	}); err != nil {
		return fail(err)
	}
	return rec, nil
}

func writeSeed(path string, spec cloudinit.VMSpec) error {
	files, err := cloudinit.VMSeed(spec)
	if err != nil {
		return err
	}
	return seed.WriteISO(path, files)
}

// waitReady waits until the VM accepts SSH and cloud-init has finished.
func (m *Manager) waitReady(ctx context.Context, rec *Record) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	var lastErr error
	for {
		c, err := m.SSH.Dial(rec.IP, rec.HostKey, 5*time.Second)
		if err == nil {
			out, err := sshkeys.Run(c, "cloud-init status --wait >/dev/null 2>&1; cloud-init status")
			c.Close()
			var exit *ssh.ExitError
			if err == nil || errors.As(err, &exit) && exit.ExitStatus() == 2 {
				if err != nil && !rec.Provisioned {
					m.say("Warning: cloud-init reported recoverable errors (details: sudo cloud-init status --long):\n%s", strings.TrimSpace(out))
				}
				return nil
			}
			return fmt.Errorf("VM %s failed to provision: %s", rec.Name, strings.TrimSpace(out))
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return fmt.Errorf("VM %s didn't become reachable over SSH at %s: %v", rec.Name, rec.IP, lastErr)
		case <-time.After(2 * time.Second):
		}
	}
}

// Stop shuts a VM down.
func (m *Manager) Stop(ctx context.Context, name string) error {
	return m.HV.Stop(ctx, name, 90*time.Second)
}

// Remove deletes a VM and all its files.
func (m *Manager) Remove(ctx context.Context, name string) error {
	if err := m.HV.Remove(ctx, name); err != nil {
		return err
	}
	var err error
	for i := 0; i < 10; i++ {
		if err = os.RemoveAll(m.Store.Dir(name)); err == nil {
			break
		}
		time.Sleep(time.Second) // Hyper-V can hold the disk briefly after removal
	}
	if err != nil {
		return err
	}
	return m.SyncSSH()
}

// SyncSSH rewrites known_hosts and the ssh config from the VM records.
func (m *Manager) SyncSSH() error {
	recs, err := m.Store.All()
	if err != nil {
		return err
	}
	hosts := make([]sshkeys.Host, 0, len(recs))
	for _, r := range recs {
		hosts = append(hosts, sshkeys.Host{Alias: r.Name, IP: r.IP, HostKey: r.HostKey})
	}
	return m.SSH.Sync(hosts)
}

// Status pairs a record with its live Hyper-V state.
type Status struct {
	Record *Record
	Info   hyperv.VMInfo
	Exists bool
}

// List returns every VM's status.
func (m *Manager) List(ctx context.Context) ([]Status, error) {
	recs, err := m.Store.All()
	if err != nil {
		return nil, err
	}
	vms, err := m.HV.ListVMs(ctx, "wdvm-")
	if err != nil {
		return nil, err
	}
	byName := map[string]hyperv.VMInfo{}
	for _, v := range vms {
		byName[v.Name] = v
	}
	out := make([]Status, 0, len(recs))
	for _, r := range recs {
		v, ok := byName[r.Name]
		out = append(out, Status{Record: r, Info: v, Exists: ok})
	}
	return out, nil
}

// Resolve finds a VM by name, or by the project containing dir.
func (m *Manager) Resolve(nameOrEmpty, dir string) (*Record, error) {
	if nameOrEmpty != "" {
		r, err := m.Store.Load(nameOrEmpty)
		if err != nil {
			return nil, fmt.Errorf("no VM named %s", nameOrEmpty)
		}
		return r, nil
	}
	project, err := config.FindProjectRoot(dir)
	if err != nil {
		return nil, err
	}
	r, err := m.Store.FindByProject(project)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("no VM for %s yet; create one with: windevvm", project)
	}
	return r, nil
}
