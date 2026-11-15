// Package config loads windevvm's global settings (%LOCALAPPDATA%\windevvm\config.toml)
// and per-project settings (.windevvm.toml).
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"

	"windevvm/internal/paths"
)

// ProjectFile is the per-project settings file name.
const ProjectFile = ".windevvm.toml"

// Resources are the caps applied to one VM. Zero fields mean "inherit".
type Resources struct {
	CPUs          int  `toml:"cpus"`
	CPUMaxPercent int  `toml:"cpu_max_percent"`
	CPUWeight     int  `toml:"cpu_weight"`
	MemoryStartup Size `toml:"memory_startup"`
	MemoryMin     Size `toml:"memory_min"`
	MemoryMax     Size `toml:"memory_max"`
	Disk          Size `toml:"disk"`
	DiskIOPS      int  `toml:"disk_iops"`
	NetMbps       int  `toml:"net_mbps"`
}

// Merge returns r with every non-zero field of o applied on top.
func (r Resources) Merge(o Resources) Resources {
	if o.CPUs != 0 {
		r.CPUs = o.CPUs
	}
	if o.CPUMaxPercent != 0 {
		r.CPUMaxPercent = o.CPUMaxPercent
	}
	if o.CPUWeight != 0 {
		r.CPUWeight = o.CPUWeight
	}
	if o.MemoryStartup != 0 {
		r.MemoryStartup = o.MemoryStartup
	}
	if o.MemoryMin != 0 {
		r.MemoryMin = o.MemoryMin
	}
	if o.MemoryMax != 0 {
		r.MemoryMax = o.MemoryMax
	}
	if o.Disk != 0 {
		r.Disk = o.Disk
	}
	if o.DiskIOPS != 0 {
		r.DiskIOPS = o.DiskIOPS
	}
	if o.NetMbps != 0 {
		r.NetMbps = o.NetMbps
	}
	return r
}

// CPUThreads is how many host threads' worth of CPU the VM may use at most.
func (r Resources) CPUThreads() float64 {
	return float64(r.CPUs) * float64(r.CPUMaxPercent) / 100
}

const twoMB = 2 << 20

// Validate checks the caps against Hyper-V's rules and the host's size.
func (r Resources) Validate(logicalCPUs int) error {
	var errs []string
	add := func(format string, a ...any) { errs = append(errs, fmt.Sprintf(format, a...)) }
	if r.CPUs < 1 || r.CPUs > logicalCPUs {
		add("cpus must be between 1 and %d (this PC's logical processors), got %d", logicalCPUs, r.CPUs)
	}
	if r.CPUMaxPercent < 1 || r.CPUMaxPercent > 100 {
		add("cpu_max_percent must be between 1 and 100, got %d", r.CPUMaxPercent)
	}
	if r.CPUWeight < 1 || r.CPUWeight > 10000 {
		add("cpu_weight must be between 1 and 10000, got %d", r.CPUWeight)
	}
	for name, v := range map[string]Size{"memory_startup": r.MemoryStartup, "memory_min": r.MemoryMin, "memory_max": r.MemoryMax} {
		if v%twoMB != 0 {
			add("%s must be a multiple of 2MB, got %s", name, v)
		}
	}
	if r.MemoryMin < 256<<20 {
		add("memory_min must be at least 256MB, got %s", r.MemoryMin)
	}
	if r.MemoryStartup < 512<<20 {
		add("memory_startup must be at least 512MB, got %s", r.MemoryStartup)
	}
	if !(r.MemoryMin <= r.MemoryStartup && r.MemoryStartup <= r.MemoryMax) {
		add("memory must satisfy memory_min (%s) <= memory_startup (%s) <= memory_max (%s)", r.MemoryMin, r.MemoryStartup, r.MemoryMax)
	}
	if r.Disk < 8<<30 {
		add("disk must be at least 8GB, got %s", r.Disk)
	}
	if r.DiskIOPS < 0 {
		add("disk_iops must be 0 (unlimited) or positive, got %d", r.DiskIOPS)
	}
	if r.NetMbps != 0 && r.NetMbps < 10 {
		add("net_mbps must be 0 (unlimited) or at least 10, got %d", r.NetMbps)
	}
	if len(errs) == 0 {
		return nil
	}
	sort.Strings(errs)
	return errors.New("invalid resources:\n  " + strings.Join(errs, "\n  "))
}

// Budget caps what all running VMs may use together. Zero means automatic.
type Budget struct {
	// Memory is the most memory all running VMs may be given (sum of their
	// maximums). Automatic: total RAM minus 6GB.
	Memory Size `toml:"memory"`
	// CPUs is the most host threads all running VMs may use (sum of
	// cpus * cpu_max_percent). Automatic: half the logical processors.
	CPUs float64 `toml:"cpus"`
	// MaxRunning is the most VMs running at once.
	MaxRunning int `toml:"max_running"`
	// Disk is the most space all VM disks may take on the host. Automatic: 200GB.
	Disk Size `toml:"disk"`
}

// Resolve fills automatic values for a host.
func (b Budget) Resolve(totalMemory int64, logicalCPUs int) Budget {
	if b.Memory == 0 {
		b.Memory = Size(max(totalMemory-6<<30, 2<<30))
	}
	if b.CPUs == 0 {
		b.CPUs = float64(logicalCPUs) / 2
	}
	if b.MaxRunning == 0 {
		b.MaxRunning = 3
	}
	if b.Disk == 0 {
		b.Disk = 200 << 30
	}
	return b
}

// Image configures the base image build.
type Image struct {
	// Release is the Ubuntu release codename.
	Release string `toml:"release"`
	// Tools are mise tool specs installed for every VM, e.g. "node@lts".
	Tools []string `toml:"tools"`
	// Packages are extra apt packages.
	Packages []string `toml:"packages"`
	// NpmGlobal are npm packages installed globally, e.g. coding agents.
	NpmGlobal []string `toml:"npm_global"`
	// Disk is the base disk size; project VMs can grow beyond it.
	Disk Size `toml:"disk"`
}

// Global is config.toml.
type Global struct {
	// StorageDir holds base images and VM disks. Empty means the data dir.
	StorageDir string    `toml:"storage_dir"`
	Resources  Resources `toml:"resources"`
	Budget     Budget    `toml:"budget"`
	Image      Image     `toml:"image"`
}

// Defaults are used for anything config.toml doesn't set.
func Defaults() Global {
	return Global{
		Resources: Resources{
			CPUs:          4,
			CPUMaxPercent: 50,
			CPUWeight:     100,
			MemoryStartup: 1 << 30,
			MemoryMin:     512 << 20,
			MemoryMax:     4 << 30,
			Disk:          64 << 30,
			DiskIOPS:      2000,
			NetMbps:       200,
		},
		Image: Image{
			Release:   "noble",
			Tools:     []string{"node@lts", "python@3.12", "uv@latest", "go@latest"},
			Packages:  []string{"git", "curl", "ca-certificates", "build-essential", "pkg-config", "libssl-dev", "unzip", "zip", "jq", "ripgrep", "fd-find", "tmux", "htop"},
			NpmGlobal: []string{"@anthropic-ai/claude-code", "@openai/codex"},
			Disk:      64 << 30,
		},
	}
}

// GlobalPath is where config.toml lives.
func GlobalPath() string { return filepath.Join(paths.DataDir(), "config.toml") }

// LoadGlobal reads config.toml over the defaults.
func LoadGlobal() (Global, error) {
	g := Defaults()
	b, err := os.ReadFile(GlobalPath())
	if errors.Is(err, fs.ErrNotExist) {
		return g, nil
	}
	if err != nil {
		return g, err
	}
	md, err := toml.Decode(string(b), &g)
	if err != nil {
		return g, fmt.Errorf("%s: %w", GlobalPath(), err)
	}
	if un := md.Undecoded(); len(un) > 0 {
		return g, fmt.Errorf("%s: unknown settings: %v", GlobalPath(), un)
	}
	return g, nil
}

// Storage returns the directory for images and VM disks.
func (g Global) Storage() string {
	if g.StorageDir != "" {
		return g.StorageDir
	}
	return paths.DataDir()
}

// Project is .windevvm.toml.
type Project struct {
	Resources Resources `toml:"resources"`
	Network   struct {
		Tier  string   `toml:"tier"`
		Allow []string `toml:"allow"`
	} `toml:"network"`
	Secrets struct {
		Use []string `toml:"use"`
	} `toml:"secrets"`
}

// LoadProject reads dir/.windevvm.toml if it exists.
func LoadProject(dir string) (Project, error) {
	var p Project
	path := filepath.Join(dir, ProjectFile)
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return p, nil
	}
	if err != nil {
		return p, err
	}
	md, err := toml.Decode(string(b), &p)
	if err != nil {
		return p, fmt.Errorf("%s: %w", path, err)
	}
	if un := md.Undecoded(); len(un) > 0 {
		return p, fmt.Errorf("%s: unknown settings: %v", path, un)
	}
	return p, nil
}

// FindProjectRoot walks up from dir to the nearest folder containing
// .windevvm.toml or .git, falling back to dir itself.
func FindProjectRoot(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	for d := abs; ; {
		for _, marker := range []string{ProjectFile, ".git"} {
			if _, err := os.Stat(filepath.Join(d, marker)); err == nil {
				return d, nil
			}
		}
		parent := filepath.Dir(d)
		if parent == d {
			return abs, nil
		}
		d = parent
	}
}
