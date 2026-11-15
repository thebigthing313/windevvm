// Package vm creates, starts, stops and removes project VMs, applying their
// resource caps and enforcing the host-wide budget.
package vm

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Network layout of the windevvm switch. VMs get static addresses and no
// gateway, so the host (HostIP) is the only machine they can reach.
const (
	Switch    = "windevvm"
	HostIP    = "10.77.0.1"
	PrefixLen = 24
	firstHost = 10
	lastHost  = 250
)

// Record is what windevvm remembers about a project VM.
type Record struct {
	Name        string    `json:"name"`
	Project     string    `json:"project"`
	IP          string    `json:"ip"`
	MAC         string    `json:"mac"`
	InstanceID  string    `json:"instance_id"`
	HostKey     string    `json:"host_key"`
	Base        string    `json:"base"`
	Created     time.Time `json:"created"`
	Provisioned bool      `json:"provisioned"`
}

// NameFor derives a stable VM name from a project path: wdvm-<folder>-<hash>.
func NameFor(project string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(filepath.Clean(project))))
	return "wdvm-" + slug(filepath.Base(project)) + "-" + hex.EncodeToString(sum[:])[:6]
}

func slug(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(s) {
		ok := r >= 'a' && r <= 'z' || r >= '0' && r <= '9'
		if ok {
			b.WriteRune(r)
			dash = false
		} else if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
		if b.Len() >= 20 {
			break
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		out = "project"
	}
	return out
}

// macFor derives a locally administered MAC from the VM's address.
func macFor(ip netip.Addr) string {
	b := ip.As4()
	return fmt.Sprintf("0277%02X%02X%02X%02X", b[0], b[1], b[2], b[3])
}

// Store keeps one directory per VM under Root, holding vm.json, its disk,
// seed ISOs and Hyper-V configuration.
type Store struct {
	Root string
}

// Dir is a VM's directory.
func (s *Store) Dir(name string) string { return filepath.Join(s.Root, name) }

func (s *Store) recordPath(name string) string { return filepath.Join(s.Dir(name), "vm.json") }

// Load reads a VM's record.
func (s *Store) Load(name string) (*Record, error) {
	b, err := os.ReadFile(s.recordPath(name))
	if err != nil {
		return nil, err
	}
	var r Record
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("%s: %w", s.recordPath(name), err)
	}
	return &r, nil
}

// Save writes a VM's record.
func (s *Store) Save(r *Record) error {
	if err := os.MkdirAll(s.Dir(r.Name), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.recordPath(r.Name) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.recordPath(r.Name))
}

// All returns every VM record, sorted by name.
func (s *Store) All() ([]*Record, error) {
	entries, err := os.ReadDir(s.Root)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []*Record
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		r, err := s.Load(e.Name())
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// FindByProject returns the VM for a project folder, if any.
func (s *Store) FindByProject(project string) (*Record, error) {
	r, err := s.Load(NameFor(project))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return r, err
}

// AllocateIP returns the lowest free address on the windevvm switch.
func (s *Store) AllocateIP() (netip.Addr, error) {
	all, err := s.All()
	if err != nil {
		return netip.Addr{}, err
	}
	used := map[string]bool{}
	for _, r := range all {
		used[r.IP] = true
	}
	base := netip.MustParseAddr(HostIP).As4()
	for n := firstHost; n <= lastHost; n++ {
		base[3] = byte(n)
		ip := netip.AddrFrom4(base)
		if !used[ip.String()] {
			return ip, nil
		}
	}
	return netip.Addr{}, errors.New("no free addresses left on the windevvm switch; remove unused VMs with: windevvm rm NAME")
}

// DiskUsage returns the bytes used by all VM directories.
func (s *Store) DiskUsage() (int64, error) {
	var total int64
	err := filepath.WalkDir(s.Root, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if !d.IsDir() {
			if info, err := d.Info(); err == nil {
				total += info.Size()
			}
		}
		return nil
	})
	return total, err
}
