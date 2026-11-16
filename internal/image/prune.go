package image

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// RecentWindow protects files changed this recently from prune: they may
// belong to a build that is still running.
const RecentWindow = time.Hour

// PruneItem is a file or folder prune would delete.
type PruneItem struct {
	Path string
	Size int64
	What string
}

// KeptImage is a base image prune leaves alone, and why.
type KeptImage struct {
	Path string
	Why  string
}

// PrunePlan is what prune would delete and which base images it keeps.
type PrunePlan struct {
	Delete []PruneItem
	Keep   []KeptImage
}

// Bytes is the space deleting the plan frees.
func (p PrunePlan) Bytes() int64 {
	var n int64
	for _, it := range p.Delete {
		n += it.Size
	}
	return n
}

// PathKey normalizes a Windows path for comparison: cleaned and lower-cased.
func PathKey(p string) string { return strings.ToLower(filepath.Clean(p)) }

// PlanPrune decides what to delete in the image directory dir: base images
// that are neither current nor used by a VM (users maps a base image path to
// the VMs whose disks depend on it), their build logs, leftovers of interrupted
// builds (unless a VM named wdvm-build-<stamp> still exists), and the cloud image download cache. Anything changed within
// RecentWindow of now is kept, so a build in progress isn't disturbed.
func PlanPrune(dir, current string, users map[string][]string, now time.Time) (PrunePlan, error) {
	var plan PrunePlan
	used := map[string][]string{}
	vmNames := map[string]bool{}
	for p, vms := range users {
		used[PathKey(p)] = append(used[PathKey(p)], vms...)
		for _, v := range vms {
			vmNames[strings.ToLower(v)] = true
		}
	}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return plan, nil
	}
	if err != nil {
		return plan, err
	}
	recent := func(info fs.FileInfo) bool { return now.Sub(info.ModTime()) < RecentWindow }
	deletedBase := map[string]bool{} // stamps of base images being deleted

	for _, e := range entries {
		name := e.Name()
		path := filepath.Join(dir, name)
		info, err := e.Info()
		if err != nil {
			return plan, err
		}
		lower := strings.ToLower(name)
		switch {
		case strings.HasPrefix(lower, "base-") && strings.HasSuffix(lower, ".vhdx") && !e.IsDir():
			vms := used[PathKey(path)]
			switch {
			case current != "" && PathKey(path) == PathKey(current):
				plan.Keep = append(plan.Keep, KeptImage{path, "current: new VMs use it"})
			case len(vms) > 0:
				sort.Strings(vms)
				plan.Keep = append(plan.Keep, KeptImage{path, "used by " + strings.Join(vms, ", ")})
			case recent(info):
				plan.Keep = append(plan.Keep, KeptImage{path, "changed in the last hour; a build may be running"})
			default:
				plan.Delete = append(plan.Delete, PruneItem{path, info.Size(), "old base image"})
				deletedBase[strings.TrimSuffix(lower, ".vhdx")] = true
			}
		case strings.HasPrefix(lower, "build-"):
			size, mod, err := treeStat(path)
			if err != nil {
				return plan, err
			}
			if now.Sub(mod) < RecentWindow {
				continue
			}
			stem := strings.SplitN(lower, ".", 2)[0]
			if vmNames["wdvm-"+stem] {
				continue // its build VM is still registered in Hyper-V
			}
			plan.Delete = append(plan.Delete, PruneItem{path, size, "left over from an interrupted build"})
		}
	}
	// Build logs go with their image, or when their build failed (no image).
	for _, e := range entries {
		lower := strings.ToLower(e.Name())
		if e.IsDir() || !strings.HasPrefix(lower, "base-") || !strings.HasSuffix(lower, ".log") {
			continue
		}
		stem := strings.TrimSuffix(lower, ".log")
		info, err := e.Info()
		if err != nil {
			return plan, err
		}
		_, statErr := os.Stat(filepath.Join(dir, strings.TrimSuffix(e.Name(), ".log")+".vhdx"))
		orphan := errors.Is(statErr, fs.ErrNotExist) && !recent(info)
		if deletedBase[stem] || orphan {
			plan.Delete = append(plan.Delete, PruneItem{filepath.Join(dir, e.Name()), info.Size(), "build log"})
		}
	}

	cache := filepath.Join(dir, "cache")
	cached, err := os.ReadDir(cache)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return plan, err
	}
	for _, e := range cached {
		path := filepath.Join(cache, e.Name())
		size, mod, err := treeStat(path)
		if err != nil {
			return plan, err
		}
		if now.Sub(mod) < RecentWindow {
			continue
		}
		plan.Delete = append(plan.Delete, PruneItem{path, size, "cached download; the next build fetches it again"})
	}
	sort.Slice(plan.Delete, func(i, j int) bool { return plan.Delete[i].Path < plan.Delete[j].Path })
	sort.Slice(plan.Keep, func(i, j int) bool { return plan.Keep[i].Path < plan.Keep[j].Path })
	return plan, nil
}

// treeStat returns the total size of the files under path and the newest
// file's modification time (path's own, if it holds no files).
func treeStat(path string) (int64, time.Time, error) {
	var n int64
	var newest time.Time
	err := filepath.WalkDir(path, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			info, err := d.Info()
			if err != nil {
				return err
			}
			n += info.Size()
			if info.ModTime().After(newest) {
				newest = info.ModTime()
			}
		}
		return nil
	})
	if err == nil && newest.IsZero() {
		if info, serr := os.Stat(path); serr == nil {
			newest = info.ModTime()
		}
	}
	return n, newest, err
}

// Prune deletes the plan's items, carrying on past failures (a disk Hyper-V
// still has open, say) and returning them together.
func Prune(plan PrunePlan) error {
	var errs []error
	for _, it := range plan.Delete {
		// Base images are read-only, which stops Windows deleting them. If
		// the delete fails (Hyper-V has the file open), they go back to
		// read-only: differencing children need their parent unchanged.
		var readOnly []string
		filepath.WalkDir(it.Path, func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				if info, err := d.Info(); err == nil && info.Mode().Perm()&0o200 == 0 {
					readOnly = append(readOnly, p)
					os.Chmod(p, 0o644)
				}
			}
			return nil
		})
		if err := os.RemoveAll(it.Path); err != nil {
			for _, p := range readOnly {
				os.Chmod(p, 0o444)
			}
			errs = append(errs, fmt.Errorf("%s: %w", it.Path, err))
		}
	}
	return errors.Join(errs...)
}
