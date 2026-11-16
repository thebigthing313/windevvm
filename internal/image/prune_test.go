package image

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func touch(t *testing.T, path string, size int, mod time.Time) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, make([]byte, size), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, mod, mod); err != nil {
		t.Fatal(err)
	}
}

func names(dir string, items []PruneItem) []string {
	var out []string
	for _, it := range items {
		rel, _ := filepath.Rel(dir, it.Path)
		out = append(out, filepath.ToSlash(rel))
	}
	sort.Strings(out)
	return out
}

func TestPlanPrune(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	old := now.Add(-48 * time.Hour)
	touch(t, filepath.Join(dir, "base-1.vhdx"), 100, old) // old, unused: delete
	touch(t, filepath.Join(dir, "base-1.log"), 1, old)    // goes with it
	touch(t, filepath.Join(dir, "base-2.vhdx"), 100, old) // used by a VM
	touch(t, filepath.Join(dir, "base-2.log"), 1, old)
	touch(t, filepath.Join(dir, "base-3.vhdx"), 100, old) // current
	touch(t, filepath.Join(dir, "base-4.vhdx"), 100, now) // being built
	touch(t, filepath.Join(dir, "base-4.log"), 1, now)
	touch(t, filepath.Join(dir, "base-5.log"), 1, old) // failed build, no image
	touch(t, filepath.Join(dir, "build-9.vhd"), 10, old)
	touch(t, filepath.Join(dir, "build-9", "vm.vmcx"), 10, old)
	touch(t, filepath.Join(dir, "build-10.iso"), 10, now) // build in progress
	touch(t, filepath.Join(dir, "current.json"), 10, old)
	touch(t, filepath.Join(dir, "cache", "noble.img"), 50, old)
	touch(t, filepath.Join(dir, "cache", "SHA256SUMS"), 5, old)
	touch(t, filepath.Join(dir, "cache", "noble.img.part"), 5, now) // download in progress

	// Paths in records may differ in case and form from the directory listing.
	users := map[string][]string{strings.ToUpper(filepath.Join(dir, ".", "base-2.vhdx")): {"wdvm-b", "wdvm-a"}}
	plan, err := PlanPrune(dir, filepath.Join(dir, "base-3.vhdx"), users, now)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(names(dir, plan.Delete), " ")
	want := "base-1.log base-1.vhdx base-5.log build-9 build-9.vhd cache/SHA256SUMS cache/noble.img"
	if got != want {
		t.Fatalf("delete:\n got %s\nwant %s", got, want)
	}
	if plan.Bytes() != 100+1+1+10+10+50+5 {
		t.Fatalf("bytes = %d", plan.Bytes())
	}
	keep := map[string]string{}
	for _, k := range plan.Keep {
		keep[filepath.Base(k.Path)] = k.Why
	}
	if !strings.Contains(keep["base-2.vhdx"], "wdvm-a, wdvm-b") || !strings.Contains(keep["base-3.vhdx"], "current") || keep["base-4.vhdx"] == "" {
		t.Fatalf("keep = %v", keep)
	}

	// Prune deletes exactly the plan, read-only images included.
	os.Chmod(filepath.Join(dir, "base-1.vhdx"), 0o444)
	if err := Prune(plan); err != nil {
		t.Fatal(err)
	}
	for _, it := range plan.Delete {
		if _, err := os.Stat(it.Path); !os.IsNotExist(err) {
			t.Errorf("%s still exists", it.Path)
		}
	}
	for _, p := range []string{"base-2.vhdx", "base-2.log", "base-3.vhdx", "base-4.vhdx", "base-4.log", "build-10.iso", "current.json", "cache/noble.img.part"} {
		if _, err := os.Stat(filepath.Join(dir, p)); err != nil {
			t.Errorf("%s was deleted: %v", p, err)
		}
	}
}

func TestPlanPruneMissingDir(t *testing.T) {
	plan, err := PlanPrune(filepath.Join(t.TempDir(), "nope"), "", nil, time.Now())
	if err != nil || len(plan.Delete) != 0 {
		t.Fatalf("plan %+v, err %v", plan, err)
	}
}

func TestPlanPruneKeepsRegisteredBuildVM(t *testing.T) {
	dir := t.TempDir()
	old := time.Now().Add(-48 * time.Hour)
	touch(t, filepath.Join(dir, "build-9.iso"), 10, old)
	touch(t, filepath.Join(dir, "build-9", "vm.vmcx"), 10, old)
	touch(t, filepath.Join(dir, "build-8.iso"), 10, old)
	touch(t, filepath.Join(dir, "base-9.vhdx"), 10, old)
	// Hyper-V still has the build VM, with the base image attached directly.
	users := map[string][]string{filepath.Join(dir, "base-9.vhdx"): {"wdvm-build-9"}}
	plan, err := PlanPrune(dir, "", users, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(names(dir, plan.Delete), " "); got != "build-8.iso" {
		t.Fatalf("delete = %s", got)
	}
}

func TestPruneRestoresReadOnlyOnFailure(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "base-1.vhdx")
	touch(t, p, 10, time.Now())
	os.Chmod(p, 0o444)
	f, err := os.Open(p) // on Windows an open file can't be deleted
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := Prune(PrunePlan{Delete: []PruneItem{{Path: p}}}); err == nil {
		t.Skip("this platform deleted an open file")
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o200 != 0 {
		t.Fatal("a base image that couldn't be deleted was left writable")
	}
	os.Chmod(p, 0o644)
}
