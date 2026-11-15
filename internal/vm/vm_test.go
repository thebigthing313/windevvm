package vm

import (
	"errors"
	"strings"
	"testing"

	"windevvm/internal/config"
	"windevvm/internal/hyperv"
)

func TestNameFor(t *testing.T) {
	a := NameFor(`F:\code\My App`)
	b := NameFor(`f:\code\my app\`)
	if a != b {
		t.Fatalf("names differ for the same folder: %s vs %s", a, b)
	}
	if !strings.HasPrefix(a, "wdvm-my-app-") || len(a) != len("wdvm-my-app-")+6 {
		t.Fatalf("name = %s", a)
	}
	if NameFor(`F:\code\other`) == a {
		t.Fatal("different folders must get different names")
	}
	if got := slug("!!!"); got != "project" {
		t.Fatalf("slug = %q", got)
	}
}

func TestAllocateIP(t *testing.T) {
	s := &Store{Root: t.TempDir()}
	ip, err := s.AllocateIP()
	if err != nil || ip.String() != "10.77.0.10" {
		t.Fatalf("first IP = %v, %v", ip, err)
	}
	s.Save(&Record{Name: "wdvm-a-000000", IP: "10.77.0.10"})
	s.Save(&Record{Name: "wdvm-b-000000", IP: "10.77.0.12"})
	ip, _ = s.AllocateIP()
	if ip.String() != "10.77.0.11" {
		t.Fatalf("next IP = %v", ip)
	}
	if mac := macFor(ip); mac != "02770A4D000B" {
		t.Fatalf("mac = %s", mac)
	}
}

func TestStoreRoundTrip(t *testing.T) {
	s := &Store{Root: t.TempDir()}
	r := &Record{Name: NameFor(`C:\p`), Project: `C:\p`, IP: "10.77.0.10"}
	if err := s.Save(r); err != nil {
		t.Fatal(err)
	}
	got, err := s.FindByProject(`C:\p`)
	if err != nil || got == nil || got.IP != "10.77.0.10" {
		t.Fatalf("FindByProject = %+v, %v", got, err)
	}
	none, err := s.FindByProject(`C:\other`)
	if err != nil || none != nil {
		t.Fatalf("expected no record, got %+v, %v", none, err)
	}
}

func TestCheckBudget(t *testing.T) {
	b := config.Budget{Memory: 10 << 30, CPUs: 6, MaxRunning: 3}
	res := config.Defaults().Resources // 4GB max, 4 x 50% = 2 CPUs
	running := func(name string, memMax int64, cpus, pct int) hyperv.VMInfo {
		return hyperv.VMInfo{Name: name, State: "Running", DynamicMemory: true, MemoryMaximum: memMax, ProcessorCount: cpus, ProcessorMaximum: pct}
	}

	if err := CheckBudget(b, nil, "wdvm-new", res); err != nil {
		t.Fatalf("empty host: %v", err)
	}
	vms := []hyperv.VMInfo{running("wdvm-a", 4<<30, 4, 50), {Name: "wdvm-off", State: "Off", MemoryMaximum: 64 << 30}}
	if err := CheckBudget(b, vms, "wdvm-new", res); err != nil {
		t.Fatalf("one running VM should fit: %v", err)
	}
	vms = append(vms, running("wdvm-b", 4<<30, 4, 50))
	err := CheckBudget(b, vms, "wdvm-new", res)
	var obe *OverBudgetError
	if !errors.As(err, &obe) {
		t.Fatalf("expected an over-budget error, got %v", err)
	}
	if len(obe.Problems) != 1 || !strings.Contains(obe.Problems[0], "memory") || len(obe.Running) != 2 {
		t.Fatalf("problems = %v, running = %d", obe.Problems, len(obe.Running))
	}
	// A VM already running isn't counted against itself.
	if err := CheckBudget(b, vms, "wdvm-b", res); err != nil {
		t.Fatalf("restarting an existing VM: %v", err)
	}
	res.CPUs, res.CPUMaxPercent = 12, 100
	if err := CheckBudget(b, nil, "wdvm-new", res); err == nil || !strings.Contains(err.Error(), "CPU") {
		t.Fatalf("expected a CPU problem, got %v", err)
	}
}
