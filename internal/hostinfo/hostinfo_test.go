//go:build windows

package hostinfo

import "testing"

func TestHostInfo(t *testing.T) {
	if m := TotalMemory(); m < 1<<30 {
		t.Fatalf("TotalMemory = %d", m)
	}
	if LogicalCPUs() < 1 {
		t.Fatal("no CPUs")
	}
	_ = IsElevated()
}
