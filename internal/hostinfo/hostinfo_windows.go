//go:build windows

// Package hostinfo reports the host's size and privileges.
package hostinfo

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

var procGlobalMemoryStatusEx = windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalMemoryStatusEx")

// TotalMemory returns installed physical memory in bytes.
func TotalMemory() int64 {
	var m memoryStatusEx
	m.Length = uint32(unsafe.Sizeof(m))
	r, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&m)))
	if r == 0 {
		return 0
	}
	return int64(m.TotalPhys)
}

// LogicalCPUs returns the number of logical processors.
func LogicalCPUs() int { return runtime.NumCPU() }

// IsElevated reports whether this process runs as an elevated administrator.
func IsElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}
