package hyperv

import (
	"context"
	"time"
)

// DefaultSwitch is Hyper-V's built-in NAT switch, used only for building the
// base image (a trusted step that needs the internet).
const DefaultSwitch = "Default Switch"

// Client wraps the Hyper-V operations windevvm needs.
type Client struct {
	R Runner
}

// VMInfo is a VM's live state and configured caps.
type VMInfo struct {
	Name             string
	State            string
	CPUUsage         int
	MemoryAssigned   int64
	MemoryDemand     int64
	MemoryStartup    int64
	MemoryMaximum    int64
	DynamicMemory    bool
	ProcessorCount   int
	ProcessorMaximum int
	UptimeSeconds    int64
}

// Running reports whether the VM is using host resources.
func (v VMInfo) Running() bool {
	switch v.State {
	case "Off", "Saved", "OffCritical", "SavedCritical":
		return false
	}
	return true
}

// MemoryCap is the most memory the VM can be given.
func (v VMInfo) MemoryCap() int64 {
	if v.DynamicMemory {
		return v.MemoryMaximum
	}
	return v.MemoryStartup
}

// CPUThreads is how many host threads' worth of CPU the VM may use.
func (v VMInfo) CPUThreads() float64 {
	return float64(v.ProcessorCount) * float64(v.ProcessorMaximum) / 100
}

// ListVMs returns VMs whose names start with prefix.
func (c *Client) ListVMs(ctx context.Context, prefix string) ([]VMInfo, error) {
	var out []VMInfo
	err := c.R.Run(ctx, `
$r = @(Get-VM | Where-Object { $_.Name.StartsWith($a.Prefix) } | ForEach-Object {
  $p = Get-VMProcessor -VM $_
  $m = Get-VMMemory -VM $_
  [pscustomobject]@{
    Name = $_.Name; State = $_.State.ToString(); CPUUsage = [int]$_.CPUUsage
    MemoryAssigned = [int64]$_.MemoryAssigned; MemoryDemand = [int64]$_.MemoryDemand
    MemoryStartup = [int64]$m.Startup; MemoryMaximum = [int64]$m.Maximum; DynamicMemory = [bool]$m.DynamicMemoryEnabled
    ProcessorCount = [int]$p.Count; ProcessorMaximum = [int]$p.Maximum
    UptimeSeconds = [int64]$_.Uptime.TotalSeconds
  }
})
ConvertTo-Json -InputObject $r -Compress -Depth 3
`, map[string]string{"Prefix": prefix}, &out)
	return out, err
}

// GetVM returns one VM, or ok=false if it doesn't exist.
func (c *Client) GetVM(ctx context.Context, name string) (VMInfo, bool, error) {
	vms, err := c.ListVMs(ctx, name)
	if err != nil {
		return VMInfo{}, false, err
	}
	for _, v := range vms {
		if v.Name == name {
			return v, true, nil
		}
	}
	return VMInfo{}, false, nil
}

// SwitchExists reports whether a virtual switch exists.
func (c *Client) SwitchExists(ctx context.Context, name string) (bool, error) {
	var out bool
	err := c.R.Run(ctx, `ConvertTo-Json -InputObject ([bool](Get-VMSwitch -Name $a.Name -ErrorAction SilentlyContinue))`, map[string]string{"Name": name}, &out)
	return out, err
}

// CreateSpec describes a new VM.
type CreateSpec struct {
	Name string
	// Dir is where Hyper-V keeps the VM's configuration.
	Dir string
	// Disk is the VM's disk. If Parent is set, Disk is created as a
	// differencing disk of Parent; otherwise Disk must already exist.
	Disk      string
	Parent    string
	DiskBytes int64 // grow the disk to this size if larger; 0 to leave it
	SeedISO   string
	Switch    string
	MAC       string // static MAC, e.g. 02770A4D0010; empty for dynamic
	ComPipe   string // named pipe for COM1, e.g. \\.\pipe\wdvm-x
	Memory    int64  // startup memory
}

// CreateVM creates a Generation 2 VM with Secure Boot for Linux, no
// automatic checkpoints, the seed ISO attached and the disk first in boot order.
func (c *Client) CreateVM(ctx context.Context, s CreateSpec) error {
	return c.R.Run(ctx, `
if ($a.Parent) { New-VHD -Path $a.Disk -ParentPath $a.Parent -Differencing | Out-Null }
if ($a.DiskBytes -gt 0 -and (Get-VHD -Path $a.Disk).Size -lt $a.DiskBytes) { Resize-VHD -Path $a.Disk -SizeBytes $a.DiskBytes }
$vm = New-VM -Name $a.Name -Generation 2 -MemoryStartupBytes $a.Memory -VHDPath $a.Disk -SwitchName $a.Switch -Path $a.Dir
try {
  Set-VM -VM $vm -AutomaticCheckpointsEnabled $false -AutomaticStartAction Nothing -AutomaticStopAction ShutDown
  Set-VMFirmware -VM $vm -EnableSecureBoot On -SecureBootTemplate MicrosoftUEFICertificateAuthority
  if ($a.SeedISO) { Add-VMDvdDrive -VM $vm -Path $a.SeedISO }
  Set-VMFirmware -VM $vm -FirstBootDevice (Get-VMHardDiskDrive -VM $vm)
  if ($a.MAC) { Set-VMNetworkAdapter -VM $vm -StaticMacAddress $a.MAC }
  if ($a.ComPipe) { Set-VMComPort -VM $vm -Number 1 -Path $a.ComPipe }
} catch {
  Remove-VM -VM $vm -Force
  throw
}
`, s, nil)
}

// Caps are the Hyper-V resource limits for one VM.
type Caps struct {
	CPUs          int
	CPUMaxPercent int
	CPUWeight     int
	MemoryStartup int64
	MemoryMin     int64
	MemoryMax     int64
	DiskIOPS      int
	NetBitsPerSec int64
	DiskBytes     int64
}

// ApplyCaps sets a VM's resource limits. vCPU count, memory sizes and disk
// growth only change while the VM is off; the rest applies immediately.
// It reports whether some caps were deferred because the VM is running.
func (c *Client) ApplyCaps(ctx context.Context, name string, caps Caps) (deferred bool, err error) {
	var out struct{ Deferred bool }
	err = c.R.Run(ctx, `
$vm = Get-VM -Name $a.Name
$deferred = $false
if ($vm.State -eq 'Off') {
  Set-VMProcessor -VM $vm -Count $a.Caps.CPUs
  Set-VMMemory -VM $vm -DynamicMemoryEnabled $true -MinimumBytes $a.Caps.MemoryMin -StartupBytes $a.Caps.MemoryStartup -MaximumBytes $a.Caps.MemoryMax
  $disk = (Get-VMHardDiskDrive -VM $vm | Select-Object -First 1).Path
  if ($a.Caps.DiskBytes -gt 0 -and (Get-VHD -Path $disk).Size -lt $a.Caps.DiskBytes) { Resize-VHD -Path $disk -SizeBytes $a.Caps.DiskBytes }
} else {
  $p = Get-VMProcessor -VM $vm; $m = Get-VMMemory -VM $vm
  $deferred = ($p.Count -ne $a.Caps.CPUs) -or ($m.Maximum -ne $a.Caps.MemoryMax) -or ($m.Minimum -ne $a.Caps.MemoryMin) -or ($m.Startup -ne $a.Caps.MemoryStartup)
}
Set-VMProcessor -VM $vm -Maximum $a.Caps.CPUMaxPercent -RelativeWeight $a.Caps.CPUWeight
Get-VMHardDiskDrive -VM $vm | Set-VMHardDiskDrive -MaximumIOPS $a.Caps.DiskIOPS
Get-VMNetworkAdapter -VM $vm | Set-VMNetworkAdapter -MaximumBandwidth $a.Caps.NetBitsPerSec
ConvertTo-Json -InputObject @{ Deferred = $deferred } -Compress
`, map[string]any{"Name": name, "Caps": caps}, &out)
	return out.Deferred, err
}

// Start starts a VM.
func (c *Client) Start(ctx context.Context, name string) error {
	return c.R.Run(ctx, `Start-VM -Name $a.Name`, map[string]string{"Name": name}, nil)
}

// Stop shuts a VM down through the guest, turning it off if that doesn't
// finish within timeout.
func (c *Client) Stop(ctx context.Context, name string, timeout time.Duration) error {
	sctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	err := c.R.Run(sctx, `Stop-VM -Name $a.Name -Force`, map[string]string{"Name": name}, nil)
	if err == nil {
		return nil
	}
	return c.TurnOff(ctx, name)
}

// TurnOff powers a VM off immediately.
func (c *Client) TurnOff(ctx context.Context, name string) error {
	return c.R.Run(ctx, `
$vm = Get-VM -Name $a.Name
if ($vm.State -ne 'Off') { Stop-VM -VM $vm -TurnOff -Force }
`, map[string]string{"Name": name}, nil)
}

// SetDVD swaps the ISO in a VM's DVD drive (empty path ejects it).
func (c *Client) SetDVD(ctx context.Context, name, iso string) error {
	return c.R.Run(ctx, `
$d = Get-VMDvdDrive -VMName $a.Name | Select-Object -First 1
if ($a.ISO) { Set-VMDvdDrive -VMDvdDrive $d -Path $a.ISO } else { Set-VMDvdDrive -VMDvdDrive $d -Path $null }
`, map[string]string{"Name": name, "ISO": iso}, nil)
}

// Remove turns a VM off and deletes it from Hyper-V. Its disk files stay.
func (c *Client) Remove(ctx context.Context, name string) error {
	return c.R.Run(ctx, `
$vm = Get-VM -Name $a.Name -ErrorAction SilentlyContinue
if ($vm) {
  if ($vm.State -ne 'Off') { Stop-VM -VM $vm -TurnOff -Force }
  Remove-VM -VM $vm -Force
}
`, map[string]string{"Name": name}, nil)
}

// ConvertToDynamicVHDX converts a VHD into a dynamically expanding VHDX.
func (c *Client) ConvertToDynamicVHDX(ctx context.Context, src, dst string) error {
	return c.R.Run(ctx, `Convert-VHD -Path $a.Src -DestinationPath $a.Dst -VHDType Dynamic`, map[string]string{"Src": src, "Dst": dst}, nil)
}

// ResizeVHD grows a virtual disk.
func (c *Client) ResizeVHD(ctx context.Context, path string, size int64) error {
	return c.R.Run(ctx, `Resize-VHD -Path $a.Path -SizeBytes $a.Size`, map[string]any{"Path": path, "Size": size}, nil)
}

// OptimizeVHD compacts a dynamic VHDX after the guest trimmed free space.
func (c *Client) OptimizeVHD(ctx context.Context, path string) error {
	return c.R.Run(ctx, `Optimize-VHD -Path $a.Path -Mode Full`, map[string]string{"Path": path}, nil)
}
