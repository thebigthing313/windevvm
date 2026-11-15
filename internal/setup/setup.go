// Package setup performs the one-time, elevated host configuration: the
// windevvm virtual switch, its host address, and firewall rules that keep
// VMs away from everything on the host except the proxy ports.
package setup

import (
	"context"

	"windevvm/internal/hyperv"
)

// Params configure setup.
type Params struct {
	User       string // DOMAIN\user to add to Hyper-V Administrators
	Switch     string
	HostIP     string
	PrefixLen  int
	Subnet     string // e.g. 10.77.0.0/24
	ProxyPorts string // e.g. 18000-18250
	// BlockedTCP are the TCP port ranges blocked from VMs (everything but ProxyPorts).
	BlockedTCP []string
}

// Result reports what setup changed.
type Result struct {
	Steps        []string
	AddedToGroup bool
}

const script = `
$steps = New-Object System.Collections.Generic.List[string]
$added = $false

$feature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All
if ($feature.State -ne 'Enabled') {
  throw "Hyper-V is not enabled. Enable it with: Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All (then reboot)"
}

# Hyper-V Administrators, by well-known SID so it works on any display language.
$group = Get-LocalGroup -SID 'S-1-5-32-578'
$member = Get-LocalGroupMember -Group $group | Where-Object { $_.Name -eq $a.User }
if (-not $member) {
  Add-LocalGroupMember -Group $group -Member $a.User
  $steps.Add("Added $($a.User) to $($group.Name) (sign out and back in for it to take effect)")
  $added = $true
}

foreach ($nat in @(Get-NetNat -ErrorAction SilentlyContinue)) {
  if ($nat.InternalIPInterfaceAddressPrefix -eq $a.Subnet) {
    throw "A NAT ($($nat.Name)) already covers $($a.Subnet); windevvm VMs must not have a route out. Remove it with Remove-NetNat."
  }
}

if (-not (Get-VMSwitch -Name $a.Switch -ErrorAction SilentlyContinue)) {
  New-VMSwitch -Name $a.Switch -SwitchType Internal | Out-Null
  $steps.Add("Created internal virtual switch '$($a.Switch)'")
}
$alias = "vEthernet ($($a.Switch))"
$adapter = $null
for ($i = 0; $i -lt 20 -and -not $adapter; $i++) {
  $adapter = Get-NetAdapter -Name $alias -ErrorAction SilentlyContinue
  if (-not $adapter) { Start-Sleep -Milliseconds 500 }
}
if (-not $adapter) { throw "The host adapter '$alias' did not appear" }

$existing = @(Get-NetIPAddress -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction SilentlyContinue)
if (-not ($existing | Where-Object { $_.IPAddress -eq $a.HostIP -and $_.PrefixLength -eq $a.PrefixLen })) {
  $existing | Remove-NetIPAddress -Confirm:$false
  New-NetIPAddress -InterfaceAlias $alias -IPAddress $a.HostIP -PrefixLength $a.PrefixLen | Out-Null
  $steps.Add("Gave the host $($a.HostIP)/$($a.PrefixLen) on '$alias'")
}
# No IPv6 on this interface, so VMs can't reach the host over link-local IPv6.
if ((Get-NetAdapterBinding -Name $alias -ComponentID ms_tcpip6).Enabled) {
  Disable-NetAdapterBinding -Name $alias -ComponentID ms_tcpip6
  $steps.Add("Disabled IPv6 on '$alias'")
}
Set-NetIPInterface -InterfaceAlias $alias -AddressFamily IPv4 -Forwarding Disabled
try { Set-NetConnectionProfile -InterfaceAlias $alias -NetworkCategory Public -ErrorAction Stop } catch { }

# Firewall: VMs may reach only the proxy ports on the host.
Get-NetFirewallRule -Group 'windevvm' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
$common = @{ Group = 'windevvm'; Direction = 'Inbound'; InterfaceAlias = $alias; Profile = 'Any' }
New-NetFirewallRule @common -DisplayName 'windevvm: allow VM proxy ports' -Action Allow -Protocol TCP -LocalAddress $a.HostIP -LocalPort $a.ProxyPorts | Out-Null
New-NetFirewallRule @common -DisplayName 'windevvm: block other TCP from VMs' -Action Block -Protocol TCP -LocalPort $a.BlockedTCP | Out-Null
New-NetFirewallRule @common -DisplayName 'windevvm: block UDP from VMs' -Action Block -Protocol UDP | Out-Null
New-NetFirewallRule @common -DisplayName 'windevvm: block ICMPv4 from VMs' -Action Block -Protocol ICMPv4 | Out-Null
New-NetFirewallRule @common -DisplayName 'windevvm: block ICMPv6 from VMs' -Action Block -Protocol ICMPv6 | Out-Null
$steps.Add("Firewall: VMs may reach only TCP $($a.ProxyPorts) on $($a.HostIP)")

ConvertTo-Json -InputObject @{ Steps = @($steps); AddedToGroup = $added } -Compress -Depth 3
`

// Run applies the host configuration. It must run elevated. Every step is
// idempotent, so it is safe to run again.
func Run(ctx context.Context, r *hyperv.Runner, p Params) (Result, error) {
	var res Result
	err := r.Run(ctx, script, p, &res)
	return res, err
}
