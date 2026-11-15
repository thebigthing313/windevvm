# windevvm

windevvm gives each dev project its own isolated Hyper-V Linux VM on Windows 11 Pro, similar to [devvm](https://github.com/devvmhq/devvm) on macOS and Linux. The design is in [DESIGN.md](DESIGN.md).

## Status

| Milestone | State |
|---|---|
| 1. Egress proxy: policy, local CA, secret injection | done |
| 2. Hyper-V lifecycle: base image, per-project VMs, resource caps, host budget | done |
| 3. Lockdown: proxy wired to VMs, port ACLs, `doctor` | next |
| 4. Workflow: clone mode, toolchain detection, ports, VS Code, idle stop | planned |

VMs from milestone 2 have **no network egress at all**. They can only talk to the host, which uses SSH to reach them. Milestone 3 gives them controlled egress through the proxy.

## Build

```powershell
go build -o bin\windevvm.exe .\cmd\windevvm
```

## First-time setup

```powershell
windevvm setup          # asks for administrator rights once: switch, host IP, firewall
windevvm image build    # about 10 minutes: Ubuntu 24.04 + toolchains + Claude Code and Codex
```

## Everyday use

```powershell
cd F:\code\myapp
windevvm                # create or start this project's VM and open a shell
windevvm ls             # VMs, their caps, and the host budget
windevvm stop           # shut down this project's VM
windevvm rm             # delete it
```

## Resource caps

Defaults are in `%LOCALAPPDATA%\windevvm\config.toml`. Override them per project in `.windevvm.toml`:

```toml
[resources]
cpus = 4                 # vCPUs
cpu_max_percent = 50     # ceiling, as a % of those vCPUs
cpu_weight = 100         # priority when the CPU is contended (host processes win)
memory_startup = "1GB"
memory_min = "512MB"
memory_max = "4GB"       # dynamic memory never grows past this
disk = "64GB"
disk_iops = 2000         # 0 = unlimited
net_mbps = 200           # 0 = unlimited
```

The host budget lives in `config.toml` and is checked before any VM starts:

```toml
[budget]
memory = "10GB"   # sum of running VMs' memory_max (default: RAM minus 6GB)
cpus = 6          # sum of cpus x cpu_max_percent (default: half the logical CPUs)
max_running = 3
disk = "200GB"
```
