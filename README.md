# windevvm

windevvm gives each dev project its own isolated Hyper-V Linux VM on Windows 11 Pro, similar to [devvm](https://github.com/devvmhq/devvm) on macOS and Linux. The design is in [DESIGN.md](DESIGN.md).

## Status

| Milestone | State |
|---|---|
| 1. Egress proxy: policy, local CA, secret injection | done |
| 2. Hyper-V lifecycle: base image, per-project VMs, resource caps, host budget | done |
| 3. Lockdown: proxy wired to VMs, port ACLs, `doctor` | done |
| 4. Workflow: clone mode, toolchain detection, ports, VS Code, idle stop | planned |

VMs have no route to the internet and no DNS. Their only way out is the proxy the windevvm daemon runs for each VM on the host, which enforces the network policy and injects secrets.

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

## Network

Every VM gets its own proxy at `10.77.0.1:<18000 + last octet of its IP>`, run by a background daemon that `windevvm up` starts on demand (`windevvm daemon status|stop|restart`). On each `up`, windevvm pushes into the VM over SSH: the local CA certificate, `HTTP(S)_PROXY`/`NO_PROXY`, `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, apt, git and npm proxy settings, and one placeholder env var per secret in use. A Hyper-V port ACL lets each VM send only from its own address.

```powershell
windevvm network                     # tier, rules by source, always-allowed hosts, secrets in use
windevvm network internet            # tiers: none | allowlist (default) | internet; "reset" clears the override
windevvm network allow api.stripe.com    # this VM; add --global for every VM
windevvm network deny '*.example.com'
windevvm network rm api.stripe.com
windevvm network log -f --blocked    # recent proxy decisions; blocks print the rule that would allow them
windevvm doctor                      # checks the lockdown from inside the VM
```

Rules come from three places, and denies always win:

- the global policy `%LOCALAPPDATA%\windevvm\policy`, created with the presets `@apt @npm @pypi @github @mise @go @crates`
- `[network] allow` in `.windevvm.toml`
- the VM's own policy file, edited by `windevvm network allow|deny|rm`

The coding agents' hosts (Anthropic, OpenAI) and the hosts of the secrets in use are allowed on every tier. Policy changes apply immediately, without restarting the VM.

## Secrets

```powershell
windevvm secret set GITHUB_TOKEN --preset github   # stored DPAPI-encrypted on the host
windevvm secret use GITHUB_TOKEN                    # this project's VM sees $GITHUB_TOKEN=wdvm_ph_...
windevvm secret unuse GITHUB_TOKEN
```

`[secrets] use = ["GITHUB_TOKEN"]` in `.windevvm.toml` does the same as `secret use`. Inside the VM the variable holds a placeholder unique to that VM. The proxy swaps in the real value only in HTTPS requests to the secret's hosts, and blocks the request if the placeholder is headed anywhere else it can see (an intercepted host, or plain HTTP). For GitHub, GitLab, Bitbucket and Codeberg, git is set up to send the placeholder as its HTTPS password. Shells that were open before `secret use` keep their old environment.
