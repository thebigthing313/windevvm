# windevvm: design

windevvm is a devvm-style sandbox for Windows 11 Pro. Each project folder gets its own Hyper-V Linux VM. Network access goes through a proxy on the host, which enforces the policy and injects secrets. Resource caps keep the host from being starved.

```
cd F:\code\myapp
windevvm            # creates the VM if needed, starts it and opens a shell; the prompt shows (windevvm)
```

## Goals

1. **Isolation.** Untrusted code and coding agents run in a real VM, never on the host.
2. **Secrets never enter the VM.** The VM sees only placeholders. The host proxy swaps in real values on the way out, and only for hosts each secret is bound to.
3. **The host never starves.** Each VM has caps, and a global budget is checked before any VM starts.
4. **Reusable.** One `windevvm.exe` works for every project, and each project only needs an optional `.windevvm.toml`.

## Components

| Component | Responsibility |
|---|---|
| `windevvm.exe` (Go, one binary) | The CLI. It also runs as a background **daemon** (`windevvm daemon`), which the CLI starts automatically. |
| daemon: proxy | One listener per VM on `10.77.0.1:<18000+n>`. It enforces the network policy, intercepts TLS for hosts that have secrets bound, injects secrets and logs requests. |
| daemon: supervisor | Stops idle VMs and forwards localhost ports into VMs (over SSH, so loopback-only servers work too). `windevvm top` reads Hyper-V and its performance counters directly. |
| `internal/hyperv` | The only package that touches Hyper-V. It shells out to `powershell.exe` with the Hyper-V module, and every command it builds is in this one place. |
| `internal/seed` | Builds the cloud-init NoCloud seed ISO (label `cidata`) in pure Go, so no ADK or oscdimg is needed. |

## VM lifecycle

- **Base image:** the Ubuntu 24.04 Azure cloud VHD, which already has Hyper-V drivers and cloud-init, converted to VHDX and run as a Gen 2 VM with Secure Boot set to the `MicrosoftUEFICertificateAuthority` template. `windevvm image build` boots it once and installs git, build-essential, mise with common Node, Python, Go and Rust versions, Claude Code and Codex. It then shuts the VM down, and the VHDX becomes read-only. Rebuilds are versioned (`base-<date>.vhdx`). A rebuild never touches existing VMs: their differencing disks keep pointing at the image they were created from, and moving one means recreating it (`pull` first). `windevvm image prune` deletes images that are neither current nor a parent of any VM disk. It takes the parents from the VM records and from Hyper-V (`Get-VHD` along each `wdvm-*` disk chain), so a VM whose record was lost still protects its image. It also removes interrupted-build leftovers and the cloud-image download cache, and skips anything changed in the last hour.
- **Per-project VM:** a differencing VHDX on top of the base, which makes creation take seconds, plus a seed ISO with hostname, static IP and SSH keys. The proxy environment, CA cert and secret placeholders are pushed over SSH on every `up`, so existing VMs pick up changes without being recreated. The VM name is `wdvm-<project>-<hash(path)[:6]>`.
- **Access:** SSH from the host to the VM's IP on the internal switch, using an ed25519 key per install. An `~/.ssh/config` include is generated, so VS Code Remote-SSH works with `windevvm code`.
- **Project files:** clone mode is the default. The VM gets its own clone, pushed in over SSH, and `windevvm pull` brings branches back as `windevvm/<branch>`. Nothing in the VM can touch the host's working tree or `.git`. A live-sync mode using Mutagen is planned as an option.
- **Toolchain detection:** `package.json` maps to node, `pyproject.toml`/`requirements.txt` to python, `go.mod` to go, `Cargo.toml` to rust and `.tool-versions`/`mise.toml` to exactly what they list. `mise install` runs on first entry.

## Network isolation

- **Internal vSwitch `windevvm`** with **no NAT**. The host vNIC is `10.77.0.1/24`, and each VM gets a static IP from `10.77.0.10` to `.250` (there's no DHCP). Windows doesn't route between interfaces, so a VM can reach only the host.
- **Windows Firewall:** the vNIC is set to the Public profile. Inbound traffic from `10.77.0.0/24` is allowed only to TCP `18000-18250` (the proxy ports). Everything else from that subnet is blocked, so host services such as SMB, RDP and local dev servers can't be reached.
- **Anti-spoofing:** a Hyper-V port ACL on each VM's NIC (`Add-VMNetworkAdapterAcl`: outbound allow from its /32, deny `0.0.0.0/0` and `::/0`; the most specific rule wins) allows only its assigned IP, and DHCP guard, router guard and MAC spoofing protection are on. `windevvm doctor` checks this by adding a spare address inside the VM and confirming its packets never arrive. The proxy also checks that the source IP matches the VM that owns the port it was reached on. One VM can't pose as another to get its secrets or policy.
- **No DNS in the VM.** Names are resolved by the proxy. `HTTP(S)_PROXY`, apt, git, npm and pip are configured to use it. A tool that ignores the proxy simply fails, which is the safe failure.
- **Tiers:** `none` allows only bound secret hosts plus agent hosts, `allowlist` is the default, and `internet` allows any public host but never private or loopback ranges. There's no `open` tier in v1. Rules use devvm's format: `example.com`, `*.example.com`, `host:port`, and `!host` to deny (denies win). They live in a global policy, a per-project policy and named presets written `@name` (`apt`, `npm`, `pypi`, `github`, `mise`, `go`, `crates` and `vscode` are in the default global policy; `ruby`, `maven`, `gradle` and `docker` are opt-in). `windevvm network presets` lists their hosts.
- A blocked request gets a `403` naming the host and the rule that would allow it. Most HTTPS clients hide that body, because the 403 answers the CONNECT. So each per-VM proxy also keeps its last 200 blocks in memory and serves them as a text page, both at `http://windevvm.internal/why` (through the proxy) and at `/why` on the proxy port. The guest script installs `/usr/local/bin/windevvm-why`, which fetches it. The page passes the same source-IP check as every other request, so a VM only ever sees its own blocks. The proxy answers it itself, without a policy decision or an event. Each entry merges repeats and says whether the current policy now allows it. `windevvm network log` reads the longer history from the daemon's event log on disk.

## Secret injection

1. **Storage (host):** each secret is DPAPI-encrypted (CurrentUser scope) under `%LOCALAPPDATA%\windevvm\secrets\`. Secrets are never written to a VM disk, seed ISO or log.
2. **Definition:** `name`, `hosts` (the secret is injected only there), and `in`, the parts of a request it may go into. `header` is the default and covers every header, including the user:password inside a decoded Basic-auth header, as git over HTTPS uses. `url` and `body` are opt-in per secret (`--in header,url,body`).
   ```
   windevvm secret set GITHUB_TOKEN --preset github          # github.com, api.github.com, uploads., codeload., raw.githubusercontent.com
   windevvm secret set ANTHROPIC_API_KEY --preset anthropic  # host: api.anthropic.com
   windevvm secret use GITHUB_TOKEN                           # expose it to this project's VM
   ```
3. **Placeholders:** each (VM, secret) pair gets a unique random placeholder, `wdvm_ph_<name>_<128-bit hex>`. It's exported as an env var in the VM, and git credentials are configured with it. A placeholder that leaks is useless anywhere else and can be traced to the VM it came from.
4. **Interception:**
   - The daemon owns a local CA (ECDSA P-256, key DPAPI-protected). Each VM trusts it through `update-ca-certificates`, `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE` and `REQUESTS_CA_BUNDLE`.
   - TLS is intercepted **only** for hosts that have a secret bound for this VM. All other allowed traffic passes through as a blind CONNECT tunnel, which avoids certificate pinning problems and limits the attack surface.
   - The proxy talks HTTP/1.1 to the VM. Upstream it uses Go's `http.Transport`, which can negotiate HTTP/2.
5. **Rules:**
   - Substitution happens only over TLS, only when the host matches one of the secret's bound hosts, and only in the configured places.
   - If a placeholder shows up in a request to any other host, the request is **blocked and logged** as a possible exfiltration attempt. The proxy can only see this in requests it decrypts (hosts with a secret bound) and in plain HTTP; blind CONNECT tunnels are opaque to it.
   - Responses are scanned, and any real secret value is replaced by its placeholder, so an echoed token doesn't leak back into the VM.
6. **Known limits:** tools that pin certificates or ignore proxy settings. SSH-based git push isn't supported (HTTPS is used instead). OAuth refresh flows: for Claude Code, use the long-lived token from `claude setup-token` with `CLAUDE_CODE_OAUTH_TOKEN`.

## Resource caps

Each VM has caps, with defaults from global config that `.windevvm.toml` can override:

| Cap | Hyper-V mechanism | Default |
|---|---|---|
| vCPUs | `Set-VMProcessor -Count` | 4 |
| CPU ceiling | `Set-VMProcessor -Maximum` (% of its vCPUs) | 50% |
| CPU weight | `Set-VMProcessor -RelativeWeight` | 100 (the host has priority) |
| Memory | dynamic memory with startup, minimum and **maximum** | 1 GB / 512 MB / 4 GB |
| Disk size | VHDX max size | 64 GB |
| Disk I/O | `Set-VMHardDiskDrive -MaximumIOPS` | 2000 |
| Network bandwidth | `Set-VMNetworkAdapter -MaximumBandwidth` | 200 Mbps |

The global **host budget** is checked before every start and resize:

- **Memory:** the sum of max memory across running VMs must stay ≤ `memory_budget`. The default is total RAM minus 6 GB, which is 10 GB on this PC.
- **CPU:** the sum of vCPUs × ceiling across running VMs must stay ≤ `cpu_budget` thread-equivalents. The default is 50% of logical CPUs, which is 6 of 12.
- **Running VMs:** `max_running`, default 3.
- **Disk:** total VM storage must stay ≤ `disk_budget`.
- **Over budget:** `windevvm up` refuses and names the running VMs it could stop, or stops the least recently used idle VM if `--evict` is passed.
- **Idle auto-stop:** the daemon stops a VM after `idle_timeout` (default 30 minutes, overridable per project) with no TCP connection between it and the host, no proxy requests since the last check, and CPU under 5%. Connections are counted on the host (`Get-NetTCPConnection` on 10.77.0.1), which covers shells, VS Code, port forwards, browsing the VM's IP and long-lived requests through the proxy. Port forwards share one SSH connection per VM, closed 15 seconds after the last forwarded stream ends, so an unused forward doesn't keep a VM awake.
- **`windevvm top`:** live CPU, memory, disk and network per VM compared with its caps and the budget.

```toml
# .windevvm.toml (per project, optional)
[resources]
cpus = 6
cpu_max_percent = 75
memory_max = "8GB"
disk = "100GB"

[network]
tier = "allowlist"
allow = ["*.supabase.co", "registry.npmjs.org"]

[secrets]
use = ["GITHUB_TOKEN", "ANTHROPIC_API_KEY"]
```

## Privileges

- **One-time `windevvm setup`, elevated:** enables the Hyper-V feature if it's missing, adds the user to *Hyper-V Administrators*, creates the vSwitch and host IP, and writes the firewall rules for the whole port range. After that, no command needs elevation.
- **Everyday commands** run unelevated as a Hyper-V Administrators member.

## Milestones

1. **Proxy core** (pure Go, unit-testable without Hyper-V): policy engine, CA, intercept-only-bound-hosts, placeholder substitution including Basic auth, blocking on exfiltration, DPAPI secret store.
2. **Hyper-V lifecycle:** base image build, differencing VMs, seed ISO, SSH, `up`, `stop`, `rm`, `ls`, applied resource caps, budget checks.
3. **Lockdown:** vSwitch, firewall, port ACLs, proxy wired per VM, `doctor` verifies a direct connection from the VM fails.
4. **Workflow:** clone mode and `pull`, toolchain detection, `ports`, `code`, `top`, idle auto-stop.
5. **Polish:** presets, `network log`, `windevvm-why`, image rebuild and garbage collection, docs.
