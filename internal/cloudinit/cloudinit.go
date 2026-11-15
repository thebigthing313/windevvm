// Package cloudinit renders the cloud-init seed files for the base image
// build and for project VMs.
package cloudinit

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"

	"windevvm/internal/seed"
)

// Serial console markers the host watches for.
const (
	BuildOK     = "WDVM-BUILD-OK"
	BuildFailed = "WDVM-BUILD-FAILED"
	Progress    = "WDVM: "
	Ready       = "WDVM-READY"
)

// BaseSpec configures the base image build.
type BaseSpec struct {
	Packages  []string
	Tools     []string // mise specs like node@lts
	NpmGlobal []string
}

var funcs = template.FuncMap{
	"quote":  func(s string) string { return fmt.Sprintf("%q", s) },
	"indent": func(n int, s string) string { return indent(n, s) },
}

func indent(n int, s string) string {
	pad := strings.Repeat(" ", n)
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		lines[i] = pad + l
	}
	return strings.Join(lines, "\n")
}

// miseTools turns ["node@lts", "go"] into TOML lines for /etc/mise/config.toml.
func miseTools(tools []string) (string, error) {
	var b strings.Builder
	b.WriteString("[tools]\n")
	for _, t := range tools {
		name, ver, ok := strings.Cut(t, "@")
		if !ok {
			ver = "latest"
		}
		if name == "" || strings.ContainsAny(name+ver, "\"\n\\ ") {
			return "", fmt.Errorf("bad tool spec %q", t)
		}
		fmt.Fprintf(&b, "%q = %q\n", name, ver)
	}
	return b.String(), nil
}

var baseTmpl = template.Must(template.New("base").Funcs(funcs).Parse(`#cloud-config
hostname: wdvm-base
users:
  - name: dev
    groups: [sudo]
    shell: /bin/bash
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    lock_passwd: true
package_update: true
package_upgrade: true
packages:
{{- range .Packages}}
  - {{quote .}}
{{- end}}
write_files:
  - path: /etc/mise/config.toml
    content: |
{{indent 6 .MiseConfig}}
  - path: /etc/environment
    content: |
      PATH="/opt/mise/shims:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin"
      MISE_DATA_DIR="/opt/mise"
      MISE_CACHE_DIR="/opt/mise/cache"
  - path: /etc/profile.d/windevvm.sh
    content: |
      export MISE_DATA_DIR=/opt/mise
      export MISE_CACHE_DIR=/opt/mise/cache
      case ":$PATH:" in *:/opt/mise/shims:*) ;; *) export PATH="/opt/mise/shims:$PATH" ;; esac
  - path: /etc/skel/.bashrc.d/windevvm.sh
    content: |
      PS1="(windevvm) $PS1"
  - path: /usr/local/bin/wdvm-provision
    permissions: "0755"
    content: |
{{indent 6 .Script}}
runcmd:
  - [/usr/local/bin/wdvm-provision]
power_state:
  mode: poweroff
  condition: "test -f /var/lib/wdvm-build-ok"
  timeout: 30
`))

var provisionTmpl = template.Must(template.New("provision").Funcs(funcs).Parse(`#!/bin/bash
set -euo pipefail
say() { echo "` + Progress + `$*" > /dev/ttyS0; }
trap 'echo "` + BuildFailed + ` at line $LINENO" > /dev/ttyS0' ERR
export HOME=/root DEBIAN_FRONTEND=noninteractive
export MISE_DATA_DIR=/opt/mise MISE_CACHE_DIR=/opt/mise/cache MISE_YES=1
mkdir -p /opt/mise

say "installing mise"
curl -fsSL https://mise.run | MISE_INSTALL_PATH=/usr/local/bin/mise sh

say "installing toolchains: {{.ToolList}}"
mise install
mise reshim
{{- if .NpmGlobal}}

say "installing npm packages: {{.NpmList}}"
mise exec -- npm install -g --no-fund --no-audit {{.NpmArgs}}
mise reshim
{{- end}}

say "configuring the dev user"
chown -R dev:dev /opt/mise
mkdir -p /home/dev/.bashrc.d
cp /etc/skel/.bashrc.d/windevvm.sh /home/dev/.bashrc.d/
grep -q 'bashrc.d' /home/dev/.bashrc || cat >> /home/dev/.bashrc <<'EOF'
for f in ~/.bashrc.d/*.sh; do [ -r "$f" ] && . "$f"; done
command -v mise >/dev/null && eval "$(mise activate bash)"
EOF
chown -R dev:dev /home/dev

say "cleaning up"
apt-get clean
rm -rf /var/lib/apt/lists/* /opt/mise/cache/* /root/.npm /root/.cache
cloud-init clean --logs --seed
truncate -s 0 /etc/machine-id
rm -f /var/lib/dbus/machine-id /etc/ssh/ssh_host_*
fstrim -av || true

touch /var/lib/wdvm-build-ok
say "done"
echo "` + BuildOK + `" > /dev/ttyS0
`))

// BaseSeed returns the seed for the one-time base image build.
func BaseSeed(s BaseSpec) (seed.Files, error) {
	mise, err := miseTools(s.Tools)
	if err != nil {
		return nil, err
	}
	for _, p := range append(append([]string{}, s.Packages...), s.NpmGlobal...) {
		if p == "" || strings.ContainsAny(p, " \"'\n\\$`;&|") {
			return nil, fmt.Errorf("bad package name %q", p)
		}
	}
	var script bytes.Buffer
	if err := provisionTmpl.Execute(&script, map[string]any{
		"ToolList":  strings.Join(s.Tools, ", "),
		"NpmGlobal": s.NpmGlobal,
		"NpmList":   strings.Join(s.NpmGlobal, ", "),
		"NpmArgs":   strings.Join(s.NpmGlobal, " "),
	}); err != nil {
		return nil, err
	}
	var ud bytes.Buffer
	if err := baseTmpl.Execute(&ud, map[string]any{
		"Packages":   s.Packages,
		"MiseConfig": mise,
		"Script":     script.String(),
	}); err != nil {
		return nil, err
	}
	return seed.Files{
		"user-data": ud.Bytes(),
		"meta-data": []byte("instance-id: wdvm-base-build\nlocal-hostname: wdvm-base\n"),
	}, nil
}

// VMSpec configures a project VM's first boot.
type VMSpec struct {
	Name          string
	InstanceID    string
	IP            string // e.g. 10.77.0.10
	PrefixLen     int
	AuthorizedKey string
	// HostKeyPrivate and HostKeyPublic set the VM's SSH host key. Leave
	// HostKeyPrivate empty for the seed that stays attached after first boot.
	HostKeyPrivate string
	HostKeyPublic  string
}

var vmTmpl = template.Must(template.New("vm").Funcs(funcs).Parse(`#cloud-config
hostname: {{.Name}}
manage_etc_hosts: true
users:
  - name: dev
    groups: [sudo]
    shell: /bin/bash
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    lock_passwd: true
    ssh_authorized_keys:
      - {{quote .AuthorizedKey}}
ssh_pwauth: false
disable_root: true
{{- if .HostKeyPrivate}}
ssh_deletekeys: true
ssh_genkeytypes: [ed25519]
ssh_keys:
  ed25519_private: |
{{indent 4 .HostKeyPrivate}}
  ed25519_public: {{quote .HostKeyPublic}}
{{- end}}
growpart:
  mode: auto
  devices: ["/"]
runcmd:
  - [sh, -c, "echo ` + Ready + ` > /dev/ttyS0"]
`))

var netTmpl = template.Must(template.New("net").Parse(`version: 2
ethernets:
  eth0:
    match:
      driver: hv_netvsc
    set-name: eth0
    dhcp4: false
    dhcp6: false
    accept-ra: false
    link-local: []
    addresses: [{{.IP}}/{{.PrefixLen}}]
`))

// VMSeed returns the seed for a project VM. The VM gets a static address on
// the windevvm switch, no gateway and no DNS: it can reach only the host.
func VMSeed(s VMSpec) (seed.Files, error) {
	var ud, nc bytes.Buffer
	if err := vmTmpl.Execute(&ud, s); err != nil {
		return nil, err
	}
	if err := netTmpl.Execute(&nc, s); err != nil {
		return nil, err
	}
	return seed.Files{
		"user-data":      ud.Bytes(),
		"meta-data":      []byte(fmt.Sprintf("instance-id: %s\nlocal-hostname: %s\n", s.InstanceID, s.Name)),
		"network-config": nc.Bytes(),
	}, nil
}
