package cloudinit

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func parseYAML(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := yaml.Unmarshal(b, &m); err != nil {
		t.Fatalf("invalid YAML: %v\n%s", err, b)
	}
	return m
}

func TestBaseSeed(t *testing.T) {
	files, err := BaseSeed(BaseSpec{
		Packages:  []string{"git", "jq"},
		Tools:     []string{"node@lts", "go"},
		NpmGlobal: []string{"@anthropic-ai/claude-code"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ud := files["user-data"]
	if !strings.HasPrefix(string(ud), "#cloud-config\n") {
		t.Fatal("missing #cloud-config header")
	}
	m := parseYAML(t, ud)
	wf := m["write_files"].([]any)
	var script, mise string
	for _, f := range wf {
		f := f.(map[string]any)
		switch f["path"] {
		case "/usr/local/bin/wdvm-provision":
			script = f["content"].(string)
		case "/etc/mise/config.toml":
			mise = f["content"].(string)
		}
	}
	if !strings.Contains(mise, `"node" = "lts"`) || !strings.Contains(mise, `"go" = "latest"`) {
		t.Errorf("mise config:\n%s", mise)
	}
	for _, want := range []string{"#!/bin/bash", "npm install -g --no-fund --no-audit @anthropic-ai/claude-code", BuildOK, "touch /var/lib/wdvm-build-ok"} {
		if !strings.Contains(script, want) {
			t.Errorf("provision script lacks %q", want)
		}
	}
}

func TestBaseSeedRejectsInjection(t *testing.T) {
	if _, err := BaseSeed(BaseSpec{Packages: []string{"git; rm -rf /"}}); err == nil {
		t.Error("expected an error for a bad package name")
	}
	if _, err := BaseSeed(BaseSpec{Tools: []string{`node@"lts"`}}); err == nil {
		t.Error("expected an error for a bad tool spec")
	}
}

func TestVMSeed(t *testing.T) {
	spec := VMSpec{
		Name: "wdvm-app-abc123", InstanceID: "wdvm-app-abc123-1", IP: "10.77.0.10", PrefixLen: 24,
		AuthorizedKey:  "ssh-ed25519 AAAAC3Nza windevvm",
		HostKeyPrivate: "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\ndef\n-----END OPENSSH PRIVATE KEY-----\n",
		HostKeyPublic:  "ssh-ed25519 AAAAhost",
	}
	files, err := VMSeed(spec)
	if err != nil {
		t.Fatal(err)
	}
	m := parseYAML(t, files["user-data"])
	keys := m["ssh_keys"].(map[string]any)
	if keys["ed25519_private"] != spec.HostKeyPrivate || keys["ed25519_public"] != spec.HostKeyPublic {
		t.Fatalf("ssh_keys = %#v", keys)
	}
	users := m["users"].([]any)
	if users[0].(map[string]any)["ssh_authorized_keys"].([]any)[0] != spec.AuthorizedKey {
		t.Fatal("authorized key not set")
	}

	nc := parseYAML(t, files["network-config"])
	eth := nc["ethernets"].(map[string]any)["eth0"].(map[string]any)
	if eth["addresses"].([]any)[0] != "10.77.0.10/24" || eth["routes"] != nil || eth["nameservers"] != nil {
		t.Fatalf("network config = %#v", eth)
	}

	spec.HostKeyPrivate = ""
	files, _ = VMSeed(spec)
	if strings.Contains(string(files["user-data"]), "ssh_keys") {
		t.Fatal("the long-lived seed must not carry the host key")
	}
}
