package vm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"windevvm/internal/protect"
	"windevvm/internal/secrets"
)

func testNet(t *testing.T) (*Net, *Record) {
	t.Helper()
	root := t.TempDir()
	n := &Net{
		Store:        &Store{Root: filepath.Join(root, "vms")},
		Secrets:      &secrets.Store{Dir: filepath.Join(root, "secrets"), P: protect.Insecure{}},
		GlobalPolicy: filepath.Join(root, "policy"),
	}
	project := filepath.Join(root, "proj")
	os.MkdirAll(project, 0o755)
	rec := &Record{Name: NameFor(project), Project: project, IP: "10.77.0.12"}
	if err := n.Store.Save(rec); err != nil {
		t.Fatal(err)
	}
	return n, rec
}

func TestNetPolicySources(t *testing.T) {
	n, rec := testNet(t)
	os.WriteFile(filepath.Join(rec.Project, ".windevvm.toml"), []byte("[network]\ntier = \"allowlist\"\nallow = [\"*.supabase.co\"]\n"), 0o644)
	os.WriteFile(n.Store.PolicyPath(rec.Name), []byte("db.example.net:5432\n!registry.npmjs.org\n"), 0o644)

	p, err := n.Policy(rec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(n.GlobalPolicy); err != nil {
		t.Fatal("global policy file not created")
	}
	for host, want := range map[string]bool{
		"pypi.org":           true,  // default global preset
		"x.supabase.co":      true,  // project file
		"registry.npmjs.org": false, // denied by the VM policy
		"api.anthropic.com":  true,  // agent host
		"example.org":        false,
	} {
		if got := p.Decide(host, 443).Allow; got != want {
			t.Errorf("%s: allow=%v want %v", host, got, want)
		}
	}
	if !p.Decide("db.example.net", 5432).Allow {
		t.Error("VM policy port rule not applied")
	}

	rec.Tier = "none"
	p, _ = n.Policy(rec)
	if p.Decide("pypi.org", 443).Allow {
		t.Error("tier override ignored")
	}
}

func TestNetSecrets(t *testing.T) {
	n, rec := testNet(t)
	os.WriteFile(filepath.Join(rec.Project, ".windevvm.toml"), []byte("[secrets]\nuse = [\"GITHUB_TOKEN\"]\n"), 0o644)
	if _, err := n.Setup(rec); err == nil || !strings.Contains(err.Error(), "windevvm secret set GITHUB_TOKEN") {
		t.Fatalf("missing secret: %v", err)
	}
	n.Secrets.Set(secrets.Secret{Name: "GITHUB_TOKEN", Hosts: []string{"github.com"}, Value: []byte("ghp_realvalue123")})
	n.Secrets.Set(secrets.Secret{Name: "EXTRA", Hosts: []string{"api.extra.dev"}, Value: []byte("extra-value-1234")})
	rec.Secrets = []string{"EXTRA"}

	s, err := n.Setup(rec)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(s.InUse, ",") != "EXTRA,GITHUB_TOKEN" {
		t.Fatalf("in use = %v", s.InUse)
	}

	// Without placeholders the proxy injects nothing.
	v, err := n.ProxyVM(rec)
	if err != nil {
		t.Fatal(err)
	}
	if v.Injector.Intercepts("github.com") {
		t.Fatal("bound a secret the VM has no placeholder for")
	}
	if !v.Policy.Decide("api.extra.dev", 443).Allow {
		t.Fatal("bound host not built in")
	}

	rec.Placeholders = map[string]string{"STALE": "wdvm_ph_STALE_00"}
	changed, err := SyncPlaceholders(rec, s.InUse)
	if err != nil || !changed {
		t.Fatal(err, changed)
	}
	if _, ok := rec.Placeholders["STALE"]; ok || len(rec.Placeholders) != 2 {
		t.Fatalf("placeholders = %v", rec.Placeholders)
	}
	before := rec.Placeholders["GITHUB_TOKEN"]
	if changed, _ := SyncPlaceholders(rec, s.InUse); changed || rec.Placeholders["GITHUB_TOKEN"] != before {
		t.Fatal("placeholders must be stable")
	}

	n.Store.Save(rec)
	targets, errs, err := n.Targets()
	if err != nil || len(errs) != 0 || len(targets) != 1 {
		t.Fatal(targets, errs, err)
	}
	tg := targets[0]
	if tg.Addr != "10.77.0.1:18012" || tg.VM.SourceIP.String() != "10.77.0.12" || !tg.VM.Injector.Intercepts("github.com") {
		t.Fatalf("target = %+v", tg)
	}

	// A VM using a deleted secret is reported, not served.
	n.Secrets.Remove("EXTRA")
	_, errs, _ = n.Targets()
	if errs[rec.Name] == nil {
		t.Fatal("expected an error for the missing secret")
	}
}
