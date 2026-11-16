package workspace

import (
	"archive/tar"
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	c := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"}, args...)...)
	out, err := c.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func commit(t *testing.T, dir, file, content string) {
	os.WriteFile(filepath.Join(dir, file), []byte(content), 0o644)
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "-q", "-m", "change "+file)
}

func TestPushAndPull(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	ctx := context.Background()
	host := t.TempDir()
	git(t, host, "init", "-q", "-b", "main")
	commit(t, host, "a.txt", "one")
	git(t, host, "branch", "feature")
	git(t, host, "tag", "v1")
	git(t, host, "branch", "windevvm/old") // pulled earlier; must not go back in

	// The VM side, set up like InitScript does.
	vm := t.TempDir()
	git(t, vm, "init", "-q")
	git(t, vm, "symbolic-ref", "HEAD", "refs/heads/windevvm-unborn")
	git(t, vm, "config", "receive.denyCurrentBranch", "updateInstead")

	if !IsRepo(ctx, host) || IsRepo(ctx, filepath.Join(host, "nope")) {
		t.Fatal("IsRepo wrong")
	}
	g := Git{Dir: host, Remote: vm}
	if br, sha := g.Head(ctx); br != "main" || sha == "" {
		t.Fatal(br, sha)
	}
	if g.Dirty(ctx) {
		t.Fatal("clean repo reported dirty")
	}
	os.WriteFile(filepath.Join(host, "untracked"), nil, 0o644)
	if !g.Dirty(ctx) {
		t.Fatal("untracked file not reported")
	}
	if err := g.Push(ctx); err != nil {
		t.Fatal(err)
	}
	refs := git(t, vm, "for-each-ref", "--format=%(refname)")
	for _, want := range []string{"refs/heads/main", "refs/heads/feature", "refs/tags/v1"} {
		if !strings.Contains(refs, want) {
			t.Fatalf("VM lacks %s:\n%s", want, refs)
		}
	}

	if strings.Contains(refs, "windevvm/old") {
		t.Fatal("pushed a windevvm/* branch into the VM")
	}

	// Work happens in the VM.
	git(t, vm, "checkout", "-q", "main")
	commit(t, vm, "b.txt", "from the vm")
	git(t, vm, "checkout", "-q", "-b", "vm-only")
	commit(t, vm, "c.txt", "new branch")

	changed, err := g.Pull(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(changed, ",") != "windevvm/feature,windevvm/main,windevvm/vm-only" {
		t.Fatalf("changed = %v", changed)
	}
	if got := git(t, host, "show", "windevvm/main:b.txt"); got != "from the vm" {
		t.Fatal(got)
	}
	if _, err := os.Stat(filepath.Join(host, "b.txt")); err == nil {
		t.Fatal("pull touched the host work tree")
	}
	if changed, _ := g.Pull(ctx); len(changed) != 0 {
		t.Fatalf("second pull changed %v", changed)
	}
}

func TestHTTPSRemote(t *testing.T) {
	for in, want := range map[string]string{
		"https://github.com/a/b.git":             "https://github.com/a/b.git",
		"git@github.com:a/b.git":                 "https://github.com/a/b.git",
		"ssh://git@gitlab.com:22/group/proj.git": "https://gitlab.com/group/proj.git",
		`C:\repos\x`:                             "",
		"C:/repos/x":                             "",
		"/srv/git/x":                             "",
	} {
		if got := HTTPSRemote(in); got != want {
			t.Errorf("%s: got %q want %q", in, got, want)
		}
	}
}

func TestScripts(t *testing.T) {
	s := CheckoutScript("/home/dev/my app", "feat/x", Identity{Name: "O'Brien", Email: "o@x.y", Origin: "https://github.com/a/b.git"})
	for _, want := range []string{"cd '/home/dev/my app'", "git checkout -q feat/x --", `user.name 'O'\''Brien'`, "git remote add origin https://github.com/a/b.git"} {
		if !strings.Contains(s, want) {
			t.Errorf("checkout script lacks %q:\n%s", want, s)
		}
	}
	if !strings.Contains(InitScript("/home/dev/x"), "receive.denyCurrentBranch updateInstead") {
		t.Fatal("init script")
	}
}

func TestWriteTar(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "src"), 0o755)
	os.MkdirAll(filepath.Join(dir, "node_modules", "x"), 0o755)
	os.WriteFile(filepath.Join(dir, "src", "main.py"), []byte("print(1)"), 0o644)
	os.WriteFile(filepath.Join(dir, "node_modules", "x", "big.js"), []byte("x"), 0o644)
	var buf bytes.Buffer
	n, err := WriteTar(&buf, dir)
	if err != nil || n != 1 {
		t.Fatal(n, err)
	}
	tr := tar.NewReader(&buf)
	var names []string
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		names = append(names, h.Name)
	}
	if strings.Join(names, ",") != "src/,src/main.py" {
		t.Fatal(names)
	}
}

func TestPullRefusesCheckedOutTarget(t *testing.T) {
	ctx := context.Background()
	host := t.TempDir()
	git(t, host, "init", "-q", "-b", "main")
	commit(t, host, "a.txt", "one")
	git(t, host, "checkout", "-q", "-b", "windevvm/main")
	if _, err := (Git{Dir: host, Remote: host}).Pull(ctx); err == nil || !strings.Contains(err.Error(), "check out another branch") {
		t.Fatalf("err = %v", err)
	}
}
