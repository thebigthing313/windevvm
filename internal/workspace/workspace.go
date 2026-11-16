// Package workspace moves project files between the host and a VM. In clone
// mode the VM gets its own git clone, pushed in from the host; branches come
// back with Pull as windevvm/<branch>. The VM never touches the host's
// working tree or .git.
package workspace

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// PullPrefix is where branches pulled from a VM land on the host.
const PullPrefix = "windevvm/"

// Git runs host-side git against a VM's clone.
type Git struct {
	Dir string // the host project
	// Remote is the VM's clone, e.g. "wdvm-x-123456:/home/dev/x" (or a local
	// path in tests).
	Remote string
	// SSHCommand becomes GIT_SSH_COMMAND, so git reaches the VM with
	// windevvm's ssh config. Empty for local remotes.
	SSHCommand string
}

func (g Git) cmd(ctx context.Context, args ...string) *exec.Cmd {
	c := exec.CommandContext(ctx, "git", append([]string{"-C", g.Dir}, args...)...)
	c.Env = os.Environ()
	if g.SSHCommand != "" {
		c.Env = append(c.Env, "GIT_SSH_COMMAND="+g.SSHCommand)
	}
	c.Env = append(c.Env, "GIT_TERMINAL_PROMPT=0")
	return c
}

func (g Git) run(ctx context.Context, args ...string) (string, error) {
	var out, errb bytes.Buffer
	c := g.cmd(ctx, args...)
	c.Stdout, c.Stderr = &out, &errb
	if err := c.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("git %s: %s", args[0], msg)
	}
	return strings.TrimSpace(out.String()), nil
}

// IsRepo reports whether dir is the top of a git work tree.
func IsRepo(ctx context.Context, dir string) bool {
	out, err := Git{Dir: dir}.run(ctx, "rev-parse", "--show-toplevel")
	if err != nil {
		return false
	}
	a, _ := filepath.Abs(filepath.FromSlash(out))
	b, _ := filepath.Abs(dir)
	return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}

// Head returns the current branch, or "" and the commit when detached.
// Both are empty in a repo with no commits.
func (g Git) Head(ctx context.Context) (branch, commit string) {
	commit, _ = g.run(ctx, "rev-parse", "--verify", "-q", "HEAD")
	branch, _ = g.run(ctx, "symbolic-ref", "-q", "--short", "HEAD")
	if commit == "" {
		branch = ""
	}
	return branch, commit
}

// Dirty reports whether the work tree has uncommitted changes (including
// untracked files), which a clone won't carry.
func (g Git) Dirty(ctx context.Context) bool {
	out, err := g.run(ctx, "status", "--porcelain")
	return err == nil && out != ""
}

// Push sends every local branch and tag to the VM's clone, except branches
// that came from a VM (windevvm/*).
func (g Git) Push(ctx context.Context) error {
	_, err := g.run(ctx, "push", "--quiet", g.Remote, "refs/heads/*:refs/heads/*", "^refs/heads/"+PullPrefix+"*", "refs/tags/*:refs/tags/*")
	return err
}

func (g Git) refs(ctx context.Context, prefix string) (map[string]string, error) {
	out, err := g.run(ctx, "for-each-ref", "--format=%(objectname) %(refname)", prefix)
	if err != nil {
		return nil, err
	}
	refs := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if sha, ref, ok := strings.Cut(line, " "); ok {
			refs[ref] = sha
		}
	}
	return refs, nil
}

// Pull fetches every branch of the VM's clone into windevvm/<branch>
// (forced, since the VM may rewrite history) and returns the branches that
// changed. Objects are checked as they arrive, and nothing is checked out.
func (g Git) Pull(ctx context.Context) ([]string, error) {
	if br, _ := g.Head(ctx); strings.HasPrefix(br, PullPrefix) {
		return nil, fmt.Errorf("the host has %s checked out, and pull updates the windevvm/* branches; check out another branch first", br)
	}
	before, err := g.refs(ctx, "refs/heads/"+PullPrefix)
	if err != nil {
		return nil, err
	}
	if _, err := g.run(ctx, "-c", "transfer.fsckObjects=true", "fetch", "--quiet", "--no-tags", g.Remote, "+refs/heads/*:refs/heads/"+PullPrefix+"*"); err != nil {
		return nil, err
	}
	after, err := g.refs(ctx, "refs/heads/"+PullPrefix)
	if err != nil {
		return nil, err
	}
	var changed []string
	for ref, sha := range after {
		if before[ref] != sha {
			changed = append(changed, strings.TrimPrefix(ref, "refs/heads/"))
		}
	}
	sort.Strings(changed)
	return changed, nil
}

// Config returns a git config value from the host repo (or "").
func (g Git) Config(ctx context.Context, key string) string {
	v, _ := g.run(ctx, "config", "--get", key)
	return v
}

var scpLikeRE = regexp.MustCompile(`^(?:[A-Za-z0-9._-]+@)?([A-Za-z0-9.-]+):([^/][^:]*)$`)
var sshURLRE = regexp.MustCompile(`^ssh://(?:[^@/]+@)?([A-Za-z0-9.-]+)(?::\d+)?/(.+)$`)

// HTTPSRemote turns an origin URL into an https URL the VM can use through
// the proxy (the VM can't do SSH to the outside). It returns "" if it can't.
func HTTPSRemote(u string) string {
	u = strings.TrimSpace(u)
	switch {
	case strings.HasPrefix(u, "https://"):
		return u
	case sshURLRE.MatchString(u):
		m := sshURLRE.FindStringSubmatch(u)
		return "https://" + m[1] + "/" + m[2]
	case scpLikeRE.MatchString(u) && !strings.Contains(u, `\`):
		m := scpLikeRE.FindStringSubmatch(u)
		if len(m[1]) == 1 {
			return "" // a Windows drive letter, not a host
		}
		return "https://" + m[1] + "/" + m[2]
	}
	return ""
}

var safeArgRE = regexp.MustCompile(`^[A-Za-z0-9@%+=:,./_~-]*$`)

// ShellQuote quotes s for bash.
func ShellQuote(s string) string {
	if s != "" && safeArgRE.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// InitScript prepares an empty repo in the VM that accepts pushes. HEAD
// points at an unborn branch, so the first push never collides with a
// checked-out branch.
func InitScript(guestDir string) string {
	d := ShellQuote(guestDir)
	return fmt.Sprintf(`set -e
mkdir -p %[1]s
cd %[1]s
if [ ! -d .git ]; then
  git init -q
  git symbolic-ref HEAD refs/heads/windevvm-unborn
fi
git config receive.denyCurrentBranch updateInstead
`, d)
}

// Identity is the git author identity and origin to set up in the VM.
type Identity struct {
	Name, Email string
	Origin      string // https URL, or ""
}

// CheckoutScript checks out ref (a branch or commit) in the VM's clone and
// configures origin and the author identity.
func CheckoutScript(guestDir, ref string, id Identity) string {
	var b strings.Builder
	fmt.Fprintf(&b, "set -e\ncd %s\n", ShellQuote(guestDir))
	if ref != "" {
		fmt.Fprintf(&b, "git checkout -q %s --\n", ShellQuote(ref))
	}
	if id.Origin != "" {
		fmt.Fprintf(&b, "git remote remove origin 2>/dev/null || true\ngit remote add origin %s\n", ShellQuote(id.Origin))
	}
	if id.Name != "" {
		fmt.Fprintf(&b, "git config --global user.name %s\n", ShellQuote(id.Name))
	}
	if id.Email != "" {
		fmt.Fprintf(&b, "git config --global user.email %s\n", ShellQuote(id.Email))
	}
	return b.String()
}

// skipDirs aren't copied for projects without git: they are rebuilt inside
// the VM (and are often huge or platform-specific).
var skipDirs = map[string]bool{".git": true, "node_modules": true, ".venv": true, "venv": true, "__pycache__": true, "target": true, ".next": true}

// WriteTar writes dir's files as a tar stream (for projects without git).
// Symlinks and the directories in skipDirs are left out.
func WriteTar(w io.Writer, dir string) (files int, err error) {
	tw := tar.NewWriter(w)
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil || rel == "." {
			return err
		}
		name := filepath.ToSlash(rel)
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: name + "/", Mode: 0o755})
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: 0o644, Size: info.Size(), ModTime: info.ModTime()}); err != nil {
			return err
		}
		if _, err := io.Copy(tw, f); err != nil {
			return err
		}
		files++
		return nil
	})
	if err != nil {
		return files, err
	}
	return files, tw.Close()
}

// ErrNotRepo means pull was asked of a project that isn't a git repo.
var ErrNotRepo = errors.New("this project isn't a git repository, so there is nothing to pull; copy files out with scp instead")
