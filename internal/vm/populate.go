package vm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"windevvm/internal/sshkeys"
	"windevvm/internal/toolchain"
	"windevvm/internal/workspace"
)

// Git returns host-side git access to the VM's clone of its project.
func (m *Manager) Git(rec *Record) workspace.Git {
	q := func(p string) string { return `"` + filepath.ToSlash(p) + `"` }
	return workspace.Git{
		Dir:        rec.Project,
		Remote:     rec.Name + ":" + rec.WorkDir(),
		SSHCommand: q(m.SSHExe) + " -F " + q(m.SSH.ConfigPath()),
	}
}

// populate copies the project into the VM the first time it starts: a git
// clone pushed from the host (or, without git, a copy of the files), then the
// toolchains the project needs.
func (m *Manager) populate(ctx context.Context, rec *Record) error {
	c, err := m.SSH.Dial(rec.IP, rec.HostKey, 10*time.Second)
	if err != nil {
		return fmt.Errorf("connect to %s: %w", rec.Name, err)
	}
	defer c.Close()
	dir := rec.WorkDir()

	if workspace.IsRepo(ctx, rec.Project) {
		if m.SSHExe == "" {
			return errors.New("ssh.exe not found, and git needs it to clone into the VM; install the Windows OpenSSH client (Settings > System > Optional features)")
		}
		if out, err := sshkeys.RunInput(c, "bash -s", workspace.InitScript(dir)); err != nil {
			return fmt.Errorf("prepare %s in the VM: %v\n%s", dir, err, out)
		}
		g := m.Git(rec)
		branch, commit := g.Head(ctx)
		if commit != "" {
			m.say("Cloning the project into %s:%s...", rec.Name, dir)
			if err := g.Push(ctx); err != nil {
				return err
			}
		}
		ref := branch
		if ref == "" {
			ref = commit
		}
		id := workspace.Identity{
			Name:   g.Config(ctx, "user.name"),
			Email:  g.Config(ctx, "user.email"),
			Origin: workspace.HTTPSRemote(g.Config(ctx, "remote.origin.url")),
		}
		if out, err := sshkeys.RunInput(c, "bash -s", workspace.CheckoutScript(dir, ref, id)); err != nil {
			return fmt.Errorf("check out %s in the VM: %v\n%s", ref, err, out)
		}
		if g.Dirty(ctx) {
			m.say("Note: uncommitted changes on the host were not copied; the VM has the last commit.")
		}
	} else {
		m.say("Copying the project into %s:%s (not a git repo, so this is a one-time copy)...", rec.Name, dir)
		pr, pw := io.Pipe()
		var files int
		go func() {
			n, err := workspace.WriteTar(pw, rec.Project)
			files = n
			pw.CloseWithError(err)
		}()
		var out strings.Builder
		q := workspace.ShellQuote(dir)
		cmd := "mkdir -p " + q + " && tar -x -C " + q
		if err := sshkeys.Stream(c, cmd, pr, &out); err != nil {
			pr.CloseWithError(err)
			return fmt.Errorf("copy the project: %v\n%s", err, out.String())
		}
		m.say("Copied %d files.", files)
	}
	return m.installTools(c, rec)
}

// installTools runs mise in the project folder: the project's own mise or
// asdf file if it has one, otherwise the tools detected from its files.
func (m *Manager) installTools(c *ssh.Client, rec *Record) error {
	plan := toolchain.Detect(rec.Project)
	dir := rec.WorkDir()
	var script strings.Builder
	fmt.Fprintf(&script, "set -e\ncd %s\n", workspace.ShellQuote(dir))
	switch {
	case plan.MiseConfig != "":
		m.say("Installing the toolchains listed in %s...", plan.MiseConfig)
		script.WriteString("mise trust --yes . >/dev/null 2>&1 || true\n")
	case len(plan.Tools) > 0:
		var why []string
		for _, t := range plan.Tools {
			why = append(why, t+" ("+plan.Reasons[t]+")")
		}
		m.say("Installing toolchains: %s...", strings.Join(why, ", "))
		fmt.Fprintf(&script, "mkdir -p ~/.config/mise\ncat > ~/.config/mise/config.toml <<'WDVM_EOF'\n%sWDVM_EOF\n", plan.MiseConfigText())
	default:
		return nil
	}
	script.WriteString("mise install --yes\n")
	// Login shell, so the proxy settings from /etc/environment apply.
	out := &miseWriter{w: m.Out, prefix: "  "}
	err := sshkeys.Stream(c, "bash -l -s", strings.NewReader(script.String()), out)
	out.Flush()
	if err != nil {
		m.say("Warning: installing toolchains failed (%v). Fix the cause (often a host missing from the allowlist: windevvm network log --blocked), then run mise install inside the VM.", err)
	}
	return nil
}

// miseWriter indents mise's streamed output and drops its progress noise.
// Without a terminal, mise reprints its progress bar and every tool's status
// line every few seconds; this keeps the first line of each step per tool
// and the result lines.
type miseWriter struct {
	mu     sync.Mutex // ssh copies stdout and stderr in separate goroutines
	w      io.Writer
	prefix string
	buf    []byte
	last   map[string]string // tool -> last status shown
}

func (m *miseWriter) Write(b []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.buf = append(m.buf, b...)
	for {
		i := bytes.IndexByte(m.buf, '\n')
		if i < 0 {
			break
		}
		line := strings.TrimRight(string(m.buf[:i]), "\r")
		m.buf = m.buf[i+1:]
		// A carriage return redraws the line; keep what a terminal would show.
		if j := strings.LastIndexByte(line, '\r'); j >= 0 {
			line = line[j+1:]
		}
		if !m.keep(line) {
			continue
		}
		if _, err := io.WriteString(m.w, m.prefix+line+"\n"); err != nil {
			return 0, err
		}
	}
	// Bound the partial line: drop redrawn parts (a trailing \r may be half
	// of \r\n, so it stays), and pass on a very long line as it is.
	if j := bytes.LastIndexByte(m.buf, '\r'); j >= 0 && j < len(m.buf)-1 {
		m.buf = append([]byte(nil), m.buf[j+1:]...)
	}
	if len(m.buf) > 4096 {
		if _, err := io.WriteString(m.w, m.prefix+string(m.buf)+"\n"); err != nil {
			return 0, err
		}
		m.buf = nil
	}
	return len(b), nil
}

// Flush writes a final line that had no newline.
func (m *miseWriter) Flush() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.buf) > 0 {
		io.WriteString(m.w, m.prefix+string(m.buf)+"\n")
		m.buf = nil
	}
}

func (m *miseWriter) keep(line string) bool {
	if strings.ContainsAny(line, "█░") { // the overall progress bar
		return strings.Contains(line, "installed")
	}
	// Status lines: "  node@22.1.0  downloading  3.0s  44.3/44.3 MB · 40 MB/s".
	if strings.HasPrefix(line, "  ") {
		f := splitWide(strings.TrimSpace(line))
		if len(f) >= 2 && strings.Contains(f[0], "@") {
			if m.last == nil {
				m.last = map[string]string{}
			}
			if m.last[f[0]] == f[1] {
				return false
			}
			m.last[f[0]] = f[1]
		}
	}
	return true
}

// splitWide splits s at runs of two or more spaces.
func splitWide(s string) []string {
	var out []string
	for _, f := range strings.Split(s, "  ") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}
