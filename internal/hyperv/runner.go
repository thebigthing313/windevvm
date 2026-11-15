// Package hyperv is the only place windevvm talks to Hyper-V. It runs
// PowerShell's Hyper-V cmdlets, passing arguments as JSON in an environment
// variable so no value is ever spliced into script text.
package hyperv

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"unicode/utf16"
)

// Runner executes PowerShell scripts.
type Runner struct {
	// Exe is the PowerShell executable. Defaults to Windows PowerShell 5.1,
	// which always ships the Hyper-V module.
	Exe string
}

const prelude = `$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$a = $env:WDVM_ARGS | ConvertFrom-Json
try {
`

const postlude = `
} catch {
  [Console]::Error.WriteLine($_.Exception.Message)
  exit 1
}
`

// Run executes script with args (any JSON-encodable value, available to the
// script as $a) and decodes the script's stdout as JSON into out, if non-nil.
func (r *Runner) Run(ctx context.Context, script string, args any, out any) error {
	exe := r.Exe
	if exe == "" {
		exe = "powershell.exe"
	}
	if args == nil {
		args = struct{}{}
	}
	argJSON, err := json.Marshal(args)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encode(prelude+script+postlude))
	cmd.Env = append(os.Environ(), "WDVM_ARGS="+string(argJSON))
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		if strings.Contains(msg, "required permission") {
			msg += " (is your account in the Hyper-V Administrators group? run: windevvm setup)"
		}
		return errors.New(msg)
	}
	if out == nil {
		return nil
	}
	text := bytes.TrimSpace(stdout.Bytes())
	if len(text) == 0 {
		return errors.New("powershell produced no output")
	}
	if err := json.Unmarshal(text, out); err != nil {
		return fmt.Errorf("decode powershell output: %w (output: %.200s)", err, text)
	}
	return nil
}

func encode(script string) string {
	u := utf16.Encode([]rune(script))
	b := make([]byte, len(u)*2)
	for i, c := range u {
		b[2*i], b[2*i+1] = byte(c), byte(c>>8)
	}
	return base64.StdEncoding.EncodeToString(b)
}
