//go:build !windows

package hyperv

import "os/exec"

func hideConsole(cmd *exec.Cmd) {}
