//go:build windows

package hyperv

import (
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

// hideConsole stops powershell.exe from opening a console window. The
// daemon has no console of its own, so without this every Hyper-V query
// it makes (each idle-stop check, every minute) flashes a window.
func hideConsole(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW, HideWindow: true}
}
