// Package paths locates windevvm's data on the host.
package paths

import (
	"os"
	"path/filepath"
)

// DataDir is the root of windevvm's host data: %LOCALAPPDATA%\windevvm, or
// $WINDEVVM_HOME when set.
func DataDir() string {
	if d := os.Getenv("WINDEVVM_HOME"); d != "" {
		return d
	}
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		base, _ = os.UserConfigDir()
	}
	return filepath.Join(base, "windevvm")
}

// SecretsDir holds encrypted secrets.
func SecretsDir() string { return filepath.Join(DataDir(), "secrets") }

// CADir holds the local certificate authority.
func CADir() string { return filepath.Join(DataDir(), "ca") }
