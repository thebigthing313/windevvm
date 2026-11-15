//go:build windows

package hyperv

import (
	"context"
	"io"
	"os"
	"time"
)

// OpenConsole connects to a VM's COM1 named pipe (Set-VMComPort), retrying
// until the VM has created it. Reads return io.EOF when the VM powers off.
func OpenConsole(ctx context.Context, pipe string) (io.ReadCloser, error) {
	for {
		f, err := os.OpenFile(pipe, os.O_RDWR, 0)
		if err == nil {
			return f, nil
		}
		select {
		case <-ctx.Done():
			return nil, err
		case <-time.After(250 * time.Millisecond):
		}
	}
}
