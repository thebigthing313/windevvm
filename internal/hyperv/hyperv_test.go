package hyperv

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// TestRunnerPassesArgsSafely checks that values with quotes and PowerShell
// syntax arrive as data, never as code.
func TestRunnerPassesArgsSafely(t *testing.T) {
	if testing.Short() {
		t.Skip("starts PowerShell")
	}
	tricky := `it's "quoted" $(Write-Error boom); exit 3 ` + "`n"
	var out struct{ Echo string }
	r := Runner{}
	err := r.Run(context.Background(), `ConvertTo-Json -InputObject @{ Echo = $a.Value } -Compress`, map[string]string{"Value": tricky}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if out.Echo != tricky {
		t.Fatalf("echo = %q, want %q", out.Echo, tricky)
	}
}

func TestRunnerReportsErrors(t *testing.T) {
	if testing.Short() {
		t.Skip("starts PowerShell")
	}
	err := (&Runner{}).Run(context.Background(), `throw "custom failure"`, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "custom failure") {
		t.Fatalf("err = %v", err)
	}
}

// TestListVMs needs Hyper-V access; set WINDEVVM_TEST_HYPERV=1.
func TestListVMs(t *testing.T) {
	if os.Getenv("WINDEVVM_TEST_HYPERV") == "" {
		t.Skip("WINDEVVM_TEST_HYPERV not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	c := &Client{}
	if _, err := c.ListVMs(ctx, "wdvm-"); err != nil {
		t.Fatal(err)
	}
	ok, err := c.SwitchExists(ctx, DefaultSwitch)
	if err != nil || !ok {
		t.Fatalf("SwitchExists(Default Switch) = %v, %v", ok, err)
	}
}
