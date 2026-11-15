package vm

import (
	"fmt"
	"sort"
	"strings"

	"windevvm/internal/config"
	"windevvm/internal/hyperv"
)

// Usage is what running VMs take from the host budget.
type Usage struct {
	Memory  int64
	CPUs    float64
	Running int
}

// Sum adds up the caps of running VMs, skipping exclude.
func Sum(vms []hyperv.VMInfo, exclude string) Usage {
	var u Usage
	for _, v := range vms {
		if v.Name == exclude || !v.Running() {
			continue
		}
		u.Memory += v.MemoryCap()
		u.CPUs += v.CPUThreads()
		u.Running++
	}
	return u
}

// OverBudgetError explains which limit starting a VM would break and which
// running VMs could be stopped to make room.
type OverBudgetError struct {
	Problems []string
	Running  []hyperv.VMInfo
}

func (e *OverBudgetError) Error() string {
	var b strings.Builder
	b.WriteString("starting this VM would exceed the host budget:\n")
	for _, p := range e.Problems {
		fmt.Fprintf(&b, "  - %s\n", p)
	}
	if len(e.Running) > 0 {
		b.WriteString("Running VMs you could stop (windevvm stop NAME):\n")
		for _, v := range e.Running {
			fmt.Fprintf(&b, "  %s  memory up to %s, %.1f CPUs\n", v.Name, config.Size(v.MemoryCap()), v.CPUThreads())
		}
	}
	b.WriteString("Or raise the [budget] in " + config.GlobalPath())
	return b.String()
}

// CheckBudget reports whether a VM with caps res can start next to the
// running VMs without exceeding the budget.
func CheckBudget(b config.Budget, vms []hyperv.VMInfo, name string, res config.Resources) error {
	u := Sum(vms, name)
	var problems []string
	if u.Running+1 > b.MaxRunning {
		problems = append(problems, fmt.Sprintf("%d VMs would be running; the limit is %d", u.Running+1, b.MaxRunning))
	}
	if mem := u.Memory + int64(res.MemoryMax); mem > int64(b.Memory) {
		problems = append(problems, fmt.Sprintf("memory: %s in use + %s for this VM > %s budget", config.Size(u.Memory), res.MemoryMax, b.Memory))
	}
	if cpu := u.CPUs + res.CPUThreads(); cpu > b.CPUs+1e-9 {
		problems = append(problems, fmt.Sprintf("CPU: %.1f in use + %.1f for this VM > %.1f budget", u.CPUs, res.CPUThreads(), b.CPUs))
	}
	if len(problems) == 0 {
		return nil
	}
	var running []hyperv.VMInfo
	for _, v := range vms {
		if v.Name != name && v.Running() {
			running = append(running, v)
		}
	}
	sort.Slice(running, func(i, j int) bool { return running[i].MemoryCap() > running[j].MemoryCap() })
	return &OverBudgetError{Problems: problems, Running: running}
}
