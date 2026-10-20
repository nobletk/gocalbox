//go:build unix

package load

import (
	"os"
	"syscall"
	"testing"
	"time"
)

// The process's CPU time is the kernel's for it as well as its own: a run
// over HTTPS spends much of it in system calls.
func TestTheCPUTimeCountsTheKernels(t *testing.T) {
	f, err := os.Open("/dev/zero")
	if err != nil {
		t.Skip(err)
	}
	defer f.Close()
	sys := func() time.Duration {
		var ru syscall.Rusage
		if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
			t.Fatal(err)
		}
		return time.Duration(ru.Stime.Nano())
	}
	cpu0, sys0 := processCPU(), sys()
	// Reading zeros is the kernel's work, filling the buffer; little of it is
	// the process's own.
	buf := make([]byte, 1<<20)
	for start := time.Now(); time.Since(start) < 300*time.Millisecond; {
		f.Read(buf)
	}
	cpu, kernel := processCPU()-cpu0, sys()-sys0
	if kernel < 50*time.Millisecond {
		t.Skipf("the kernel's time grew by %v only", kernel)
	}
	if cpu < kernel*8/10 {
		t.Errorf("CPU grew by %v while the kernel's time grew by %v", cpu, kernel)
	}
}
