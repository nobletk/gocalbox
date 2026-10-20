//go:build unix

package load

import (
	"syscall"
	"time"
)

func processCPU() time.Duration {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return -1
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}
