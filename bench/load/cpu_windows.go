package load

import (
	"syscall"
	"time"
)

func processCPU() time.Duration {
	h, err := syscall.GetCurrentProcess()
	if err != nil {
		return -1
	}
	var created, exited, kernel, user syscall.Filetime
	if err := syscall.GetProcessTimes(h, &created, &exited, &kernel, &user); err != nil {
		return -1
	}
	ticks := func(f syscall.Filetime) int64 { return int64(f.HighDateTime)<<32 | int64(f.LowDateTime) }
	return time.Duration(ticks(kernel)+ticks(user)) * 100
}
