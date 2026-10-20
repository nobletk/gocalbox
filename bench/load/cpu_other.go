//go:build !unix && !windows

package load

import "time"

func processCPU() time.Duration { return -1 }
