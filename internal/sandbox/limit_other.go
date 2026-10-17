//go:build !linux && !darwin && !freebsd && !windows

package sandbox

import "os"

func fileSizeLimit(*os.File) int64 { return 0 }
