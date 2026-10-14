//go:build !(linux || darwin || freebsd || openbsd || netbsd || dragonfly || windows)

package audit

import "os"

// On other systems nothing stops a second process from writing to the log.
func lockFile(*os.File) error { return nil }

func unlockFile(*os.File) error { return nil }
