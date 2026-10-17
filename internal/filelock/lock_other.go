//go:build !(linux || darwin || freebsd || openbsd || netbsd || dragonfly || windows)

package filelock

import "os"

// On other systems nothing stops a second process from using the file.
func Lock(*os.File) error { return nil }

func Unlock(*os.File) error { return nil }
