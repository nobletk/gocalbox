//go:build unix && !linux

package fsops

import "golang.org/x/sys/unix"

// mayWrite asks the kernel whether the server may write in the folder fd,
// for its real user ID, which is the server's own.
func mayWrite(fd int) error { return unix.Faccessat(fd, ".", unix.W_OK, 0) }
