//go:build unix

package transfer

import "syscall"

var (
	errDiskFull   error = syscall.ENOSPC
	errFileTooBig error = syscall.EFBIG
)
