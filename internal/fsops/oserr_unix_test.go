//go:build unix

package fsops

import "syscall"

var (
	noSpaceErr     error = syscall.ENOSPC
	quotaErr       error = syscall.EDQUOT
	crossDeviceErr error = syscall.EXDEV
	readOnlyErr    error = syscall.EROFS
)
