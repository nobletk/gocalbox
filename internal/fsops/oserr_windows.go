package fsops

import (
	"errors"
	"syscall"
)

const (
	errorNotSameDevice     syscall.Errno = 17
	errorWriteProtect      syscall.Errno = 19
	errorHandleDiskFull    syscall.Errno = 39
	errorDiskFull          syscall.Errno = 112
	errorDiskQuotaExceeded syscall.Errno = 1295
)

func isNoSpace(err error) bool {
	return errors.Is(err, errorDiskFull) || errors.Is(err, errorHandleDiskFull) || errors.Is(err, errorDiskQuotaExceeded)
}

func isCrossDevice(err error) bool { return errors.Is(err, errorNotSameDevice) }

func isReadOnly(err error) bool { return errors.Is(err, errorWriteProtect) }
