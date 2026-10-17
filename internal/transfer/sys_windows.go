package transfer

import (
	"errors"
	"os"
	"syscall"
)

const (
	errorHandleDiskFull    syscall.Errno = 39
	errorDiskFull          syscall.Errno = 112
	errorFileTooLarge      syscall.Errno = 223
	errorDiskQuotaExceeded syscall.Errno = 1295
)

// Go opens a folder on Windows with a handle that can't be flushed; NTFS's
// own journal is all that makes a new entry durable there.
func syncDir(*os.Root, string) error { return nil }

func isNoSpace(err error) bool {
	return errors.Is(err, errorDiskFull) || errors.Is(err, errorHandleDiskFull) || errors.Is(err, errorDiskQuotaExceeded)
}

func isTooBig(err error) bool { return errors.Is(err, errorFileTooLarge) }
