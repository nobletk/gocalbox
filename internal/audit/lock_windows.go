//go:build windows

package audit

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// The lock covers one byte far beyond the end of the file: Windows locks are
// mandatory, and a lock on the data would also stop this process's own reads
// through another handle, such as Verify's. LockFileEx needs a handle with
// read or write access; one opened only for appending is refused.
func lockRange() *windows.Overlapped {
	return &windows.Overlapped{Offset: ^uint32(0), OffsetHigh: ^uint32(0)}
}

func lockFile(f *os.File) error {
	err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, lockRange())
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return ErrLocked
	}
	return err
}

func unlockFile(f *os.File) error {
	return windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, lockRange())
}
