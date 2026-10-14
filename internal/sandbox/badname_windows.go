package sandbox

import (
	"errors"
	"syscall"
)

// Windows reports a name it cannot hold, too long or with a character it
// forbids, with these errors rather than ENAMETOOLONG.
const (
	errorInvalidName        syscall.Errno = 123
	errorBadPathname        syscall.Errno = 161
	errorFilenameExcedRange syscall.Errno = 206
)

// IsBadName reports whether the file system refused a name it cannot hold,
// which is the client's error, not the server's.
func IsBadName(err error) bool {
	return errors.Is(err, errorInvalidName) || errors.Is(err, errorBadPathname) ||
		errors.Is(err, errorFilenameExcedRange) || errors.Is(err, syscall.ENAMETOOLONG)
}
