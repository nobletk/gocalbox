//go:build !windows

package sandbox

import (
	"errors"
	"syscall"
)

// IsBadName reports whether the file system refused a name it cannot hold,
// which is the client's error, not the server's.
func IsBadName(err error) bool { return errors.Is(err, syscall.ENAMETOOLONG) }
