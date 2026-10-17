// Package filelock takes exclusive locks on open files, so that a second
// process using the same file fails at once instead of interfering.
package filelock

import "errors"

// ErrLocked is returned by Lock while another process holds the lock.
var ErrLocked = errors.New("the file is locked by another process")
