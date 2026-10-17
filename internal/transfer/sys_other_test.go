//go:build !unix && !windows

package transfer

import "errors"

var (
	errDiskFull = errors.New("disk full")
	// isTooBig knows no error on these systems.
	errFileTooBig error
)
