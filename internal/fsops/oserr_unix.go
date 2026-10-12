//go:build unix

package fsops

import (
	"errors"
	"syscall"
)

func isNoSpace(err error) bool {
	return errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EDQUOT)
}

func isCrossDevice(err error) bool { return errors.Is(err, syscall.EXDEV) }

func isReadOnly(err error) bool { return errors.Is(err, syscall.EROFS) }
