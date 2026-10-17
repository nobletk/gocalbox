//go:build unix

package transfer

import (
	"errors"
	"os"
	"syscall"
)

// syncDir makes the entries of the folder dir durable.
func syncDir(root *os.Root, dir string) error {
	f, err := root.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func isNoSpace(err error) bool {
	return errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EDQUOT)
}

func isTooBig(err error) bool { return errors.Is(err, syscall.EFBIG) }
