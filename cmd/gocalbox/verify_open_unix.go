//go:build unix

package main

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// openToVerify opens path for reading without waiting for a writer, as
// opening a FIFO would. A regular file is then read in blocking mode, which
// network and FUSE file systems may otherwise refuse with EAGAIN.
func openToVerify(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.EAGAIN) {
		// Another process holds a write lease on the file, as Samba does for
		// an oplock; only a blocking open waits for it to be broken.
		return os.Open(path)
	}
	if err != nil {
		return nil, err
	}
	if info, err := f.Stat(); err == nil && info.Mode().IsRegular() {
		rc, err := f.SyscallConn()
		if err == nil {
			err = rc.Control(func(fd uintptr) { err = unix.SetNonblock(int(fd), false) })
		}
		if err != nil {
			f.Close()
			return nil, err
		}
	}
	return f, nil
}
