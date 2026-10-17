//go:build darwin || freebsd

package sandbox

import (
	"os"

	"golang.org/x/sys/unix"
)

func fileSizeLimit(f *os.File) int64 {
	rc, err := f.SyscallConn()
	if err != nil {
		return 0
	}
	var st unix.Statfs_t
	var serr error
	if rc.Control(func(fd uintptr) { serr = unix.Fstatfs(int(fd), &st) }) != nil || serr != nil {
		return 0
	}
	switch unix.ByteSliceToString(st.Fstypename[:]) {
	case "msdos", "msdosfs":
		return fat32Limit
	}
	return 0
}
