package space

import (
	"os"
	"syscall"
)

// Free reports the bytes available to unprivileged writers on the file
// system holding dir. Using the open directory rather than its path keeps
// measuring the served folder even if it is renamed.
func Free(dir *os.File) (int64, error) {
	var st syscall.Statfs_t
	if err := fstatfs(dir, &st); err != nil {
		return 0, err
	}
	// f_frsize is the unit of the block counts; f_bsize is only the preferred
	// I/O size, and some file systems leave f_frsize zero.
	size := int64(st.Frsize)
	if size == 0 {
		size = int64(st.Bsize)
	}
	return clamp(st.Bavail, size), nil
}

func fstatfs(dir *os.File, st *syscall.Statfs_t) error {
	rc, err := dir.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if err := rc.Control(func(fd uintptr) { serr = syscall.Fstatfs(int(fd), st) }); err != nil {
		return err
	}
	return serr
}
