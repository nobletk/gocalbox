package space

import (
	"os"
	"syscall"
)

// Free reports the bytes available to unprivileged writers on the file
// system holding dir. Using the open directory rather than its path keeps
// measuring the served folder even if it is renamed.
func Free(dir *os.File) (int64, error) {
	rc, err := dir.SyscallConn()
	if err != nil {
		return 0, err
	}
	var st syscall.Statfs_t
	var serr error
	if err := rc.Control(func(fd uintptr) { serr = syscall.Fstatfs(int(fd), &st) }); err != nil {
		return 0, err
	}
	if serr != nil {
		return 0, serr
	}
	return clamp(st.Bavail, int64(st.Bsize)), nil
}
