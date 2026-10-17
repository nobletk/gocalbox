//go:build unix

package fsops

import (
	"io/fs"
	"os"
	"syscall"
)

// openNonblock makes opening a FIFO return at once instead of waiting for a
// writer.
const openNonblock = syscall.O_NONBLOCK

// clearNonblock undoes openNonblock once the file is known to be regular or
// a directory. Local file systems ignore the flag, but FUSE and network file
// systems may pass it on and answer reads with EAGAIN.
func clearNonblock(f *os.File) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if err := rc.Control(func(fd uintptr) { serr = syscall.SetNonblock(int(fd), false) }); err != nil {
		return err
	}
	return serr
}

func fileID(info fs.FileInfo) (dev, ino uint64) {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Dev), uint64(st.Ino)
	}
	return 0, 0
}

// writable reports whether the server may create entries in the folder dir:
// an error for a read-only file system, an immutable folder or missing
// permission.
func writable(root *os.Root, dir string) error {
	f, err := root.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var aerr error
	if err := rc.Control(func(fd uintptr) { aerr = mayWrite(int(fd)) }); err != nil {
		return err
	}
	return aerr
}

// syncDir makes the entries of the folder dir durable.
func syncDir(root *os.Root, dir string) error {
	f, err := root.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
