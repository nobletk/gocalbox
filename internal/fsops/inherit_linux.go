package fsops

import (
	"errors"
	"io/fs"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

const accessACL = "system.posix_acl_access"

// openUnnamed opens a file without a name in the folder dirfd, which the
// kernel gives the folder's group, permissions and default ACL as it would
// a new file, and which vanishes once closed.
var openUnnamed = func(dirfd int) (int, error) {
	return unix.Openat(dirfd, ".", unix.O_TMPFILE|unix.O_WRONLY|unix.O_CLOEXEC, 0o644)
}

func groupOf(info fs.FileInfo) (int, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Gid), true
}

// inheritedFrom tells what a file created in the folder dir gets from it.
// Where the file system has no unnamed files, only a set-group-ID folder's
// group is given; a file in another folder keeps the group it was created
// with, the server's unless the staging folder is set-group-ID. Volumes
// without unnamed files include FAT and exFAT, where every file has the
// group of the mount and no other can be given.
func inheritedFrom(root *os.Root, dir string) (inherited, error) {
	d, err := root.Open(dir)
	if err != nil {
		return inherited{}, err
	}
	defer d.Close()
	info, err := d.Stat()
	if err != nil {
		return inherited{}, err
	}
	rc, err := d.SyscallConn()
	if err != nil {
		return inherited{}, err
	}
	var in inherited
	var ierr error
	unnamed := false
	if err := rc.Control(func(dirfd uintptr) {
		fd, err := openUnnamed(int(dirfd))
		if err != nil {
			return
		}
		defer unix.Close(fd)
		unnamed = true
		var st unix.Stat_t
		if ierr = unix.Fstat(fd, &st); ierr != nil {
			return
		}
		in = inherited{gid: int(st.Gid), full: true, mode: os.FileMode(st.Mode & 0o777)}
		in.acl, ierr = fgetxattr(fd, accessACL)
	}); err != nil {
		return inherited{}, err
	}
	if unnamed {
		return in, ierr
	}
	in.gid = -1
	if gid, ok := groupOf(info); ok && info.Mode()&fs.ModeSetgid != 0 {
		in.gid = gid
	}
	return in, nil
}

// fgetxattr reads the attribute name of fd, nil if it has none.
func fgetxattr(fd int, name string) ([]byte, error) {
	buf := make([]byte, 256)
	for {
		n, err := unix.Fgetxattr(fd, name, buf)
		switch {
		case err == nil:
			return buf[:n], nil
		case errors.Is(err, unix.ENODATA), errors.Is(err, unix.EOPNOTSUPP):
			return nil, nil
		case errors.Is(err, unix.ERANGE):
			if n, err = unix.Fgetxattr(fd, name, nil); err != nil {
				return nil, err
			}
			buf = make([]byte, n)
		default:
			return nil, err
		}
	}
}

// giveTo gives f the group, and where they are known the permissions and
// access ACL, of in.
func (in inherited) giveTo(f *os.File) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var gerr error
	if err := rc.Control(func(p uintptr) {
		fd := int(p)
		var st unix.Stat_t
		if gerr = unix.Fstat(fd, &st); gerr != nil {
			return
		}
		if in.gid >= 0 && int(st.Gid) != in.gid {
			if gerr = unix.Fchown(fd, -1, in.gid); gerr != nil {
				return
			}
		}
		if !in.full {
			return
		}
		if in.acl != nil {
			gerr = unix.Fsetxattr(fd, accessACL, in.acl, 0)
		} else if err := unix.Fremovexattr(fd, accessACL); err != nil && !errors.Is(err, unix.ENODATA) && !errors.Is(err, unix.EOPNOTSUPP) {
			gerr = err
		}
		if gerr == nil {
			gerr = unix.Fchmod(fd, uint32(in.mode))
		}
	}); err != nil {
		return err
	}
	return gerr
}
