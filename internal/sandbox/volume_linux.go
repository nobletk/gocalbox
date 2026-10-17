package sandbox

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// A bind mount keeps its file system's device number but gets a mount ID of
// its own; a btrfs subvolume keeps the mount but gets a device number of its
// own. Links and renames fail across either, so both must match. Kernels
// before 5.8 report no mount ID, and before 4.11, or under some seccomp
// filters, statx itself is missing.
func volumeOf(f *os.File) (Volume, error) {
	rc, err := f.SyscallConn()
	if err != nil {
		return Volume{}, err
	}
	var st unix.Statx_t
	var serr error
	if err := rc.Control(func(fd uintptr) {
		serr = unix.Statx(int(fd), "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &st)
	}); err != nil {
		return Volume{}, err
	}
	if errors.Is(serr, unix.ENOSYS) || errors.Is(serr, unix.EPERM) {
		return volumeOfStat(f)
	}
	if serr != nil {
		return Volume{}, serr
	}
	v := Volume{dev: unix.Mkdev(st.Dev_major, st.Dev_minor)}
	if st.Mask&unix.STATX_MNT_ID != 0 {
		v.mount = st.Mnt_id
	}
	return v, nil
}
