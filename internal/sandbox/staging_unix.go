//go:build unix

package sandbox

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"syscall"
)

// checkPrivate makes sure dir belongs to the server and no one else may use
// it. Some volumes, such as FAT, exFAT, FUSE file systems and SMB shares
// without Unix extensions, take every file's owner and mode from their mount
// options and silently ignore chmod; a folder on one of those is accepted
// with a warning, since every file there has the same owner and mode anyway.
// Such a volume is told by what it does to a new folder, not by its name.
func checkPrivate(root *os.Root, dir string) (warning string, err error) {
	native := filepath.FromSlash(dir)
	info, err := root.Lstat(native)
	if err != nil {
		return "", fmt.Errorf("check %s: %w", dir, err)
	}
	if ownPrivate(info) {
		return "", nil
	}
	if owned(info) {
		root.Chmod(native, info.Mode().Perm()&^0o077)
		if info, err = root.Lstat(native); err != nil {
			return "", fmt.Errorf("check %s: %w", dir, err)
		}
		if ownPrivate(info) {
			return "", nil
		}
	}
	setByMount, err := volumeSetsModes(root)
	if err != nil {
		return "", fmt.Errorf("%s %s, and no folder to test its volume could be made: %w", dir, whyNotPrivate(info), err)
	}
	if !setByMount {
		return "", fmt.Errorf("%s %s", dir, whyNotPrivate(info))
	}
	return fmt.Sprintf("%s %s, because its volume sets owners and modes from its mount options; mount it with uid=%d and dmask=077 to make it private to the server",
		ReservedName, whyNotPrivate(info), os.Geteuid()), nil
}

func owned(info fs.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Geteuid()
}

// ownPrivate reports whether info is the server's own, with no permission
// bits for group or others; set-group-ID and the other special bits don't
// matter.
func ownPrivate(info fs.FileInfo) bool { return owned(info) && info.Mode().Perm()&0o077 == 0 }

func whyNotPrivate(info fs.FileInfo) string {
	if st, ok := info.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
		return fmt.Sprintf("belongs to user ID %d, not to the server's %d", st.Uid, os.Geteuid())
	}
	return fmt.Sprintf("is open to other users (mode %04o)", info.Mode().Perm())
}

// volumeSetsModes makes a private folder in TmpDir and reports whether it
// came back someone else's or open to others.
var volumeSetsModes = func(root *os.Root) (bool, error) {
	name := filepath.FromSlash(path.Join(TmpDir, TempName()))
	if err := root.Mkdir(name, 0o700); err != nil {
		return false, err
	}
	defer root.Remove(name)
	info, err := root.Lstat(name)
	if err != nil {
		return false, err
	}
	return !ownPrivate(info), nil
}
