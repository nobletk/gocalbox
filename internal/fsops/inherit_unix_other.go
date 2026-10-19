//go:build unix && !linux

package fsops

import (
	"io/fs"
	"os"
	"runtime"
	"syscall"
)

func groupOf(info fs.FileInfo) (int, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Gid), true
}

// inheritedFrom tells the group a file created in the folder dir gets: on
// the BSDs and macOS always the folder's, elsewhere the folder's if it is
// set-group-ID; a file in another folder keeps the group it was created
// with.
func inheritedFrom(root *os.Root, dir string) (inherited, error) {
	info, err := root.Stat(dir)
	if err != nil {
		return inherited{}, err
	}
	gid, ok := groupOf(info)
	if !ok {
		return inherited{gid: -1}, nil
	}
	switch runtime.GOOS {
	case "darwin", "ios", "freebsd", "netbsd", "openbsd", "dragonfly":
		return inherited{gid: gid}, nil
	}
	if info.Mode()&fs.ModeSetgid == 0 {
		gid = -1
	}
	return inherited{gid: gid}, nil
}

func (in inherited) giveTo(f *os.File) error {
	if in.gid < 0 {
		return nil
	}
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if gid, ok := groupOf(info); ok && gid == in.gid {
		return nil
	}
	return f.Chown(-1, in.gid)
}
