package sandbox

import (
	"errors"
	"os"
	"path/filepath"
)

// Volume identifies the file system a folder is on, as far as links and
// renames are concerned: between folders of one Volume they work, between
// two they fail as crossing devices.
type Volume struct {
	dev   uint64
	mount uint64 // Linux's mount ID; 0 where none is known
}

// SameDisk reports whether v and w are one file system, and so share free
// space, although links between them may fail, as across a bind mount.
func (v Volume) SameDisk(w Volume) bool { return v.dev == w.dev }

var errNoVolume = errors.New("this system tells no volume identity")

// VolumeOf returns the Volume of the folder name inside root.
func VolumeOf(root *os.Root, name string) (Volume, error) {
	f, err := root.Open(filepath.FromSlash(name))
	if err != nil {
		return Volume{}, err
	}
	defer f.Close()
	return volumeOf(f)
}
