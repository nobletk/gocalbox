package lib

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Mark names the marker file of a benchmark folder.
const Mark = ".gocalbox-bench"

var markLine = regexp.MustCompile(`^gocalbox-bench ([0-9a-f]{32})(\r?\n)?$`)

// Folder is a benchmark folder, made by bench/init.sh: everything a
// benchmark writes lives in it, and it deletes nothing outside it.
type Folder struct {
	Dir string // its real path
	ID  string // its marker's ID
	dev uint64
	// hasDev is false where the file system can't be told from a file's
	// information; there, links and other reparse points are never entered.
	hasDev bool
}

// Use checks that dir is a benchmark folder: an absolute path to a folder,
// not a link, that holds the marker bench/init.sh leaves.
func Use(dir string) (*Folder, error) {
	if dir == "" {
		return nil, errors.New("no benchmark folder given; make one with bench/init.sh")
	}
	if !filepath.IsAbs(dir) {
		return nil, fmt.Errorf("the benchmark folder must be an absolute path: %s", dir)
	}
	fi, err := os.Lstat(dir)
	if err != nil || !fi.IsDir() {
		return nil, fmt.Errorf("not a folder: %s", dir)
	}
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, err
	}
	if filepath.Dir(real) == real {
		return nil, fmt.Errorf("the benchmark folder can't be the root of a disk: %s", dir)
	}
	notOne := fmt.Errorf("%s is not a benchmark folder; make one with bench/init.sh", dir)
	mfi, err := os.Lstat(filepath.Join(real, Mark))
	if err != nil || !mfi.Mode().IsRegular() || mfi.Size() > 64 {
		return nil, notOne
	}
	b, err := os.ReadFile(filepath.Join(real, Mark))
	m := markLine.FindSubmatch(b)
	if err != nil || m == nil {
		return nil, notOne
	}
	rfi, err := os.Lstat(real)
	if err != nil {
		return nil, err
	}
	f := &Folder{Dir: real, ID: string(m[1])}
	f.dev, f.hasDev = device(rfi)
	return f, nil
}

// Inside returns p as it lies in the folder, with its parent's links
// resolved. p must be absolute, not a link, not the folder itself or its
// marker, and, if it exists, on the folder's file system, with nothing
// mounted inside the folder on the way to it, at it or inside it.
func (f *Folder) Inside(p string) (string, error) {
	if p == "" {
		return "", errors.New("an empty path")
	}
	if !filepath.IsAbs(p) {
		return "", fmt.Errorf("not an absolute path: %s", p)
	}
	for len(p) > len(filepath.VolumeName(p))+1 && os.IsPathSeparator(p[len(p)-1]) {
		p = p[:len(p)-1]
	}
	base := filepath.Base(p)
	if base == "." || base == ".." || len(base) == 1 && os.IsPathSeparator(base[0]) {
		return "", fmt.Errorf("not a name: %s", p)
	}
	fi, err := os.Lstat(p)
	if err == nil && fi.Mode()&fs.ModeSymlink != 0 {
		return "", fmt.Errorf("a link: %s", p)
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(p))
	if err != nil {
		return "", fmt.Errorf("no such folder: %s", filepath.Dir(p))
	}
	real := filepath.Join(parent, base)
	if !strings.HasPrefix(real, f.Dir+string(filepath.Separator)) {
		return "", fmt.Errorf("outside the benchmark folder %s: %s", f.Dir, p)
	}
	if real == filepath.Join(f.Dir, Mark) {
		return "", fmt.Errorf("the benchmark folder's marker: %s", p)
	}
	if fi, err := os.Lstat(real); err == nil && f.hasDev {
		if d, ok := device(fi); ok && d != f.dev {
			return "", fmt.Errorf("on another file system than the benchmark folder: %s", p)
		}
	}
	switch m, err := mountedOnTheWay(f.Dir, real); {
	case err != nil:
		return "", fmt.Errorf("reading the mount table: %w", err)
	case m:
		return "", fmt.Errorf("a file system is mounted in the benchmark folder on the way to, at or inside %s", p)
	}
	return real, nil
}

// Remove deletes each path, which must lie in the folder, with what it
// holds; a path that doesn't exist is skipped. It stops at the first path
// refused, and never enters a link or another file system.
func (f *Folder) Remove(paths ...string) error {
	if len(paths) == 0 {
		return errors.New("nothing to delete")
	}
	for _, p := range paths {
		real, err := f.Inside(p)
		if err != nil {
			return err
		}
		if err := f.removeTree(real); err != nil {
			return err
		}
	}
	return nil
}

func (f *Folder) removeTree(p string) error {
	fi, err := os.Lstat(p)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return err
	case !fi.IsDir():
		// A link, a junction or a mount point is removed, not entered.
		return os.Remove(p)
	}
	if f.hasDev {
		if d, ok := device(fi); ok && d != f.dev {
			return fmt.Errorf("on another file system than the benchmark folder: %s", p)
		}
	}
	entries, err := os.ReadDir(p)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := f.removeTree(filepath.Join(p, e.Name())); err != nil {
			return err
		}
	}
	return os.Remove(p)
}
