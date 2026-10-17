package sandbox

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"

	"github.com/nobletk/gocalbox/internal/filelock"
)

// The server's own folders inside ReservedName.
const (
	UploadsDir = ReservedName + "/uploads"
	TmpDir     = ReservedName + "/tmp"
	TrashDir   = ReservedName + "/trash"
	lockName   = ReservedName + "/lock"
)

var stagingDirs = []string{ReservedName, UploadsDir, TmpDir, TrashDir}

// ErrStagingLocked means another process serves the same folder.
var ErrStagingLocked = errors.New("another gocalbox serves this folder")

// tempName matches the names TempName makes, and those of single-request
// uploads staged in TmpDir.
var tempName = regexp.MustCompile(`^[ns]-[0-9a-f]{32}$`)

// TempName returns a new name for a short-lived file or folder in TmpDir,
// one that start-up removes if a crash leaves it behind.
func TempName() string {
	var b [16]byte
	rand.Read(b[:])
	return "n-" + hex.EncodeToString(b[:])
}

// Staging is ReservedName at the root as start-up found it.
type Staging struct {
	// Problem says why nothing may be kept there, neither uploads nor
	// deleted folders, or is nil.
	Problem error
	// Warning, if set, says why the folder was accepted although it isn't
	// private to the server.
	Warning string
	// Links reports whether hard links work on its volume.
	Links bool
	// MaxFileSize is the largest file its volume holds, or 0 if no limit
	// that matters is known.
	MaxFileSize int64
	// Unknown lists entries of TmpDir that the server didn't make, which
	// start-up leaves alone.
	Unknown []string

	lock *os.File
}

func (s *Staging) Usable() bool { return s.Problem == nil }

// Close releases the lock on the folder.
func (s *Staging) Close() error {
	if s.lock == nil {
		return nil
	}
	err := filelock.Unlock(s.lock)
	if cerr := s.lock.Close(); err == nil {
		err = cerr
	}
	s.lock = nil
	return err
}

// CheckStaging makes sure ReservedName at the root of root and its folders
// exist, are real folders on the root's volume, and belong to the server
// alone; locks the folder; then removes what earlier runs left in TmpDir and
// tests hard links. Only the lock makes it fail, with ErrStagingLocked while
// another process holds it, before anything in TmpDir is removed; every
// other problem goes into Problem, and one found after the lock is taken
// leaves it held.
func CheckStaging(root *os.Root) (*Staging, error) {
	s := &Staging{}
	if s.Problem = s.check(root); s.Problem != nil {
		return s, nil
	}
	if err := s.takeLock(root); err != nil {
		if errors.Is(err, ErrStagingLocked) {
			return nil, err
		}
		s.Problem = err
		return s, nil
	}
	s.Problem = s.prepare(root)
	return s, nil
}

func (s *Staging) check(root *os.Root) error {
	rootVolume, volumeErr := VolumeOf(root, ".")
	for _, dir := range stagingDirs {
		if err := ensureDir(root, dir); err != nil {
			return err
		}
		if volumeErr != nil {
			continue
		}
		if v, err := VolumeOf(root, dir); err == nil && v != rootVolume {
			return fmt.Errorf("%s is on another file system than the served folder", dir)
		}
	}
	for _, dir := range stagingDirs {
		warning, err := checkPrivate(root, dir)
		if err != nil {
			return err
		}
		if warning != "" && s.Warning == "" {
			s.Warning = warning
		}
	}
	return nil
}

func (s *Staging) prepare(root *os.Root) error {
	if err := s.clearTmp(root); err != nil {
		return err
	}
	if err := s.testLinks(root); err != nil {
		return err
	}
	if f, err := root.Open(UploadsDir); err == nil {
		s.MaxFileSize = fileSizeLimit(f)
		f.Close()
	}
	return nil
}

func ensureDir(root *os.Root, dir string) error {
	native := filepath.FromSlash(dir)
	info, err := root.Lstat(native)
	if errors.Is(err, fs.ErrNotExist) {
		if err := root.Mkdir(native, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("create %s: %w", dir, err)
		}
		info, err = root.Lstat(native)
	}
	if err != nil {
		return fmt.Errorf("check %s: %w", dir, err)
	}
	if info.Mode().Type() != fs.ModeDir {
		return fmt.Errorf("%s is not a folder but a %s", dir, kindOf(info))
	}
	return nil
}

func kindOf(info fs.FileInfo) string {
	switch t := info.Mode().Type(); {
	case t&fs.ModeSymlink != 0:
		return "symlink"
	case t == 0:
		return "file"
	}
	return "link to another place, or a special file"
}

func (s *Staging) clearTmp(root *os.Root) error {
	d, err := root.Open(filepath.FromSlash(TmpDir))
	if err != nil {
		return fmt.Errorf("open %s: %w", TmpDir, err)
	}
	names, err := d.Readdirnames(-1)
	d.Close()
	if err != nil {
		return fmt.Errorf("read %s: %w", TmpDir, err)
	}
	for _, name := range names {
		if !tempName.MatchString(name) {
			s.Unknown = append(s.Unknown, name)
			continue
		}
		if err := root.RemoveAll(filepath.FromSlash(path.Join(TmpDir, name))); err != nil {
			return fmt.Errorf("remove %s/%s: %w", TmpDir, name, err)
		}
	}
	return nil
}

func (s *Staging) testLinks(root *os.Root) error {
	from := filepath.FromSlash(path.Join(TmpDir, TempName()))
	to := filepath.FromSlash(path.Join(TmpDir, TempName()))
	f, err := root.OpenFile(from, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("write in %s: %w", TmpDir, err)
	}
	f.Close()
	s.Links = root.Link(from, to) == nil
	root.Remove(to)
	if err := root.Remove(from); err != nil {
		return fmt.Errorf("remove a file in %s: %w", TmpDir, err)
	}
	return nil
}

func (s *Staging) takeLock(root *os.Root) error {
	native := filepath.FromSlash(lockName)
	if info, err := root.Lstat(native); err == nil && !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a file but a %s", lockName, kindOf(info))
	}
	f, err := root.OpenFile(native, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("open %s: %w", lockName, err)
	}
	if err := filelock.Lock(f); err != nil {
		f.Close()
		if errors.Is(err, filelock.ErrLocked) {
			return ErrStagingLocked
		}
		return fmt.Errorf("lock %s: %w", lockName, err)
	}
	s.lock = f
	return nil
}
