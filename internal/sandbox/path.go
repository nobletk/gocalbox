// Package sandbox confines client-supplied paths to one root directory.
package sandbox

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
)

var (
	ErrTraversal   = errors.New("security violation: path escapes the sandbox")
	ErrRootTarget  = errors.New("operation not permitted on the sandbox root")
	ErrBrokenLink  = errors.New("path goes through a broken symlink")
	ErrInvalidPath = errors.New("invalid path")
	ErrReserved    = errors.New("reserved path")
	// ErrUnnamable marks a client path that stays in the root but names what
	// the system can't hold: on Windows a device, such as NUL, or a name with
	// a colon.
	ErrUnnamable = fmt.Errorf("%w: a name in it can't be held here", ErrInvalidPath)
)

// ReservedName is the server's own folder, at the root for the upload engine
// and the trash of deleted folders. It is refused at any depth.
const ReservedName = ".gocalbox"

// IsReserved reports whether a volume may take name for ReservedName: in
// any letter case; with trailing dots and spaces, which Windows drops (FAT
// and exFAT drop the dots on Linux too); and as the 8.3 short name FAT and
// Windows give it, which Linux finds as well; and on Windows with a stream
// after a colon, since on NTFS .gocalbox::$INDEX_ALLOCATION is the folder
// itself. Short names a volume makes after collisions, such as GO3F2A~1,
// can't be told from the name; changes check the stored spelling of their
// folders for those.
func IsReserved(name string) bool {
	if filepath.Separator == '\\' {
		if i := strings.IndexByte(name, ':'); i >= 0 {
			name = name[:i]
		}
	}
	name = strings.TrimRight(name, ". ")
	if strings.EqualFold(name, ReservedName) {
		return true
	}
	const short = "GOCALB~"
	if len(name) <= len(short) || !strings.EqualFold(name[:len(short)], short) {
		return false
	}
	return strings.Trim(name[len(short):], "0123456789") == ""
}

// HasReserved reports whether any component of the path rel is reserved.
func HasReserved(rel string) bool {
	return slices.ContainsFunc(strings.Split(filepath.ToSlash(rel), "/"), IsReserved)
}

type Sandbox struct {
	root string
	fs   *os.Root
}

type Path struct {
	// Rel is canonical (no symlinks, "." or ".."), so access rules must use it.
	// On case-insensitive file systems, spellings differing in case or Unicode
	// normalization can still give different Rel values.
	Rel string
	Abs string
}

func (p Path) Native() string { return filepath.FromSlash(p.Rel) }

func (p Path) Contains(q Path) bool {
	return p.Rel == "." || q.Rel == p.Rel || strings.HasPrefix(q.Rel, p.Rel+"/")
}

func New(rootDir string) (*Sandbox, error) {
	abs, err := filepath.Abs(rootDir)
	if err != nil {
		return nil, fmt.Errorf("resolve root %q: %w", rootDir, err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, fmt.Errorf("resolve root %q: %w", rootDir, err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return nil, fmt.Errorf("stat root %q: %w", rootDir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("root %q is not a directory", rootDir)
	}
	r, err := os.OpenRoot(resolved)
	if err != nil {
		return nil, fmt.Errorf("open root %q: %w", rootDir, err)
	}
	return &Sandbox{root: resolved, fs: r}, nil
}

func (s *Sandbox) Root() string { return s.root }

func (s *Sandbox) OSRoot() *os.Root { return s.fs }

func (s *Sandbox) Close() error { return s.fs.Close() }

func (s *Sandbox) Resolve(userPath string) (Path, error) {
	rel, err := cleanRel(userPath)
	if err != nil {
		return Path{}, err
	}
	full, err := evalExisting(filepath.Join(s.root, rel))
	if err != nil {
		return Path{}, err
	}
	return s.path(full)
}

func (s *Sandbox) ResolveEntry(userPath string) (Path, error) {
	rel, err := cleanRel(userPath)
	if err != nil {
		return Path{}, err
	}
	if rel == "." {
		return Path{}, ErrRootTarget
	}
	parent, err := evalExisting(filepath.Join(s.root, filepath.Dir(rel)))
	if err != nil {
		return Path{}, err
	}
	if !Within(s.root, parent) {
		return Path{}, ErrTraversal
	}
	return s.path(filepath.Join(parent, filepath.Base(rel)))
}

func (s *Sandbox) path(abs string) (Path, error) {
	if !Within(s.root, abs) {
		return Path{}, ErrTraversal
	}
	rel, err := filepath.Rel(s.root, abs)
	if err != nil {
		return Path{}, ErrTraversal
	}
	if HasReserved(rel) {
		return Path{}, ErrReserved
	}
	return Path{Rel: path.Clean(filepath.ToSlash(rel)), Abs: abs}, nil
}

const rootEscapeMsg = "path escapes from parent"

func FromRoot(err error) error {
	for e := err; e != nil; e = errors.Unwrap(e) {
		if e.Error() == rootEscapeMsg {
			return fmt.Errorf("%w: %v", ErrTraversal, err)
		}
	}
	if IsBadName(err) {
		return fmt.Errorf("%w: %v", ErrInvalidPath, err)
	}
	return err
}

// ResolveExisting resolves the symlinks in the longest prefix of the
// absolute path that exists, and appends the rest unchanged. Checking it
// against the root before creating the missing folders keeps a path that
// reaches the root through a symlink from creating anything there.
func ResolveExisting(path string) (string, error) {
	var rest []string
	for p := path; ; {
		if _, err := os.Lstat(p); err == nil {
			resolved, err := filepath.EvalSymlinks(p)
			if err != nil {
				return "", err
			}
			return filepath.Join(append([]string{resolved}, rest...)...), nil
		}
		parent := filepath.Dir(p)
		if parent == p {
			return path, nil
		}
		rest = append([]string{filepath.Base(p)}, rest...)
		p = parent
	}
}

func Within(base, target string) bool {
	rel, err := filepath.Rel(base, target)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// Clean checks a client's path without reading the file system and returns
// it cleaned and slash-separated. Its errors therefore tell nothing about
// what exists.
func Clean(userPath string) (string, error) {
	rel, err := cleanRel(userPath)
	return filepath.ToSlash(rel), err
}

func cleanRel(userPath string) (string, error) {
	if strings.ContainsRune(userPath, 0) {
		return "", ErrInvalidPath
	}
	trimmed := strings.TrimLeft(userPath, "/"+string(filepath.Separator))
	rel := filepath.Clean(filepath.FromSlash(trimmed))
	if rel != "." && !filepath.IsLocal(rel) {
		if leavesRoot(userPath, trimmed) {
			return "", ErrTraversal
		}
		if HasReserved(rel) {
			return "", ErrReserved
		}
		return "", ErrUnnamable
	}
	// Client paths are separated by "/" only, on every system.
	if filepath.Separator == '\\' && strings.ContainsRune(userPath, '\\') {
		return "", ErrInvalidPath
	}
	if HasReserved(rel) {
		return "", ErrReserved
	}
	return rel, nil
}

// leavesRoot reports whether a client path that filepath.IsLocal refuses
// leaves the root: through "..", or as an absolute path of Windows, which
// starts with a drive and a separator, or with a share or device prefix such
// as \\server\share or \\?\. Otherwise it is refused only for a name the
// system can't hold; a drive letter and a colon with no separator after them
// are such a name. Leading separators are read as the root, so two slashes
// before a name are no share: a share prefix counts only with a backslash in
// its first two characters, or as a device prefix in either slash. trimmed is
// userPath without its leading separators.
func leavesRoot(userPath, trimmed string) bool {
	if len(filepath.VolumeName(userPath)) > 2 {
		switch strings.ReplaceAll(userPath[:min(4, len(userPath))], "/", `\`) {
		case `\\?\`, `\\.\`, `\??\`:
			return true
		}
		if userPath[0] == '\\' || userPath[1] == '\\' {
			return true
		}
	}
	if v := filepath.VolumeName(trimmed); v != "" && len(trimmed) > len(v) && os.IsPathSeparator(trimmed[len(v)]) {
		return true
	}
	if filepath.Separator == '\\' {
		trimmed = strings.ReplaceAll(trimmed, `\`, "/")
	}
	c := path.Clean(trimmed)
	return c == ".." || strings.HasPrefix(c, "../")
}

func isLoop(err error) bool {
	return errors.Is(err, syscall.ELOOP) || strings.Contains(err.Error(), "too many links")
}

func evalExisting(p string) (string, error) {
	var missing []string
	cur := p
	for {
		resolved, err := filepath.EvalSymlinks(cur)
		if err == nil {
			for i := len(missing) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, missing[i])
			}
			return resolved, nil
		}
		if isLoop(err) {
			return "", fmt.Errorf("%w: %v", ErrBrokenLink, err)
		}
		if IsBadName(err) {
			return "", fmt.Errorf("%w: %v", ErrInvalidPath, err)
		}
		if !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, syscall.ENOTDIR) {
			return "", err
		}
		if _, lerr := os.Lstat(cur); lerr == nil {
			return "", ErrBrokenLink
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return "", err
		}
		missing = append(missing, filepath.Base(cur))
		cur = parent
	}
}
