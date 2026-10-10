// Package sandbox confines client-supplied paths to one root directory.
package sandbox

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
)

var (
	ErrTraversal   = errors.New("security violation: path escapes the sandbox")
	ErrRootTarget  = errors.New("operation not permitted on the sandbox root")
	ErrBrokenLink  = errors.New("path goes through a broken symlink")
	ErrInvalidPath = errors.New("invalid path")
)

type Sandbox struct {
	root string
	fs   *os.Root
}

type Path struct {
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
	return Path{Rel: path.Clean(filepath.ToSlash(rel)), Abs: abs}, nil
}

const rootEscapeMsg = "path escapes from parent"

func FromRoot(err error) error {
	for e := err; e != nil; e = errors.Unwrap(e) {
		if e.Error() == rootEscapeMsg {
			return fmt.Errorf("%w: %v", ErrTraversal, err)
		}
	}
	if errors.Is(err, syscall.ENAMETOOLONG) {
		return fmt.Errorf("%w: %v", ErrInvalidPath, err)
	}
	return err
}

func Within(base, target string) bool {
	rel, err := filepath.Rel(base, target)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func cleanRel(userPath string) (string, error) {
	if strings.ContainsRune(userPath, 0) {
		return "", ErrInvalidPath
	}
	trimmed := strings.TrimLeft(userPath, "/"+string(filepath.Separator))
	rel := filepath.Clean(filepath.FromSlash(trimmed))
	if rel == "." {
		return ".", nil
	}
	if !filepath.IsLocal(rel) {
		return "", ErrTraversal
	}
	return rel, nil
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
		if errors.Is(err, syscall.ENAMETOOLONG) {
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
