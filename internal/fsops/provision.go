package fsops

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/state"
)

type IfExists int

const (
	Reuse         IfExists = iota // an existing folder is kept
	Refuse                        // an existing entry is a conflict
	TakeOverEmpty                 // an existing folder is kept only if it is empty
)

type Folder struct {
	Path     string // relative to the root, slash-separated, no symlinks
	Detail   string // recorded in the folder.created event
	IfExists IfExists
}

// ConflictError lists the folders that exist although their IfExists says
// they may not; nothing was created.
type ConflictError struct {
	Paths []string
}

func (e *ConflictError) Error() string {
	return "already exists: " + strings.Join(e.Paths, ", ")
}

func (e *ConflictError) Unwrap() error { return ErrExists }

// Provision creates the missing folders in order, then runs commit, all under
// the lock that serializes changes. If any folder conflicts, nothing is
// created; if creating one or commit fails, the folders created by this call
// are removed again. A symlink or a file in a folder's place is always a
// conflict, and so is a folder that a case-insensitive volume finds under
// another spelling, since bindings name the spelling the directory stores.
func (s *Service) Provision(ctx context.Context, folders []Folder, commit func() error) error {
	for _, f := range folders {
		if !validLayoutPath(f.Path) {
			return fmt.Errorf("%w: %q", ErrInvalidName, f.Path)
		}
	}
	s.mu.Lock()
	created, err := s.provision(folders, commit)
	s.mu.Unlock()
	for _, f := range created {
		s.publish(ctx, events.Event{Type: events.FolderCreated, Path: f.Path, Resolved: f.Path, Detail: f.Detail}, nil)
	}
	return err
}

func (s *Service) provision(folders []Folder, commit func() error) ([]Folder, error) {
	var conflicts []string
	missing := make([]bool, len(folders))
	for i, f := range folders {
		info, err := s.root.Lstat(filepath.FromSlash(f.Path))
		switch {
		case notExist(err):
			missing[i] = true
		case err != nil:
			return nil, osErr(fmt.Errorf("stat %s: %w", f.Path, err))
		case !info.IsDir() || f.IfExists == Refuse:
			conflicts = append(conflicts, f.Path)
		case !s.storedAs(f.Path):
			conflicts = append(conflicts, f.Path)
		case f.IfExists == TakeOverEmpty:
			empty, err := s.isEmptyDir(f.Path)
			if err != nil {
				return nil, err
			}
			if !empty {
				conflicts = append(conflicts, f.Path)
			}
		}
	}
	if len(conflicts) > 0 {
		return nil, &ConflictError{Paths: conflicts}
	}

	var created []Folder
	for i, f := range folders {
		if !missing[i] {
			continue
		}
		if err := s.root.Mkdir(filepath.FromSlash(f.Path), 0o755); err != nil {
			s.removeFolders(created)
			return nil, osErr(fmt.Errorf("create folder %s: %w", f.Path, nameErr(err)))
		}
		created = append(created, f)
	}
	// A folder created or taken over here is the server's, and keeps no
	// uploader record from an earlier folder at its place.
	err := s.update(func(tx *state.Tx) error {
		for i, f := range folders {
			if missing[i] || f.IfExists == TakeOverEmpty {
				if err := tx.DeleteUploaders(f.Path); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err == nil && commit != nil {
		err = commit()
	}
	if err != nil {
		s.removeFolders(created)
		return nil, err
	}
	return created, nil
}

func (s *Service) storedAs(rel string) bool {
	parent, name := path.Split(rel)
	d, err := s.root.Open(filepath.FromSlash(cmp.Or(strings.TrimSuffix(parent, "/"), ".")))
	if err != nil {
		return false
	}
	defer d.Close()
	names, err := d.Readdirnames(-1)
	return err == nil && slices.Contains(names, name)
}

func (s *Service) isEmptyDir(rel string) (bool, error) {
	f, err := s.root.Open(filepath.FromSlash(rel))
	if err != nil {
		return false, fmt.Errorf("open %s: %w", rel, err)
	}
	defer f.Close()
	_, err = f.Readdirnames(1)
	if errors.Is(err, io.EOF) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("read %s: %w", rel, err)
	}
	return false, nil
}

func (s *Service) removeFolders(created []Folder) {
	for _, f := range slices.Backward(created) {
		s.root.Remove(filepath.FromSlash(f.Path))
	}
}

func validLayoutPath(p string) bool {
	if p == "" || path.Clean(p) != p || path.IsAbs(p) {
		return false
	}
	for _, part := range strings.Split(p, "/") {
		if !ValidName(part) {
			return false
		}
	}
	return true
}
