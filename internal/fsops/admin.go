package fsops

import (
	"context"
	"fmt"
	"log"
	"path/filepath"

	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/sandbox"
	"github.com/nobletk/gocalbox/internal/state"
)

// MoveHome moves a home folder for the server, such as into the archive of
// a deleted user's files. It is not decided like a user's move, and the
// bound-folder rule doesn't hold it, since its binding goes with its user.
// The folder that receives it must exist. An error for which
// events.IsUnrecorded holds means the folder was moved.
func (s *Service) MoveHome(ctx context.Context, from, to, detail string) error {
	if !validLayoutPath(from) || !validLayoutPath(to) {
		return fmt.Errorf("%w: %q or %q", ErrInvalidName, from, to)
	}
	s.mu.Lock()
	err := s.moveHome(from, to)
	s.mu.Unlock()
	return s.publishChange(ctx, events.Event{
		Type: events.FileMoved, Path: from, Target: to, Resolved: from, ResolvedTarget: to, Detail: detail,
	}, osErr(err))
}

func (s *Service) moveHome(from, to string) error {
	info, err := s.root.Lstat(filepath.FromSlash(from))
	switch {
	case notExist(err):
		return ErrNotFound
	case err != nil:
		return fmt.Errorf("stat %s: %w", from, err)
	case !info.IsDir():
		return ErrNotDir
	}
	if !s.isDir(filepath.Dir(filepath.FromSlash(to))) {
		return ErrParentNotFound
	}
	if _, err := s.root.Lstat(filepath.FromSlash(to)); err == nil {
		return ErrExists
	} else if !notExist(err) {
		return fmt.Errorf("stat %s: %w", to, err)
	}
	if err := s.root.Rename(filepath.FromSlash(from), filepath.FromSlash(to)); err != nil {
		return fmt.Errorf("rename: %w", nameErr(err))
	}
	if err := s.update(func(tx *state.Tx) error { return tx.MoveUploaders(from, to) }); err != nil {
		if rerr := s.root.Rename(filepath.FromSlash(to), filepath.FromSlash(from)); rerr != nil {
			log.Printf("Cannot move %s back to %s after failing to move its uploader records: %v", to, from, rerr)
		}
		return fmt.Errorf("move uploader records: %w", err)
	}
	return nil
}

// BindFolder runs commit with the stored spelling of folder, which must be
// an existing folder the request's admin can reach, while holding the lock
// that serializes changes: the folder can't be moved before the binding
// naming it is made.
func (s *Service) BindFolder(ctx context.Context, folder string, commit func(stored string) error) error {
	sub, ok := s.subject(ctx)
	if !ok || !sub.admin() {
		return ErrForbidden
	}
	p, err := s.resolve(sub, folder, false, ErrNotFound)
	if err != nil {
		return sandbox.FromRoot(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key, err := s.storedFor(sub, p.Rel, ErrNotFound)
	if err != nil {
		return err
	}
	if sandbox.HasReserved(key) {
		return sandbox.ErrReserved
	}
	info, err := s.root.Stat(p.Native())
	switch {
	case notExist(err):
		return ErrNotFound
	case err != nil:
		return fmt.Errorf("stat %s: %w", key, err)
	case !info.IsDir():
		return ErrNotDir
	}
	return commit(key)
}
