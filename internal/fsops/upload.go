package fsops

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/nobletk/gocalbox/internal/authz"
	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/sandbox"
	"github.com/nobletk/gocalbox/internal/state"
)

// ErrNoStaging is returned by the calls of the upload engine when start-up
// found the staging folder unusable.
var ErrNoStaging = errors.New("the staging folder can't be used")

// adoptRounds bounds how often Adopt starts again because another file took
// the name it chose, or the folder moved, while it logged its choice.
const adoptRounds = 3

// Who returns the user a request acts for, and whether they are an admin;
// ok is false for a request without an enabled account.
func (s *Service) Who(ctx context.Context) (id string, admin, ok bool) {
	sub, ok := s.subject(ctx)
	return sub.ID, ok && sub.admin(), ok
}

// UserName names the user id; false only for a user the policy knows was
// deleted. Without a policy no user is known, and none counts as deleted.
func (s *Service) UserName(id string) (string, bool) {
	if s.policy == nil {
		return "", true
	}
	return s.policy.UserName(id)
}

// Outcome classifies an error of the calls of fsops for the audit log.
func (s *Service) Outcome(err error) events.Outcome { return outcomeOf(err) }

// PrepareUpload checks, before any data is sent, that the user of ctx may
// upload a file called name into the folder dir, and that the upload can be
// finished there: the folder is on the staging folder's file system, the
// server may write to it, and the file system accepts the name. It returns
// the folder's path cleaned and its key. It changes nothing in the served
// tree and publishes nothing; Adopt decides again when the upload ends.
func (s *Service) PrepareUpload(ctx context.Context, dir, name string) (clean, folder string, err error) {
	clean, folder, err = s.prepareUpload(ctx, dir, name)
	if err != nil {
		return "", "", osErr(sandbox.FromRoot(err))
	}
	return clean, folder, nil
}

func (s *Service) prepareUpload(ctx context.Context, dir, name string) (string, string, error) {
	if !s.trash {
		return "", "", ErrNoStaging
	}
	if err := s.allow(); err != nil {
		return "", "", err
	}
	sub, ok := s.subject(ctx)
	if !ok {
		return "", "", hide(ErrParentNotFound)
	}
	clean, err := sandbox.Clean(dir)
	if err != nil {
		return "", "", err
	}
	if !ValidName(name) {
		return "", "", ErrInvalidName
	}
	if sandbox.IsReserved(name) {
		return "", "", sandbox.ErrReserved
	}
	p, err := s.resolve(sub, dir, false, ErrParentNotFound)
	if err != nil {
		return "", "", err
	}
	_, key, err := s.uploadFolder(ctx, p)
	if err != nil {
		return "", "", err
	}
	if !s.isDir(p.Native()) {
		return "", "", ErrParentNotFound
	}
	if !s.onStagingVolume(p.Native()) {
		return "", "", ErrCrossDevice
	}
	if err := writable(s.root, p.Native()); err != nil {
		return "", "", fmt.Errorf("check the folder: %w", err)
	}
	if err := s.testName(name); err != nil {
		return "", "", err
	}
	return clean, key, nil
}

// testName creates name in a new folder of its own inside the staging
// folder, which is on the target's file system, so that a name the file
// system refuses is found before the upload starts, without anything
// appearing in the target folder.
func (s *Service) testName(name string) error {
	dir := filepath.FromSlash(path.Join(sandbox.TmpDir, sandbox.TempName()))
	if err := s.root.Mkdir(dir, 0o700); err != nil {
		return fmt.Errorf("test the name: %w", err)
	}
	defer s.root.RemoveAll(dir)
	f, err := s.root.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(sandbox.FromRoot(err), sandbox.ErrTraversal) {
		// Only the name is new here, so os.Root refuses it as leaving the
		// root only because the system reads it as a device, such as NUL or
		// COM1 on Windows.
		return fmt.Errorf("%w: %v", ErrInvalidName, err)
	}
	if err != nil {
		return fmt.Errorf("test the name: %w", nameErr(err))
	}
	return f.Close()
}

// MayUpload decides in memory, without reading the file system, whether the
// user of ctx may still upload into the folder whose key is folder. The key
// may be stale if the folder moved; Adopt decides on the folder as it is.
func (s *Service) MayUpload(ctx context.Context, folder string) error {
	sub, ok := s.subject(ctx)
	if !ok {
		return hide(ErrParentNotFound)
	}
	if sandbox.HasReserved(folder) {
		return sandbox.ErrReserved
	}
	return refusal(sub.decide(folder, authz.Unowned, authz.Upload), ErrParentNotFound)
}

// Adopt places the staged file at a free name, name or a numbered variant,
// in the folder dir, deciding the upload for the user of ctx as for any
// upload, and records them as its uploader. staged is the file's path inside
// the staging folder. Where hard links work the file is linked to its new
// name, and the staged name is the caller's to remove; otherwise it is
// renamed.
//
// Before placing the file, Adopt passes the path it chose to intent, with
// no lock held, and places it only if intent succeeds; if the name is taken
// or the folder moves meanwhile, it chooses again, a few times at most.
// It returns the path and the file.uploaded event, which the caller
// publishes. An error means that nothing was placed.
func (s *Service) Adopt(ctx context.Context, staged, dir, name string, intent func(path string) error) (string, events.Event, error) {
	rel, size, err := s.adopt(ctx, staged, dir, name, intent)
	if err != nil {
		return "", events.Event{}, osErr(sandbox.FromRoot(err))
	}
	ev := events.Event{Type: events.FileUploaded, Path: logicalJoin(dir, path.Base(rel)), Resolved: rel, Size: size}
	return rel, fill(ctx, ev, nil), nil
}

func (s *Service) adopt(ctx context.Context, staged, dir, name string, intent func(string) error) (string, int64, error) {
	if !s.trash {
		return "", 0, ErrNoStaging
	}
	if !isStaged(staged) {
		return "", 0, fmt.Errorf("%q is not a staged file", staged)
	}
	if info, err := s.root.Lstat(filepath.FromSlash(staged)); err != nil || !info.Mode().IsRegular() {
		return "", 0, fmt.Errorf("staged file %s: not a regular file (%v)", staged, err)
	}
	if !ValidName(name) {
		return "", 0, ErrInvalidName
	}
	if sandbox.IsReserved(name) {
		return "", 0, sandbox.ErrReserved
	}
	for range adoptRounds {
		var folder, candidate string
		err := s.locked(func() (err error) { folder, candidate, err = s.chooseName(ctx, dir, name); return err })
		if err != nil {
			return "", 0, err
		}
		rel := path.Join(folder, candidate)
		if err := intent(rel); err != nil {
			return "", 0, fmt.Errorf("log the chosen name: %w", err)
		}
		var size int64
		var again bool
		err = s.locked(func() (err error) { size, again, err = s.place(ctx, staged, dir, folder, rel); return err })
		if again {
			continue
		}
		if err != nil {
			return "", 0, err
		}
		s.makeDurable(rel, staged)
		return rel, size, nil
	}
	return "", 0, fmt.Errorf("%w: other files kept taking the names chosen for %q", ErrExists, name)
}

func (s *Service) locked(fn func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fn()
}

// isStaged reports whether p names a file inside the staging folder. A
// backslash is refused because Windows reads it as a separator.
func isStaged(p string) bool {
	return path.Clean(p) == p && !strings.Contains(p, `\`) &&
		(strings.HasPrefix(p, sandbox.UploadsDir+"/") || strings.HasPrefix(p, sandbox.TmpDir+"/"))
}

// chooseName decides the upload into dir and picks the first free name for
// it there. The caller holds s.mu.
func (s *Service) chooseName(ctx context.Context, dir, name string) (folder, candidate string, err error) {
	if err := s.allow(); err != nil {
		return "", "", err
	}
	p, _, err := s.uploadTarget(ctx, dir)
	if err != nil {
		return "", "", err
	}
	for candidate := range candidates(name) {
		_, err := s.root.Lstat(filepath.FromSlash(path.Join(p.Rel, candidate)))
		if notExist(err) {
			return p.Rel, candidate, nil
		}
		if err != nil {
			return "", "", nameErr(err)
		}
	}
	return "", "", fmt.Errorf("%w: no free numbered variant of %q", ErrExists, name)
}

// uploadTarget resolves dir for the user of ctx and decides an upload into
// it, returning the user it decided for. The caller holds s.mu.
func (s *Service) uploadTarget(ctx context.Context, dir string) (sandbox.Path, Subject, error) {
	sub, ok := s.subject(ctx)
	if !ok {
		return sandbox.Path{}, sub, hide(ErrParentNotFound)
	}
	p, err := s.resolve(sub, dir, false, ErrParentNotFound)
	if err != nil {
		return p, sub, err
	}
	if sub, _, err = s.uploadFolder(ctx, p); err != nil {
		return p, sub, err
	}
	if !s.isDir(p.Native()) {
		return p, sub, ErrParentNotFound
	}
	if !s.onStagingVolume(p.Native()) {
		return p, sub, ErrCrossDevice
	}
	return p, sub, nil
}

// place decides the upload again, places the staged file at rel and records
// its uploader. again is true when it must choose another name: rel was
// taken, or dir no longer resolves to folder. The caller holds s.mu.
func (s *Service) place(ctx context.Context, staged, dir, folder, rel string) (size int64, again bool, err error) {
	if err := s.allow(); err != nil {
		return 0, false, err
	}
	p, sub, err := s.uploadTarget(ctx, dir)
	if err != nil {
		return 0, false, err
	}
	if p.Rel != folder {
		return 0, true, nil
	}
	from, to := filepath.FromSlash(staged), filepath.FromSlash(rel)
	if s.links {
		err = s.root.Link(from, to)
		if errors.Is(err, fs.ErrExist) {
			return 0, true, nil
		}
	} else {
		// A rename replaces what is at to, so to must be free; like a move,
		// this doesn't cover other processes.
		if _, err := s.root.Lstat(to); !notExist(err) {
			if err == nil {
				return 0, true, nil
			}
			return 0, false, fmt.Errorf("check %s: %w", rel, err)
		}
		err = s.root.Rename(from, to)
	}
	if err != nil {
		return 0, false, fmt.Errorf("place the upload: %w", err)
	}

	info, err := s.root.Lstat(to)
	if err == nil {
		var key string
		if key, err = s.stored(rel, sub.look()); err == nil {
			err = s.update(func(tx *state.Tx) error { return tx.PutUploader(key, withIdentity(newRecord(sub.ID, false), info)) })
		}
	}
	if err == nil {
		return info.Size(), false, nil
	}
	if uerr := s.unplace(from, to); uerr != nil {
		log.Printf("WARNING: the upload placed at %s has no uploader record (%v), and taking it back failed (%v); only admins can change it", rel, err, uerr)
		return placedSize(info), false, nil
	}
	return 0, false, fmt.Errorf("record uploader: %w", err)
}

func placedSize(info fs.FileInfo) int64 {
	if info == nil {
		return 0
	}
	return info.Size()
}

// unplace takes back a placement whose record failed: the link, if it is
// still the staged file, or the rename. The caller holds s.mu.
func (s *Service) unplace(from, to string) error {
	if !s.links {
		return s.root.Rename(to, from)
	}
	a, err := s.root.Lstat(from)
	if err != nil {
		return err
	}
	b, err := s.root.Lstat(to)
	if err != nil {
		return err
	}
	if !os.SameFile(a, b) {
		return fmt.Errorf("%s is no longer the staged file", to)
	}
	return s.root.Remove(to)
}

// makeDurable flushes the folders a placement changed, so that a power cut
// can't lose the new entry once the caller has logged it. The file is
// placed already, so a failure is only logged.
func (s *Service) makeDurable(rel, staged string) {
	dirs := []string{path.Dir(rel)}
	if !s.links {
		dirs = append(dirs, path.Dir(staged))
	}
	for _, d := range dirs {
		if err := syncDir(s.root, filepath.FromSlash(d)); err != nil {
			log.Printf("WARNING: cannot flush the folder %s after placing an upload: %v", d, err)
		}
	}
}

// RecordAdopted writes the uploader record of a file Adopt placed for owner
// at rel, when a crash came between placing it and recording it. The file
// must still have the size and modification time logged before it was
// placed. A record already at its key is replaced unless it is this one.
func (s *Service) RecordAdopted(owner, rel string, size, mtime int64) error {
	if clean, err := sandbox.Clean(rel); err != nil || clean != rel || rel == "." || sandbox.HasReserved(rel) {
		return fmt.Errorf("%w: %q", ErrInvalidName, rel)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	info, err := s.root.Lstat(filepath.FromSlash(rel))
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() != size || info.ModTime().UnixNano() != mtime {
		return fmt.Errorf("%w: %s is no longer the file that was placed", ErrNotFound, rel)
	}
	key, err := s.stored(rel, nil)
	if err != nil {
		return err
	}
	return s.update(func(tx *state.Tx) error {
		rec, ok, err := tx.Uploader(key)
		if err == nil && ok && rec.User == owner && !rec.Dir && rec.Size != nil && *rec.Size == size && rec.MTime != nil && *rec.MTime == mtime {
			return nil
		}
		return tx.PutUploader(key, withIdentity(newRecord(owner, false), info))
	})
}
