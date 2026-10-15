package fsops

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/nobletk/gocalbox/internal/authz"
	"github.com/nobletk/gocalbox/internal/sandbox"
	"github.com/nobletk/gocalbox/internal/state"
)

var (
	ErrForbidden   = errors.New("not allowed")
	ErrBoundFolder = errors.New("a folder with a binding, or one leading to it, can't be moved or deleted")
)

// Subject is the user a request acts for, with the bindings in force.
type Subject struct {
	ID       string
	Role     authz.Role
	Bindings *authz.Bindings
}

// Policy tells fsops who a request acts for.
type Policy interface {
	// Subject returns the user a request acts for; false for a request
	// without one, which may then do nothing.
	Subject(ctx context.Context) (Subject, bool)
	// UserName names the user an uploader record names; false for a user
	// who was deleted.
	UserName(id string) (string, bool)
}

// DeletedUser stands for the uploader of a record whose user was deleted.
const DeletedUser = "(deleted user)"

// Actions offered in a listing (§7.6).
const (
	ActionRename = "rename"
	ActionMove   = "move"
	ActionDelete = "delete"
)

// hiddenError answers a path the user may not see as if it didn't exist
// (AD14); the audit records it as denied.
type hiddenError struct{ err error }

func (e hiddenError) Error() string { return "no access: " + e.err.Error() }
func (e hiddenError) Unwrap() error { return e.err }

func hide(err error) error { return hiddenError{err} }

func isHidden(err error) bool {
	var h hiddenError
	return errors.As(err, &h)
}

// SetPolicy gives the service its policy. It is called once, before the
// service is used; without a policy every operation is refused.
func (s *Service) SetPolicy(p Policy) { s.policy = p }

func (s *Service) subject(ctx context.Context) (Subject, bool) {
	if s.policy == nil {
		return Subject{}, false
	}
	sub, ok := s.policy.Subject(ctx)
	if ok && sub.Bindings == nil {
		sub.Bindings = authz.NewBindings(nil)
	}
	return sub, ok
}

func (sub Subject) admin() bool { return sub.Role == authz.Admin }

// decide applies the decision table to folder, the folder that counts for
// the action.
func (sub Subject) decide(folder string, rel authz.Relation, a authz.Action) authz.Decision {
	return authz.Decide(sub.Role, sub.Bindings.Granted(sub.ID, folder), rel, a)
}

func (sub Subject) canRead(folder string) bool {
	return sub.decide(folder, authz.Unowned, authz.Read) == authz.Allow
}

// sees reports whether sub can see the entry p: its folder is readable, or
// a traversal shows it on the way to one of sub's bound folders.
func (sub Subject) sees(p string) bool {
	return sub.admin() || sub.canRead(path.Dir(p)) || sub.Bindings.Granted(sub.ID, p) != authz.GrantNone
}

func refusal(d authz.Decision, hiddenAs error) error {
	switch d {
	case authz.Allow, authz.Filtered:
		return nil
	case authz.Forbidden:
		return ErrForbidden
	}
	return hide(hiddenAs)
}

// resolve resolves a client's path for sub, as an entry or as a folder. An
// error from resolving it is reported only if sub may read the deepest
// folder of the typed path that resolves; otherwise the path is hidden, so
// that a broken link or a symlink leaving the root in another user's home
// tells nothing (§7.4).
func (s *Service) resolve(sub Subject, userPath string, entry bool, hiddenAs error) (sandbox.Path, error) {
	clean, err := sandbox.Clean(userPath)
	if err != nil {
		return sandbox.Path{}, err
	}
	var p sandbox.Path
	if entry {
		p, err = s.sb.ResolveEntry(userPath)
	} else {
		p, err = s.sb.Resolve(userPath)
	}
	if err == nil || errors.Is(err, sandbox.ErrRootTarget) || sub.admin() {
		return p, err
	}
	for dir := path.Dir(clean); ; dir = path.Dir(dir) {
		if q, qerr := s.sb.Resolve(dir); qerr == nil {
			if sub.canRead(q.Rel) {
				return p, err
			}
			return p, hide(hiddenAs)
		}
		if dir == "." {
			return p, hide(hiddenAs)
		}
	}
}

// errUnseen stops stored at a folder the user can't see into.
var errUnseen = errors.New("folder not visible")

// A lookup tells stored which names of a folder it may compare: all of them
// (nil, true), only those given (names, true), or none (nil, false). A nil
// lookup allows all.
type lookup func(dir string) (names []string, ok bool)

// stored returns the canonical path rel with each existing component in the
// spelling its directory stores, so that two spellings of one file on a
// case-insensitive volume give one key, and two files never share one
// (§7.7). Components that don't exist keep the spelling typed. Folders are
// read only as look allows: a folder read only when the name in it exists
// would tell, by the time it takes, whether a name exists there (AD14).
func (s *Service) stored(rel string, look lookup) (string, error) {
	if rel == "." {
		return rel, nil
	}
	parts := strings.Split(rel, "/")
	out := "."
	for i, name := range parts {
		typed := path.Join(out, name)
		info, err := s.root.Lstat(filepath.FromSlash(typed))
		if notExist(err) {
			return path.Join(append([]string{out}, parts[i:]...)...), nil
		}
		if err != nil {
			return "", fmt.Errorf("stat %s: %w", typed, err)
		}
		var names []string
		if look != nil {
			only, ok := look(out)
			if !ok {
				return "", errUnseen
			}
			names = only
		}
		if names == nil {
			if names, err = s.names(out); err != nil {
				return "", err
			}
		}
		out = path.Join(out, s.storedName(out, name, info, names))
	}
	return out, nil
}

// look is what sub may see of each folder: all of a folder sub can read,
// only the names on the way to sub's bound folders in one sub can traverse,
// which bindings name in their stored spelling, and nothing of any other.
func (sub Subject) look() lookup {
	if sub.admin() {
		return nil
	}
	return func(dir string) ([]string, bool) {
		switch sub.Bindings.Granted(sub.ID, dir) {
		case authz.GrantNone:
			return nil, false
		case authz.GrantTraverse:
			return sub.Bindings.Next(sub.ID, dir), true
		}
		return nil, true
	}
}

// storedFor is stored for a change by sub, seeing only what sub may see,
// and answering as for a missing path at the first folder sub can't see
// into. An error from reading the folders is reported only if sub may read
// the folder holding rel, as for an error from resolving it.
func (s *Service) storedFor(sub Subject, rel string, hiddenAs error) (string, error) {
	key, err := s.stored(rel, sub.look())
	if errors.Is(err, errUnseen) || err != nil && !sub.admin() && !sub.canRead(path.Dir(rel)) {
		return "", hide(hiddenAs)
	}
	return key, err
}

func (s *Service) storedName(dir, name string, info fs.FileInfo, names []string) string {
	if slices.Contains(names, name) {
		return name
	}
	// Names differing only in case are the likeliest; any other the volume
	// treats as the same, such as another Unicode normalization, comes after.
	slices.SortStableFunc(names, func(a, b string) int {
		return boolInt(!strings.EqualFold(a, name)) - boolInt(!strings.EqualFold(b, name))
	})
	for _, n := range names {
		if other, err := s.root.Lstat(filepath.FromSlash(path.Join(dir, n))); err == nil && os.SameFile(info, other) {
			return n
		}
	}
	return name
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (s *Service) names(dir string) ([]string, error) { return readNames(s.root, dir) }

var readNames = func(root *os.Root, dir string) ([]string, error) {
	d, err := root.Open(filepath.FromSlash(dir))
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", dir, err)
	}
	defer d.Close()
	names, err := d.Readdirnames(-1)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", dir, err)
	}
	return names, nil
}

// view runs fn in a read transaction of the records, or with a nil Tx where
// the service keeps none.
func (s *Service) view(fn func(*state.Tx) error) error {
	if s.db == nil {
		return fn(nil)
	}
	return s.db.View(fn)
}

func (s *Service) update(fn func(*state.Tx) error) error {
	if s.db == nil {
		return nil
	}
	return s.db.Update(fn)
}

// record returns the uploader record of key and whether it matches the
// entry described by info: one of the same kind, and for a file with its
// size and modification time, unless it was made without them.
func record(tx *state.Tx, key string, info fs.FileInfo) (state.Uploader, bool) {
	if tx == nil {
		return state.Uploader{}, false
	}
	rec, ok, err := tx.Uploader(key)
	if err != nil || !ok || rec.Dir != info.IsDir() {
		return state.Uploader{}, false
	}
	if info.IsDir() || rec.Size == nil || rec.MTime == nil {
		return rec, true
	}
	return rec, *rec.Size == info.Size() && *rec.MTime == info.ModTime().UnixNano()
}

func (sub Subject) relation(tx *state.Tx, key string, info fs.FileInfo) authz.Relation {
	rec, matching := record(tx, key, info)
	return authz.RelationOf(sub.ID, sub.Bindings.Home(sub.ID), key, rec.User, matching)
}

// mayChange decides a move's source or a delete of the entry at key, stored
// spelling, for a non-admin. A folder carries everything below it along, so
// every entry below must pass as well (§7.4).
func (s *Service) mayChange(sub Subject, key string, info fs.FileInfo, a authz.Action) error {
	var rel authz.Relation
	if err := s.view(func(tx *state.Tx) error { rel = sub.relation(tx, key, info); return nil }); err != nil {
		return err
	}
	if err := refusal(sub.decide(path.Dir(key), rel, a), ErrNotFound); err != nil {
		return err
	}
	if !info.IsDir() || (a == authz.Delete && rel == authz.HomeOwner) {
		return nil
	}
	type entry struct {
		path string
		info fs.FileInfo
	}
	var below []entry
	err := fs.WalkDir(s.root.FS(), key, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("walk %s: %w", p, err)
		}
		if p == key {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return fmt.Errorf("stat %s: %w", p, err)
		}
		below = append(below, entry{p, info})
		return nil
	})
	if err != nil {
		return err
	}
	return s.view(func(tx *state.Tx) error {
		for _, e := range below {
			if sub.decide(path.Dir(e.path), sub.relation(tx, e.path, e.info), a) != authz.Allow {
				return ErrForbidden
			}
		}
		return nil
	})
}

func newRecord(user string, dir bool) state.Uploader {
	return state.Uploader{User: user, Created: time.Now().UTC(), Dir: dir}
}

func withIdentity(rec state.Uploader, info fs.FileInfo) state.Uploader {
	size, mtime := info.Size(), info.ModTime().UnixNano()
	rec.Size, rec.MTime = &size, &mtime
	return rec
}

const trashDir = sandbox.ReservedName + "/trash"

// EmptyTrash removes what deletes left in the trash, which a crash or a
// failed removal can leave behind. It runs at start-up.
func (s *Service) EmptyTrash() error {
	return s.root.RemoveAll(filepath.FromSlash(trashDir))
}

// toTrash renames the folder at native into the trash and returns its name
// there, or "" if the folder is on another file system and was removed in
// place.
func (s *Service) toTrash(native string) (string, error) {
	if err := s.root.MkdirAll(filepath.FromSlash(trashDir), 0o700); err != nil {
		return "", fmt.Errorf("create trash: %w", err)
	}
	var b [8]byte
	rand.Read(b[:])
	name := filepath.Join(filepath.FromSlash(trashDir), hex.EncodeToString(b[:]))
	err := s.root.Rename(native, name)
	if err != nil && isCrossDevice(err) {
		return "", s.root.RemoveAll(native)
	}
	if err != nil {
		return "", err
	}
	return name, nil
}

func (s *Service) removeTrash(name string) {
	if name == "" {
		return
	}
	if err := s.root.RemoveAll(name); err != nil {
		log.Printf("Cannot remove a deleted folder from the trash, %s: %v", name, err)
	}
}
