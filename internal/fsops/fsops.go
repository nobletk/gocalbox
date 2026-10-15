// Package fsops implements the file operations
package fsops

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"unicode"
	"unicode/utf8"

	"github.com/nobletk/gocalbox/internal/authz"
	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/sandbox"
	"github.com/nobletk/gocalbox/internal/space"
	"github.com/nobletk/gocalbox/internal/state"
)

var (
	ErrNotFound           = errors.New("not found")
	ErrParentNotFound     = errors.New("parent folder not found")
	ErrNotDir             = errors.New("not a directory")
	ErrExists             = errors.New("already exists")
	ErrInvalidName        = errors.New("invalid name")
	ErrMoveIntoSelf       = errors.New("cannot move a folder into itself")
	ErrInvalidRange       = errors.New("requested range not satisfiable")
	ErrPreconditionFailed = errors.New("precondition failed")
	ErrAborted            = errors.New("transfer aborted")
	ErrUploadMoved        = errors.New("the file was moved or deleted while it was uploaded")

	ErrInsufficientStorage = space.ErrInsufficient
	ErrCrossDevice         = errors.New("source and destination are on different file systems")
	ErrReadOnly            = fmt.Errorf("read-only file system: %w", fs.ErrPermission)
)

type Entry struct {
	Name  string
	Size  int64
	IsDir bool

	// Uploader names who created the entry: nil when no record matches it,
	// DeletedUser for a user who no longer exists.
	Uploader *string
	// Actions lists what the user may do with the entry: ActionRename,
	// ActionMove and ActionDelete. For a folder it reflects the folder's own
	// record only; the request itself also checks everything below.
	Actions []string
}

type Publisher interface {
	Publish(events.Event)
}

const maxLogged = 1024

const maxNameBytes = 255

var maxAutoRename = 10000

type Service struct {
	sb     *sandbox.Sandbox
	root   *os.Root
	pub    Publisher
	space  *space.Ledger
	policy Policy
	db     *state.DB
	audit  events.Auditor

	// mu serializes check-then-act sequences (unique names, no-overwrite
	// moves, the decision and the uploader records of every change) within
	// this process only; other processes are not covered.
	mu sync.Mutex
}

type Option func(*Service)

// WithSpace makes Create reserve room in l before writing. Without it,
// uploads are limited only by the disk filling up.
func WithSpace(l *space.Ledger) Option { return func(s *Service) { s.space = l } }

// WithRecords keeps uploader records in db. Without it no file has an
// uploader, so only admins and home owners can change files.
func WithRecords(db *state.DB) Option { return func(s *Service) { s.db = db } }

// WithAudit applies the audit log's policies: a change is refused once the
// log has failed, and replies only once its record is on disk.
func WithAudit(a events.Auditor) Option { return func(s *Service) { s.audit = a } }

func New(sb *sandbox.Sandbox, pub Publisher, opts ...Option) *Service {
	s := &Service{sb: sb, root: sb.OSRoot(), pub: pub}
	for _, o := range opts {
		o(s)
	}
	return s
}

func ValidName(name string) bool {
	if name == "" || name == "." || name == ".." || len(name) > maxNameBytes || !utf8.ValidString(name) {
		return false
	}
	if strings.TrimSpace(name) != name {
		return false
	}
	for _, r := range name {
		if r == '/' || r == '\\' || unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) {
			return false
		}
	}
	return true
}

func (s *Service) List(ctx context.Context, dir string) ([]Entry, error) {
	p, entries, err := s.list(ctx, dir)
	err = sandbox.FromRoot(err)
	s.publish(ctx, events.Event{Type: events.FileListed, Path: dir, Resolved: p.Rel}, err)
	return entries, err
}

func (s *Service) list(ctx context.Context, dir string) (sandbox.Path, []Entry, error) {
	sub, ok := s.subject(ctx)
	if !ok {
		return sandbox.Path{}, nil, hide(ErrNotFound)
	}
	p, err := s.resolve(sub, dir, false, ErrNotFound)
	if err != nil {
		return p, nil, err
	}
	decision := sub.decide(p.Rel, authz.Unowned, authz.List)
	if err := refusal(decision, ErrNotFound); err != nil {
		return p, nil, err
	}
	f, _, err := s.openChecked(p, fs.FileInfo.IsDir, ErrNotDir)
	if err != nil {
		return p, nil, err
	}
	defer f.Close()
	dirEntries, err := f.ReadDir(-1)
	if err != nil {
		return p, nil, fmt.Errorf("read directory: %w", err)
	}
	storedDir, err := s.stored(p.Rel, sub.look())
	if err != nil {
		return p, nil, err
	}

	type listed struct {
		name        string
		info, shown fs.FileInfo
	}
	var found []listed
	for _, de := range dirEntries {
		if sandbox.IsReserved(de.Name()) {
			continue
		}
		child := path.Join(p.Rel, de.Name())
		if decision == authz.Filtered && sub.Bindings.Granted(sub.ID, child) == authz.GrantNone {
			continue
		}
		info, err := de.Info()
		if err != nil {
			continue
		}
		shown := info
		if de.Type()&fs.ModeSymlink != 0 {
			target, err := s.sb.Resolve(child)
			if err != nil {
				continue
			}
			if shown, err = s.root.Stat(target.Native()); err != nil || !sub.mayOpen(target.Rel, shown) {
				continue
			}
		}
		if !shown.IsDir() && !shown.Mode().IsRegular() {
			continue
		}
		found = append(found, listed{de.Name(), info, shown})
	}

	// The records are read only once the directory has been, so that no read
	// transaction waits on the file system: a writer that must grow the
	// file's mapping waits for every open one.
	entries := make([]Entry, 0, len(found))
	err = s.view(func(tx *state.Tx) error {
		for _, f := range found {
			key := path.Join(storedDir, f.name)
			entries = append(entries, Entry{
				Name: f.name, Size: f.shown.Size(), IsDir: f.shown.IsDir(),
				Uploader: s.uploaderName(tx, key, f.info),
				Actions:  s.actions(sub, tx, key, f.info),
			})
		}
		return nil
	})
	if err != nil {
		return p, nil, err
	}
	slices.SortFunc(entries, func(a, b Entry) int { return strings.Compare(a.Name, b.Name) })
	return p, entries, nil
}

// mayOpen reports whether sub may read what a symlink in a listing points
// to: a folder sub may list, or a file in a folder sub may read.
func (sub Subject) mayOpen(target string, info fs.FileInfo) bool {
	if info.IsDir() {
		return sub.decide(target, authz.Unowned, authz.List) != authz.Hidden
	}
	return sub.canRead(path.Dir(target))
}

func (s *Service) uploaderName(tx *state.Tx, key string, info fs.FileInfo) *string {
	rec, matching := record(tx, key, info)
	if !matching {
		return nil
	}
	name := DeletedUser
	if s.policy != nil {
		if n, ok := s.policy.UserName(rec.User); ok {
			name = n
		}
	}
	return &name
}

func (s *Service) actions(sub Subject, tx *state.Tx, key string, info fs.FileInfo) []string {
	out := []string{}
	if sub.Bindings.Bound(key) {
		return out
	}
	folder := path.Dir(key)
	rel := sub.relation(tx, key, info)
	if sub.decide(folder, rel, authz.MoveSource) == authz.Allow {
		out = append(out, ActionRename, ActionMove)
	}
	if sub.decide(folder, rel, authz.Delete) == authz.Allow {
		out = append(out, ActionDelete)
	}
	return out
}

func isRegular(fi fs.FileInfo) bool { return fi.Mode().IsRegular() }

func (s *Service) openChecked(p sandbox.Path, kind func(fs.FileInfo) bool, wrong error) (*os.File, fs.FileInfo, error) {
	info, err := s.root.Stat(p.Native())
	if err != nil {
		if notExist(err) {
			return nil, nil, ErrNotFound
		}
		return nil, nil, fmt.Errorf("stat: %w", err)
	}
	if !kind(info) {
		return nil, nil, wrong
	}
	f, err := s.root.OpenFile(p.Native(), os.O_RDONLY|openNonblock, 0)
	if err != nil {
		if notExist(err) {
			return nil, nil, ErrNotFound
		}
		return nil, nil, fmt.Errorf("open: %w", err)
	}
	if info, err = f.Stat(); err != nil || !kind(info) {
		f.Close()
		if err != nil {
			return nil, nil, fmt.Errorf("stat: %w", err)
		}
		return nil, nil, wrong
	}
	if err := clearNonblock(f); err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("open: %w", err)
	}
	return f, info, nil
}

func (s *Service) Open(ctx context.Context, userPath string) (*File, error) {
	p, f, info, err := s.open(ctx, userPath)
	err = sandbox.FromRoot(err)
	ev := events.Event{Type: events.FileDownloaded, Path: userPath, Resolved: p.Rel}
	if err != nil {
		s.publish(ctx, ev, err)
		return nil, err
	}
	return &File{f: f, info: info, svc: s, ctx: ctx, ev: ev}, nil
}

func (s *Service) open(ctx context.Context, userPath string) (sandbox.Path, *os.File, fs.FileInfo, error) {
	sub, ok := s.subject(ctx)
	if !ok {
		return sandbox.Path{}, nil, nil, hide(ErrNotFound)
	}
	p, err := s.resolve(sub, userPath, false, ErrNotFound)
	if err != nil {
		return p, nil, nil, err
	}
	if !sub.canRead(path.Dir(p.Rel)) {
		return p, nil, nil, hide(ErrNotFound)
	}
	f, info, err := s.openChecked(p, isRegular, ErrNotFound)
	return p, f, info, err
}

type File struct {
	f    *os.File
	info fs.FileInfo
	svc  *Service
	ctx  context.Context
	ev   events.Event

	transfer *Transfer
	closed   bool
}

// Transfer describes how a download ended.
type Transfer struct {
	Sent         int64
	Range        string
	Err          error
	MetadataOnly bool
}

func (f *File) Content() io.ReadSeeker { return f.f }

func (f *File) Info() fs.FileInfo { return f.info }

// ETag stays the same for an in-place rewrite of the same size within one
// tick of the kernel's file clock, and, where the OS reports no file identity
// (Windows), for a replacement with the same size and modification time.
func (f *File) ETag() string {
	dev, ino := fileID(f.info)
	h := sha256.New()
	fmt.Fprintf(h, "%d:%d:%d:%d", dev, ino, f.info.Size(), f.info.ModTime().UnixNano())
	return `"` + hex.EncodeToString(h.Sum(nil)[:16]) + `"`
}

func (f *File) Finish(t Transfer) { f.transfer = &t }

func (f *File) Close() error {
	if f.closed {
		return nil
	}
	f.closed = true
	err := f.f.Close()

	ev := f.ev
	var outcomeErr error
	if t := f.transfer; t != nil {
		ev.Size = t.Sent
		ev.Range = truncate(t.Range)
		outcomeErr = t.Err
		if t.MetadataOnly {
			ev.Type = events.FileChecked
		}
	}
	f.svc.publish(f.ctx, ev, outcomeErr)
	return err
}

// sizeHint is an upper bound on the length of r, or negative when unknown;
// room is reserved for it before anything is written. With ErrUploadMoved,
// the name the upload was made under is returned too.
func (s *Service) Create(ctx context.Context, dir, name string, r io.Reader, sizeHint int64) (string, int64, error) {
	stored, size, err := s.create(ctx, dir, name, r, sizeHint)
	err = osErr(sandbox.FromRoot(err))
	ev := events.Event{Type: events.FileUploaded, Path: logicalJoin(dir, name), Size: size}
	if stored != "" {
		ev.Path = logicalJoin(dir, path.Base(stored))
		ev.Resolved = stored
	}
	return stored, size, s.publishChange(ctx, ev, err)
}

func (s *Service) mayUpload(ctx context.Context, p sandbox.Path) (Subject, error) {
	sub, ok := s.subject(ctx)
	if !ok {
		return sub, hide(ErrParentNotFound)
	}
	dir, err := s.storedFor(sub, p.Rel, ErrParentNotFound)
	if err != nil {
		return sub, err
	}
	if sandbox.HasReserved(dir) {
		return sub, sandbox.ErrReserved
	}
	return sub, refusal(sub.decide(dir, authz.Unowned, authz.Upload), ErrParentNotFound)
}

func (s *Service) create(ctx context.Context, dir, name string, r io.Reader, sizeHint int64) (string, int64, error) {
	if err := s.allow(); err != nil {
		return "", 0, err
	}
	sub, ok := s.subject(ctx)
	if !ok {
		return "", 0, hide(ErrParentNotFound)
	}
	if _, err := sandbox.Clean(dir); err != nil {
		return "", 0, err
	}
	if !ValidName(name) {
		return "", 0, ErrInvalidName
	}
	if sandbox.IsReserved(name) {
		return "", 0, sandbox.ErrReserved
	}
	p, err := s.resolve(sub, dir, false, ErrParentNotFound)
	if err != nil {
		return "", 0, err
	}
	// Decided before the space is reserved, and again under mu with the file.
	if _, err := s.mayUpload(ctx, p); err != nil {
		return "", 0, err
	}
	if !s.isDir(p.Native()) {
		return "", 0, ErrParentNotFound
	}

	var res *space.Reservation
	if s.space != nil && s.onServedVolume(p.Native()) {
		if res, err = s.space.Reserve(sizeHint); err != nil {
			return "", 0, err
		}
		defer res.Release()
	}

	s.mu.Lock()
	up, err := s.createRecorded(ctx, p, name)
	s.mu.Unlock()
	if err != nil {
		return "", 0, err
	}

	var w io.Writer = up.f
	if res != nil {
		w = res.Writer(up.f)
	}
	size, err := io.Copy(w, r)
	s.mu.Lock()
	defer s.mu.Unlock()
	here := s.stillAt(up)
	if cerr := up.f.Close(); err == nil {
		err = cerr
	}
	switch {
	case err != nil:
		err = fmt.Errorf("write file: %w", err)
	case !here:
		err = ErrUploadMoved
	default:
		if err = s.allow(); err != nil {
			break
		}
		if err = s.finishUpload(up); err != nil {
			err = fmt.Errorf("write file: %w", err)
		}
	}
	if err != nil {
		s.discardUpload(up, here)
		if errors.Is(err, ErrUploadMoved) {
			return up.rel, size, err
		}
		return "", size, err
	}
	return up.rel, size, nil
}

// An upload is a file being written, with the record made for it. The file
// is no longer at rel if its uploader or an admin moved or deleted it
// meanwhile, and another upload may have taken the name.
type upload struct {
	f    *os.File
	rel  string
	key  string
	made state.Uploader
}

// createRecorded decides the upload again, creates the file under a free
// name and records its uploader without identity, which the end of the
// upload adds. The caller holds s.mu.
func (s *Service) createRecorded(ctx context.Context, p sandbox.Path, name string) (*upload, error) {
	if err := s.allow(); err != nil {
		return nil, err
	}
	sub, err := s.mayUpload(ctx, p)
	if err != nil {
		return nil, err
	}
	f, rel, err := s.createUnique(p.Rel, name)
	if err != nil {
		return nil, fmt.Errorf("create file: %w", err)
	}
	up := &upload{f: f, rel: rel, made: newRecord(sub.ID, false)}
	up.key, err = s.stored(rel, sub.look())
	if err == nil {
		err = s.update(func(tx *state.Tx) error { return tx.PutUploader(up.key, up.made) })
	}
	if err != nil {
		f.Close()
		s.root.Remove(filepath.FromSlash(rel))
		return nil, fmt.Errorf("record uploader: %w", err)
	}
	return up, nil
}

// stillAt reports whether the upload's file is still at its name. It is
// asked while the file is open: FAT and some network file systems give a
// file another identity each time it is opened. The caller holds s.mu.
func (s *Service) stillAt(up *upload) bool {
	open, err := up.f.Stat()
	if err != nil {
		return false
	}
	at, err := s.root.Lstat(filepath.FromSlash(up.rel))
	return err == nil && os.SameFile(open, at)
}

// finishUpload adds the finished file's size and modification time to its
// record, read after the file was closed, which is when some file systems
// settle the time. The caller holds s.mu, which it held since stillAt.
func (s *Service) finishUpload(up *upload) error {
	info, err := s.root.Lstat(filepath.FromSlash(up.rel))
	if err != nil {
		return err
	}
	return s.updateOwn(up, func(tx *state.Tx) error { return tx.PutUploader(up.key, withIdentity(up.made, info)) })
}

// discardUpload removes what a failed upload left at its name, unless the
// name now holds something else. The caller holds s.mu.
func (s *Service) discardUpload(up *upload, here bool) {
	if here {
		s.root.Remove(filepath.FromSlash(up.rel))
	}
	if err := s.updateOwn(up, func(tx *state.Tx) error { return tx.DeleteUploader(up.key) }); err != nil {
		log.Printf("Cannot remove the uploader record of a failed upload, %s: %v", up.key, err)
	}
}

// updateOwn runs fn only while the record at the upload's key is still the
// one the upload made. The caller holds s.mu.
func (s *Service) updateOwn(up *upload, fn func(*state.Tx) error) error {
	return s.update(func(tx *state.Tx) error {
		rec, ok, err := tx.Uploader(up.key)
		if err != nil || !ok || rec.User != up.made.User || !rec.Created.Equal(up.made.Created) {
			return err
		}
		return fn(tx)
	})
}

func (s *Service) createUnique(dir, name string) (*os.File, string, error) {
	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)
	if base == "" { // dotfile such as ".env"
		base, ext = name, ""
	}
	for i := 0; i < maxAutoRename; i++ {
		candidate := name
		if i > 0 {
			var ok bool
			if candidate, ok = numbered(base, ext, i); !ok {
				break
			}
		}
		rel := path.Join(dir, candidate)
		f, err := s.root.OpenFile(filepath.FromSlash(rel), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err == nil {
			return f, rel, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, "", nameErr(err)
		}
	}
	return nil, "", fmt.Errorf("%w: no free numbered variant of %q", ErrExists, name)
}

func numbered(base, ext string, i int) (string, bool) {
	suffix := fmt.Sprintf(" (%d)", i)
	if over := len(base) + len(suffix) + len(ext) - maxNameBytes; over > 0 {
		cut := len(base) - over
		for cut > 0 && !utf8.RuneStart(base[cut]) {
			cut--
		}
		if cut <= 0 {
			return "", false
		}
		base = base[:cut]
	}
	return base + suffix + ext, true
}

func (s *Service) Mkdir(ctx context.Context, parent, name string) (string, error) {
	p, err := s.mkdir(ctx, parent, name)
	err = osErr(sandbox.FromRoot(err))
	return p.Rel, s.publishChange(ctx, events.Event{Type: events.FolderCreated, Path: logicalJoin(parent, name), Resolved: p.Rel}, err)
}

func (s *Service) mkdir(ctx context.Context, parent, name string) (sandbox.Path, error) {
	if err := s.allow(); err != nil {
		return sandbox.Path{}, err
	}
	sub, ok := s.subject(ctx)
	if !ok {
		return sandbox.Path{}, hide(ErrParentNotFound)
	}
	if !ValidName(name) {
		return sandbox.Path{}, ErrInvalidName
	}
	p, err := s.resolve(sub, path.Join(parent, name), true, ErrParentNotFound)
	if err != nil {
		return p, err
	}
	// Under mu also because rename(2) silently replaces an empty directory,
	// so a concurrent Move could overwrite the new folder.
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.allow(); err != nil {
		return p, err
	}
	if sub, ok = s.subject(ctx); !ok {
		return p, hide(ErrParentNotFound)
	}
	dir, err := s.storedFor(sub, path.Dir(p.Rel), ErrParentNotFound)
	if err != nil {
		return p, err
	}
	if sandbox.HasReserved(dir) {
		return p, sandbox.ErrReserved
	}
	if err := refusal(sub.decide(dir, authz.Unowned, authz.Mkdir), ErrParentNotFound); err != nil {
		return p, err
	}
	if !s.isDir(filepath.Dir(p.Native())) {
		return p, ErrParentNotFound
	}
	if err := s.root.Mkdir(p.Native(), 0o755); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return p, ErrExists
		}
		return p, fmt.Errorf("create folder: %w", nameErr(err))
	}
	key, err := s.stored(p.Rel, sub.look())
	if err == nil {
		err = s.update(func(tx *state.Tx) error { return tx.PutUploader(key, newRecord(sub.ID, true)) })
	}
	if err != nil {
		s.root.Remove(p.Native())
		return p, fmt.Errorf("record uploader: %w", err)
	}
	return p, nil
}

func (s *Service) Delete(ctx context.Context, userPath string) (string, error) {
	p, err := s.delete(ctx, userPath)
	err = osErr(sandbox.FromRoot(err))
	return p.Rel, s.publishChange(ctx, events.Event{Type: events.FileDeleted, Path: userPath, Resolved: p.Rel}, err)
}

func (s *Service) delete(ctx context.Context, userPath string) (sandbox.Path, error) {
	if err := s.allow(); err != nil {
		return sandbox.Path{}, err
	}
	sub, ok := s.subject(ctx)
	if !ok {
		return sandbox.Path{}, hide(ErrNotFound)
	}
	p, err := s.resolve(sub, userPath, true, ErrNotFound)
	if err != nil {
		return p, err
	}
	s.mu.Lock()
	trash, err := s.deleteLocked(ctx, p)
	s.mu.Unlock()
	if err != nil {
		return p, err
	}
	s.removeTrash(trash)
	return p, nil
}

// deleteLocked removes the entry p, or moves it into the trash if it is a
// folder, and returns its name there. The caller holds s.mu.
func (s *Service) deleteLocked(ctx context.Context, p sandbox.Path) (string, error) {
	if err := s.allow(); err != nil {
		return "", err
	}
	sub, ok := s.subject(ctx)
	if !ok {
		return "", hide(ErrNotFound)
	}
	key, err := s.storedFor(sub, p.Rel, ErrNotFound)
	if err != nil {
		return "", err
	}
	if !sub.sees(key) {
		return "", hide(ErrNotFound)
	}
	if sandbox.HasReserved(key) {
		return "", sandbox.ErrReserved
	}
	info, err := s.root.Lstat(p.Native())
	if err != nil {
		if notExist(err) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("stat entry: %w", err)
	}
	if sub.Bindings.Bound(key) {
		return "", ErrBoundFolder
	}
	if !sub.admin() {
		if err := s.mayChange(sub, key, info, authz.Delete); err != nil {
			return "", err
		}
	}
	var trash string
	if info.IsDir() {
		trash, err = s.toTrash(p.Native())
	} else {
		err = s.root.Remove(p.Native())
	}
	if err != nil {
		return "", fmt.Errorf("delete entry: %w", err)
	}
	if err := s.update(func(tx *state.Tx) error { return tx.DeleteUploaders(key) }); err != nil {
		log.Printf("Cannot remove the uploader records of a deleted entry, %s: %v", key, err)
	}
	return trash, nil
}

func (s *Service) Move(ctx context.Context, oldPath, newPath string) (string, error) {
	from, to, err := s.move(ctx, oldPath, newPath)
	err = osErr(sandbox.FromRoot(err))
	return to.Rel, s.publishChange(ctx, events.Event{
		Type: events.FileMoved, Path: oldPath, Target: newPath,
		Resolved: from.Rel, ResolvedTarget: to.Rel,
	}, err)
}

func (s *Service) move(ctx context.Context, oldPath, newPath string) (from, to sandbox.Path, err error) {
	if err := s.allow(); err != nil {
		return sandbox.Path{}, sandbox.Path{}, err
	}
	sub, ok := s.subject(ctx)
	if !ok {
		return sandbox.Path{}, sandbox.Path{}, hide(ErrNotFound)
	}
	if _, err := sandbox.Clean(oldPath); err != nil {
		return from, sandbox.Path{}, err
	}
	if clean, err := sandbox.Clean(newPath); err == nil && clean != "." && !ValidName(path.Base(clean)) {
		return from, sandbox.Path{}, ErrInvalidName
	}
	if from, err = s.resolve(sub, oldPath, true, ErrNotFound); err != nil {
		return from, sandbox.Path{}, err
	}
	if to, err = s.resolve(sub, newPath, true, ErrParentNotFound); err != nil {
		// A new name holding a backslash is an invalid name on every system,
		// also where the path is refused for using it as a separator.
		if errors.Is(err, sandbox.ErrInvalidPath) && strings.ContainsRune(path.Base(newPath), '\\') {
			return from, sandbox.Path{}, ErrInvalidName
		}
		return from, sandbox.Path{}, err
	}
	if !ValidName(path.Base(to.Rel)) {
		return from, to, ErrInvalidName
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	return from, to, s.moveLocked(ctx, from, to)
}

// moveLocked decides and makes the move. The decisions come before the
// checks that compare the two paths, which could otherwise tell how
// symlinks in an unreadable folder resolve. The caller holds s.mu.
func (s *Service) moveLocked(ctx context.Context, from, to sandbox.Path) error {
	if err := s.allow(); err != nil {
		return err
	}
	sub, ok := s.subject(ctx)
	if !ok {
		return hide(ErrNotFound)
	}
	fromKey, err := s.storedFor(sub, from.Rel, ErrNotFound)
	if err != nil {
		return err
	}
	if !sub.sees(fromKey) {
		return hide(ErrNotFound)
	}
	if sandbox.HasReserved(fromKey) {
		return sandbox.ErrReserved
	}
	info, err := s.root.Lstat(from.Native())
	if err != nil {
		if notExist(err) {
			return ErrNotFound
		}
		return fmt.Errorf("stat source: %w", err)
	}
	if sub.Bindings.Bound(fromKey) {
		return ErrBoundFolder
	}
	toDir, err := s.storedFor(sub, path.Dir(to.Rel), ErrParentNotFound)
	if err != nil {
		return err
	}
	if sandbox.HasReserved(toDir) {
		return sandbox.ErrReserved
	}
	if err := refusal(sub.decide(toDir, authz.Unowned, authz.MoveTarget), ErrParentNotFound); err != nil {
		return err
	}
	toKey := path.Join(toDir, path.Base(to.Rel))
	if from.Rel == to.Rel || toKey == fromKey {
		return ErrExists
	}
	if from.Contains(to) || authz.Within(toKey, fromKey) {
		return ErrMoveIntoSelf
	}
	if !sub.admin() {
		if err := s.mayChange(sub, fromKey, info, authz.MoveSource); err != nil {
			return err
		}
	}
	if !s.isDir(filepath.Dir(to.Native())) {
		return ErrParentNotFound
	}
	if _, err := s.root.Lstat(to.Native()); err == nil {
		return ErrExists
	} else if !notExist(err) {
		return fmt.Errorf("stat destination: %w", err)
	}
	if err := s.root.Rename(from.Native(), to.Native()); err != nil {
		return fmt.Errorf("rename: %w", nameErr(err))
	}
	toKey, err = s.stored(to.Rel, sub.look())
	if err == nil {
		err = s.update(func(tx *state.Tx) error { return tx.MoveUploaders(fromKey, toKey) })
	}
	if err != nil {
		if rerr := s.root.Rename(to.Native(), from.Native()); rerr != nil {
			log.Printf("Cannot move %s back to %s after failing to move its uploader records: %v", to.Rel, from.Rel, rerr)
		}
		return fmt.Errorf("move uploader records: %w", err)
	}
	return nil
}

func notExist(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR)
}

func osErr(err error) error {
	switch {
	case err == nil:
		return nil
	case isNoSpace(err):
		return fmt.Errorf("%w: %v", ErrInsufficientStorage, err)
	case isCrossDevice(err):
		return fmt.Errorf("%w: %v", ErrCrossDevice, err)
	case isReadOnly(err):
		return fmt.Errorf("%w: %v", ErrReadOnly, err)
	}
	return err
}

var deviceOf = func(info fs.FileInfo) uint64 {
	dev, _ := fileID(info)
	return dev
}

// The ledger measures only the served folder's file system. A folder on
// another file system mounted inside the root is not checked, and a full disk
// there still fails the write. Where fileID reports no device (Windows), every
// folder counts as being on the served file system.
func (s *Service) onServedVolume(dir string) bool {
	root, err := s.root.Stat(".")
	if err != nil {
		return true
	}
	target, err := s.root.Stat(dir)
	if err != nil {
		return true
	}
	return deviceOf(root) == deviceOf(target)
}

func nameErr(err error) error {
	if sandbox.IsBadName(err) {
		return fmt.Errorf("%w: %v", ErrInvalidName, err)
	}
	return err
}

func (s *Service) isDir(name string) bool {
	info, err := s.root.Stat(name)
	return err == nil && info.IsDir()
}

func (s *Service) publish(ctx context.Context, ev events.Event, err error) {
	if s.pub != nil {
		s.pub.Publish(fill(ctx, ev, err))
	}
}

// publishChange publishes the event of a change. A change that was made
// returns only once its record is on disk, or with the error saying it isn't.
func (s *Service) publishChange(ctx context.Context, ev events.Event, err error) error {
	if err != nil || s.audit == nil {
		s.publish(ctx, ev, err)
		return err
	}
	return s.audit.Record(ctx, fill(ctx, ev, nil))
}

func (s *Service) allow() error {
	if s.audit == nil {
		return nil
	}
	return s.audit.Allow()
}

func fill(ctx context.Context, ev events.Event, err error) events.Event {
	ev.Actor = events.ActorFrom(ctx)
	ev.RequestID = events.RequestIDFrom(ctx)
	ev.Outcome = outcomeOf(err)
	ev.Path = truncate(ev.Path)
	ev.Target = truncate(ev.Target)
	if err != nil {
		ev.Detail = truncate(err.Error())
	}
	return ev
}

func outcomeOf(err error) events.Outcome {
	switch {
	case err == nil:
		return events.OutcomeOK
	case isHidden(err),
		errors.Is(err, ErrForbidden),
		errors.Is(err, ErrBoundFolder),
		errors.Is(err, events.ErrChangesPaused),
		errors.Is(err, sandbox.ErrReserved),
		errors.Is(err, sandbox.ErrTraversal),
		errors.Is(err, sandbox.ErrRootTarget),
		errors.Is(err, fs.ErrPermission):
		return events.OutcomeDenied
	case errors.Is(err, ErrNotFound), errors.Is(err, ErrParentNotFound):
		return events.OutcomeNotFound
	case errors.Is(err, ErrExists):
		return events.OutcomeExists
	case errors.Is(err, ErrAborted), errors.Is(err, ErrUploadMoved):
		return events.OutcomeAborted
	case errors.Is(err, ErrInsufficientStorage):
		return events.OutcomeNoSpace
	case errors.Is(err, ErrNotDir),
		errors.Is(err, ErrInvalidName),
		errors.Is(err, ErrMoveIntoSelf),
		errors.Is(err, ErrCrossDevice),
		errors.Is(err, ErrInvalidRange),
		errors.Is(err, ErrPreconditionFailed),
		errors.Is(err, sandbox.ErrBrokenLink),
		errors.Is(err, sandbox.ErrInvalidPath):
		return events.OutcomeInvalid
	default:
		return events.OutcomeError
	}
}

func logicalJoin(dir, name string) string {
	if dir == "" {
		return name
	}
	return strings.TrimRight(dir, "/") + "/" + name
}

func truncate(s string) string {
	if len(s) <= maxLogged {
		return s
	}
	return strings.ToValidUTF8(s[:maxLogged], "") + "…(truncated)"
}
