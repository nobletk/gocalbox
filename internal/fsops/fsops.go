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
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"unicode"
	"unicode/utf8"

	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/sandbox"
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
)

type Entry struct {
	Name  string
	Size  int64
	IsDir bool
}

type Publisher interface {
	Publish(events.Event)
}

const maxLogged = 1024

const maxNameBytes = 255

var maxAutoRename = 10000

type Service struct {
	sb   *sandbox.Sandbox
	root *os.Root
	pub  Publisher

	mu sync.Mutex
}

func New(sb *sandbox.Sandbox, pub Publisher) *Service {
	return &Service{sb: sb, root: sb.OSRoot(), pub: pub}
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
	p, entries, err := s.list(dir)
	err = sandbox.FromRoot(err)
	s.publish(ctx, events.Event{Type: events.FileListed, Path: dir, Resolved: p.Rel}, err)
	return entries, err
}

func (s *Service) list(dir string) (sandbox.Path, []Entry, error) {
	p, err := s.sb.Resolve(dir)
	if err != nil {
		return sandbox.Path{}, nil, err
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

	entries := make([]Entry, 0, len(dirEntries))
	for _, de := range dirEntries {
		fi, err := de.Info()
		if err != nil {
			continue
		}
		if de.Type()&fs.ModeSymlink != 0 {
			target, err := s.sb.Resolve(path.Join(p.Rel, de.Name()))
			if err != nil {
				continue
			}
			if fi, err = s.root.Stat(target.Native()); err != nil {
				continue
			}
		}
		if !fi.IsDir() && !fi.Mode().IsRegular() {
			continue
		}
		entries = append(entries, Entry{Name: de.Name(), Size: fi.Size(), IsDir: fi.IsDir()})
	}
	slices.SortFunc(entries, func(a, b Entry) int { return strings.Compare(a.Name, b.Name) })
	return p, entries, nil
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
	p, f, info, err := s.open(userPath)
	err = sandbox.FromRoot(err)
	ev := events.Event{Type: events.FileDownloaded, Path: userPath, Resolved: p.Rel}
	if err != nil {
		s.publish(ctx, ev, err)
		return nil, err
	}
	return &File{f: f, info: info, svc: s, ctx: ctx, ev: ev}, nil
}

func (s *Service) open(userPath string) (sandbox.Path, *os.File, fs.FileInfo, error) {
	p, err := s.sb.Resolve(userPath)
	if err != nil {
		return sandbox.Path{}, nil, nil, err
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

func (s *Service) Create(ctx context.Context, dir, name string, r io.Reader) (string, int64, error) {
	stored, size, err := s.create(dir, name, r)
	err = sandbox.FromRoot(err)
	ev := events.Event{Type: events.FileUploaded, Path: logicalJoin(dir, name), Size: size}
	if err == nil {
		ev.Path = logicalJoin(dir, path.Base(stored))
		ev.Resolved = stored
	}
	s.publish(ctx, ev, err)
	return stored, size, err
}

func (s *Service) create(dir, name string, r io.Reader) (string, int64, error) {
	p, err := s.sb.Resolve(dir)
	if err != nil {
		return "", 0, err
	}
	if !ValidName(name) {
		return "", 0, ErrInvalidName
	}
	if !s.isDir(p.Native()) {
		return "", 0, ErrParentNotFound
	}

	s.mu.Lock()
	f, rel, err := s.createUnique(p.Rel, name)
	s.mu.Unlock()
	if err != nil {
		return "", 0, fmt.Errorf("create file: %w", err)
	}

	size, err := io.Copy(f, r)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		s.root.Remove(filepath.FromSlash(rel))
		return "", size, fmt.Errorf("write file: %w", err)
	}
	return rel, size, nil
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
	p, err := s.mkdir(parent, name)
	err = sandbox.FromRoot(err)
	s.publish(ctx, events.Event{Type: events.FolderCreated, Path: logicalJoin(parent, name), Resolved: p.Rel}, err)
	return p.Rel, err
}

func (s *Service) mkdir(parent, name string) (sandbox.Path, error) {
	if !ValidName(name) {
		return sandbox.Path{}, ErrInvalidName
	}
	p, err := s.sb.ResolveEntry(path.Join(parent, name))
	if err != nil {
		return sandbox.Path{}, err
	}
	if !s.isDir(filepath.Dir(p.Native())) {
		return p, ErrParentNotFound
	}
	s.mu.Lock()
	err = s.root.Mkdir(p.Native(), 0o755)
	s.mu.Unlock()
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return p, ErrExists
		}
		return p, fmt.Errorf("create folder: %w", nameErr(err))
	}
	return p, nil
}

func (s *Service) Delete(ctx context.Context, userPath string) (string, error) {
	p, err := s.delete(userPath)
	err = sandbox.FromRoot(err)
	s.publish(ctx, events.Event{Type: events.FileDeleted, Path: userPath, Resolved: p.Rel}, err)
	return p.Rel, err
}

func (s *Service) delete(userPath string) (sandbox.Path, error) {
	p, err := s.sb.ResolveEntry(userPath)
	if err != nil {
		return sandbox.Path{}, err
	}
	if _, err := s.root.Lstat(p.Native()); err != nil {
		if notExist(err) {
			return p, ErrNotFound
		}
		return p, fmt.Errorf("stat entry: %w", err)
	}
	if err := s.root.RemoveAll(p.Native()); err != nil {
		return p, fmt.Errorf("delete entry: %w", err)
	}
	return p, nil
}

func (s *Service) Move(ctx context.Context, oldPath, newPath string) (string, error) {
	from, to, err := s.move(oldPath, newPath)
	err = sandbox.FromRoot(err)
	s.publish(ctx, events.Event{
		Type: events.FileMoved, Path: oldPath, Target: newPath,
		Resolved: from.Rel, ResolvedTarget: to.Rel,
	}, err)
	return to.Rel, err
}

func (s *Service) move(oldPath, newPath string) (from, to sandbox.Path, err error) {
	if from, err = s.sb.ResolveEntry(oldPath); err != nil {
		return sandbox.Path{}, sandbox.Path{}, err
	}
	if to, err = s.sb.ResolveEntry(newPath); err != nil {
		return from, sandbox.Path{}, err
	}
	if !ValidName(path.Base(to.Rel)) {
		return from, to, ErrInvalidName
	}
	if from.Rel == to.Rel {
		return from, to, ErrExists
	}
	if from.Contains(to) {
		return from, to, ErrMoveIntoSelf
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.root.Lstat(from.Native()); err != nil {
		if notExist(err) {
			return from, to, ErrNotFound
		}
		return from, to, fmt.Errorf("stat source: %w", err)
	}
	if !s.isDir(filepath.Dir(to.Native())) {
		return from, to, ErrParentNotFound
	}
	if _, err := s.root.Lstat(to.Native()); err == nil {
		return from, to, ErrExists
	} else if !notExist(err) {
		return from, to, fmt.Errorf("stat destination: %w", err)
	}
	if err := s.root.Rename(from.Native(), to.Native()); err != nil {
		return from, to, fmt.Errorf("rename: %w", nameErr(err))
	}
	return from, to, nil
}

func notExist(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR)
}

func nameErr(err error) error {
	if errors.Is(err, syscall.ENAMETOOLONG) {
		return fmt.Errorf("%w: %v", ErrInvalidName, err)
	}
	return err
}

func (s *Service) isDir(name string) bool {
	info, err := s.root.Stat(name)
	return err == nil && info.IsDir()
}

func (s *Service) publish(ctx context.Context, ev events.Event, err error) {
	if s.pub == nil {
		return
	}
	ev.Actor = events.ActorFrom(ctx)
	ev.RequestID = events.RequestIDFrom(ctx)
	ev.Outcome = outcomeOf(err)
	ev.Path = truncate(ev.Path)
	ev.Target = truncate(ev.Target)
	if err != nil {
		ev.Detail = truncate(err.Error())
	}
	s.pub.Publish(ev)
}

func outcomeOf(err error) events.Outcome {
	switch {
	case err == nil:
		return events.OutcomeOK
	case errors.Is(err, sandbox.ErrTraversal),
		errors.Is(err, sandbox.ErrRootTarget),
		errors.Is(err, fs.ErrPermission):
		return events.OutcomeDenied
	case errors.Is(err, ErrNotFound), errors.Is(err, ErrParentNotFound):
		return events.OutcomeNotFound
	case errors.Is(err, ErrExists):
		return events.OutcomeExists
	case errors.Is(err, ErrAborted):
		return events.OutcomeAborted
	case errors.Is(err, ErrNotDir),
		errors.Is(err, ErrInvalidName),
		errors.Is(err, ErrMoveIntoSelf),
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
