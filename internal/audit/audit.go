// Package audit writes events to an append-only, hash-chained JSON Lines file
// and verifies such files.
package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/filelock"
	"github.com/nobletk/gocalbox/internal/sandbox"
)

var GenesisHash = strings.Repeat("0", 64)

var (
	ErrTampered = errors.New("audit log is corrupt or has been tampered with")
	ErrTornTail = errors.New("audit log ends with an incomplete record")
	ErrBroken   = errors.New("audit log could not be repaired after a failed write; recording stopped")
	ErrLocked   = errors.New("the audit log is in use by another process")
	ErrClosed   = errors.New("the audit log is closed")
)

type TamperError struct {
	Line   int // 1-based
	Reason string
}

func (e *TamperError) Error() string {
	return fmt.Sprintf("audit log record %d: %s", e.Line, e.Reason)
}

func (e *TamperError) Unwrap() error { return ErrTampered }

type TornTailError struct {
	Offset int64
}

func (e *TornTailError) Error() string {
	return fmt.Sprintf("audit log has an incomplete record at byte %d", e.Offset)
}

func (e *TornTailError) Unwrap() error { return ErrTornTail }

type record struct {
	Event    json.RawMessage `json:"event"`
	PrevHash string          `json:"prev_hash"`
	Hash     string          `json:"hash"`
}

func hashOf(prev string, eventJSON []byte) string {
	h := sha256.New()
	h.Write([]byte(prev))
	h.Write([]byte{'\n'})
	h.Write(eventJSON)
	return hex.EncodeToString(h.Sum(nil))
}

type Report struct {
	Records  int
	LastHash string
	Size     int64
}

func Verify(path string) (Report, error) {
	f, err := os.Open(path)
	if err != nil {
		return Report{}, err
	}
	defer f.Close()

	rep := Report{LastHash: GenesisHash}
	br := bufio.NewReaderSize(f, 64<<10)

	for line := 1; ; line++ {
		data, err := br.ReadBytes('\n')
		if len(data) == 0 && errors.Is(err, io.EOF) {
			return rep, nil
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return rep, &TornTailError{Offset: rep.Size}
			}
			return rep, err
		}

		var rec record
		body := bytes.TrimSuffix(data, []byte{'\n'})
		if err := json.Unmarshal(body, &rec); err != nil {
			return rep, &TamperError{Line: line, Reason: "not a valid record: " + err.Error()}
		}
		// The hash covers only the event object, and encoding/json accepts
		// keys in any letter case, unknown and duplicate keys and extra white
		// space. Requiring the writer's exact bytes leaves no byte of the line
		// unprotected.
		if canonical, err := json.Marshal(rec); err != nil || !bytes.Equal(canonical, body) {
			return rep, &TamperError{Line: line, Reason: "record is not in the form the audit writer produces (edited)"}
		}
		if rec.PrevHash != rep.LastHash {
			return rep, &TamperError{Line: line, Reason: "does not follow the previous record (a record was removed, reordered or edited)"}
		}
		if hashOf(rec.PrevHash, rec.Event) != rec.Hash {
			return rep, &TamperError{Line: line, Reason: "content does not match its hash (the record was edited)"}
		}
		rep.Records++
		rep.LastHash = rec.Hash
		rep.Size += int64(len(data))
	}
}

type logFile interface {
	io.Writer
	io.Seeker
	Sync() error
	Truncate(size int64) error
	Close() error
}

type Writer struct {
	mu      sync.Mutex
	f       logFile
	locked  *os.File
	path    string
	prev    string
	records int
	size    int64
	broken  bool

	// failed holds the first error apart from mu, which a write holds
	// through its fsync, so that asking never waits for the disk.
	failed atomic.Pointer[error]
}

// Open takes an exclusive lock on the log, failing with ErrLocked while
// another process holds it, then verifies it. Locking comes first, so an
// incomplete last record is a crash's, not another writer's record in
// progress.
func Open(path string) (*Writer, error) {
	// Not O_APPEND: on Windows an append-only handle can be neither locked
	// nor truncated. Where the lock holds, this writer is the only one, so it
	// keeps its own position at the end.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	if err := lockFile(f); err != nil {
		f.Close()
		if errors.Is(err, ErrLocked) {
			return nil, err
		}
		return nil, fmt.Errorf("lock audit log: %w", err)
	}
	rep, err := Verify(path)
	var torn *TornTailError
	switch {
	case err == nil:
	case errors.As(err, &torn):
		log.Printf("audit: removing incomplete last record of %s (byte %d onwards), probably left by a crash", path, torn.Offset)
		if err := f.Truncate(torn.Offset); err != nil {
			release(f)
			return nil, fmt.Errorf("repair audit log: %w", err)
		}
	default:
		release(f)
		return nil, fmt.Errorf("existing audit log %s failed verification (investigate it, or move it aside to start a new log): %w", path, err)
	}
	if _, err := f.Seek(rep.Size, io.SeekStart); err != nil {
		release(f)
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	return &Writer{f: f, locked: f, path: path, prev: rep.LastHash, records: rep.Records, size: rep.Size}, nil
}

func release(f *os.File) {
	unlockFile(f)
	f.Close()
}

func lockFile(f *os.File) error {
	err := filelock.Lock(f)
	if errors.Is(err, filelock.ErrLocked) {
		return ErrLocked
	}
	return err
}

func unlockFile(f *os.File) error { return filelock.Unlock(f) }

func (w *Writer) Path() string { return w.path }

// Records counts the records in the file, including earlier runs.
func (w *Writer) Records() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.records
}

func (w *Writer) Err() error {
	if p := w.failed.Load(); p != nil {
		return *p
	}
	return nil
}

func (w *Writer) Handle(ev events.Event) { w.HandleBatch([]events.Event{ev}) }

// HandleBatch writes evs and answers their Acks once they are on disk. Events
// it cannot write are printed on the console, their only copy, and their
// Acks get the error.
func (w *Writer) HandleBatch(evs []events.Event) {
	if len(evs) == 0 {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	switch {
	case w.f == nil:
		lose(evs, ErrClosed)
		return
	case w.broken:
		lose(evs, ErrBroken)
		return
	}
	if err := w.append(evs); err != nil {
		w.failed.CompareAndSwap(nil, &err)
		log.Printf("AUDIT ERROR: could not record %d event(s) starting at %s seq=%d: %v", len(evs), evs[0].Type, evs[0].Seq, err)
		lose(evs, err)
		return
	}
	for _, ev := range evs {
		ev.Ack.Done(nil)
	}
}

func lose(evs []events.Event, cause error) {
	for _, ev := range evs {
		events.PrintLost(ev, events.LostNotRecorded, cause)
		ev.Ack.Done(cause)
	}
}

func (w *Writer) append(evs []events.Event) error {
	var buf bytes.Buffer
	prev := w.prev
	for _, ev := range evs {
		eventJSON, err := json.Marshal(ev)
		if err != nil {
			return err
		}
		hash := hashOf(prev, eventJSON)
		line, err := json.Marshal(record{Event: eventJSON, PrevHash: prev, Hash: hash})
		if err != nil {
			return err
		}
		buf.Write(line)
		buf.WriteByte('\n')
		prev = hash
	}

	n, err := w.f.Write(buf.Bytes())
	if err != nil {
		if n > 0 {
			if terr := w.rewind(); terr != nil {
				w.broken = true
				return fmt.Errorf("%w: write: %v; truncate: %v", ErrBroken, err, terr)
			}
		}
		return fmt.Errorf("write: %w", err)
	}
	if err := w.f.Sync(); err != nil {
		terr := w.rewind()
		if terr == nil {
			terr = w.f.Sync()
		}
		if terr != nil {
			w.broken = true
			return fmt.Errorf("%w: sync: %v; rollback: %v", ErrBroken, err, terr)
		}
		return fmt.Errorf("sync: %w", err)
	}
	w.size += int64(n)
	w.prev = prev
	w.records += len(evs)
	return nil
}

func (w *Writer) rewind() error {
	if err := w.f.Truncate(w.size); err != nil {
		return err
	}
	_, err := w.f.Seek(w.size, io.SeekStart)
	return err
}

func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return nil
	}
	err := w.f.Sync()
	// Windows releases the lock of a closed handle only after a delay, which
	// would refuse a users command run right after the server stops.
	if uerr := unlockFile(w.locked); err == nil {
		err = uerr
	}
	if cerr := w.f.Close(); err == nil {
		err = cerr
	}
	w.f = nil
	return err
}

// Keep names the events the log leaves out unless asked to keep them.
type Keep struct {
	// Metadata keeps successful listings and file checks.
	Metadata bool
	// Parts keeps every accepted part of an upload.
	Parts bool
}

// Subscribe makes c the bus's audit subscriber. A log that takes no event
// for stallAfter pauses changes through g; from then on, the events it has
// no room for are printed instead of waited for.
func Subscribe(bus *events.Bus, c *Coalescer, g *Guard, keep Keep, stallAfter time.Duration) {
	bus.SubscribeBatch("audit", c.HandleBatch, events.Options{
		Mode:       events.Block,
		Buffer:     1024,
		Filter:     Filter(keep),
		StallAfter: stallAfter,
		OnStall:    g.Trip,
	})
}

// Filter passes every event the log keeps: all but successful listings and
// file checks, and accepted parts of uploads, unless keep asks for them. An
// event with an Ack always passes.
func Filter(keep Keep) func(events.Event) bool {
	return func(ev events.Event) bool {
		switch {
		case ev.Ack != nil:
			return true
		case ev.Progress():
			return keep.Parts
		case ev.Type == events.FileListed || ev.Type == events.FileChecked:
			return keep.Metadata || ev.Outcome != events.OutcomeOK
		}
		return true
	}
}

func EnsureOutside(root, path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	// Checked before creating the folder too, so a refused start leaves
	// nothing in the served directory.
	if pre, err := sandbox.ResolveExisting(abs); err == nil && (sandbox.Within(root, abs) || sandbox.Within(root, pre)) {
		return "", fmt.Errorf("audit log %s is inside the served directory %s; choose a location outside it with -audit-log", pre, root)
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
		return "", fmt.Errorf("create audit log folder: %w", err)
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return "", err
	}
	resolved := filepath.Join(dir, filepath.Base(abs))
	if _, err := os.Lstat(resolved); err == nil { // the file itself may be a symlink
		if resolved, err = filepath.EvalSymlinks(resolved); err != nil {
			return "", err
		}
	}

	if sandbox.Within(root, resolved) {
		return "", fmt.Errorf("audit log %s is inside the served directory %s; choose a location outside it with -audit-log", resolved, root)
	}
	return resolved, nil
}
