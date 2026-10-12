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
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/sandbox"
)

var GenesisHash = strings.Repeat("0", 64)

var (
	ErrTampered = errors.New("audit log is corrupt or has been tampered with")
	ErrTornTail = errors.New("audit log ends with an incomplete record")
	ErrBroken   = errors.New("audit log could not be repaired after a failed write; recording stopped")
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
	Sync() error
	Truncate(size int64) error
	Close() error
}

type Writer struct {
	mu      sync.Mutex
	f       logFile
	path    string
	prev    string
	records int
	size    int64
	err     error
	broken  bool
}

func Open(path string) (*Writer, error) {
	rep, err := Verify(path)
	var torn *TornTailError
	switch {
	case err == nil:
	case errors.Is(err, fs.ErrNotExist):
		rep = Report{LastHash: GenesisHash}
	case errors.As(err, &torn):
		log.Printf("audit: removing incomplete last record of %s (byte %d onwards), probably left by a crash", path, torn.Offset)
		if err := os.Truncate(path, torn.Offset); err != nil {
			return nil, fmt.Errorf("repair audit log: %w", err)
		}
	default:
		return nil, fmt.Errorf("existing audit log %s failed verification (investigate it, or move it aside to start a new log): %w", path, err)
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	return &Writer{f: f, path: path, prev: rep.LastHash, records: rep.Records, size: rep.Size}, nil
}

func (w *Writer) Path() string { return w.path }

// Records counts the records in the file, including earlier runs.
func (w *Writer) Records() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.records
}

func (w *Writer) Err() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.err
}

func (w *Writer) Handle(ev events.Event) { w.HandleBatch([]events.Event{ev}) }

func (w *Writer) HandleBatch(evs []events.Event) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil || w.broken || len(evs) == 0 {
		return
	}
	if err := w.append(evs); err != nil {
		if w.err == nil {
			w.err = err
		}
		log.Printf("AUDIT ERROR: could not record %d event(s) starting at %s seq=%d: %v", len(evs), evs[0].Type, evs[0].Seq, err)
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
			if terr := w.f.Truncate(w.size); terr != nil {
				w.broken = true
				return fmt.Errorf("%w: write: %v; truncate: %v", ErrBroken, err, terr)
			}
		}
		return fmt.Errorf("write: %w", err)
	}
	if err := w.f.Sync(); err != nil {
		terr := w.f.Truncate(w.size)
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

func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return nil
	}
	err := w.f.Sync()
	if cerr := w.f.Close(); err == nil {
		err = cerr
	}
	w.f = nil
	return err
}

func Filter(metadata bool) func(events.Event) bool {
	return func(ev events.Event) bool {
		isMetadata := ev.Type == events.FileListed || ev.Type == events.FileChecked
		return metadata || !isMetadata || ev.Outcome != events.OutcomeOK
	}
}

func EnsureOutside(root, path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
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
