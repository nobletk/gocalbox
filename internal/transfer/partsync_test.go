package transfer

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/nobletk/gocalbox/internal/events"
)

// flushLog records which of an upload's files were flushed, in order.
type flushLog struct {
	mu    sync.Mutex
	names []string
	fail  string // a file name whose flush fails
}

func (l *flushLog) sync(f *os.File) error {
	name := filepath.Base(f.Name())
	l.mu.Lock()
	l.names = append(l.names, name)
	fail := l.fail
	l.mu.Unlock()
	if name == fail {
		return &os.PathError{Op: "sync", Path: f.Name(), Err: syscall.EIO}
	}
	return f.Sync()
}

func (l *flushLog) count(name string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, x := range l.names {
		if x == name {
			n++
		}
	}
	return n
}

func (l *flushLog) reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.names = nil
}

func (l *flushLog) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.names...)
}

func withPartSyncs(data, log bool, fl *flushLog) option {
	return withEngine(func(e *Engine) {
		e.syncPartData, e.syncPartLog = data, log
		e.syncFile = fl.sync
	})
}

// Each accepted part flushes its data and its log line by default, and a
// benchmark setting leaves out either or both; the completion still finds the
// whole file on disk before it places it.
func TestAPartsFlushesFollowTheSetting(t *testing.T) {
	for _, c := range []struct {
		name      string
		data, log bool
	}{{"both", true, true}, {"data only", true, false}, {"log only", false, true}, {"neither", false, false}} {
		t.Run(c.name, func(t *testing.T) {
			fl := &flushLog{}
			en := newEnv(t, withPartSyncs(c.data, c.log, fl))
			f := newFile(3 * testPartSize)
			up := en.create(alice, "public", "a.bin", f)
			fl.reset()
			en.sendAll(alice, up.UploadID, f)
			wantData, wantLog := 0, 0
			if c.data {
				wantData = f.parts()
			}
			if c.log {
				wantLog = f.parts()
			}
			if got := fl.count(dataName); got != wantData {
				t.Errorf("the parts flushed the data %d times, want %d", got, wantData)
			}
			if got := fl.count(logName); got != wantLog {
				t.Errorf("the parts flushed the log %d times, want %d", got, wantLog)
			}
			if got := len(ops(en.logLines(up.UploadID))); got < f.parts() {
				t.Errorf("the log holds %d lines, fewer than the parts", got)
			}

			fl.reset()
			res, err := en.e.Complete(as(alice), up.UploadID, f.composite())
			if err != nil {
				t.Fatalf("complete: %v", err)
			}
			b, err := os.ReadFile(filepath.Join(en.dir, filepath.FromSlash(res.Path)))
			if err != nil || string(b) != string(f.data) {
				t.Fatalf("the placed file: %d bytes, %v", len(b), err)
			}
			names := fl.all()
			data := fl.count(dataName)
			switch {
			case c.data && data != 0:
				t.Errorf("the completion flushed data its parts had flushed: %q", names)
			case !c.data && data != 1:
				t.Errorf("the completion flushed the data %d times, want once: %q", data, names)
			case !c.data && (len(names) == 0 || names[0] != dataName):
				t.Errorf("the data wasn't flushed before the completion was logged: %q", names)
			}
		})
	}
}

// The data is flushed at the completion even when nothing has it open, as
// after a restart.
func TestACompletionAfterARestartFlushesTheData(t *testing.T) {
	fl := &flushLog{}
	en := newEnv(t, withPartSyncs(false, false, fl))
	f := newFile(2 * testPartSize)
	up := en.create(alice, "public", "a.bin", f)
	en.sendAll(alice, up.UploadID, f)
	next := en.restart(withPartSyncs(false, false, fl))
	fl.reset()
	if _, err := next.e.Complete(as(alice), up.UploadID, f.composite()); err != nil {
		t.Fatalf("complete: %v", err)
	}
	if got := fl.count(dataName); got != 1 {
		t.Errorf("the data was flushed %d times: %q", got, fl.all())
	}
}

// A flush of the data that fails at the completion fails the upload, as a
// part's failed flush does, and nothing is placed.
func TestAFailedFlushAtTheCompletionFailsTheUpload(t *testing.T) {
	fl := &flushLog{}
	en := newEnv(t, withPartSyncs(false, true, fl))
	f := newFile(2 * testPartSize)
	up := en.create(alice, "public", "a.bin", f)
	en.sendAll(alice, up.UploadID, f)
	fl.mu.Lock()
	fl.fail = dataName
	fl.mu.Unlock()
	_, err := en.e.Complete(as(alice), up.UploadID, f.composite())
	var ce *ClosedError
	if !errors.As(err, &ce) || ce.State != Failed || !strings.Contains(err.Error(), "flush") {
		t.Fatalf("complete: %v", err)
	}
	if exists(filepath.Join(en.dir, "public", "a.bin")) {
		t.Error("a file whose data wasn't flushed was placed")
	}
	if en.state(up.UploadID) != Failed {
		t.Errorf("state %s", en.state(up.UploadID))
	}
	if evs := en.bus.of(events.UploadFailed); len(evs) != 1 || !strings.Contains(evs[0].Detail, "flush") {
		t.Errorf("events %+v", evs)
	}
	s := en.session(up.UploadID)
	s.mu.Lock()
	counted := s.counted
	s.mu.Unlock()
	if counted {
		t.Error("the failed upload still counts against its owner")
	}
}

// The whole file's flush at the completion doesn't hold up the session's
// other calls.
func TestTheFlushAtTheCompletionLeavesTheSessionFree(t *testing.T) {
	release := make(chan struct{})
	flushing := make(chan struct{}, 1)
	en := newEnv(t, withEngine(func(e *Engine) {
		e.syncPartData = false
		e.syncFile = func(f *os.File) error {
			if filepath.Base(f.Name()) == dataName {
				flushing <- struct{}{}
				<-release
			}
			return f.Sync()
		}
	}))
	f := newFile(2 * testPartSize)
	up := en.create(alice, "public", "a.bin", f)
	en.sendAll(alice, up.UploadID, f)
	done := make(chan error, 1)
	go func() {
		_, err := en.e.Complete(as(alice), up.UploadID, f.composite())
		done <- err
	}()
	within(t, flushing)
	var once sync.Once
	free := func() { once.Do(func() { close(release) }) }
	t.Cleanup(free)
	status := make(chan error, 1)
	go func() {
		_, err := en.e.Status(as(alice), up.UploadID, nil)
		status <- err
	}()
	if err := within(t, status); err != nil {
		t.Errorf("status during the flush: %v", err)
	}
	free()
	if err := within(t, done); err != nil {
		t.Errorf("complete: %v", err)
	}
}

// An ordinary engine flushes both.
func TestAnEngineFlushesEachPartByDefault(t *testing.T) {
	en := newEnv(t)
	if !en.e.syncPartData || !en.e.syncPartLog {
		t.Errorf("syncPartData %v, syncPartLog %v", en.e.syncPartData, en.e.syncPartLog)
	}
}
