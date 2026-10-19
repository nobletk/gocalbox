package fsops

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/nobletk/gocalbox/internal/events"
)

type fakeAuditor struct {
	t   *testing.T
	svc *Service

	mu         sync.Mutex
	paused     bool
	fail       error
	calls      [][]events.Event
	protective int
}

func (f *fakeAuditor) Allow() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.paused {
		return fmt.Errorf("%w: disk full", events.ErrChangesPaused)
	}
	return nil
}

func (f *fakeAuditor) Record(_ context.Context, evs ...events.Event) error {
	if f.svc.mu.TryLock() {
		f.svc.mu.Unlock()
	} else {
		f.t.Error("a change waits for its record while holding the lock")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, evs)
	return f.fail
}

func (f *fakeAuditor) RecordProtective(ctx context.Context, evs ...events.Event) error {
	f.mu.Lock()
	f.protective++
	f.mu.Unlock()
	return f.Record(ctx, evs...)
}

func (f *fakeAuditor) recorded() [][]events.Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]events.Event(nil), f.calls...)
}

func newAuditedEnv(t *testing.T) (*env, *recorder, *fakeAuditor) {
	t.Helper()
	e := newEnv(t)
	rec := &recorder{}
	a := &fakeAuditor{t: t}
	e.svc = asAdmin(New(e.sb, rec, WithAudit(a)))
	a.svc = e.svc
	return e, rec, a
}

func TestPausedChangesDoNothingWhileReadsGoOn(t *testing.T) {
	e, rec, a := newAuditedEnv(t)
	e.write("a.txt", "A")
	e.write("dir/b.txt", "B")
	a.paused = true

	for name, op := range map[string]func() error{
		"upload": func() error { return errOf3(e.svc.Create(bg, "", "new.txt", strings.NewReader("N"), 1)) },
		"mkdir":  func() error { _, err := e.svc.Mkdir(bg, "", "new"); return err },
		"delete": func() error { _, err := e.svc.Delete(bg, "a.txt"); return err },
		"move":   func() error { _, err := e.svc.Move(bg, "dir", "moved"); return err },
	} {
		if err := op(); !errors.Is(err, events.ErrChangesPaused) {
			t.Errorf("%s while paused = %v", name, err)
		}
	}
	if e.exists("new.txt") || e.exists("new") || !e.exists("a.txt") || !e.exists("dir/b.txt") || e.exists("moved") {
		t.Error("a change was made while changes are paused")
	}
	for _, ev := range rec.all() {
		if ev.Outcome != events.OutcomeDenied || !strings.Contains(ev.Detail, "paused") {
			t.Errorf("event of a refused change = %+v", ev)
		}
	}
	if n := len(rec.all()); n != 4 {
		t.Errorf("%d events for 4 refused changes", n)
	}
	if len(a.recorded()) != 0 {
		t.Error("a refused change waited for a record")
	}

	if _, err := e.svc.List(bg, ""); err != nil {
		t.Errorf("listing while paused: %v", err)
	}
	f, err := e.svc.Open(bg, "a.txt")
	if err != nil {
		t.Fatalf("download while paused: %v", err)
	}
	f.Close()
}

func TestEveryChangeWaitsForItsRecord(t *testing.T) {
	e, rec, a := newAuditedEnv(t)
	e.write("a.txt", "A")
	e.write("b.txt", "B")

	steps := []struct {
		typ events.Type
		run func() error
	}{
		{events.FileUploaded, func() error { return errOf3(e.svc.Create(bg, "", "new.txt", strings.NewReader("N"), 1)) }},
		{events.FolderCreated, func() error { _, err := e.svc.Mkdir(bg, "", "dir"); return err }},
		{events.FileMoved, func() error { _, err := e.svc.Move(bg, "a.txt", "dir/a.txt"); return err }},
		{events.FileDeleted, func() error { _, err := e.svc.Delete(bg, "b.txt"); return err }},
		{events.FileDeleted, func() error { _, err := e.svc.Delete(bg, "dir"); return err }},
	}
	for i, s := range steps {
		if err := s.run(); err != nil {
			t.Fatalf("%s: %v", s.typ, err)
		}
		calls := a.recorded()
		if len(calls) != i+1 || len(calls[i]) != 1 || calls[i][0].Type != s.typ || calls[i][0].Outcome != events.OutcomeOK {
			t.Fatalf("after %s: records waited for = %+v", s.typ, calls)
		}
	}
	if evs := rec.all(); len(evs) != 0 {
		t.Errorf("changes published without waiting: %+v", evs)
	}
	if a.protective != 0 {
		t.Error("a file change counted as protective")
	}
}

func TestAChangeWhoseRecordFailedKeepsItsResult(t *testing.T) {
	e, _, a := newAuditedEnv(t)
	a.fail = fmt.Errorf("%w: disk full", events.ErrNotRecorded)
	e.write("a.txt", "A")
	e.write("taken.txt", "T")

	stored, size, err := e.svc.Create(bg, "", "taken.txt", strings.NewReader("NEW"), 3)
	if !events.IsUnrecorded(err) || stored != "taken (1).txt" || size != 3 || e.read("taken (1).txt") != "NEW" {
		t.Errorf("upload = %q, %d, %v", stored, size, err)
	}
	if p, err := e.svc.Mkdir(bg, "", "dir"); !events.IsUnrecorded(err) || p != "dir" || !e.exists("dir") {
		t.Errorf("mkdir = %q, %v", p, err)
	}
	if p, err := e.svc.Move(bg, "a.txt", "dir/a.txt"); !events.IsUnrecorded(err) || p != "dir/a.txt" || !e.exists("dir/a.txt") {
		t.Errorf("move = %q, %v", p, err)
	}
	if p, err := e.svc.Delete(bg, "dir/a.txt"); !events.IsUnrecorded(err) || p != "dir/a.txt" || e.exists("dir/a.txt") {
		t.Errorf("delete = %q, %v", p, err)
	}
}

func TestAFailedChangeDoesntWait(t *testing.T) {
	e, rec, a := newAuditedEnv(t)
	if _, err := e.svc.Delete(bg, "missing.txt"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete = %v", err)
	}
	if len(a.recorded()) != 0 {
		t.Error("a change that failed waited for a record")
	}
	check(t, rec.one(t), events.FileDeleted, events.OutcomeNotFound, "missing.txt")
}

func TestProvisionWaitsForTheRecordsOfItsFolders(t *testing.T) {
	e, _, a := newAuditedEnv(t)
	a.fail = fmt.Errorf("%w: disk full", events.ErrNotRecorded)
	committed := false
	err := e.svc.Provision(bg, []Folder{{Path: "users"}, {Path: "users/alice"}, {Path: "public"}}, func() error {
		committed = true
		return nil
	})
	if !events.IsUnrecorded(err) || !committed || !e.exists("users/alice") || !e.exists("public") {
		t.Fatalf("Provision = %v; committed %v", err, committed)
	}
	calls := a.recorded()
	if len(calls) != 1 || len(calls[0]) != 3 {
		t.Fatalf("records waited for = %+v; want the three folders in one wait", calls)
	}

	a.fail = nil
	if err := e.svc.Provision(bg, []Folder{{Path: "users", IfExists: Reuse}}, nil); err != nil || len(a.recorded()) != 1 {
		t.Errorf("Provision that created nothing = %v, waits %d", err, len(a.recorded()))
	}
}

// pausesAfter lets the first n questions pass, then pauses changes.
type pausesAfter struct {
	fakeAuditor
	n int
}

func (p *pausesAfter) Allow() error {
	p.mu.Lock()
	p.n--
	p.paused = p.n < 0
	p.mu.Unlock()
	return p.fakeAuditor.Allow()
}

func TestAChangeAsksAgainOnceItHoldsTheLock(t *testing.T) {
	e := newEnv(t)
	e.write("a.txt", "A")
	e.write("b.txt", "B")
	a := &pausesAfter{fakeAuditor: fakeAuditor{t: t}, n: 1}
	e.svc = asAdmin(New(e.sb, &recorder{}, WithAudit(a)))
	directUploads(e.svc)
	a.svc = e.svc

	for name, op := range map[string]func() error{
		"mkdir":  func() error { _, err := e.svc.Mkdir(bg, "", "new"); return err },
		"delete": func() error { _, err := e.svc.Delete(bg, "a.txt"); return err },
		"move":   func() error { _, err := e.svc.Move(bg, "b.txt", "c.txt"); return err },
		"upload": func() error { return errOf3(e.svc.Create(bg, "", "up.txt", untouched{t}, 1)) },
	} {
		a.n = 1
		if err := op(); !errors.Is(err, events.ErrChangesPaused) {
			t.Errorf("%s paused while it waited for the lock = %v", name, err)
		}
	}
	if e.exists("new") || !e.exists("a.txt") || !e.exists("b.txt") || e.exists("c.txt") || e.exists("up.txt") {
		t.Error("a change was made after changes were paused")
	}
}

// pausingReader pauses changes once the upload's body has been read.
type pausingReader struct {
	r io.Reader
	a *fakeAuditor
}

func (p pausingReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if err == io.EOF {
		p.a.mu.Lock()
		p.a.paused = true
		p.a.mu.Unlock()
	}
	return n, err
}

func TestAnUploadPausedWhileItsBodyArrivesIsDiscarded(t *testing.T) {
	e, _, a := newAuditedEnv(t)
	stored, _, err := e.svc.Create(bg, "", "big.bin", pausingReader{strings.NewReader("data"), a}, 4)
	if !errors.Is(err, events.ErrChangesPaused) || stored != "" {
		t.Fatalf("upload = %q, %v", stored, err)
	}
	if e.exists("big.bin") {
		t.Error("the upload was kept after changes were paused")
	}
	if len(a.recorded()) != 0 {
		t.Error("a discarded upload waited for a record")
	}
}

// untouched fails the test when an upload reads it.
type untouched struct{ t *testing.T }

func (u untouched) Read([]byte) (int, error) {
	u.t.Error("the body of an upload refused under the lock was read")
	return 0, io.EOF
}
