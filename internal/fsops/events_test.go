package fsops

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/sandbox"
)

type recorder struct {
	mu  sync.Mutex
	evs []events.Event
}

func (r *recorder) Publish(ev events.Event) {
	r.mu.Lock()
	r.evs = append(r.evs, ev)
	r.mu.Unlock()
}

func (r *recorder) all() []events.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]events.Event(nil), r.evs...)
}

func (r *recorder) last(t *testing.T) events.Event {
	t.Helper()
	evs := r.all()
	if len(evs) == 0 {
		t.Fatal("no event published")
	}
	return evs[len(evs)-1]
}

func (r *recorder) one(t *testing.T) events.Event {
	t.Helper()
	evs := r.all()
	if len(evs) != 1 {
		t.Fatalf("got %d events, want exactly 1: %+v", len(evs), evs)
	}
	return evs[0]
}

func newObservedEnv(t *testing.T) (*env, *recorder) {
	t.Helper()
	e := newEnv(t)
	rec := &recorder{}
	e.svc = New(e.sb, rec)
	return e, rec
}

func check(t *testing.T, ev events.Event, typ events.Type, outcome events.Outcome, path string) {
	t.Helper()
	if ev.Type != typ || ev.Outcome != outcome || ev.Path != path {
		t.Errorf("event = {%s %s %q}, want {%s %s %q} (detail %q)", ev.Type, ev.Outcome, ev.Path, typ, outcome, path, ev.Detail)
	}
}

func download(e *env, p string) {
	if f, err := e.svc.Open(bg, p); err == nil {
		f.Close()
	}
}

func TestEveryOperationPublishesExactlyOneEvent(t *testing.T) {
	e, rec := newObservedEnv(t)
	e.write("a.txt", "A")
	e.write("dir/inner.txt", "I")

	steps := []struct {
		name string
		do   func()
		typ  events.Type
		out  events.Outcome
		path string
	}{
		{"list ok", func() { e.svc.List(bg, "dir") }, events.FileListed, events.OutcomeOK, "dir"},
		{"list missing", func() { e.svc.List(bg, "nope") }, events.FileListed, events.OutcomeNotFound, "nope"},
		{"download ok", func() { download(e, "a.txt") }, events.FileDownloaded, events.OutcomeOK, "a.txt"},
		{"download missing", func() { download(e, "nope.txt") }, events.FileDownloaded, events.OutcomeNotFound, "nope.txt"},
		{"upload ok", func() { e.svc.Create(bg, "dir", "new.txt", strings.NewReader("12345"), -1) }, events.FileUploaded, events.OutcomeOK, "dir/new.txt"},
		{"upload bad name", func() { e.svc.Create(bg, "dir", "..", strings.NewReader("x"), -1) }, events.FileUploaded, events.OutcomeInvalid, "dir/.."},
		{"mkdir ok", func() { e.svc.Mkdir(bg, "dir", "sub") }, events.FolderCreated, events.OutcomeOK, "dir/sub"},
		{"mkdir exists", func() { e.svc.Mkdir(bg, "dir", "sub") }, events.FolderCreated, events.OutcomeExists, "dir/sub"},
		{"move ok", func() { e.svc.Move(bg, "a.txt", "b.txt") }, events.FileMoved, events.OutcomeOK, "a.txt"},
		{"move missing", func() { e.svc.Move(bg, "dog4.jpg", "dog3.jpg") }, events.FileMoved, events.OutcomeNotFound, "dog4.jpg"},
		{"delete ok", func() { e.svc.Delete(bg, "b.txt") }, events.FileDeleted, events.OutcomeOK, "b.txt"},
		{"delete root", func() { e.svc.Delete(bg, "") }, events.FileDeleted, events.OutcomeDenied, ""},
	}

	for _, st := range steps {
		before := len(rec.all())
		st.do()
		evs := rec.all()
		if len(evs) != before+1 {
			t.Fatalf("%s: published %d events, want 1", st.name, len(evs)-before)
		}
		check(t, evs[len(evs)-1], st.typ, st.out, st.path)
	}
}

func TestEventDetails(t *testing.T) {
	e, rec := newObservedEnv(t)
	e.write("a.txt", "A")

	ctx := events.WithActor(context.Background(), events.Actor{ID: "alice", Role: "editor", RemoteAddr: "10.0.0.7:4242"})
	ctx = events.WithRequestID(ctx, "req-77")

	e.svc.Delete(ctx, "missing")
	ev := rec.one(t)
	if ev.Actor.ID != "alice" || ev.Actor.Role != "editor" || ev.Actor.RemoteAddr != "10.0.0.7:4242" || ev.RequestID != "req-77" {
		t.Errorf("actor/request id not carried: %+v", ev)
	}
	if ev.Detail == "" {
		t.Error("failed operation has no detail")
	}

	e.svc.Delete(bg, "missing")
	if got := rec.last(t).Actor.ID; got != events.AnonymousID {
		t.Errorf("default actor = %q", got)
	}

	e.svc.Move(bg, "a.txt", "b.txt")
	if mv := rec.last(t); mv.Path != "a.txt" || mv.Target != "b.txt" {
		t.Errorf("move event = %+v", mv)
	}
	e.svc.Create(bg, "", "b.txt", strings.NewReader("123456"), -1)
	if up := rec.last(t); up.Path != "b (1).txt" || up.Size != 6 || up.Outcome != events.OutcomeOK {
		t.Errorf("upload event should name the file as stored, with size: %+v", up)
	}
}

func TestEventsCarryCanonicalPaths(t *testing.T) {
	e, rec := newObservedEnv(t)
	e.write("docs/a.txt", "A")
	e.symlink(filepath.Join(e.root, "docs"), "alias")

	download(e, "alias/../alias/a.txt")
	if ev := rec.last(t); ev.Path != "alias/../alias/a.txt" || ev.Resolved != "docs/a.txt" {
		t.Errorf("download: path %q resolved %q", ev.Path, ev.Resolved)
	}
	e.svc.Move(bg, "/docs/a.txt", "alias/b.txt")
	if ev := rec.last(t); ev.Resolved != "docs/a.txt" || ev.ResolvedTarget != "docs/b.txt" {
		t.Errorf("move: resolved %q -> %q", ev.Resolved, ev.ResolvedTarget)
	}
	e.svc.List(bg, "../outside")
	if ev := rec.last(t); ev.Resolved != "" || ev.Path != "../outside" {
		t.Errorf("rejected path must have no resolved form: %+v", ev)
	}
}

func TestDownloadEventReportsTheTransfer(t *testing.T) {
	e, rec := newObservedEnv(t)
	e.write("movie.bin", "0123456789")

	cases := []struct {
		name    string
		finish  *Transfer
		outcome events.Outcome
		size    int64
		rng     string
		typ     events.Type
	}{
		{"not reported", nil, events.OutcomeOK, 0, "", events.FileDownloaded},
		{"full", &Transfer{Sent: 10}, events.OutcomeOK, 10, "", events.FileDownloaded},
		{"range", &Transfer{Sent: 4, Range: "bytes=2-5"}, events.OutcomeOK, 4, "bytes=2-5", events.FileDownloaded},
		{"client gone", &Transfer{Sent: 3, Err: fmt.Errorf("%w: broken pipe", ErrAborted)}, events.OutcomeAborted, 3, "", events.FileDownloaded},
		{"bad range", &Transfer{Range: "bytes=50-", Err: ErrInvalidRange}, events.OutcomeInvalid, 0, "bytes=50-", events.FileDownloaded},
		{"precondition", &Transfer{Err: ErrPreconditionFailed}, events.OutcomeInvalid, 0, "", events.FileDownloaded},
		{"metadata only", &Transfer{MetadataOnly: true}, events.OutcomeOK, 0, "", events.FileChecked},
	}
	for _, tc := range cases {
		before := len(rec.all())
		f, err := e.svc.Open(bg, "movie.bin")
		if err != nil {
			t.Fatal(err)
		}
		if n := len(rec.all()); n != before {
			t.Fatalf("%s: event published before Close", tc.name)
		}
		if tc.finish != nil {
			f.Finish(*tc.finish)
		}
		f.Close()
		f.Close()
		if n := len(rec.all()); n != before+1 {
			t.Fatalf("%s: %d events, want 1", tc.name, n-before)
		}
		ev := rec.last(t)
		if ev.Type != tc.typ || ev.Outcome != tc.outcome || ev.Size != tc.size || ev.Range != tc.rng || ev.Resolved != "movie.bin" {
			t.Errorf("%s: event = %+v", tc.name, ev)
		}
	}
}

func TestBlockedAttemptsAreDeniedAndKeepTheRawPath(t *testing.T) {
	e, rec := newObservedEnv(t)
	e.symlink(e.outside, "escape")
	e.write("a.txt", "A")

	attempts := []struct {
		name string
		do   func()
		typ  events.Type
		path string
	}{
		{"list traversal", func() { e.svc.List(bg, "../outside") }, events.FileListed, "../outside"},
		{"download traversal", func() { download(e, "../outside/secret.txt") }, events.FileDownloaded, "../outside/secret.txt"},
		{"download via symlink", func() { download(e, "escape/secret.txt") }, events.FileDownloaded, "escape/secret.txt"},
		{"upload traversal", func() { e.svc.Create(bg, "../outside", "x.txt", strings.NewReader("x"), -1) }, events.FileUploaded, "../outside/x.txt"},
		{"mkdir via symlink", func() { e.svc.Mkdir(bg, "escape", "x") }, events.FolderCreated, "escape/x"},
		{"move out", func() { e.svc.Move(bg, "a.txt", "../a.txt") }, events.FileMoved, "a.txt"},
		{"delete traversal", func() { e.svc.Delete(bg, "../outside/secret.txt") }, events.FileDeleted, "../outside/secret.txt"},
		{"delete root", func() { e.svc.Delete(bg, ".") }, events.FileDeleted, "."},
	}
	for _, a := range attempts {
		before := len(rec.all())
		a.do()
		evs := rec.all()
		if len(evs) != before+1 {
			t.Fatalf("%s: %d events, want 1", a.name, len(evs)-before)
		}
		check(t, evs[len(evs)-1], a.typ, events.OutcomeDenied, a.path)
	}
}

func TestOutcomeClassification(t *testing.T) {
	boom := errors.New("disk on fire")
	for _, tc := range []struct {
		err  error
		want events.Outcome
	}{
		{nil, events.OutcomeOK},
		{ErrNotFound, events.OutcomeNotFound},
		{ErrParentNotFound, events.OutcomeNotFound},
		{ErrExists, events.OutcomeExists},
		{ErrNotDir, events.OutcomeInvalid},
		{ErrInvalidName, events.OutcomeInvalid},
		{ErrMoveIntoSelf, events.OutcomeInvalid},
		{ErrInvalidRange, events.OutcomeInvalid},
		{fmt.Errorf("%w: reset", ErrAborted), events.OutcomeAborted},
		{sandbox.ErrBrokenLink, events.OutcomeInvalid},
		{sandbox.ErrInvalidPath, events.OutcomeInvalid},
		{sandbox.ErrTraversal, events.OutcomeDenied},
		{sandbox.ErrRootTarget, events.OutcomeDenied},
		{fmt.Errorf("open file: %w", fs.ErrPermission), events.OutcomeDenied},
		{fmt.Errorf("wrapped: %w", ErrExists), events.OutcomeExists},
		{boom, events.OutcomeError},
	} {
		if got := outcomeOf(tc.err); got != tc.want {
			t.Errorf("outcomeOf(%v) = %s, want %s", tc.err, got, tc.want)
		}
	}
}

func TestFailedUploadIsRecordedAsErrorWithSize(t *testing.T) {
	e, rec := newObservedEnv(t)
	e.svc.Create(bg, "", "partial.bin", &failingReader{data: "half", err: errors.New("connection reset")}, -1)

	ev := rec.one(t)
	check(t, ev, events.FileUploaded, events.OutcomeError, "partial.bin")
	if !strings.Contains(ev.Detail, "connection reset") || ev.Size != 4 {
		t.Errorf("event = %+v", ev)
	}
	if _, err := os.Stat(filepath.Join(e.root, "partial.bin")); err == nil {
		t.Error("partial file left behind")
	}
}

func TestLongPathsAreTruncatedInEvents(t *testing.T) {
	e, rec := newObservedEnv(t)
	e.svc.Delete(bg, strings.Repeat("a", 100000))

	ev := rec.one(t)
	if len(ev.Path) > maxLogged+20 || !strings.HasSuffix(ev.Path, "(truncated)") {
		t.Errorf("path not truncated: %d bytes", len(ev.Path))
	}
	if len(ev.Detail) > maxLogged+20 {
		t.Errorf("detail not truncated: %d bytes", len(ev.Detail))
	}
}

func TestNilPublisherIsAllowed(t *testing.T) {
	e := newEnv(t)
	if _, err := e.svc.Delete(bg, "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v", err)
	}
}

func TestEventsFromConcurrentOperations(t *testing.T) {
	e, rec := newObservedEnv(t)
	const n = 30
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.svc.Create(bg, "", "same.txt", strings.NewReader("x"), -1)
		}()
	}
	wg.Wait()

	evs := rec.all()
	if len(evs) != n {
		t.Fatalf("%d events for %d uploads", len(evs), n)
	}
	seen := map[string]bool{}
	for _, ev := range evs {
		if ev.Outcome != events.OutcomeOK || seen[ev.Path] {
			t.Errorf("unexpected or duplicate event: %+v", ev)
		}
		seen[ev.Path] = true
	}
}
