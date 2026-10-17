package transfer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"maps"
	"math/rand/v2"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/sandbox"
)

// image is what a crash at one moment leaves on disk: the served folder
// with its staging, and the registry.
type image struct {
	dir  string
	recs map[string]Record
}

// freeze copies the served folder and the registry as they are now.
func (en *env) freeze() image {
	en.t.Helper()
	dst := en.t.TempDir()
	copyTree(en.t, en.dir, dst)
	en.reg.mu.Lock()
	recs := maps.Clone(en.reg.recs)
	en.reg.mu.Unlock()
	return image{dst, recs}
}

// boot starts an engine on img, as the start after a crash does.
func (en *env) boot(img image, opts ...option) *env {
	en.t.Helper()
	next := &env{t: en.t, dir: img.dir, reg: &fakeRegistry{recs: img.recs}, clock: en.clock}
	next.start(opts...)
	return next
}

// restart stops the engine and starts the next one on what it left.
func (en *env) restart(opts ...option) *env {
	en.t.Helper()
	en.e.Close(context.Background())
	return en.boot(en.freeze(), opts...)
}

// crashAt returns, once the engine has passed point, what a crash there
// would have left.
func (en *env) crashAt(point string) func() image {
	var img *image
	en.e.point = func(name string) {
		if name == point && img == nil {
			i := en.freeze()
			img = &i
		}
	}
	return func() image {
		en.t.Helper()
		if img == nil {
			en.t.Fatalf("the engine never passed %q", point)
		}
		return *img
	}
}

// copyTree copies src to dst with the hard links, modes and modification
// times recovery looks at. The staging folder's lock is left out: the next
// start takes its own.
func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	type copied struct {
		info fs.FileInfo
		path string
	}
	var files []copied
	lock := filepath.Join(src, sandbox.ReservedName, "lock")
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == lock {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		to := filepath.Join(dst, rel)
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		switch {
		case info.Mode()&fs.ModeSymlink != 0:
			target, err := os.Readlink(p)
			if err != nil {
				return err
			}
			return os.Symlink(target, to)
		case info.IsDir():
			return os.MkdirAll(to, info.Mode().Perm())
		case info.Mode().IsRegular():
			for _, c := range files {
				if os.SameFile(c.info, info) {
					return os.Link(c.path, to)
				}
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			if err := os.WriteFile(to, b, info.Mode().Perm()); err != nil {
				return err
			}
			files = append(files, copied{info, to})
			return os.Chtimes(to, info.ModTime(), info.ModTime())
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// logs collects what the engine logs until the test ends.
func logs(t *testing.T) *syncBuffer {
	b := &syncBuffer{}
	prev := log.Writer()
	log.SetOutput(b)
	t.Cleanup(func() { log.SetOutput(prev) })
	return b
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

func (en *env) received(id string) []Range {
	en.t.Helper()
	st, err := en.e.Status(as(alice), id, nil)
	if err != nil {
		en.t.Fatal(err)
	}
	return st.Received
}

func (en *env) finish(user, id string, f file) {
	en.t.Helper()
	for n := 1; n <= f.parts(); n++ {
		if _, err := en.send(user, id, f, n); err != nil {
			en.t.Fatalf("part %d: %v", n, err)
		}
	}
	res, err := en.e.Complete(as(user), id, f.composite())
	if err != nil {
		en.t.Fatalf("complete: %v", err)
	}
	if got, _ := os.ReadFile(filepath.Join(en.dir, filepath.FromSlash(res.Path))); !bytes.Equal(got, f.data) {
		en.t.Errorf("the file at %s differs", res.Path)
	}
}

// recovered checks that a completed session was recorded again, once, in
// the name of its completing request.
func (en *env) recovered(id string) {
	en.t.Helper()
	en.audit.mu.Lock()
	recorded := slices.Clone(en.audit.recorded)
	en.audit.mu.Unlock()
	if len(recorded) != 1 || len(recorded[0]) != 2 {
		en.t.Fatalf("records %+v", recorded)
	}
	for i, typ := range []events.Type{events.FileUploaded, events.UploadCompleted} {
		ev := recorded[0][i]
		if ev.Type != typ || ev.Detail != "recovered" || ev.Actor != events.ActorFrom(as(alice)) || ev.RequestID != "req-"+alice ||
			ev.Upload == nil || ev.Upload.ID != id || ev.Resolved != "public/a.bin" {
			en.t.Errorf("record %d: %+v", i, ev)
		}
	}
	if ls := en.logLines(id); ls[len(ls)-1].Op != opRecorded {
		en.t.Errorf("the log ends with %v", ops(ls))
	}
}

func TestARestartRecoversWhatACrashAtEachPointLeft(t *testing.T) {
	f := newFile(3*testPartSize - 100)
	for _, tc := range []struct {
		point string
		check func(t *testing.T, en *env, id string)
	}{
		{"registered", func(t *testing.T, en *env, id string) {
			if en.e.lookup(id) != nil || en.reg.has(id) || exists(en.staged(id, "")) {
				t.Errorf("session %v, record %v, folder %v", en.e.lookup(id) != nil, en.reg.has(id), exists(en.staged(id, "")))
			}
		}},
		{"written", func(t *testing.T, en *env, id string) {
			if got := en.received(id); !slices.Equal(got, []Range{{1, 1}}) || en.state(id) != Receiving {
				t.Errorf("received %v", got)
			}
			en.finish(alice, id, f)
		}},
		{"logged", func(t *testing.T, en *env, id string) {
			if got := en.received(id); !slices.Equal(got, []Range{{1, 2}}) {
				t.Errorf("received %v", got)
			}
			en.finish(alice, id, f)
		}},
		{"finishing", func(t *testing.T, en *env, id string) {
			if got := en.received(id); !slices.Equal(got, []Range{{1, 3}}) || en.state(id) != Receiving ||
				exists(filepath.Join(en.dir, "public", "a.bin")) {
				t.Errorf("received %v, state %s", got, en.state(id))
			}
			en.finish(alice, id, f)
		}},
		{"linked", func(t *testing.T, en *env, id string) {
			if en.state(id) != Completed || exists(en.staged(id, dataName)) {
				t.Fatalf("state %s, data %v", en.state(id), exists(en.staged(id, dataName)))
			}
			info, err := os.Stat(filepath.Join(en.dir, "public", "a.bin"))
			if err != nil || !slices.Equal(en.files.recorded, []adoptedRecord{{alice, "public/a.bin", info.Size(), info.ModTime().UnixNano()}}) {
				t.Errorf("uploader records %+v, %v", en.files.recorded, err)
			}
			got := en.logLines(id)
			if n := len(got); n < 3 || !slices.Equal(ops(got[n-3:]), []string{opFinishing, opCompleted, opRecorded}) ||
				got[n-2].Actor == nil || got[n-2].Actor.ID != alice || got[n-2].Request != "req-"+alice {
				t.Errorf("log %+v", got)
			}
			en.recovered(id)
		}},
		{"completed", func(t *testing.T, en *env, id string) {
			if en.state(id) != Completed || exists(en.staged(id, dataName)) || len(en.files.recorded) != 0 {
				t.Errorf("state %s, data %v, uploader records %v", en.state(id), exists(en.staged(id, dataName)), en.files.recorded)
			}
			en.recovered(id)
		}},
		{"recorded", func(t *testing.T, en *env, id string) {
			if en.state(id) != Completed {
				t.Errorf("state %s", en.state(id))
			}
			en.recovered(id)
		}},
	} {
		t.Run(tc.point, func(t *testing.T) {
			warnings := logs(t)
			en := newEnv(t)
			var crashed func() image
			arm := func() {}
			switch tc.point {
			case "finishing", "linked":
				var img *image
				hook := func(string) error {
					if img == nil {
						i := en.freeze()
						img = &i
					}
					return nil
				}
				en.files.set(func(f *fakeFiles) {
					if tc.point == "finishing" {
						f.adopt = hook
					} else {
						f.linked = func(rel string) { hook(rel) }
					}
				})
				crashed = func() image { return *img }
			case "registered":
				crashed = en.crashAt(tc.point)
			default:
				arm = func() { crashed = en.crashAt(tc.point) }
			}
			c := en.create(alice, "public", "a.bin", f)
			en.send(alice, c.UploadID, f, 1)
			arm()
			en.send(alice, c.UploadID, f, 2)
			en.send(alice, c.UploadID, f, 3)
			if _, err := en.e.Complete(as(alice), c.UploadID, f.composite()); err != nil {
				t.Fatal(err)
			}
			next := en.boot(crashed())
			if evs := next.bus.of(events.UploadFailed); len(evs) != 0 {
				t.Errorf("failed %+v", evs)
			}
			tc.check(t, next, c.UploadID)
			if strings.Contains(warnings.String(), "has no record") {
				t.Errorf("logged as foreign: %s", warnings)
			}

			again := next.restart()
			again.audit.mu.Lock()
			n := len(again.audit.recorded)
			again.audit.mu.Unlock()
			if n != 0 || len(again.bus.all()) != 0 {
				t.Errorf("the next start recorded %d, published %+v", n, again.bus.all())
			}
		})
	}
}

func TestARemovalCutShortIsFinished(t *testing.T) {
	en := newEnv(t)
	c := en.create(alice, "public", "a.bin", newFile(10))
	en.e.Abort(as(alice), c.UploadID)
	en.clock.add(DefaultLimits.TombstoneTTL)
	crashed := en.crashAt("moved")
	en.e.sweep()
	next := en.boot(crashed())
	if next.e.lookup(c.UploadID) != nil || next.reg.has(c.UploadID) || len(next.bus.all()) != 0 {
		t.Errorf("session %v, record %v, events %+v", next.e.lookup(c.UploadID) != nil, next.reg.has(c.UploadID), next.bus.all())
	}
}

func TestAFileRenamedIntoPlaceIsFoundByItsSizeAndTime(t *testing.T) {
	for _, change := range []string{"", "touched", "resized"} {
		en := newEnv(t)
		f := newFile(2*testPartSize + 7)
		var img *image
		en.files.set(func(ff *fakeFiles) {
			ff.rename = true
			ff.linked = func(string) {
				if img == nil {
					i := en.freeze()
					img = &i
				}
			}
		})
		c := en.create(alice, "public", "a.bin", f)
		en.sendAll(alice, c.UploadID, f)
		if _, err := en.e.Complete(as(alice), c.UploadID, f.composite()); err != nil {
			t.Fatal(err)
		}
		placed := filepath.Join(img.dir, "public", "a.bin")
		switch change {
		case "touched":
			later := time.Now().Add(time.Hour)
			os.Chtimes(placed, later, later)
		case "resized":
			info, _ := os.Stat(placed)
			os.Truncate(placed, info.Size()-1)
			os.Chtimes(placed, info.ModTime(), info.ModTime())
		}
		next := en.boot(*img)
		switch {
		case change == "" && next.state(c.UploadID) != Completed:
			t.Errorf("state %s", next.state(c.UploadID))
		case change == "":
			next.recovered(c.UploadID)
		case next.state(c.UploadID) != Failed || len(next.bus.of(events.UploadFailed)) != 1 || !exists(placed) ||
			!strings.Contains(next.bus.of(events.UploadFailed)[0].Detail, "isn't the file it was placed as"):
			t.Errorf("%s since: state %s, events %+v", change, next.state(c.UploadID), next.bus.all())
		}
	}
}

func TestOneRestartRecoversEveryKindOfSessionTogether(t *testing.T) {
	en := newEnv(t)
	f := newFile(testPartSize + 1)
	done := en.create(alice, "public", "done.bin", f)
	en.finish(alice, done.UploadID, f)
	aborted := en.create(alice, "public", "aborted.bin", f)
	en.send(alice, aborted.UploadID, f, 1)
	en.e.Abort(as(alice), aborted.UploadID)
	expired := en.create(bob, "users/bob", "expired.bin", f)
	open := en.create(bob, "users/bob", "open.bin", f)
	en.send(bob, open.UploadID, f, 2)
	en.clock.add(DefaultLimits.FirstPartTTL)
	en.e.sweep()

	var img *image
	en.files.set(func(ff *fakeFiles) {
		ff.rename = true
		ff.linked = func(string) {
			i := en.freeze()
			img = &i
		}
	})
	renamed := en.create(alice, "public", "a.bin", f)
	en.sendAll(alice, renamed.UploadID, f)
	if _, err := en.e.Complete(as(alice), renamed.UploadID, f.composite()); err != nil {
		t.Fatal(err)
	}

	next := en.boot(*img)
	for id, want := range map[string]State{done.UploadID: Completed, aborted.UploadID: Aborted, expired.UploadID: Expired,
		open.UploadID: Receiving, renamed.UploadID: Completed} {
		if got := next.state(id); got != want {
			t.Errorf("%s: %s, want %s", id, got, want)
		}
	}
	if evs := next.bus.of(events.UploadFailed); len(evs) != 0 {
		t.Errorf("failed %+v", evs)
	}
	if res, err := next.e.Complete(as(alice), done.UploadID, f.composite()); err != nil || res.Path != "public/done.bin" || res.CompositeSHA256 != f.composite() {
		t.Errorf("the tombstone of a completed upload: %+v, %v", res, err)
	}
	if st, _ := next.e.Status(as(bob), expired.UploadID, nil); st.Reason != "no_parts" {
		t.Errorf("expired for %q", st.Reason)
	}
	if _, err := next.e.Create(as(bob), CreateRequest{Dir: "users/bob", Name: "b", Size: 1}); err != nil {
		t.Errorf("bob creates: %v", err)
	}
	next.e.mu.Lock()
	open1, total := next.e.open[bob], next.e.openTotal
	next.e.mu.Unlock()
	if open1 != 2 || total != 2 {
		t.Errorf("open sessions: bob %d, all %d", open1, total)
	}
}

func TestARecoveredSessionCountsAgainstTheLimits(t *testing.T) {
	en := newEnv(t, withLimits(Limits{MaxSessions: 1}))
	c := en.create(alice, "public", "a.bin", newFile(10))
	next := en.restart(withLimits(Limits{MaxSessions: 1}))
	if _, err := next.e.Create(as(alice), CreateRequest{Dir: "public", Name: "b", Size: 1}); !errors.Is(err, ErrTooManyUploads) {
		t.Errorf("a second session: %v", err)
	}
	next.e.Abort(as(alice), c.UploadID)
	if _, err := next.e.Create(as(alice), CreateRequest{Dir: "public", Name: "b", Size: 1}); err != nil {
		t.Errorf("once the first ended: %v", err)
	}
}

func TestRecoveredTimersRunFromTheLog(t *testing.T) {
	en := newEnv(t)
	f := newFile(2 * testPartSize)
	idle := en.create(alice, "public", "idle.bin", f)
	en.send(alice, idle.UploadID, f, 1)
	done := en.create(alice, "public", "done.bin", newFile(10))
	en.finish(alice, done.UploadID, newFile(10))
	aborted := en.create(alice, "public", "aborted.bin", newFile(10))
	en.e.Abort(as(alice), aborted.UploadID)
	en.clock.add(DefaultLimits.IdleTTL - time.Minute)
	next := en.restart()
	next.e.sweep()
	if next.state(idle.UploadID) != Receiving || next.e.lookup(done.UploadID) == nil || next.e.lookup(aborted.UploadID) == nil {
		t.Fatalf("a minute early: %s", next.state(idle.UploadID))
	}
	next.clock.add(time.Minute)
	next.e.sweep()
	if next.state(idle.UploadID) != Expired || next.e.lookup(done.UploadID) != nil || next.e.lookup(aborted.UploadID) != nil {
		t.Errorf("idle since its last part: %s; tombstones kept %v, %v", next.state(idle.UploadID),
			next.e.lookup(done.UploadID) != nil, next.e.lookup(aborted.UploadID) != nil)
	}
}

func TestATornLastLineIsCutOff(t *testing.T) {
	en := newEnv(t)
	f := newFile(2 * testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	en.send(alice, c.UploadID, f, 1)
	en.e.Close(context.Background())
	img := en.freeze()
	logPath := filepath.Join(img.dir, sandbox.ReservedName, uploadsDir, c.UploadID, logName)
	whole, _ := os.ReadFile(logPath)
	lf, _ := os.OpenFile(logPath, os.O_WRONLY|os.O_APPEND, 0)
	lf.WriteString(`{"op":"part","n":2,"sha2`)
	lf.Close()

	next := en.boot(img)
	if got, _ := os.ReadFile(logPath); !bytes.Equal(got, whole) {
		t.Errorf("log after the start:\n%s", got)
	}
	if got := next.received(c.UploadID); !slices.Equal(got, []Range{{1, 1}}) {
		t.Errorf("received %v", got)
	}
	if _, err := next.send(alice, c.UploadID, f, 2); err != nil {
		t.Fatal(err)
	}
	again := next.restart()
	if got := again.received(c.UploadID); !slices.Equal(got, []Range{{1, 2}}) || again.state(c.UploadID) != Receiving {
		t.Errorf("after the next start: %v", got)
	}
}

func TestAnAbortAfterACompletionThatPlacedNothingRecoversAsAborted(t *testing.T) {
	en := newEnv(t)
	f := newFile(10)
	c := en.create(alice, "public", "a.bin", f)
	en.sendAll(alice, c.UploadID, f)
	en.files.set(func(ff *fakeFiles) { ff.adopt = func(string) error { return errForbidden } })
	if _, err := en.e.Complete(as(alice), c.UploadID, f.composite()); !errors.Is(err, errForbidden) {
		t.Fatal(err)
	}
	en.e.Abort(as(alice), c.UploadID)
	if got := ops(en.logLines(c.UploadID)); !slices.Equal(got, []string{opPart, opFinishing, opReject, opAborted}) {
		t.Fatalf("log %v", got)
	}
	if next := en.restart(); next.state(c.UploadID) != Aborted || len(next.bus.all()) != 0 {
		t.Errorf("state %s, events %+v", next.state(c.UploadID), next.bus.all())
	}
}

func TestACreateCutShortIsTold(t *testing.T) {
	for _, tc := range []struct {
		name      string
		log, data string // "" for a missing file
		want      State  // "" for a session that is gone
	}{
		{"no log, empty data", "", "empty", ""},
		{"no log, no data", "", "", ""},
		{"empty log, no data", "empty", "", ""},
		{"empty log and data", "empty", "empty", Receiving},
		{"no log, data", "", "bytes", Failed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			warnings := logs(t)
			en := newEnv(t)
			c := en.create(alice, "public", "a.bin", newFile(10))
			en.e.Close(context.Background())
			img := en.freeze()
			dir := filepath.Join(img.dir, sandbox.ReservedName, uploadsDir, c.UploadID)
			for name, how := range map[string]string{logName: tc.log, dataName: tc.data} {
				switch how {
				case "":
					os.Remove(filepath.Join(dir, name))
				case "bytes":
					os.WriteFile(filepath.Join(dir, name), []byte("hello"), 0o644)
				}
			}
			next := en.boot(img)
			s := next.e.lookup(c.UploadID)
			switch {
			case tc.want == "" && (s != nil || next.reg.has(c.UploadID) || exists(dir)):
				t.Errorf("session %v, record %v, folder %v", s != nil, next.reg.has(c.UploadID), exists(dir))
			case tc.want != "" && (s == nil || next.state(c.UploadID) != tc.want):
				t.Errorf("session %v", s != nil)
			case tc.want == Failed && (len(next.bus.of(events.UploadFailed)) != 1 || exists(filepath.Join(dir, dataName)) ||
				!slices.Equal(ops(next.logLines(c.UploadID)), []string{opFailed})):
				t.Errorf("events %+v, data %v", next.bus.all(), exists(filepath.Join(dir, dataName)))
			case tc.want != Failed && len(next.bus.all()) != 0:
				t.Errorf("events %+v", next.bus.all())
			}
			if strings.Contains(warnings.String(), "has no record") {
				t.Errorf("logged as foreign: %s", warnings)
			}
		})
	}
}

func mustLine(t *testing.T, l line) string {
	t.Helper()
	b, err := json.Marshal(l)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestALogThatCantBeTrustedFailsTheSession(t *testing.T) {
	at := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	f := newFile(2 * testPartSize)
	size := int64(len(f.data))
	var mtime int64 = 1
	actor := events.Actor{ID: alice}
	for _, tc := range []struct {
		name  string
		parts int // the valid part lines kept first
		bad   func(t *testing.T) []string
	}{
		{"not JSON", 2, func(t *testing.T) []string { return []string{"not json"} }},
		{"an unknown op", 2, func(t *testing.T) []string { return []string{mustLine(t, line{Op: "exploded", At: at})} }},
		{"an unknown field", 2, func(t *testing.T) []string {
			return []string{strings.TrimSuffix(mustLine(t, line{Op: opReject, At: at}), "}") + `,"evil":1}`}
		}},
		{"two values on a line", 2, func(t *testing.T) []string {
			l := mustLine(t, line{Op: opReject, At: at})
			return []string{l + l}
		}},
		{"no time", 2, func(t *testing.T) []string { return []string{`{"op":"reject"}`} }},
		{"a part out of range", 2, func(t *testing.T) []string {
			return []string{mustLine(t, line{Op: opPart, N: 3, SHA256: f.sum(1), At: at})}
		}},
		{"a part number of zero", 2, func(t *testing.T) []string {
			return []string{`{"op":"part","n":0,"sha256":"` + f.sum(1) + `","at":"2026-10-17T12:00:00Z"}`}
		}},
		{"a malformed hash", 1, func(t *testing.T) []string {
			return []string{mustLine(t, line{Op: opPart, N: 2, SHA256: strings.ToUpper(f.sum(2)), At: at})}
		}},
		{"a part twice with another hash", 2, func(t *testing.T) []string {
			return []string{mustLine(t, line{Op: opPart, N: 1, SHA256: f.sum(2), At: at})}
		}},
		{"finishing outside the root", 2, func(t *testing.T) []string {
			return []string{mustLine(t, line{Op: opFinishing, Path: "../a.bin", Size: &size, MTime: &mtime, Actor: &actor, At: at})}
		}},
		{"finishing at an absolute path", 2, func(t *testing.T) []string {
			return []string{mustLine(t, line{Op: opFinishing, Path: "/etc/passwd", Size: &size, MTime: &mtime, Actor: &actor, At: at})}
		}},
		{"finishing in the staging folder", 2, func(t *testing.T) []string {
			return []string{mustLine(t, line{Op: opFinishing, Path: ".gocalbox/a.bin", Size: &size, MTime: &mtime, Actor: &actor, At: at})}
		}},
		{"finishing with another size", 2, func(t *testing.T) []string {
			other := size + 1
			return []string{mustLine(t, line{Op: opFinishing, Path: "public/a.bin", Size: &other, MTime: &mtime, Actor: &actor, At: at})}
		}},
		{"finishing before every part", 1, func(t *testing.T) []string {
			return []string{mustLine(t, line{Op: opFinishing, Path: "public/a.bin", Size: &size, MTime: &mtime, Actor: &actor, At: at})}
		}},
		{"completed without finishing", 2, func(t *testing.T) []string {
			return []string{mustLine(t, line{Op: opCompleted, Path: "public/a.bin", Actor: &actor, At: at})}
		}},
		{"completed elsewhere", 2, func(t *testing.T) []string {
			return []string{
				mustLine(t, line{Op: opFinishing, Path: "public/a.bin", Size: &size, MTime: &mtime, Actor: &actor, At: at}),
				mustLine(t, line{Op: opCompleted, Path: "public/b.bin", Actor: &actor, At: at}),
			}
		}},
		{"recorded without completed", 2, func(t *testing.T) []string { return []string{mustLine(t, line{Op: opRecorded, At: at})} }},
		{"a line after aborted", 2, func(t *testing.T) []string {
			return []string{mustLine(t, line{Op: opAborted, By: alice, At: at}), mustLine(t, line{Op: opReject, At: at})}
		}},
		{"aborted by no one", 2, func(t *testing.T) []string { return []string{mustLine(t, line{Op: opAborted, At: at})} }},
		{"expired for no reason", 2, func(t *testing.T) []string { return []string{mustLine(t, line{Op: opExpired, At: at})} }},
		{"finishing at an unclean path", 2, func(t *testing.T) []string {
			return []string{mustLine(t, line{Op: opFinishing, Path: "public//a.bin", Size: &size, MTime: &mtime, Actor: &actor, At: at})}
		}},
		{"finishing at another name", 2, func(t *testing.T) []string {
			return []string{mustLine(t, line{Op: opFinishing, Path: "public/b.bin", Size: &size, MTime: &mtime, Actor: &actor, At: at})}
		}},
		{"finishing without its modification time", 2, func(t *testing.T) []string {
			return []string{mustLine(t, line{Op: opFinishing, Path: "public/a.bin", Size: &size, Actor: &actor, At: at})}
		}},
		{"finishing without its actor", 2, func(t *testing.T) []string {
			return []string{mustLine(t, line{Op: opFinishing, Path: "public/a.bin", Size: &size, MTime: &mtime, At: at})}
		}},
		{"a part after finishing", 1, func(t *testing.T) []string {
			return []string{
				mustLine(t, line{Op: opPart, N: 2, SHA256: f.sum(2), At: at}),
				mustLine(t, line{Op: opFinishing, Path: "public/a.bin", Size: &size, MTime: &mtime, Actor: &actor, At: at}),
				mustLine(t, line{Op: opPart, N: 2, SHA256: f.sum(2), At: at}),
			}
		}},
		{"a refusal after completed", 2, func(t *testing.T) []string {
			return []string{
				mustLine(t, line{Op: opFinishing, Path: "public/a.bin", Size: &size, MTime: &mtime, Actor: &actor, At: at}),
				mustLine(t, line{Op: opCompleted, Path: "public/a.bin", Actor: &actor, At: at}),
				mustLine(t, line{Op: opReject, At: at}),
			}
		}},
		{"aborted after completed", 2, func(t *testing.T) []string {
			return []string{
				mustLine(t, line{Op: opFinishing, Path: "public/a.bin", Size: &size, MTime: &mtime, Actor: &actor, At: at}),
				mustLine(t, line{Op: opCompleted, Path: "public/a.bin", Actor: &actor, At: at}),
				mustLine(t, line{Op: opAborted, By: alice, At: at}),
			}
		}},
		{"completed first", 0, func(t *testing.T) []string {
			return []string{mustLine(t, line{Op: opCompleted, Path: "public/a.bin", Actor: &actor, At: at})}
		}},
		{"a failed line without a time after a bad one", 2, func(t *testing.T) []string {
			return []string{"not json", `{"op":"failed","reason":"earlier"}`}
		}},
		{"an unknown field with a long name", 2, func(t *testing.T) []string {
			return []string{`{"op":"reject","at":"2026-10-17T12:00:00Z","` + strings.Repeat(`\u0000`, 6000) + `":1}`}
		}},
		{"a line too long", 2, func(t *testing.T) []string {
			return []string{mustLine(t, line{Op: opReject, Reason: strings.Repeat("x", maxLine), At: at})}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			en := newEnv(t)
			c := en.create(alice, "public", "a.bin", f)
			en.sendAll(alice, c.UploadID, f)
			en.e.Close(context.Background())
			img := en.freeze()
			logPath := filepath.Join(img.dir, sandbox.ReservedName, uploadsDir, c.UploadID, logName)
			var b strings.Builder
			for _, l := range en.logLines(c.UploadID)[:tc.parts] {
				b.WriteString(mustLine(t, l) + "\n")
			}
			for _, l := range tc.bad(t) {
				b.WriteString(l + "\n")
			}
			os.WriteFile(logPath, []byte(b.String()), 0o600)

			next := en.boot(img)
			evs := next.bus.of(events.UploadFailed)
			if len(evs) == 1 && !strings.HasPrefix(evs[0].Detail, "its log can't be trusted: line ") {
				t.Errorf("the reason doesn't name the line: %q", evs[0].Detail)
			}
			if next.state(c.UploadID) != Failed || len(evs) != 1 || evs[0].Actor.ID != events.SystemID ||
				exists(filepath.Join(img.dir, sandbox.ReservedName, uploadsDir, c.UploadID, dataName)) {
				t.Fatalf("state %s, events %+v", next.state(c.UploadID), next.bus.all())
			}
			written, _ := os.ReadFile(logPath)
			lines := strings.Split(strings.TrimSuffix(string(written), "\n"), "\n")
			if l, err := decodeLine([]byte(lines[len(lines)-1])); err != nil || l.Op != opFailed || l.Reason != evs[0].Detail {
				t.Errorf("the log ends with %q", lines[len(lines)-1])
			}
			first, _ := next.e.Status(as(alice), c.UploadID, nil)
			next.clock.add(5 * time.Hour)
			again := next.restart()
			st, _ := again.e.Status(as(alice), c.UploadID, nil)
			if st.State != Failed || st.Reason != evs[0].Detail || len(again.bus.all()) != 0 || !st.ExpiresAt.Equal(first.ExpiresAt) {
				t.Errorf("the next start: %+v, events %+v; it expired at %v", st, again.bus.all(), first.ExpiresAt)
			}
			if n := len(lines[len(lines)-1]); n > 8*maxLogged {
				t.Errorf("the failed line takes %d bytes", n)
			}
		})
	}
}

func TestDataShorterThanItsLoggedPartsFailsTheSession(t *testing.T) {
	en := newEnv(t)
	f := newFile(2 * testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	en.sendAll(alice, c.UploadID, f)
	en.e.Close(context.Background())
	img := en.freeze()
	os.Truncate(filepath.Join(img.dir, sandbox.ReservedName, uploadsDir, c.UploadID, dataName), int64(len(f.data))-1)
	if next := en.boot(img); next.state(c.UploadID) != Failed || len(next.bus.of(events.UploadFailed)) != 1 {
		t.Errorf("state %s", next.state(c.UploadID))
	}
}

func TestStagingThatIsntTheSessionsOwnIsLeftAsItIs(t *testing.T) {
	for _, name := range []string{"", logName, dataName} {
		t.Run("link at "+name, func(t *testing.T) {
			en := newEnv(t)
			f := newFile(10)
			c := en.create(alice, "public", "a.bin", f)
			en.sendAll(alice, c.UploadID, f)
			victim := en.create(bob, "users/bob", "b.bin", f)
			en.sendAll(bob, victim.UploadID, f)
			en.e.Close(context.Background())
			img := en.freeze()
			uploads := filepath.Join(img.dir, sandbox.ReservedName, uploadsDir)
			from := filepath.Join(uploads, c.UploadID, name)
			// A relative link, which os.Root follows inside the root.
			to := filepath.Join("..", victim.UploadID, name)
			if name == "" {
				to = victim.UploadID
			}
			os.RemoveAll(from)
			if err := os.Symlink(to, from); err != nil {
				t.Skip("no symbolic links here:", err)
			}
			before := snapshotDir(t, filepath.Join(uploads, victim.UploadID))

			next := en.boot(img)
			if evs := next.bus.of(events.UploadFailed); len(evs) != 1 || evs[0].Upload.ID != c.UploadID || next.state(victim.UploadID) != Receiving {
				t.Fatalf("events %+v", next.bus.all())
			}
			if next.e.lookup(c.UploadID) != nil || next.reg.has(c.UploadID) || exists(filepath.Join(uploads, c.UploadID)) {
				t.Error("the untrusted staging stays")
			}
			if after := snapshotDir(t, filepath.Join(uploads, victim.UploadID)); !maps.Equal(before, after) {
				t.Errorf("the other session's files changed:\n%v\n%v", before, after)
			}
			if again := next.restart(); len(again.bus.all()) != 0 {
				t.Errorf("reported again: %+v", again.bus.all())
			}
		})
	}
}

// snapshotDir maps each file under dir to its contents.
func snapshotDir(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			b, _ := os.ReadFile(p)
			out[p] = string(b)
		}
		return err
	})
	return out
}

func TestAFolderWithoutARecordIsLeftAlone(t *testing.T) {
	warnings := logs(t)
	en := newEnv(t)
	c := en.create(alice, "public", "a.bin", newFile(10))
	en.e.Close(context.Background())
	img := en.freeze()
	delete(img.recs, c.UploadID)
	next := en.boot(img)
	if next.e.lookup(c.UploadID) != nil || !exists(next.staged(c.UploadID, logName)) || !strings.Contains(warnings.String(), c.UploadID+" has no record") {
		t.Errorf("session %v, folder %v, log:\n%s", next.e.lookup(c.UploadID) != nil, exists(next.staged(c.UploadID, "")), warnings)
	}
}

func TestRecordsThatCantBeTrustedAreDeleted(t *testing.T) {
	warnings := logs(t)
	en := newEnv(t)
	c := en.create(alice, "public", "a.bin", newFile(10))
	en.e.Close(context.Background())
	img := en.freeze()
	good := img.recs[c.UploadID]
	bad := func(id string, change func(r *Record)) {
		r := good
		r.ID = id
		change(&r)
		img.recs[id] = r
	}
	ids := []string{strings.Repeat("1", 32), strings.Repeat("2", 32), strings.Repeat("3", 32), strings.Repeat("4", 32),
		strings.Repeat("5", 32), strings.Repeat("6", 32), strings.Repeat("7", 32), strings.Repeat("8", 32), "ABC"}
	bad(ids[0], func(r *Record) { r.Dir = "public/../users" })
	bad(ids[1], func(r *Record) { r.Name = "a/b" })
	bad(ids[2], func(r *Record) { r.Name = ".gocalbox" })
	bad(ids[3], func(r *Record) { r.Size, r.PartCount = MaxSize+1, PartCount(MaxSize+1, r.PartSize) })
	bad(ids[4], func(r *Record) { r.PartCount++ })
	bad(ids[5], func(r *Record) { r.Owner = "" })
	bad(ids[6], func(r *Record) { r.Created = time.Time{} })
	bad(ids[7], func(r *Record) { r.ClientKey = "a b" })
	bad(ids[8], func(r *Record) {})
	// Each has staging that would make it a session if its record were
	// trusted. The staging stays, and is reported as having no record.
	uploads := filepath.Join(img.dir, sandbox.ReservedName, uploadsDir)
	for _, id := range append(ids, "zz") {
		copyTree(t, filepath.Join(uploads, c.UploadID), filepath.Join(uploads, id))
	}

	next := en.boot(img, func(_ *Config, en *env) { en.reg.bad = map[string]error{"zz": errors.New("unreadable")} })
	for _, id := range append(ids, "zz") {
		if next.reg.has(id) || next.e.lookup(id) != nil || !strings.Contains(warnings.String(), id+" has no record") {
			t.Errorf("%s kept", id)
		}
	}
	if next.state(c.UploadID) != Receiving {
		t.Errorf("the good one: %s; log:\n%s", next.state(c.UploadID), warnings)
	}
}

func TestARegistryThatCantBeReadStopsTheStart(t *testing.T) {
	en := newEnv(t)
	en.e.Close(context.Background())
	root, err := os.OpenRoot(en.freeze().dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	st, err := sandbox.CheckStaging(root)
	if err != nil || !st.Usable() {
		t.Fatal(err)
	}
	defer st.Close()
	_, err = New(Config{Root: root, Staging: st, Files: en.files, Registry: &fakeRegistry{listErr: errors.New("locked")},
		Events: en.bus, JanitorEvery: -1})
	if err == nil {
		t.Error("started without its records")
	}
}

func TestAnotherFileAtThePathIsntTakenForThePlacedOne(t *testing.T) {
	en := newEnv(t)
	f := newFile(10)
	var img *image
	en.files.set(func(ff *fakeFiles) {
		ff.adopt = func(string) error {
			i := en.freeze()
			img = &i
			return nil
		}
	})
	c := en.create(alice, "public", "a.bin", f)
	en.sendAll(alice, c.UploadID, f)
	if _, err := en.e.Complete(as(alice), c.UploadID, f.composite()); err != nil {
		t.Fatal(err)
	}
	// Someone else's file of the same size took the name.
	other := filepath.Join(img.dir, "public", "a.bin")
	os.WriteFile(other, bytes.Repeat([]byte("x"), len(f.data)), 0o644)
	next := en.boot(*img)
	if next.state(c.UploadID) != Receiving || len(next.files.recorded) != 0 {
		t.Fatalf("state %s, uploader records %v", next.state(c.UploadID), next.files.recorded)
	}
	res, err := next.e.Complete(as(alice), c.UploadID, f.composite())
	if err != nil || res.Path != "public/a (1).bin" {
		t.Errorf("complete: %+v, %v", res, err)
	}
	if got, _ := os.ReadFile(other); string(got) != strings.Repeat("x", len(f.data)) {
		t.Error("the other file changed")
	}
}

func TestACompletionStillUnrecordedIsTriedAgainAtTheNextStart(t *testing.T) {
	en := newEnv(t)
	f := newFile(10)
	c := en.create(alice, "public", "a.bin", f)
	en.sendAll(alice, c.UploadID, f)
	crashed := en.crashAt("completed")
	en.e.Complete(as(alice), c.UploadID, f.composite())

	stalled := fmt.Errorf("%w: the audit log stalled", events.ErrNotConfirmed)
	next := en.boot(crashed(), func(_ *Config, en *env) { en.audit.recErr = stalled })
	if _, err := next.e.Complete(as(alice), c.UploadID, f.composite()); !errors.Is(err, events.ErrNotConfirmed) {
		t.Errorf("the tombstone while unrecorded: %v", err)
	}
	if ls := next.logLines(c.UploadID); ls[len(ls)-1].Op != opCompleted {
		t.Errorf("the log ends with %v", ops(ls))
	}
	again := next.restart()
	again.recovered(c.UploadID)
	if _, err := again.e.Complete(as(alice), c.UploadID, f.composite()); err != nil {
		t.Errorf("the tombstone once recorded: %v", err)
	}
}

func TestAPlacedFileWhoseUploaderCantBeRecordedStillCompletes(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"no longer the placed file", errNotPlaced},
		{"gone meanwhile", &os.PathError{Op: "lstat", Path: "public/a.bin", Err: fs.ErrNotExist}},
	} {
		en := newEnv(t)
		f := newFile(10)
		var img *image
		en.files.set(func(ff *fakeFiles) {
			ff.linked = func(string) {
				i := en.freeze()
				img = &i
			}
		})
		c := en.create(alice, "public", "a.bin", f)
		en.sendAll(alice, c.UploadID, f)
		en.e.Complete(as(alice), c.UploadID, f.composite())
		next := en.boot(*img, func(_ *Config, en *env) { en.files.recordErr = tc.err })
		if next.state(c.UploadID) != Completed || len(next.files.recorded) != 1 {
			t.Errorf("%s: state %s, uploader records %v", tc.name, next.state(c.UploadID), next.files.recorded)
		}
		next.recovered(c.UploadID)
	}
}

func TestAnUploaderRecordThatFailsOtherwiseIsTriedAgainAtTheNextStart(t *testing.T) {
	en := newEnv(t)
	f := newFile(10)
	var img *image
	en.files.set(func(ff *fakeFiles) {
		ff.linked = func(string) {
			i := en.freeze()
			img = &i
		}
	})
	c := en.create(alice, "public", "a.bin", f)
	en.sendAll(alice, c.UploadID, f)
	en.e.Complete(as(alice), c.UploadID, f.composite())
	next := en.boot(*img, func(_ *Config, en *env) { en.files.recordErr = errors.New("no space left on device") })
	if next.e.lookup(c.UploadID) != nil || !next.reg.has(c.UploadID) || len(next.bus.all()) != 0 || len(next.files.recorded) != 1 {
		t.Fatalf("session %v, record %v, events %+v", next.e.lookup(c.UploadID) != nil, next.reg.has(c.UploadID), next.bus.all())
	}
	again := next.restart()
	if again.state(c.UploadID) != Completed || len(again.files.recorded) != 1 {
		t.Errorf("state %s, uploader records %v", again.state(c.UploadID), again.files.recorded)
	}
	again.recovered(c.UploadID)
}

func TestRecordingAgainAtAStartWaitsOnceInAll(t *testing.T) {
	en := newEnv(t)
	f := newFile(10)
	en.audit.recErr = events.ErrNotRecorded
	for _, name := range []string{"a.bin", "b.bin"} {
		c := en.create(alice, "public", name, f)
		en.sendAll(alice, c.UploadID, f)
		en.e.Complete(as(alice), c.UploadID, f.composite())
	}
	next := en.restart(func(_ *Config, en *env) { en.audit.spend = 6 * time.Second })
	if !slices.Equal(next.audit.left, []time.Duration{10 * time.Second, 4 * time.Second}) {
		t.Errorf("left before each wait: %v", next.audit.left)
	}
}

func TestTimersThatRanOutWhileTheServerWasDownApplyAtOnce(t *testing.T) {
	en := newEnv(t)
	c := en.create(alice, "public", "a.bin", newFile(10))
	en.clock.add(DefaultLimits.FirstPartTTL)
	next := en.restart(func(c *Config, _ *env) { c.JanitorEvery = time.Hour })
	for deadline := time.Now().Add(10 * time.Second); next.state(c.UploadID) != Expired; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("not expired ten seconds after the start")
		}
	}
}

func TestDataLeftByAnEndedSessionIsRemoved(t *testing.T) {
	en := newEnv(t)
	f := newFile(10)
	c := en.create(alice, "public", "a.bin", f)
	en.sendAll(alice, c.UploadID, f)
	en.e.Abort(as(alice), c.UploadID)
	en.e.Close(context.Background())
	img := en.freeze()
	data := filepath.Join(img.dir, sandbox.ReservedName, uploadsDir, c.UploadID, dataName)
	// A crash between the aborted line and the data's removal.
	os.WriteFile(data, f.data, 0o644)
	if next := en.boot(img); next.state(c.UploadID) != Aborted || exists(data) {
		t.Errorf("state %s, data %v", next.state(c.UploadID), exists(data))
	}
}

func TestRecoveryFlushesWhatItCutsAndWhatItCompletes(t *testing.T) {
	en := newEnv(t)
	f := newFile(10)
	var img *image
	en.files.set(func(ff *fakeFiles) {
		ff.linked = func(string) {
			i := en.freeze()
			img = &i
		}
	})
	c := en.create(alice, "public", "a.bin", f)
	en.sendAll(alice, c.UploadID, f)
	en.e.Complete(as(alice), c.UploadID, f.composite())
	lf, _ := os.OpenFile(filepath.Join(img.dir, sandbox.ReservedName, uploadsDir, c.UploadID, logName), os.O_WRONLY|os.O_APPEND, 0)
	lf.WriteString(`{"op":`)
	lf.Close()
	flushes := 0
	next := en.boot(*img, withEngine(func(e *Engine) {
		e.syncFile = func(f *os.File) error {
			if filepath.Base(f.Name()) == logName {
				flushes++
			}
			return f.Sync()
		}
	}))
	if next.state(c.UploadID) != Completed || flushes != 2 {
		t.Errorf("state %s, %d flushes of the log: the cut and the completed line", next.state(c.UploadID), flushes)
	}
}

// fullFor makes every log write of op answer that the disk is full while
// *full is set.
func fullFor(op string, full *bool) option {
	return withEngine(func(e *Engine) {
		e.writeLog = func(f *os.File, b []byte, off int64) (int, error) {
			if *full && bytes.Contains(b, []byte(`"op":"`+op+`"`)) {
				return 0, &os.PathError{Op: "write", Path: f.Name(), Err: errDiskFull}
			}
			return f.WriteAt(b, off)
		}
	})
}

func TestACompletedLineWithNoRoomIsWrittenLaterBeforeRecorded(t *testing.T) {
	full := true
	en := newEnv(t, fullFor(opCompleted, &full))
	f := newFile(10)
	c := en.create(alice, "public", "a.bin", f)
	en.sendAll(alice, c.UploadID, f)
	if _, err := en.e.Complete(as(alice), c.UploadID, f.composite()); err != nil {
		t.Fatal(err)
	}
	if got := ops(en.logLines(c.UploadID)); !slices.Equal(got, []string{opPart, opFinishing}) {
		t.Fatalf("with no room: %v", got)
	}
	full = false
	en.e.sweep()
	if got := ops(en.logLines(c.UploadID)); !slices.Equal(got, []string{opPart, opFinishing, opCompleted, opRecorded}) {
		t.Errorf("once there is room: %v", got)
	}
	if next := en.restart(); next.state(c.UploadID) != Completed || len(next.bus.all()) != 0 {
		t.Errorf("the next start: %s, %+v", next.state(c.UploadID), next.bus.all())
	}
}

func TestARecoveredCompletionWithNoRoomForItsLineIsNotMarkedRecorded(t *testing.T) {
	en := newEnv(t)
	f := newFile(10)
	var img *image
	en.files.set(func(ff *fakeFiles) {
		ff.linked = func(string) {
			i := en.freeze()
			img = &i
		}
	})
	c := en.create(alice, "public", "a.bin", f)
	en.sendAll(alice, c.UploadID, f)
	en.e.Complete(as(alice), c.UploadID, f.composite())

	full := true
	next := en.boot(*img, fullFor(opCompleted, &full))
	if got := ops(next.logLines(c.UploadID)); got[len(got)-1] != opFinishing {
		t.Fatalf("with no room: %v", got)
	}
	full = false
	next.e.sweep()
	if got := ops(next.logLines(c.UploadID)); !slices.Equal(got[len(got)-3:], []string{opFinishing, opCompleted, opRecorded}) {
		t.Errorf("once there is room: %v", got)
	}
	if again := next.restart(); again.state(c.UploadID) != Completed || len(again.bus.all()) != 0 {
		t.Errorf("the next start: %s, %+v", again.state(c.UploadID), again.bus.all())
	}
}

func TestStagingThatCantBeReadNowIsLeftForTheNextStart(t *testing.T) {
	en := newEnv(t)
	f := newFile(2 * testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	en.send(alice, c.UploadID, f, 1)
	en.e.Close(context.Background())
	img := en.freeze()
	logPath := filepath.Join(img.dir, sandbox.ReservedName, uploadsDir, c.UploadID, logName)
	if !unwritable(t, logPath) {
		t.Skip("the log can't be made unwritable here")
	}
	warnings := logs(t)
	next := en.boot(img)
	if next.e.lookup(c.UploadID) != nil || !next.reg.has(c.UploadID) || len(next.bus.all()) != 0 ||
		!exists(filepath.Join(img.dir, sandbox.ReservedName, uploadsDir, c.UploadID, dataName)) {
		t.Fatalf("session %v, record %v, events %+v", next.e.lookup(c.UploadID) != nil, next.reg.has(c.UploadID), next.bus.all())
	}
	if !strings.Contains(warnings.String(), "left for the next start") {
		t.Errorf("log:\n%s", warnings)
	}
	writable(t, logPath)
	if again := next.restart(); again.state(c.UploadID) != Receiving || !slices.Equal(again.received(c.UploadID), []Range{{1, 1}}) {
		t.Errorf("once readable: %s", again.state(c.UploadID))
	}
}

func TestATombstoneKeepsTheTimeOfItsCompletion(t *testing.T) {
	en := newEnv(t)
	f := newFile(10)
	c := en.create(alice, "public", "a.bin", f)
	en.sendAll(alice, c.UploadID, f)
	crashed := en.crashAt("completed")
	en.clock.add(time.Minute)
	en.e.Complete(as(alice), c.UploadID, f.composite())
	en.clock.add(5 * time.Hour)
	next := en.boot(crashed())
	if ev := next.bus.of(events.UploadCompleted); len(ev) != 1 || ev[0].Upload.DurationMS != time.Minute.Milliseconds() {
		t.Errorf("recorded again: %+v", ev)
	}
	next.clock.add(5 * time.Hour)
	again := next.restart()
	again.clock.add(DefaultLimits.TombstoneTTL - 10*time.Hour - time.Second)
	again.e.sweep()
	if again.e.lookup(c.UploadID) == nil {
		t.Fatal("removed early")
	}
	again.clock.add(time.Second)
	again.e.sweep()
	if again.e.lookup(c.UploadID) != nil {
		t.Error("its tombstone counts from a later line")
	}
}

func TestAReconciledCompletionKeepsItsTombstoneFromTheStart(t *testing.T) {
	en := newEnv(t)
	f := newFile(10)
	var img *image
	en.files.set(func(ff *fakeFiles) {
		ff.linked = func(string) {
			i := en.freeze()
			img = &i
		}
	})
	c := en.create(alice, "public", "a.bin", f)
	en.sendAll(alice, c.UploadID, f)
	en.e.Complete(as(alice), c.UploadID, f.composite())
	en.clock.add(10 * time.Hour)
	next := en.boot(*img)
	next.clock.add(DefaultLimits.TombstoneTTL - time.Second)
	next.e.sweep()
	if next.e.lookup(c.UploadID) == nil {
		t.Fatal("removed before a day since the start that completed it")
	}
}

func TestAFolderAtThePathIsntTakenForThePlacedFile(t *testing.T) {
	en := newEnv(t)
	f := newFile(10)
	var img *image
	en.files.set(func(ff *fakeFiles) {
		ff.adopt = func(string) error {
			i := en.freeze()
			img = &i
			return nil
		}
	})
	c := en.create(alice, "public", "a.bin", f)
	en.sendAll(alice, c.UploadID, f)
	en.e.Complete(as(alice), c.UploadID, f.composite())
	os.Mkdir(filepath.Join(img.dir, "public", "a.bin"), 0o755)
	if next := en.boot(*img); next.state(c.UploadID) != Receiving {
		t.Errorf("state %s", next.state(c.UploadID))
	}
}

func TestPartsLoggedWithoutTheirDataFailTheSession(t *testing.T) {
	for _, finishing := range []bool{false, true} {
		en := newEnv(t)
		f := newFile(2 * testPartSize)
		var img *image
		en.files.set(func(ff *fakeFiles) {
			ff.adopt = func(string) error {
				i := en.freeze()
				img = &i
				return nil
			}
		})
		c := en.create(alice, "public", "a.bin", f)
		en.sendAll(alice, c.UploadID, f)
		if finishing {
			en.e.Complete(as(alice), c.UploadID, f.composite())
		} else {
			en.e.Close(context.Background())
			i := en.freeze()
			img = &i
		}
		data := filepath.Join(img.dir, sandbox.ReservedName, uploadsDir, c.UploadID, dataName)
		if finishing {
			os.Truncate(data, 10)
		} else {
			os.Remove(data)
		}
		if next := en.boot(*img); next.state(c.UploadID) != Failed || len(next.bus.of(events.UploadFailed)) != 1 {
			t.Errorf("finishing %v: state %s", finishing, next.state(c.UploadID))
		}
	}
}

func TestACrashDuringRecoveryRecoversOnce(t *testing.T) {
	en := newEnv(t)
	f := newFile(10)
	var placed *image
	en.files.set(func(ff *fakeFiles) {
		ff.linked = func(string) {
			i := en.freeze()
			placed = &i
		}
	})
	c := en.create(alice, "public", "a.bin", f)
	en.sendAll(alice, c.UploadID, f)
	en.e.Complete(as(alice), c.UploadID, f.composite())

	var during *image
	en.boot(*placed, func(_ *Config, next *env) {
		next.files.onRecord = func() {
			i := next.freeze()
			during = &i
		}
	})
	last := en.boot(*during)
	if last.state(c.UploadID) != Completed || len(last.files.recorded) != 1 || len(last.bus.of(events.UploadFailed)) != 0 {
		t.Errorf("state %s, uploader records %v", last.state(c.UploadID), last.files.recorded)
	}
	last.recovered(c.UploadID)
}

func TestVariantOf(t *testing.T) {
	long := strings.Repeat("x", 250) + ".bin"
	for _, tc := range []struct {
		name, got string
		want      bool
	}{
		{"a.bin", "a.bin", true},
		{"a.bin", "a (1).bin", true},
		{"a.bin", "a (12).bin", true},
		{"a.bin", "a (0).bin", false},
		{"a.bin", "a (01).bin", false},
		{"a.bin", "a (+1).bin", false},
		{"a.bin", "a (1).txt", false},
		{"a.bin", "b (1).bin", false},
		{"a.bin", "b.bin", false},
		{"abc.bin", "a (1).bin", false},
		{".env", ".env (2)", true},
		{"a", "a (3)", true},
		{long, strings.Repeat("x", 247) + " (1).bin", true},
		{long, strings.Repeat("x", 10) + " (1).bin", true},
		{"short.bin", "sh (1).bin", false},
	} {
		if got := variantOf(tc.name, tc.got); got != tc.want {
			t.Errorf("variantOf(%q, %q) = %v", tc.name, tc.got, got)
		}
	}
}

func FuzzReplay(f *testing.F) {
	at := `"at":"2026-10-17T12:00:00Z"`
	f.Add([]byte(`{"op":"part","n":1,"sha256":"` + strings.Repeat("ab", 32) + `",` + at + "}\n"))
	f.Add([]byte(`{"op":"part","n":2,"sha256":"` + strings.Repeat("cd", 32) + `",` + at + `}` + "\n" + `{"op":"finishing","path":"public/a.bin","size":10,"mtime":1,"actor":{"id":"u"},` + at + "}\n"))
	f.Add([]byte(`{"op":"aborted","by":"u",` + at + "}\n"))
	f.Add([]byte("not json\n"))
	part := func(n int) string {
		return `{"op":"part","n":` + strconv.Itoa(n) + `,"sha256":"` + strings.Repeat("ab", 32) + `",` + at + `,"ip":"192.0.2.7"}` + "\n"
	}
	finishing := `{"op":"finishing","path":"public/a (1).bin","size":8191,"mtime":1,"actor":{"id":"u"},"request":"r",` + at + "}\n"
	for _, log := range []string{
		part(1) + part(2) + finishing + `{"op":"completed","path":"public/a (1).bin","actor":{"id":"u"},` + at + "}\n" + `{"op":"recorded",` + at + "}\n",
		part(2) + `{"op":"reject","reason":"checksum_mismatch",` + at + "}\n" + part(1) + finishing + `{"op":"reject","reason":"forbidden",` + at + "}\n" + `{"op":"aborted","by":"u",` + at + "}\n",
		part(1) + `{"op":"expired","reason":"idle",` + at + "}\n",
		part(1) + part(2) + finishing + finishing + `{"op":"failed","reason":"x",` + at + "}\n",
	} {
		f.Add([]byte(log))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		rec := Record{ID: strings.Repeat("a", 32), Owner: alice, Dir: "public", Name: "a.bin", Size: 2*testPartSize - 1,
			PartSize: testPartSize, PartCount: 2, Created: time.Unix(1, 0)}
		s := newSession(rec)
		r, err := replayFrom(s, bytes.NewReader(b))
		var bad *errBadLine
		if err != nil && !errors.As(err, &bad) {
			t.Fatalf("an error of reading from memory: %v", err)
		}
		if err != nil {
			return
		}
		_, known := next[r.last]
		terminal := r.last == opRecorded || r.last == opAborted || r.last == opExpired || r.last == opFailed
		if s.nReceived > rec.PartCount || r.dataEnd > rec.Size || !known && !terminal ||
			(r.last == opFinishing || r.last == opCompleted || r.last == opRecorded) &&
				(s.nReceived != rec.PartCount || !validPath(r.finishing.Path) || !variantOf(rec.Name, path.Base(r.finishing.Path))) {
			t.Errorf("accepted: %+v, %d parts", r, s.nReceived)
		}
	})
}

func FuzzValidRecord(f *testing.F) {
	f.Add(strings.Repeat("a", 32), "u-alice", "public", "a.bin", int64(10), "key")
	f.Add(".", "u", "..", "../x", int64(-1), "a b")
	f.Add(strings.Repeat("0", 32), "0", "..0", "0", int64(83), "0")
	f.Fuzz(func(t *testing.T, id, owner, dir, name string, size int64, key string) {
		e := &Engine{partSize: PartSize}
		rec := Record{ID: id, Owner: owner, Dir: dir, Name: name, Size: size, ClientKey: key, Created: time.Unix(1, 0)}
		if size >= 0 && size <= MaxSize {
			rec.PartSize = PartSize(size)
			rec.PartCount = PartCount(size, rec.PartSize)
		}
		if e.validRecord(rec) != nil {
			return
		}
		if !ValidID(id) || strings.ContainsAny(name, "/\\") || name == "." || name == ".." || slices.Contains(strings.Split(dir, "/"), "..") {
			t.Errorf("accepted %+v", rec)
		}
	})
}

func TestRandomPartsDuplicatesRefusalsAndRestartsEndWithTheFile(t *testing.T) {
	rnd := rand.New(rand.NewPCG(1, 2))
	for round := range 20 {
		en := newEnv(t)
		f := newFile(rnd.IntN(8*testPartSize) + 1)
		c := en.create(alice, "public", "a.bin", f)
		for len(en.received(c.UploadID)) == 0 || !slices.Equal(en.received(c.UploadID), []Range{{1, f.parts()}}) {
			n := rnd.IntN(f.parts()) + 1
			switch rnd.IntN(5) {
			case 0:
				en = en.restart()
			case 1:
				b := bytes.Clone(f.part(n))
				b[0]++
				en.e.Part(as(alice), PartRequest{ID: c.UploadID, N: n, SHA256: f.sum(n), Length: -1, Body: bytes.NewReader(b)})
			default:
				en.send(alice, c.UploadID, f, n)
			}
		}
		if rnd.IntN(2) == 0 {
			en = en.restart()
		}
		res, err := en.e.Complete(as(alice), c.UploadID, f.composite())
		if err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		if got, _ := os.ReadFile(filepath.Join(en.dir, filepath.FromSlash(res.Path))); !bytes.Equal(got, f.data) {
			t.Fatalf("round %d: the file differs", round)
		}
		if again := en.restart(); again.state(c.UploadID) != Completed {
			t.Fatalf("round %d: after a restart, %s", round, again.state(c.UploadID))
		}
	}
}

func TestARecoveredCompletionWhoseLineIsLostIsReconciledAgain(t *testing.T) {
	en := newEnv(t)
	f := newFile(10)
	var img *image
	en.files.set(func(ff *fakeFiles) {
		ff.linked = func(string) {
			i := en.freeze()
			img = &i
		}
	})
	c := en.create(alice, "public", "a.bin", f)
	en.sendAll(alice, c.UploadID, f)
	en.e.Complete(as(alice), c.UploadID, f.composite())

	next := en.boot(*img, withEngine(func(e *Engine) {
		e.writeLog = func(f *os.File, b []byte, off int64) (int, error) {
			if bytes.Contains(b, []byte(`"op":"completed"`)) {
				return 0, &os.PathError{Op: "write", Path: f.Name(), Err: errors.New("input/output error")}
			}
			return f.WriteAt(b, off)
		}
	}))
	if got := ops(next.logLines(c.UploadID)); got[len(got)-1] != opFinishing {
		t.Fatalf("the log ends with %v", got)
	}
	again := next.restart()
	if again.state(c.UploadID) != Completed || len(again.bus.of(events.UploadFailed)) != 0 {
		t.Errorf("the next start: %s", again.state(c.UploadID))
	}
	again.recovered(c.UploadID)
}

func TestAWaitingCompletedLineLostOtherwiseTakesRecordedWithIt(t *testing.T) {
	var fail error
	en := newEnv(t, withEngine(func(e *Engine) {
		e.writeLog = func(f *os.File, b []byte, off int64) (int, error) {
			if fail != nil && bytes.Contains(b, []byte(`"op":"completed"`)) {
				return 0, &os.PathError{Op: "write", Path: f.Name(), Err: fail}
			}
			return f.WriteAt(b, off)
		}
	}))
	f := newFile(10)
	c := en.create(alice, "public", "a.bin", f)
	en.sendAll(alice, c.UploadID, f)
	fail = errDiskFull
	if _, err := en.e.Complete(as(alice), c.UploadID, f.composite()); err != nil {
		t.Fatal(err)
	}
	fail = errors.New("input/output error")
	en.e.sweep()
	fail = nil
	en.e.sweep()
	if got := ops(en.logLines(c.UploadID)); slices.Contains(got, opRecorded) {
		t.Errorf("recorded written after its completed line was lost: %v", got)
	}
	if next := en.restart(); next.state(c.UploadID) != Completed || len(next.bus.of(events.UploadFailed)) != 0 {
		t.Errorf("the next start: %s", next.state(c.UploadID))
	}
}

// unreadable gives the engine a served folder it can't read.
func unreadable(t *testing.T) option {
	return withEngine(func(e *Engine) {
		closed, err := os.OpenRoot(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		closed.Close()
		e.served = closed
	})
}

func TestATargetThatCantBeReadNowLeavesTheSessionForTheNextStart(t *testing.T) {
	for _, rename := range []bool{false, true} {
		en := newEnv(t)
		f := newFile(10)
		var img *image
		en.files.set(func(ff *fakeFiles) {
			ff.rename = rename
			ff.linked = func(string) {
				i := en.freeze()
				img = &i
			}
		})
		c := en.create(alice, "public", "a.bin", f)
		en.sendAll(alice, c.UploadID, f)
		en.e.Complete(as(alice), c.UploadID, f.composite())
		before, _ := os.ReadFile(filepath.Join(img.dir, sandbox.ReservedName, uploadsDir, c.UploadID, logName))

		next := en.boot(*img, unreadable(t))
		after, _ := os.ReadFile(filepath.Join(img.dir, sandbox.ReservedName, uploadsDir, c.UploadID, logName))
		if next.e.lookup(c.UploadID) != nil || !next.reg.has(c.UploadID) || !bytes.Equal(before, after) || len(next.bus.all()) != 0 {
			t.Fatalf("rename %v: session %v, record %v, events %+v", rename, next.e.lookup(c.UploadID) != nil, next.reg.has(c.UploadID), next.bus.all())
		}
		if again := next.restart(); again.state(c.UploadID) != Completed {
			t.Errorf("rename %v: once readable, %s", rename, again.state(c.UploadID))
		}
	}
}

func TestAnErrorReadingTheStagingLeavesTheSession(t *testing.T) {
	for _, at := range []string{"", dataName, logName} {
		en := newEnv(t)
		f := newFile(10)
		c := en.create(alice, "public", "a.bin", f)
		en.send(alice, c.UploadID, f, 1)
		en.e.Close(context.Background())
		img := en.freeze()
		target := filepath.Join(uploadsDir, c.UploadID, at)
		next := en.boot(img, withEngine(func(e *Engine) {
			e.lstat = func(name string) (fs.FileInfo, error) {
				if name == target {
					return nil, &os.PathError{Op: "lstat", Path: name, Err: errors.New("input/output error")}
				}
				return e.root.Lstat(name)
			}
		}))
		if next.e.lookup(c.UploadID) != nil || !next.reg.has(c.UploadID) || len(next.bus.all()) != 0 ||
			!exists(filepath.Join(img.dir, sandbox.ReservedName, uploadsDir, c.UploadID, dataName)) {
			t.Errorf("an error at %q: session %v, record %v, events %+v", at, next.e.lookup(c.UploadID) != nil, next.reg.has(c.UploadID), next.bus.all())
		}
	}
}

type unreadableLog struct{}

func (unreadableLog) Read([]byte) (int, error) { return 0, errors.New("input/output error") }
func (unreadableLog) ReadAt([]byte, int64) (int, error) {
	return 0, errors.New("input/output error")
}
func (unreadableLog) Close() error { return nil }

func TestAnErrorReadingTheLogLeavesTheSession(t *testing.T) {
	en := newEnv(t)
	f := newFile(10)
	c := en.create(alice, "public", "a.bin", f)
	en.send(alice, c.UploadID, f, 1)
	en.e.Close(context.Background())
	for _, open := range []func(string) (logReader, error){
		func(string) (logReader, error) { return unreadableLog{}, nil },
		func(string) (logReader, error) { return nil, errors.New("sharing violation") },
	} {
		next := en.boot(en.freeze(), withEngine(func(e *Engine) { e.openLog = open }))
		if next.e.lookup(c.UploadID) != nil || !next.reg.has(c.UploadID) || len(next.bus.all()) != 0 {
			t.Errorf("session %v, record %v, events %+v", next.e.lookup(c.UploadID) != nil, next.reg.has(c.UploadID), next.bus.all())
		}
		if again := next.restart(); again.state(c.UploadID) != Receiving {
			t.Errorf("once readable, %s", again.state(c.UploadID))
		}
	}
	if _, err := replayFrom(newSession(en.reg.recs[c.UploadID]), unreadableLog{}); err == nil || errors.As(err, new(*errBadLine)) {
		t.Errorf("a read error taken for bad content: %v", err)
	}
}

func TestAnUntrustedReasonIsCutShort(t *testing.T) {
	en := newEnv(t)
	en.create(alice, "public", "a.bin", newFile(10))
	en.e.Close(context.Background())
	img := en.freeze()
	next := en.boot(img, withEngine(func(e *Engine) {
		e.lstat = func(name string) (fs.FileInfo, error) {
			if filepath.Base(name) == dataName {
				return nil, fmt.Errorf("%s: %w", strings.Repeat("x", 10000), errUntrusted)
			}
			return e.root.Lstat(name)
		}
	}))
	if evs := next.bus.of(events.UploadFailed); len(evs) != 1 || len(evs[0].Detail) > maxLogged+len("…(truncated)") {
		t.Errorf("%d failed events: %+v", len(evs), evs)
	}
}

func TestARecordWhoseStagingIsGoneIsLogged(t *testing.T) {
	warnings := logs(t)
	en := newEnv(t)
	c := en.create(alice, "public", "a.bin", newFile(10))
	en.e.Close(context.Background())
	img := en.freeze()
	os.RemoveAll(filepath.Join(img.dir, sandbox.ReservedName, uploadsDir, c.UploadID))
	if next := en.boot(img); next.reg.has(c.UploadID) || !strings.Contains(warnings.String(), c.UploadID+", whose staging is gone") {
		t.Errorf("record %v, log:\n%s", next.reg.has(c.UploadID), warnings)
	}
}

func TestCloseWritesTheLinesStillWaiting(t *testing.T) {
	full := true
	en := newEnv(t, withEngine(func(e *Engine) {
		e.writeLog = func(f *os.File, b []byte, off int64) (int, error) {
			if full && bytes.Contains(b, []byte(`"op":"completed"`)) {
				return 0, &os.PathError{Op: "write", Path: f.Name(), Err: errDiskFull}
			}
			return f.WriteAt(b, off)
		}
	}))
	f := newFile(10)
	c := en.create(alice, "public", "a.bin", f)
	en.sendAll(alice, c.UploadID, f)
	if _, err := en.e.Complete(as(alice), c.UploadID, f.composite()); err != nil {
		t.Fatal(err)
	}
	if got := ops(en.logLines(c.UploadID)); slices.Contains(got, opCompleted) {
		t.Fatalf("completed written on a full disk: %v", got)
	}
	full = false
	if err := en.e.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := ops(en.logLines(c.UploadID)); !slices.Equal(got[len(got)-2:], []string{opCompleted, opRecorded}) {
		t.Errorf("the log after Close: %v", got)
	}
}

func TestALinkAtThePathToTheStagedDataIsntThePlacedFile(t *testing.T) {
	en := newEnv(t)
	f := newFile(10)
	var img *image
	en.files.set(func(ff *fakeFiles) {
		ff.adopt = func(string) error {
			i := en.freeze()
			img = &i
			return nil
		}
	})
	c := en.create(alice, "public", "a.bin", f)
	en.sendAll(alice, c.UploadID, f)
	en.e.Complete(as(alice), c.UploadID, f.composite())
	// A relative link, which os.Root follows inside the root.
	to := filepath.Join("..", sandbox.ReservedName, uploadsDir, c.UploadID, dataName)
	if err := os.Symlink(to, filepath.Join(img.dir, "public", "a.bin")); err != nil {
		t.Skip("no symbolic links here:", err)
	}
	if next := en.boot(*img); next.state(c.UploadID) != Receiving || len(next.files.recorded) != 0 {
		t.Errorf("state %s, uploader records %v", next.state(c.UploadID), next.files.recorded)
	}
}

// pastDeadline is a context whose deadline has passed without its Done
// channel being ready, so Close gets past its waits.
type pastDeadline struct{ context.Context }

func (pastDeadline) Err() error { return context.DeadlineExceeded }

func TestCloseLeavesWaitingLinesPastItsDeadline(t *testing.T) {
	full := true
	en := newEnv(t, withEngine(func(e *Engine) {
		e.writeLog = func(f *os.File, b []byte, off int64) (int, error) {
			if full && bytes.Contains(b, []byte(`"op":"completed"`)) {
				return 0, &os.PathError{Op: "write", Path: f.Name(), Err: errDiskFull}
			}
			return f.WriteAt(b, off)
		}
	}))
	f := newFile(10)
	c := en.create(alice, "public", "a.bin", f)
	en.sendAll(alice, c.UploadID, f)
	en.e.Complete(as(alice), c.UploadID, f.composite())
	full = false
	en.e.Close(pastDeadline{context.Background()})
	if got := ops(en.logLines(c.UploadID)); slices.Contains(got, opCompleted) {
		t.Errorf("written past the deadline: %v", got)
	}
	if next := en.restart(); next.state(c.UploadID) != Completed {
		t.Errorf("the next start: %s", next.state(c.UploadID))
	}
}

func TestAFileWhereTheTargetsFolderWasCountsAsAbsent(t *testing.T) {
	for _, placed := range []bool{false, true} {
		en := newEnv(t)
		f := newFile(10)
		var img *image
		freeze := func(string) {
			i := en.freeze()
			img = &i
		}
		en.files.set(func(ff *fakeFiles) {
			ff.rename = true
			if placed {
				ff.linked = freeze
			} else {
				ff.adopt = func(rel string) error { freeze(rel); return nil }
			}
		})
		c := en.create(alice, "public", "a.bin", f)
		en.sendAll(alice, c.UploadID, f)
		en.e.Complete(as(alice), c.UploadID, f.composite())
		folder := filepath.Join(img.dir, "public")
		os.RemoveAll(folder)
		os.WriteFile(folder, []byte("x"), 0o644)
		want := Receiving
		if placed {
			want = Failed
		}
		if next := en.boot(*img); next.state(c.UploadID) != want {
			t.Errorf("renamed %v: state %s", placed, next.state(c.UploadID))
		}
	}
}

// flakyLog fails from its failAt-th ReadAt on.
type flakyLog struct {
	logReader
	reads, failAt int
}

func (l *flakyLog) ReadAt(b []byte, off int64) (int, error) {
	if l.reads++; l.reads >= l.failAt {
		return 0, errors.New("input/output error")
	}
	return l.logReader.ReadAt(b, off)
}

func TestAnErrorReadingAFailureReportedBeforeLeavesTheSession(t *testing.T) {
	en := newEnv(t)
	f := newFile(10)
	c := en.create(alice, "public", "a.bin", f)
	en.send(alice, c.UploadID, f, 1)
	en.e.Close(context.Background())
	logPath := filepath.Join(en.dir, sandbox.ReservedName, uploadsDir, c.UploadID, logName)
	lf, err := os.OpenFile(logPath, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	lf.WriteString("not json\n" + mustLine(t, line{Op: opFailed, Reason: "earlier", At: en.clock.now()}) + "\n")
	lf.Close()

	// Recovery opens the log once to replay it, and again to read its last
	// line.
	for _, failAt := range []int{0, 1, 2} {
		opened := 0
		next := en.boot(en.freeze(), withEngine(func(e *Engine) {
			e.openLog = func(id string) (logReader, error) {
				f, err := e.root.Open(native(uploadsDir, id, logName))
				if opened++; opened == 1 || err != nil {
					return f, err
				}
				if failAt == 0 {
					f.Close()
					return nil, errors.New("sharing violation")
				}
				return &flakyLog{logReader: f, failAt: failAt}, nil
			}
		}))
		if next.e.lookup(c.UploadID) != nil || !next.reg.has(c.UploadID) || len(next.bus.all()) != 0 {
			t.Fatalf("failing at %d: session %v, record %v, events %+v", failAt, next.e.lookup(c.UploadID) != nil, next.reg.has(c.UploadID), next.bus.all())
		}
		if again := next.restart(); again.state(c.UploadID) != Failed || len(again.bus.all()) != 0 {
			t.Errorf("failing at %d, then readable: %s, events %+v", failAt, again.state(c.UploadID), again.bus.all())
		}
	}
}

func TestACopyWithTheSameSizeAndTimeIsntThePlacedFile(t *testing.T) {
	en := newEnv(t)
	f := newFile(10)
	var img *image
	en.files.set(func(ff *fakeFiles) {
		ff.adopt = func(string) error {
			i := en.freeze()
			img = &i
			return nil
		}
	})
	c := en.create(alice, "public", "a.bin", f)
	en.sendAll(alice, c.UploadID, f)
	en.e.Complete(as(alice), c.UploadID, f.composite())
	data := filepath.Join(img.dir, sandbox.ReservedName, uploadsDir, c.UploadID, dataName)
	info, err := os.Stat(data)
	if err != nil {
		t.Fatal(err)
	}
	copied := filepath.Join(img.dir, "public", "a.bin")
	os.WriteFile(copied, f.data, 0o644)
	os.Chtimes(copied, info.ModTime(), info.ModTime())
	if next := en.boot(*img); next.state(c.UploadID) != Receiving || len(next.files.recorded) != 0 {
		t.Errorf("state %s, uploader records %v", next.state(c.UploadID), next.files.recorded)
	}
}

func TestClosePastItsDeadlineStillReleasesWindowsAndFiles(t *testing.T) {
	en := newEnv(t, withFree(1<<30))
	f := newFile(3 * testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	en.send(alice, c.UploadID, f, 1)
	s := en.session(c.UploadID)
	s.mu.Lock()
	held := s.window != nil && s.window.Left() > 0 && s.data != nil && s.log != nil
	s.mu.Unlock()
	if !held {
		t.Fatal("the session holds no window or files to give back")
	}
	en.e.Close(pastDeadline{context.Background()})
	s.mu.Lock()
	defer s.mu.Unlock()
	if (s.window != nil && s.window.Left() != 0) || s.data != nil || s.log != nil {
		t.Errorf("kept: window %v, data %v, log %v", s.window != nil && s.window.Left() != 0, s.data != nil, s.log != nil)
	}
}
