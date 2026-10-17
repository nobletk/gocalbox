package transfer

import (
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/sandbox"
	"github.com/nobletk/gocalbox/internal/space"
)

func TestCreateRegistersAndStagesASession(t *testing.T) {
	en := newEnv(t)
	f := newFile(10 << 10)
	c, err := en.e.Create(as(alice), CreateRequest{Dir: "users//alice/", Name: "a.bin", Size: int64(len(f.data)), ClientKey: "k1"})
	if err != nil {
		t.Fatal(err)
	}
	if !ValidID(c.UploadID) || c.PartSize != testPartSize || c.PartCount != 3 || c.MaxParallel != 4 || c.Resumed || len(c.Received) != 0 {
		t.Errorf("answer %+v", c)
	}
	if want := en.clock.now().Add(DefaultLimits.FirstPartTTL); !c.ExpiresAt.Equal(want) {
		t.Errorf("expires at %v, want %v", c.ExpiresAt, want)
	}
	rec := en.reg.recs[c.UploadID]
	want := Record{ID: c.UploadID, Owner: alice, Dir: "users/alice", Folder: "key:users/alice", Name: "a.bin",
		Size: int64(len(f.data)), PartSize: testPartSize, PartCount: 3, ClientKey: "k1", Created: en.clock.now()}
	if rec != want {
		t.Errorf("record\n%+v, want\n%+v", rec, want)
	}
	for name, mode := range map[string]os.FileMode{"": 0o700 | os.ModeDir, logName: 0o600, dataName: 0o644} {
		info, err := os.Lstat(en.staged(c.UploadID, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Size() != 0 && name != "" {
			t.Errorf("%s holds %d bytes", name, info.Size())
		}
		if runtime.GOOS != "windows" && info.Mode()&^0o022 != mode&^0o022 {
			t.Errorf("%q has mode %v, want %v", name, info.Mode(), mode)
		}
	}
	evs := en.bus.of(events.UploadCreated)
	if len(evs) != 1 {
		t.Fatalf("created events: %+v", evs)
	}
	ev := evs[0]
	if ev.Actor.ID != alice || ev.RequestID != "req-"+alice || ev.Outcome != events.OutcomeOK || ev.Path != "users/alice/a.bin" ||
		ev.Resolved != "key:users/alice" || ev.Size != int64(len(f.data)) || ev.Upload.ID != c.UploadID || ev.Upload.Owner != alice ||
		ev.Upload.Parts != 3 || ev.Upload.PartSize != testPartSize || ev.Detail != "" || !slices.Equal(ev.Upload.Clients, []string{"192.0.2.7"}) {
		t.Errorf("event %+v %+v", ev, ev.Upload)
	}
}

func TestCreateRefusals(t *testing.T) {
	en := newEnv(t, withLimits(Limits{MaxSize: 100 << 10}))
	en.e.maxFile = 50 << 10
	for _, c := range []struct {
		name string
		user string
		req  CreateRequest
		want error
	}{
		{"negative size", alice, CreateRequest{Dir: "users/alice", Name: "a", Size: -1}, ErrInvalidRequest},
		{"client key", alice, CreateRequest{Dir: "users/alice", Name: "a", Size: 1, ClientKey: "a/b"}, ErrInvalidRequest},
		{"traversal", alice, CreateRequest{Dir: "../x", Name: "a", Size: 1}, sandbox.ErrTraversal},
		{"too large", alice, CreateRequest{Dir: "users/alice", Name: "a", Size: 100<<10 + 1}, ErrTooLarge},
		{"too large for the volume", alice, CreateRequest{Dir: "users/alice", Name: "a", Size: 50<<10 + 1}, ErrTooLargeForVolume},
		{"no folder", alice, CreateRequest{Dir: "users/carol", Name: "a", Size: 1}, errParentAbsent},
		{"no account", "u-nobody", CreateRequest{Dir: "users/alice", Name: "a", Size: 1}, errParentAbsent},
	} {
		en.bus.reset()
		_, err := en.e.Create(as(c.user), c.req)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
			continue
		}
		evs := en.bus.all()
		if len(evs) != 1 || evs[0].Type != events.UploadRejected || evs[0].Outcome == events.OutcomeOK || evs[0].Detail == "" {
			t.Errorf("%s: events %+v", c.name, evs)
		}
	}
	if len(en.reg.recs) != 0 || len(en.e.open) != 0 || en.e.openTotal != 0 {
		t.Errorf("records %v, open %v %d", en.reg.recs, en.e.open, en.e.openTotal)
	}
	entries, _ := os.ReadDir(filepath.Join(en.dir, sandbox.ReservedName, uploadsDir))
	if len(entries) != 0 {
		t.Errorf("staging holds %v", entries)
	}
}

func TestCreateWhileOff(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	files := newFakeFiles(root)
	e, err := New(Config{Root: root, Staging: &sandbox.Staging{Problem: errors.New("symlinked")}, Files: files,
		Registry: &fakeRegistry{recs: map[string]Record{}}, Events: &recBus{}})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close(context.Background())
	if e.Off() == nil {
		t.Fatal("the engine is on")
	}
	if _, err := e.Create(as(alice), CreateRequest{Dir: ".", Name: "a", Size: 1}); !errors.Is(err, ErrUnavailable) {
		t.Errorf("create: %v", err)
	}
	if _, err := e.List(as(alice), false); !errors.Is(err, ErrUnavailable) {
		t.Errorf("list: %v", err)
	}
	if exists(filepath.Join(dir, sandbox.ReservedName)) {
		t.Error("the engine made a staging folder")
	}
}

func TestCreateResumesTheUsersOwnSession(t *testing.T) {
	en := newEnv(t)
	f := newFile(10 << 10)
	req := CreateRequest{Dir: "public", Name: "a.bin", Size: int64(len(f.data)), ClientKey: "same"}
	first, err := en.e.Create(as(alice), req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := en.send(alice, first.UploadID, f, 2); err != nil {
		t.Fatal(err)
	}
	en.bus.reset()
	again, err := en.e.Create(as(alice), CreateRequest{Dir: "public/", Name: "a.bin", Size: int64(len(f.data)), ClientKey: "same"})
	if err != nil {
		t.Fatal(err)
	}
	if again.UploadID != first.UploadID || !again.Resumed || len(again.Received) != 1 || again.Received[0] != (Range{2, 2}) {
		t.Errorf("resumed %+v", again)
	}
	if evs := en.bus.of(events.UploadCreated); len(evs) != 1 || evs[0].Detail != "resumed" {
		t.Errorf("events %+v", evs)
	}
	if len(en.reg.recs) != 1 {
		t.Errorf("records %v", en.reg.recs)
	}

	for name, other := range map[string]CreateRequest{
		"another user":   req,
		"another size":   {Dir: req.Dir, Name: req.Name, Size: req.Size + 1, ClientKey: req.ClientKey},
		"another name":   {Dir: req.Dir, Name: "b.bin", Size: req.Size, ClientKey: req.ClientKey},
		"another folder": {Dir: "users/alice", Name: req.Name, Size: req.Size, ClientKey: req.ClientKey},
		"no key":         {Dir: req.Dir, Name: req.Name, Size: req.Size},
	} {
		user := alice
		if name == "another user" {
			user = bob
		}
		c, err := en.e.Create(as(user), other)
		if err != nil || c.UploadID == first.UploadID || c.Resumed {
			t.Errorf("%s: %+v, %v", name, c, err)
		}
	}

	// A session that ended never matches.
	if _, err := en.e.Abort(as(alice), first.UploadID); err != nil {
		t.Fatal(err)
	}
	c, err := en.e.Create(as(alice), req)
	if err != nil || c.UploadID == first.UploadID || c.Resumed {
		t.Errorf("after abort: %+v, %v", c, err)
	}
}

func TestResumeTakesTheNewerOfTwoSessions(t *testing.T) {
	en := newEnv(t)
	req := CreateRequest{Dir: "public", Name: "a.bin", Size: 10, ClientKey: "k"}
	older, err := en.e.Create(as(alice), CreateRequest{Dir: "public", Name: "a.bin", Size: 10})
	if err != nil {
		t.Fatal(err)
	}
	newer, err := en.e.Create(as(alice), CreateRequest{Dir: "public", Name: "a.bin", Size: 10})
	if err != nil {
		t.Fatal(err)
	}
	// Two creates that raced with the same key both made a session.
	for i, id := range []string{older.UploadID, newer.UploadID} {
		s := en.session(id)
		s.rec.ClientKey = "k"
		s.rec.Created = en.clock.now().Add(time.Duration(i) * time.Second)
	}
	c, err := en.e.Create(as(alice), req)
	if err != nil || c.UploadID != newer.UploadID || !c.Resumed {
		t.Errorf("resumed %+v, %v; want %s", c, err, newer.UploadID)
	}
}

func TestResumeAsksWhetherTheUserMayStillUpload(t *testing.T) {
	en := newEnv(t)
	req := CreateRequest{Dir: "public", Name: "a.bin", Size: 10, ClientKey: "k"}
	first, err := en.e.Create(as(alice), req)
	if err != nil {
		t.Fatal(err)
	}
	en.files.set(func(f *fakeFiles) { f.deny["key:public"] = true })
	en.bus.reset()
	if _, err := en.e.Create(as(alice), req); !errors.Is(err, errForbidden) {
		t.Fatalf("resume after losing the right: %v", err)
	}
	evs := en.bus.all()
	if len(evs) != 1 || evs[0].Type != events.UploadRejected || evs[0].Outcome != events.OutcomeDenied || evs[0].Upload.ID != first.UploadID {
		t.Errorf("events %+v", evs)
	}
}

func TestResumeIsAllowedWhileChangesArePaused(t *testing.T) {
	en := newEnv(t)
	req := CreateRequest{Dir: "public", Name: "a.bin", Size: 10, ClientKey: "k"}
	first, err := en.e.Create(as(alice), req)
	if err != nil {
		t.Fatal(err)
	}
	// Files refuses a new session once changes are paused; a resume makes
	// none.
	en.files.set(func(f *fakeFiles) { f.prepare = events.ErrChangesPaused })
	if c, err := en.e.Create(as(alice), req); err != nil || c.UploadID != first.UploadID {
		t.Errorf("resume: %+v, %v", c, err)
	}
	if _, err := en.e.Create(as(alice), CreateRequest{Dir: "public", Name: "b", Size: 1}); !errors.Is(err, events.ErrChangesPaused) {
		t.Errorf("a new session: %v", err)
	}
}

func TestOpenSessionLimits(t *testing.T) {
	en := newEnv(t, withLimits(Limits{MaxSessions: 2, MaxSessionsTotal: 3}))
	var ids []string
	for i := range 2 {
		c, err := en.e.Create(as(alice), CreateRequest{Dir: "public", Name: "a", Size: int64(i + 1)})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, c.UploadID)
	}
	en.bus.reset()
	if _, err := en.e.Create(as(alice), CreateRequest{Dir: "public", Name: "a", Size: 1}); !errors.Is(err, ErrTooManyUploads) {
		t.Errorf("alice's third: %v", err)
	}
	if _, err := en.e.Create(as(bob), CreateRequest{Dir: "public", Name: "b", Size: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := en.e.Create(as(bob), CreateRequest{Dir: "public", Name: "b", Size: 1}); !errors.Is(err, ErrBusy) {
		t.Errorf("the fourth on the server: %v", err)
	}
	if evs := en.bus.of(events.UploadRejected); len(evs) != 0 {
		t.Errorf("admission refusals were recorded: %+v", evs)
	}
	// An ended session frees its slot; its tombstone doesn't count.
	if _, err := en.e.Abort(as(alice), ids[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := en.e.Create(as(alice), CreateRequest{Dir: "public", Name: "a", Size: 1}); err != nil {
		t.Errorf("after an abort: %v", err)
	}
}

func TestCreateHoldsAWindowOfTheLedger(t *testing.T) {
	en := newEnv(t, withFree(1<<20), withLimits(Limits{Window: 16 << 10, MaxParallel: 2}))
	small, err := en.e.Create(as(alice), CreateRequest{Dir: "public", Name: "small", Size: 3})
	if err != nil {
		t.Fatal(err)
	}
	if got := en.ledger.Reserved(); got != 3 {
		t.Errorf("reserved %d for 3 bytes", got)
	}
	big, err := en.e.Create(as(alice), CreateRequest{Dir: "public", Name: "big", Size: 900 << 10})
	if err != nil {
		t.Fatal(err)
	}
	if got := en.ledger.Reserved(); got != 3+16<<10 {
		t.Errorf("reserved %d, want the window of 16 KiB more", got)
	}
	en.bus.reset()
	if _, err := en.e.Create(as(alice), CreateRequest{Dir: "public", Name: "huge", Size: 1 << 20}); !errors.Is(err, space.ErrInsufficient) {
		t.Fatalf("a size that doesn't fit: %v", err)
	}
	if evs := en.bus.of(events.UploadRejected); len(evs) != 1 || evs[0].Outcome != events.OutcomeNoSpace {
		t.Errorf("events %+v", evs)
	}
	if en.e.openTotal != 2 || len(en.reg.recs) != 2 {
		t.Errorf("open %d, records %d", en.e.openTotal, len(en.reg.recs))
	}
	for _, id := range []string{small.UploadID, big.UploadID} {
		if _, err := en.e.Abort(as(alice), id); err != nil {
			t.Fatal(err)
		}
	}
	if got := en.ledger.Reserved(); got != 0 {
		t.Errorf("reserved %d after both ended", got)
	}
}

func TestAFailedCreateLeavesNothing(t *testing.T) {
	en := newEnv(t, withFree(1<<30))
	en.reg.putErr = errors.New("disk on fire")
	if _, err := en.e.Create(as(alice), CreateRequest{Dir: "public", Name: "a", Size: 10}); err == nil {
		t.Fatal("create succeeded without a record")
	}
	en.reg.putErr = nil

	// Staging fails once the record is in: the record goes again.
	uploads := filepath.Join(en.dir, sandbox.ReservedName, uploadsDir)
	if err := os.Remove(uploads); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(uploads, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := en.e.Create(as(alice), CreateRequest{Dir: "public", Name: "a", Size: 10}); err == nil {
		t.Fatal("create succeeded without staging")
	}
	if len(en.reg.recs) != 0 || en.reg.deletes != 1 || en.e.openTotal != 0 || en.ledger.Reserved() != 0 {
		t.Errorf("records %v (%d deletes), open %d, reserved %d", en.reg.recs, en.reg.deletes, en.e.openTotal, en.ledger.Reserved())
	}
	if evs := en.bus.of(events.UploadRejected); len(evs) != 2 || evs[0].Outcome != events.OutcomeError {
		t.Errorf("events %+v", evs)
	}
}

func TestTheWindowCoversTheAdvisedParallelParts(t *testing.T) {
	en := newEnv(t, withFree(1<<30), withLimits(Limits{Window: testPartSize, MaxParallel: 4}))
	en.create(alice, "public", "a.bin", newFile(10*testPartSize))
	if got := en.ledger.Reserved(); got != 4*testPartSize {
		t.Errorf("reserved %d, want 4 parts of %d", got, testPartSize)
	}
}

func TestASessionExpiresAtItsMaximumAge(t *testing.T) {
	en := newEnv(t, withLimits(Limits{MaxAge: 30 * time.Minute}))
	c := en.create(alice, "public", "a.bin", newFile(10))
	if want := en.clock.now().Add(30 * time.Minute); !c.ExpiresAt.Equal(want) {
		t.Errorf("expires at %v, want %v", c.ExpiresAt, want)
	}
}

func TestHugeSizesAreRefusedBeforeAnythingIsKept(t *testing.T) {
	en := newEnv(t)
	en.e.partSize = PartSize
	for _, size := range []int64{MaxSize + 1, 1 << 62, math.MaxInt64} {
		if _, err := en.e.Create(as(alice), CreateRequest{Dir: "public", Name: "a", Size: size}); !errors.Is(err, ErrTooLarge) {
			t.Errorf("size %d: %v", size, err)
		}
	}
	if en.e.openTotal != 0 || len(en.reg.recs) != 0 {
		t.Errorf("open %d, records %d", en.e.openTotal, len(en.reg.recs))
	}
	// The largest size keeps a pointer per 1,024 parts, and nothing else
	// until parts arrive.
	c, err := en.e.Create(as(alice), CreateRequest{Dir: "public", Name: "a", Size: MaxSize})
	if err != nil {
		t.Fatal(err)
	}
	s := en.session(c.UploadID)
	if c.PartSize != 64<<20 || c.PartCount != 1<<20 || len(s.chunks) != 1024 || s.chunks[0] != nil {
		t.Errorf("part size %d, %d parts, %d chunks", c.PartSize, c.PartCount, len(s.chunks))
	}
}

func TestAFullDiskWhileStagingIsRefusedLikeTheLedger(t *testing.T) {
	en := newEnv(t)
	en.e.syncDir = func(*os.Root, string) error { return &os.PathError{Op: "sync", Path: "uploads", Err: errDiskFull} }
	if _, err := en.e.Create(as(alice), CreateRequest{Dir: "public", Name: "a", Size: 10}); !errors.Is(err, space.ErrInsufficient) {
		t.Fatalf("create: %v", err)
	}
	if evs := en.bus.of(events.UploadRejected); len(evs) != 1 || evs[0].Outcome != events.OutcomeNoSpace {
		t.Errorf("events %+v", evs)
	}
	entries, _ := os.ReadDir(filepath.Join(en.dir, sandbox.ReservedName, uploadsDir))
	if len(entries) != 0 || len(en.reg.recs) != 0 || en.e.openTotal != 0 {
		t.Errorf("staging %v, records %d, open %d", entries, len(en.reg.recs), en.e.openTotal)
	}
}

func TestCreateFlushesTheStagingFolders(t *testing.T) {
	en := newEnv(t)
	var flushed []string
	en.e.syncDir = func(root *os.Root, dir string) error {
		flushed = append(flushed, filepath.ToSlash(dir))
		return syncDir(root, dir)
	}
	c := en.create(alice, "public", "a", newFile(10))
	if !slices.Equal(flushed, []string{uploadsDir + "/" + c.UploadID, uploadsDir}) {
		t.Errorf("flushed %v", flushed)
	}
}

func TestResumeChecksTheSessionAgainAfterAsking(t *testing.T) {
	en := newEnv(t)
	req := CreateRequest{Dir: "public", Name: "a.bin", Size: 10, ClientKey: "k"}
	first, err := en.e.Create(as(alice), req)
	if err != nil {
		t.Fatal(err)
	}
	// The session ends while the right to it is asked for.
	var once sync.Once
	en.files.set(func(f *fakeFiles) {
		f.may = func() { once.Do(func() { en.e.Abort(as(alice), first.UploadID) }) }
	})
	c, err := en.e.Create(as(alice), req)
	if err != nil || c.UploadID == first.UploadID || c.Resumed {
		t.Errorf("%+v, %v", c, err)
	}
}
