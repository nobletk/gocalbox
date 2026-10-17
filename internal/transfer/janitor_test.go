package transfer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/sandbox"
)

func TestTheJanitorExpiresSessions(t *testing.T) {
	lim := DefaultLimits
	for _, c := range []struct {
		name   string
		setup  func(en *env, id string, f file)
		wait   time.Duration
		reason string
	}{
		{"no part", nil, lim.FirstPartTTL, "no_parts"},
		{"idle", func(en *env, id string, f file) { en.send(alice, id, f, 1) }, lim.IdleTTL, "idle"},
		{"too old", func(en *env, id string, f file) {
			// A new part each day keeps it from being idle.
			for n := 1; n <= 7; n++ {
				en.clock.add(23 * time.Hour)
				if _, err := en.send(alice, id, f, n); err != nil {
					en.t.Fatal(err)
				}
				en.e.sweep()
			}
		}, 7 * time.Hour, "max_age"},
		{"owner deleted", func(en *env, id string, f file) {
			en.files.set(func(ff *fakeFiles) { delete(ff.users, alice) })
		}, 0, "owner_deleted"},
	} {
		t.Run(c.name, func(t *testing.T) {
			en := newEnv(t, withFree(1<<30))
			f := newFile(20 * testPartSize)
			cr := en.create(alice, "public", "a.bin", f)
			if c.setup != nil {
				c.setup(en, cr.UploadID, f)
			}
			if c.wait > 0 {
				en.clock.add(c.wait - time.Second)
				en.e.sweep()
				if en.state(cr.UploadID) != Receiving {
					t.Fatalf("expired a second early: %s", en.state(cr.UploadID))
				}
				en.clock.add(time.Second)
			}
			en.bus.reset()
			en.e.sweep()
			s := en.session(cr.UploadID)
			if s.state != Expired || s.reason != c.reason {
				t.Fatalf("state %s (%s), want expired (%s)", s.state, s.reason, c.reason)
			}
			evs := en.bus.all()
			if len(evs) != 1 || evs[0].Type != events.UploadExpired || evs[0].Actor.ID != events.SystemID || evs[0].Detail != c.reason {
				t.Errorf("events %+v", evs)
			}
			if exists(en.staged(cr.UploadID, dataName)) || en.e.openTotal != 0 || en.ledger.Reserved() != 0 {
				t.Errorf("data %v, open %d, reserved %d", exists(en.staged(cr.UploadID, dataName)), en.e.openTotal, en.ledger.Reserved())
			}
			if ls := en.logLines(cr.UploadID); ls[len(ls)-1].Op != opExpired || ls[len(ls)-1].Reason != c.reason {
				t.Errorf("log %+v", ls[len(ls)-1])
			}
		})
	}
}

func TestDuplicatesDontKeepASessionAlive(t *testing.T) {
	en := newEnv(t)
	f := newFile(2 * testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	en.send(alice, c.UploadID, f, 1)
	for range 5 {
		en.clock.add(DefaultLimits.IdleTTL / 5)
		if res, err := en.send(alice, c.UploadID, f, 1); err != nil || !res.Duplicate {
			t.Fatalf("duplicate: %+v, %v", res, err)
		}
	}
	en.e.sweep()
	if st := en.state(c.UploadID); st != Expired {
		t.Errorf("state %s after a day of duplicates", st)
	}
}

func TestTheJanitorLeavesASessionWithAPartInFlight(t *testing.T) {
	en := newEnv(t)
	f := newFile(2 * testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	g := newGate(f.part(1))
	done := make(chan error)
	go func() {
		_, err := en.e.Part(as(alice), PartRequest{ID: c.UploadID, N: 1, SHA256: f.sum(1), Length: -1, Body: g})
		done <- err
	}()
	within(t, g.reached)
	en.clock.add(DefaultLimits.FirstPartTTL)
	en.e.sweep()
	if st := en.state(c.UploadID); st != Receiving {
		t.Errorf("state %s with a part in flight", st)
	}
	g.open()
	if err := within(t, done); err != nil {
		t.Fatal(err)
	}
}

func TestTheJanitorGivesBackTheWindowsOfIdleSessions(t *testing.T) {
	en := newEnv(t, withFree(1<<30), withLimits(Limits{Window: 16 << 10, MaxParallel: 1}))
	f := newFile(10 * testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	en.send(alice, c.UploadID, f, 1)
	s := en.session(c.UploadID)
	en.clock.add(DefaultLimits.IdleRelease - time.Second)
	en.e.sweep()
	if s.window.Left() == 0 || s.data == nil {
		t.Fatal("released too early")
	}
	en.clock.add(time.Second)
	en.e.sweep()
	if s.window.Left() != 0 || en.ledger.Reserved() != 0 || s.data != nil || s.log != nil {
		t.Errorf("window %d, reserved %d, data %v, log %v", s.window.Left(), en.ledger.Reserved(), s.data, s.log)
	}
	if _, err := en.send(alice, c.UploadID, f, 2); err != nil {
		t.Fatal(err)
	}
	if got := en.ledger.Reserved(); got != 16<<10-testPartSize {
		t.Errorf("reserved %d after the next part", got)
	}
	if ls := en.logLines(c.UploadID); len(ls) != 2 {
		t.Errorf("log %+v", ls)
	}
}

func TestTheJanitorRemovesOldTombstones(t *testing.T) {
	en := newEnv(t)
	f := newFile(testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	en.sendAll(alice, c.UploadID, f)
	if _, err := en.e.Complete(as(alice), c.UploadID, f.composite()); err != nil {
		t.Fatal(err)
	}
	en.clock.add(DefaultLimits.TombstoneTTL - time.Second)
	en.e.sweep()
	if _, err := en.e.Status(as(alice), c.UploadID, nil); err != nil {
		t.Fatalf("removed early: %v", err)
	}
	en.clock.add(time.Second)
	en.e.sweep()
	if _, err := en.e.Status(as(alice), c.UploadID, nil); !errors.Is(err, ErrUploadNotFound) {
		t.Errorf("status after the tombstone's time: %v", err)
	}
	if en.reg.has(c.UploadID) || exists(en.staged(c.UploadID, "")) {
		t.Errorf("record %v, staging %v", en.reg.has(c.UploadID), exists(en.staged(c.UploadID, "")))
	}
	trash, _ := os.ReadDir(filepath.Join(en.dir, sandbox.ReservedName, trashDir))
	if len(trash) != 0 {
		t.Errorf("trash %v", trash)
	}
	if !exists(filepath.Join(en.dir, "public", "a.bin")) {
		t.Error("removing the tombstone removed the file")
	}
}

func TestARemovalThatFailsIsTriedAgain(t *testing.T) {
	en := newEnv(t)
	c := en.create(alice, "public", "a.bin", newFile(10))
	en.e.Abort(as(alice), c.UploadID)
	en.clock.add(DefaultLimits.TombstoneTTL)
	en.reg.delErr = errors.New("state file locked")
	en.e.sweep()
	if _, err := en.e.Status(as(alice), c.UploadID, nil); err != nil {
		t.Fatalf("status while its record stays: %v", err)
	}
	en.reg.delErr = nil
	en.e.sweep()
	if _, err := en.e.Status(as(alice), c.UploadID, nil); !errors.Is(err, ErrUploadNotFound) || en.reg.has(c.UploadID) {
		t.Errorf("after the second run: %v, record %v", err, en.reg.has(c.UploadID))
	}
}

func TestEachUserKeepsAtMostSoManyTombstones(t *testing.T) {
	en := newEnv(t, withLimits(Limits{MaxTombstones: 3}))
	en.e.Close(context.Background())
	// A janitor whose period outlasts the test, so it runs when woken.
	e2, err := New(Config{Root: en.root, Staging: &sandbox.Staging{Links: true}, Files: en.files, Registry: en.reg, Events: en.bus,
		Audit: en.audit, Limits: Limits{MaxTombstones: 3}, JanitorEvery: time.Hour, Now: en.clock.now})
	if err != nil {
		t.Fatal(err)
	}
	e2.partSize = en.e.partSize
	defer e2.Close(context.Background())
	en.e = e2

	f := newFile(10)
	var completed []string
	for range 2 {
		c := en.create(alice, "public", "a.bin", f)
		en.sendAll(alice, c.UploadID, f)
		if _, err := en.e.Complete(as(alice), c.UploadID, f.composite()); err != nil {
			t.Fatal(err)
		}
		completed = append(completed, c.UploadID)
		en.clock.add(time.Second)
	}
	var aborted []string
	for range 3 {
		c := en.create(alice, "public", "b.bin", f)
		en.e.Abort(as(alice), c.UploadID)
		aborted = append(aborted, c.UploadID)
		en.clock.add(time.Second)
	}
	other := en.create(bob, "public", "c.bin", f).UploadID
	en.e.Abort(as(bob), other)

	deadline := time.Now().Add(5 * time.Second)
	for {
		l, _ := en.e.List(as(alice), false)
		if len(l) <= 3 {
			var kept []string
			for _, s := range l {
				kept = append(kept, s.UploadID)
			}
			slices.Sort(kept)
			want := append([]string{aborted[2]}, completed...)
			slices.Sort(want)
			if !slices.Equal(kept, want) {
				t.Errorf("kept %v, want the newest aborted %s and both completed %v", kept, aborted[2], completed)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d tombstones left", len(l))
		}
		time.Sleep(10 * time.Millisecond)
	}
	if l, _ := en.e.List(as(bob), false); len(l) != 1 {
		t.Errorf("bob's %d", len(l))
	}
}

func TestCloseWaitsForTheCallsUnderWay(t *testing.T) {
	en := newEnv(t, withFree(1<<30))
	f := newFile(2 * testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	g := newGate(f.part(1))
	done := make(chan error)
	go func() {
		_, err := en.e.Part(as(alice), PartRequest{ID: c.UploadID, N: 1, SHA256: f.sum(1), Length: -1, Body: g})
		done <- err
	}()
	within(t, g.reached)
	closed := make(chan error)
	go func() { closed <- en.e.Close(context.Background()) }()
	select {
	case err := <-closed:
		t.Fatalf("Close returned with a part under way: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if _, err := en.e.Create(as(alice), CreateRequest{Dir: "public", Name: "b", Size: 1}); !errors.Is(err, ErrShuttingDown) {
		t.Errorf("create while closing: %v", err)
	}
	g.open()
	if err := within(t, done); err != nil {
		t.Errorf("the part: %v", err)
	}
	if err := within(t, closed); err != nil {
		t.Errorf("Close: %v", err)
	}
	if en.ledger.Reserved() != 0 {
		t.Errorf("reserved %d after Close", en.ledger.Reserved())
	}
	if !exists(en.staged(c.UploadID, dataName)) || !en.reg.has(c.UploadID) {
		t.Error("Close removed the session")
	}
	if _, err := en.e.root.Stat("."); err == nil {
		t.Error("Close left the staging folder open")
	}
}

func TestCloseGivesUpAtItsDeadline(t *testing.T) {
	en := newEnv(t)
	f := newFile(2 * testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	g := newGate(f.part(1))
	done := make(chan error)
	go func() {
		_, err := en.e.Part(as(alice), PartRequest{ID: c.UploadID, N: 1, SHA256: f.sum(1), Length: -1, Body: g})
		done <- err
	}()
	within(t, g.reached)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := en.e.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Close: %v", err)
	}
	// What is still running finds its files open.
	g.open()
	if err := within(t, done); err != nil {
		t.Errorf("the part still running at the deadline: %v", err)
	}
	if st := en.state(c.UploadID); st != Receiving || len(en.logLines(c.UploadID)) != 1 {
		t.Errorf("state %s, log %v", st, en.logLines(c.UploadID))
	}
	if err := en.e.Close(context.Background()); err != nil {
		t.Errorf("Close again: %v", err)
	}
	if _, err := en.e.root.Stat("."); err == nil {
		t.Error("the second Close left the staging folder open")
	}
}

func TestCloseGivesUpOnAJanitorRunAtItsDeadline(t *testing.T) {
	en := newEnv(t)
	en.e.Close(context.Background())
	e2, err := New(Config{Root: en.root, Staging: &sandbox.Staging{Links: true}, Files: en.files, Registry: en.reg, Events: en.bus,
		JanitorEvery: time.Hour, Now: en.clock.now})
	if err != nil {
		t.Fatal(err)
	}
	e2.partSize = en.e.partSize
	t.Cleanup(func() { e2.Close(context.Background()) })
	en.e = e2
	c := en.create(alice, "public", "a.bin", newFile(10))
	held, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	en.e.syncFile = func(f *os.File) error {
		once.Do(func() { close(held); <-release })
		return f.Sync()
	}
	en.clock.add(DefaultLimits.FirstPartTTL)
	en.e.wakeJanitor()
	within(t, held) // the janitor is flushing the expired line
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := en.e.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Close: %v", err)
	}
	close(release)
	within(t, en.e.janitorDone)
	if st := en.state(c.UploadID); st != Expired {
		t.Errorf("state %s", st)
	}
}

func TestATombstoneWaitsForItsLastPart(t *testing.T) {
	en := newEnv(t)
	f := newFile(2 * testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	g := newGate(f.part(1))
	done := make(chan error)
	go func() {
		_, err := en.e.Part(as(alice), PartRequest{ID: c.UploadID, N: 1, SHA256: f.sum(1), Length: -1, Body: g})
		done <- err
	}()
	within(t, g.reached)
	en.e.Abort(as(alice), c.UploadID)
	en.clock.add(DefaultLimits.TombstoneTTL)
	en.e.sweep()
	if en.e.lookup(c.UploadID) == nil || !exists(en.staged(c.UploadID, dataName)) {
		t.Fatal("removed with a part still writing to it")
	}
	g.open()
	within(t, done)
	en.e.sweep()
	if en.e.lookup(c.UploadID) != nil || exists(en.staged(c.UploadID, "")) {
		t.Error("not removed once the part ended")
	}
}

func TestTheJanitorRemovesDataACommandCouldNot(t *testing.T) {
	en := newEnv(t)
	c := en.create(alice, "public", "a.bin", newFile(10))
	en.e.Abort(as(alice), c.UploadID)
	// As if removing it had failed, as it does on Windows while the file
	// is open elsewhere.
	if err := os.WriteFile(en.staged(c.UploadID, dataName), []byte("left"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := en.session(c.UploadID)
	s.mu.Lock()
	s.dataGone = false
	s.mu.Unlock()
	en.e.sweep()
	if exists(en.staged(c.UploadID, dataName)) {
		t.Error("the janitor left the data of an aborted upload")
	}
}

func TestTheExpiredLineIsFlushed(t *testing.T) {
	en := newEnv(t)
	c := en.create(alice, "public", "a.bin", newFile(10))
	syncs := 0
	en.e.syncFile = func(f *os.File) error {
		syncs++
		return f.Sync()
	}
	en.clock.add(DefaultLimits.FirstPartTTL)
	en.e.sweep()
	if en.state(c.UploadID) != Expired || syncs != 1 {
		t.Errorf("state %s, %d flushes", en.state(c.UploadID), syncs)
	}
}

func TestASessionWithoutPartsGivesBackItsWindow(t *testing.T) {
	en := newEnv(t, withFree(1<<30))
	c := en.create(alice, "public", "a.bin", newFile(3*testPartSize))
	en.clock.add(DefaultLimits.IdleRelease - time.Second)
	en.e.sweep()
	if en.ledger.Reserved() == 0 {
		t.Fatal("released a second early")
	}
	en.clock.add(time.Second)
	en.e.sweep()
	if s := en.session(c.UploadID); en.ledger.Reserved() != 0 || s.data != nil || s.log != nil {
		t.Errorf("reserved %d, data %v, log %v", en.ledger.Reserved(), s.data, s.log)
	}
}

func TestARemovalKeepsTheRecordUntilTheFolderMoved(t *testing.T) {
	en := newEnv(t)
	c := en.create(alice, "public", "a.bin", newFile(10))
	en.e.Abort(as(alice), c.UploadID)
	trash := filepath.Join(en.dir, sandbox.ReservedName, trashDir)
	os.Remove(trash)
	if err := os.WriteFile(trash, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	en.clock.add(DefaultLimits.TombstoneTTL)
	en.e.sweep()
	if !en.reg.has(c.UploadID) || en.e.lookup(c.UploadID) == nil || !exists(en.staged(c.UploadID, "")) {
		t.Errorf("record %v, session %v", en.reg.has(c.UploadID), en.e.lookup(c.UploadID) != nil)
	}
}
