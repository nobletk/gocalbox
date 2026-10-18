package transfer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
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
	defer closeWithin(t, e2, context.Background())
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
	if err := closeWithin(t, en.e, ctx); !errors.Is(err, context.DeadlineExceeded) {
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
	if err := closeWithin(t, en.e, context.Background()); err != nil {
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
	t.Cleanup(func() { closeWithin(t, e2, context.Background()) })
	en.e = e2
	c := en.create(alice, "public", "a.bin", newFile(10))
	held, release := make(chan struct{}), make(chan struct{})
	var once, freed sync.Once
	free := func() { freed.Do(func() { close(release) }) }
	t.Cleanup(free)
	en.e.syncFile = func(f *os.File) error {
		once.Do(func() { close(held); <-release })
		return f.Sync()
	}
	en.clock.add(DefaultLimits.FirstPartTTL)
	en.e.wakeJanitor()
	within(t, held) // the janitor is flushing the expired line
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := closeWithin(t, en.e, ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Close: %v", err)
	}
	free()
	within(t, en.e.janitorDone)
	if st := en.state(c.UploadID); st != Expired {
		t.Errorf("state %s", st)
	}
}

// A shutdown whose deadline the HTTP server's drain used up still closes an
// engine that has nothing running, its janitor included.
func TestCloseAfterItsDeadlineClosesWhenNothingRuns(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for i := range 32 {
		en := newEnv(t)
		e, held, release := janitorEngine(t, en)
		within(t, held)
		if err := closeWithin(t, e, ctx); err != nil {
			t.Fatalf("try %d: %v", i, err)
		}
		if _, err := e.root.Stat("."); err == nil {
			t.Fatalf("try %d: the staging folder is still open", i)
		}
		give(t, release)
		within(t, e.janitorDone)
	}
}

// janitorEngine is an engine of en's with a janitor of its own. Each run
// of the janitor stops at the point "janitor", sends on held and waits for
// release, the first one, which recovery wakes, included.
func janitorEngine(t *testing.T, en *env) (e *Engine, held, release chan struct{}) {
	t.Helper()
	en.e.Close(context.Background())
	held, release = make(chan struct{}), make(chan struct{})
	e, err := New(Config{Root: en.root, Staging: &sandbox.Staging{Links: true}, Files: en.files, Registry: en.reg, Events: en.bus,
		JanitorEvery: time.Hour, Now: en.clock.now, prepare: func(e *Engine) {
			e.partSize = func(int64) int64 { return testPartSize }
			e.point = func(name string) {
				if name == "janitor" {
					held <- struct{}{}
					<-release
				}
			}
		}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		close(release)
		closeWithin(t, e, context.Background())
	})
	en.e = e
	return e, held, release
}

// A run of the janitor that began just as Close ended does nothing: the
// files it would use are closed.
func TestAJanitorRunThatStartsAfterCloseDoesNothing(t *testing.T) {
	en := newEnv(t)
	e, held, release := janitorEngine(t, en)
	c := en.create(alice, "public", "a.bin", newFile(10))
	en.clock.add(DefaultLimits.FirstPartTTL)
	within(t, held)
	if err := closeWithin(t, e, context.Background()); err != nil {
		t.Fatal(err)
	}
	give(t, release)
	within(t, e.janitorDone)
	if st := en.state(c.UploadID); st != Receiving {
		t.Errorf("state %s after a run that began once Close had ended", st)
	}
	if evs := en.bus.of(events.UploadExpired); len(evs) != 0 {
		t.Errorf("published %v", evs)
	}
}

// Close waits for a run of the janitor under way, and then closes.
func TestCloseWaitsForAJanitorRunUnderWay(t *testing.T) {
	en := newEnv(t)
	e, point, pass := janitorEngine(t, en)
	c := en.create(alice, "public", "a.bin", newFile(10))
	held, release := make(chan struct{}), make(chan struct{})
	var once, freed sync.Once
	free := func() { freed.Do(func() { close(release) }) }
	t.Cleanup(free)
	e.syncFile = func(f *os.File) error {
		once.Do(func() { close(held); <-release })
		return f.Sync()
	}
	en.clock.add(DefaultLimits.FirstPartTTL)
	within(t, point)
	give(t, pass)
	within(t, held)
	closed := make(chan error)
	go func() { closed <- e.Close(context.Background()) }()
	select {
	case err := <-closed:
		t.Fatalf("Close returned during a run of the janitor: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	free()
	if err := within(t, closed); err != nil {
		t.Errorf("Close: %v", err)
	}
	if st := en.state(c.UploadID); st != Expired {
		t.Errorf("state %s", st)
	}
	if _, err := e.root.Stat("."); err == nil {
		t.Error("the staging folder is still open")
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
	for _, tc := range []struct {
		name  string
		trash func(path string) error
	}{
		{"the trash is missing", func(string) error { return nil }},
		{"the trash is a file", func(path string) error { return os.WriteFile(path, nil, 0o600) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			en := newEnv(t)
			c := en.create(alice, "public", "a.bin", newFile(10))
			en.e.Abort(as(alice), c.UploadID)
			trash := filepath.Join(en.dir, sandbox.ReservedName, trashDir)
			if err := os.Remove(trash); err != nil {
				t.Fatal(err)
			}
			if err := tc.trash(trash); err != nil {
				t.Fatal(err)
			}
			en.clock.add(DefaultLimits.TombstoneTTL)
			en.e.sweep()
			if !en.reg.has(c.UploadID) || en.e.lookup(c.UploadID) == nil || !exists(en.staged(c.UploadID, "")) {
				t.Fatalf("record %v, session %v, folder %v", en.reg.has(c.UploadID), en.e.lookup(c.UploadID) != nil, exists(en.staged(c.UploadID, "")))
			}
			os.Remove(trash)
			if err := os.Mkdir(trash, 0o700); err != nil {
				t.Fatal(err)
			}
			en.e.sweep()
			if en.reg.has(c.UploadID) || en.e.lookup(c.UploadID) != nil || exists(en.staged(c.UploadID, "")) {
				t.Errorf("once the trash is back: record %v, session %v, folder %v", en.reg.has(c.UploadID), en.e.lookup(c.UploadID) != nil, exists(en.staged(c.UploadID, "")))
			}
		})
	}
}

// Two Close calls during one run of the janitor both wait for it, and both
// return once it ends.
func TestTwoClosesWaitForOneJanitorRun(t *testing.T) {
	en := newEnv(t)
	e, point, pass := janitorEngine(t, en)
	en.create(alice, "public", "a.bin", newFile(10))
	held, release := make(chan struct{}), make(chan struct{})
	var once, freed sync.Once
	free := func() { freed.Do(func() { close(release) }) }
	t.Cleanup(free)
	e.syncFile = func(f *os.File) error {
		once.Do(func() { close(held); <-release })
		return f.Sync()
	}
	en.clock.add(DefaultLimits.FirstPartTTL)
	within(t, point)
	give(t, pass)
	within(t, held)
	first, second := make(chan error, 1), make(chan error, 1)
	go func() { first <- e.Close(context.Background()) }()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(time.Millisecond) {
		e.mu.Lock()
		closed := e.closed
		e.mu.Unlock()
		if closed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the first Close never began")
		}
	}
	go func() { second <- e.Close(context.Background()) }()
	select {
	case err := <-first:
		t.Fatalf("Close returned during a run of the janitor: %v", err)
	case err := <-second:
		t.Fatalf("the second Close returned during a run of the janitor: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	free()
	if err := within(t, second); err != nil {
		t.Errorf("the second Close: %v", err)
	}
	if err := within(t, first); err != nil {
		t.Errorf("the first Close: %v", err)
	}
}

// A Close whose deadline has already passed, during a run of the janitor,
// leaves open what the run uses; a later Close finishes the job.
func TestClosePastItsDeadlineLeavesAJanitorRunItsFiles(t *testing.T) {
	en := newEnv(t)
	e, point, pass := janitorEngine(t, en)
	c := en.create(alice, "public", "a.bin", newFile(10))
	held, release := make(chan struct{}), make(chan struct{})
	var once, freed sync.Once
	free := func() { freed.Do(func() { close(release) }) }
	t.Cleanup(free)
	e.syncFile = func(f *os.File) error {
		once.Do(func() { close(held); <-release })
		return f.Sync()
	}
	en.clock.add(DefaultLimits.FirstPartTTL)
	within(t, point)
	give(t, pass)
	within(t, held)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := closeWithin(t, e, ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("Close: %v", err)
	}
	if _, err := e.root.Stat("."); err != nil {
		t.Errorf("the staging folder was closed under the janitor: %v", err)
	}
	free()
	if err := closeWithin(t, e, context.Background()); err != nil {
		t.Errorf("Close again: %v", err)
	}
	if st := en.state(c.UploadID); st != Expired {
		t.Errorf("state %s", st)
	}
}

// Close that begins with a part and a janitor run under way waits for the
// run after the part has ended, also when the run holds no session lock.
func TestCloseWaitsForAJanitorRunAfterTheCallsEnd(t *testing.T) {
	en := newEnv(t)
	e, point, pass := janitorEngine(t, en)
	f := newFile(10)
	c := en.create(alice, "public", "a.bin", f)
	en.create(alice, "public", "b.bin", f)
	g := newGate(f.part(1))
	sent := make(chan error, 1)
	go func() {
		_, err := e.Part(as(alice), PartRequest{ID: c.UploadID, N: 1, SHA256: f.sum(1), Length: int64(len(f.data)), Body: g})
		sent <- err
	}()
	within(t, g.reached)
	held, release := make(chan struct{}), make(chan struct{})
	var first atomic.Bool
	var freed sync.Once
	free := func() { freed.Do(func() { close(release) }) }
	t.Cleanup(free)
	en.bus.publish = func(ev events.Event) {
		if ev.Type == events.UploadExpired && first.CompareAndSwap(false, true) {
			close(held)
			<-release
		}
	}
	en.clock.add(DefaultLimits.FirstPartTTL)
	within(t, point)
	give(t, pass)
	within(t, held)
	closed := make(chan error, 1)
	go func() { closed <- e.Close(context.Background()) }()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(time.Millisecond) {
		e.mu.Lock()
		began := e.closed
		e.mu.Unlock()
		if began {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Close never began")
		}
	}
	g.open()
	if err := within(t, sent); err != nil {
		t.Fatalf("the part: %v", err)
	}
	select {
	case err := <-closed:
		t.Fatalf("Close returned during a run of the janitor: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if _, err := e.root.Stat("."); err != nil {
		t.Errorf("the staging folder was closed under the run: %v", err)
	}
	free()
	if err := within(t, closed); err != nil {
		t.Errorf("Close: %v", err)
	}
}
