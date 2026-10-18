package transfer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/sandbox"
	"github.com/nobletk/gocalbox/internal/space"
)

func TestCompletePlacesTheFileAndRecordsIt(t *testing.T) {
	en := newEnv(t, withFree(1<<30))
	f := newFile(3*testPartSize + 7)
	c := en.create(alice, "public", "a.bin", f)
	en.sendAll(alice, c.UploadID, f)
	en.bus.reset()
	res, err := en.e.Complete(as(alice), c.UploadID, f.composite())
	if err != nil {
		t.Fatal(err)
	}
	if res != (Result{Path: "public/a.bin", Name: "a.bin", Size: int64(len(f.data)), CompositeSHA256: f.composite()}) {
		t.Errorf("result %+v", res)
	}
	got, err := os.ReadFile(filepath.Join(en.dir, "public", "a.bin"))
	if err != nil || !bytes.Equal(got, f.data) {
		t.Fatalf("placed file: %v", err)
	}
	if exists(en.staged(c.UploadID, dataName)) {
		t.Error("the staged data name is still there")
	}
	ls := en.logLines(c.UploadID)
	if got := ops(ls); !slices.Equal(got[len(got)-3:], []string{opFinishing, opCompleted, opRecorded}) {
		t.Errorf("log %v", got)
	}
	fin := ls[len(ls)-3]
	if fin.Path != "public/a.bin" || fin.Size == nil || *fin.Size != int64(len(f.data)) || fin.MTime == nil ||
		fin.Actor == nil || fin.Actor.ID != alice || fin.Request != "req-"+alice {
		t.Errorf("finishing line %+v", fin)
	}
	if done := ls[len(ls)-2]; done.Path != "public/a.bin" || done.Actor == nil || done.Actor.ID != alice || done.Request != "req-"+alice {
		t.Errorf("completed line %+v", done)
	}
	if len(en.audit.recorded) != 1 {
		t.Fatalf("records %+v", en.audit.recorded)
	}
	evs := en.audit.recorded[0]
	if len(evs) != 2 || evs[0].Type != events.FileUploaded || evs[1].Type != events.UploadCompleted {
		t.Fatalf("recorded %+v", evs)
	}
	if up := evs[0].Upload; up == nil || up.ID != c.UploadID || up.Owner != alice {
		t.Errorf("file.uploaded's upload %+v", up)
	}
	done := evs[1]
	if done.Path != "public/a.bin" || done.Resolved != "public/a.bin" || done.Size != int64(len(f.data)) || done.Actor.ID != alice ||
		done.Upload.SHA256 != f.composite() || done.Upload.Received != 4 || done.Upload.Parts != 4 || done.Upload.PartSize != testPartSize ||
		done.Upload.Clients[0] != "192.0.2.7" || !done.Upload.Started.Equal(en.clock.now()) {
		t.Errorf("upload.completed %+v %+v", done, done.Upload)
	}
	if en.state(c.UploadID) != Completed || en.e.openTotal != 0 || en.ledger.Reserved() != 0 {
		t.Errorf("state %s, open %d, reserved %d", en.state(c.UploadID), en.e.openTotal, en.ledger.Reserved())
	}

	// The tombstone answers again, without placing or recording anything.
	again, err := en.e.Complete(as(alice), c.UploadID, f.composite())
	if err != nil || again != res || en.files.adopts != 1 || len(en.audit.recorded) != 1 {
		t.Errorf("again: %+v, %v; %d adopts, %d records", again, err, en.files.adopts, len(en.audit.recorded))
	}
	st, err := en.e.Status(as(alice), c.UploadID, nil)
	if err != nil || st.State != Completed || st.Result == nil || *st.Result != res {
		t.Errorf("status %+v, %v", st, err)
	}
	for _, call := range []func() error{
		func() error { _, err := en.send(alice, c.UploadID, f, 1); return err },
		func() error { _, err := en.e.Abort(as(alice), c.UploadID); return err },
	} {
		if err := call(); !errors.Is(err, ErrClosed) {
			t.Errorf("a call on a completed upload: %v", err)
		}
	}
}

func TestCompletingAnEmptyFile(t *testing.T) {
	en := newEnv(t)
	c := en.create(alice, "public", "empty", newFile(0))
	if c.PartCount != 0 {
		t.Fatalf("%d parts", c.PartCount)
	}
	res, err := en.e.Complete(as(alice), c.UploadID, Composite(nil))
	if err != nil || res.Size != 0 {
		t.Fatalf("%+v, %v", res, err)
	}
	if info, err := os.Stat(filepath.Join(en.dir, "public", "empty")); err != nil || info.Size() != 0 {
		t.Errorf("placed: %v", err)
	}
}

func TestCompleteRefusals(t *testing.T) {
	en := newEnv(t)
	f := newFile(3 * testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	for _, n := range []int{1, 3} {
		if _, err := en.send(alice, c.UploadID, f, n); err != nil {
			t.Fatal(err)
		}
	}
	check := func(name, user, id, composite string, want error, outcome events.Outcome) {
		t.Helper()
		en.bus.reset()
		_, err := en.e.Complete(as(user), id, composite)
		if !errors.Is(err, want) {
			t.Errorf("%s: %v, want %v", name, err, want)
			return
		}
		evs := en.bus.all()
		if len(evs) != 1 || evs[0].Type != events.UploadRejected || evs[0].Outcome != outcome {
			t.Errorf("%s: events %+v", name, evs)
		}
		if en.files.adopts != 0 || en.state(c.UploadID) != Receiving {
			t.Errorf("%s: %d adopts, state %s", name, en.files.adopts, en.state(c.UploadID))
		}
	}
	check("malformed composite", alice, c.UploadID, "abc", ErrInvalidRequest, events.OutcomeInvalid)
	check("another user", bob, c.UploadID, f.composite(), ErrUploadNotFound, events.OutcomeDenied)
	check("an admin", admin, c.UploadID, f.composite(), ErrUploadNotFound, events.OutcomeDenied)
	check("parts missing", alice, c.UploadID, f.composite(), ErrPartsMissing, events.OutcomeInvalid)
	_, err := en.e.Complete(as(alice), c.UploadID, f.composite())
	var me *MissingError
	if !errors.As(err, &me) || !slices.Equal(me.Missing, []Range{{2, 2}}) {
		t.Errorf("missing %v", err)
	}
	if _, err := en.send(alice, c.UploadID, f, 2); err != nil {
		t.Fatal(err)
	}
	check("wrong composite", alice, c.UploadID, newFile(10).composite(), ErrChecksumMismatch, events.OutcomeInvalid)
	en.audit.paused = errors.New("the audit log failed")
	check("changes paused", alice, c.UploadID, f.composite(), events.ErrChangesPaused, events.OutcomeDenied)
	en.audit.paused = nil

	if _, err := en.e.Complete(as(alice), c.UploadID, f.composite()); err != nil {
		t.Errorf("once everything is right: %v", err)
	}
}

func TestCompleteWithAPartInFlight(t *testing.T) {
	en := newEnv(t)
	f := newFile(3 * testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	en.send(alice, c.UploadID, f, 1)
	g := newGate(f.part(2))
	done := make(chan error)
	go func() {
		_, err := en.e.Part(as(alice), PartRequest{ID: c.UploadID, N: 2, SHA256: f.sum(2), Length: -1, Body: g})
		done <- err
	}()
	within(t, g.reached)
	// Part 3 is missing too, but the client is to wait for part 2 rather
	// than send it again.
	if _, err := en.e.Complete(as(alice), c.UploadID, f.composite()); !errors.Is(err, ErrPartsInFlight) {
		t.Errorf("complete: %v", err)
	}
	g.open()
	if err := within(t, done); err != nil {
		t.Fatal(err)
	}
	en.send(alice, c.UploadID, f, 3)
	if _, err := en.e.Complete(as(alice), c.UploadID, f.composite()); err != nil {
		t.Errorf("complete: %v", err)
	}
}

func TestCallsDuringCompletion(t *testing.T) {
	en := newEnv(t)
	f := newFile(2 * testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	en.sendAll(alice, c.UploadID, f)
	entered, release := make(chan struct{}), make(chan struct{})
	en.files.set(func(ff *fakeFiles) {
		ff.adopt = func(string) error {
			close(entered)
			<-release
			return nil
		}
	})
	done := make(chan error)
	go func() {
		_, err := en.e.Complete(as(alice), c.UploadID, f.composite())
		done <- err
	}()
	within(t, entered)
	if _, err := en.send(alice, c.UploadID, f, 1); !errors.Is(err, ErrCompleting) {
		t.Errorf("a part: %v", err)
	}
	other := newFile(len(f.data))
	other.data[0]++
	if _, err := en.send(alice, c.UploadID, other, 1); !errors.Is(err, ErrCompleting) {
		t.Errorf("a part with another hash: %v", err)
	}
	if _, err := en.e.Abort(as(alice), c.UploadID); !errors.Is(err, ErrCompleting) {
		t.Errorf("abort: %v", err)
	}
	if _, err := en.e.Complete(as(alice), c.UploadID, f.composite()); !errors.Is(err, ErrCompleting) {
		t.Errorf("another complete: %v", err)
	}
	if st, err := en.e.Status(as(alice), c.UploadID, nil); err != nil || st.State != Completing {
		t.Errorf("status %+v, %v", st, err)
	}
	close(release)
	if err := within(t, done); err != nil {
		t.Fatal(err)
	}
}

func TestAFailedAdoptLeavesTheSessionReceiving(t *testing.T) {
	en := newEnv(t, withFree(1<<30))
	f := newFile(2 * testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	en.sendAll(alice, c.UploadID, f)
	reserved := en.ledger.Reserved()
	en.files.set(func(ff *fakeFiles) { ff.adopt = func(string) error { return errForbidden } })
	en.bus.reset()
	if _, err := en.e.Complete(as(alice), c.UploadID, f.composite()); !errors.Is(err, errForbidden) {
		t.Fatalf("complete: %v", err)
	}
	if en.state(c.UploadID) != Receiving || en.e.openTotal != 1 || en.ledger.Reserved() != reserved {
		t.Errorf("state %s, open %d, reserved %d", en.state(c.UploadID), en.e.openTotal, en.ledger.Reserved())
	}
	if evs := en.bus.all(); len(evs) != 1 || evs[0].Type != events.UploadRejected || evs[0].Outcome != events.OutcomeDenied || evs[0].Upload.Part != 0 {
		t.Errorf("events %+v", evs)
	}
	if got := ops(en.logLines(c.UploadID)); !slices.Equal(got[len(got)-2:], []string{opFinishing, opReject}) {
		t.Errorf("log %v", got)
	}
	if exists(filepath.Join(en.dir, "public", "a.bin")) || !exists(en.staged(c.UploadID, dataName)) {
		t.Error("a refused completion moved the file")
	}
	// The staged data was closed for the placement; a part reopens it.
	if res, err := en.send(alice, c.UploadID, f, 1); err != nil || !res.Duplicate {
		t.Errorf("a part afterwards: %+v, %v", res, err)
	}
	en.files.set(func(ff *fakeFiles) { ff.adopt = nil })
	if _, err := en.e.Complete(as(alice), c.UploadID, f.composite()); err != nil {
		t.Errorf("complete again: %v", err)
	}
}

func TestCompleteNumbersATakenName(t *testing.T) {
	en := newEnv(t)
	f := newFile(10)
	os.WriteFile(filepath.Join(en.dir, "public", "a.bin"), []byte("there first"), 0o644)
	c := en.create(alice, "public", "a.bin", f)
	en.sendAll(alice, c.UploadID, f)
	res, err := en.e.Complete(as(alice), c.UploadID, f.composite())
	if err != nil || res.Path != "public/a (1).bin" || res.Name != "a (1).bin" {
		t.Errorf("%+v, %v", res, err)
	}
}

func TestAnUnloggableCompletionFailsTheSession(t *testing.T) {
	en := newEnv(t)
	f := newFile(2 * testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	en.sendAll(alice, c.UploadID, f)
	en.e.syncFile = func(f *os.File) error {
		if strings.HasSuffix(f.Name(), logName) {
			return &os.PathError{Op: "sync", Path: f.Name(), Err: syscall.EIO}
		}
		return f.Sync()
	}
	_, err := en.e.Complete(as(alice), c.UploadID, f.composite())
	var ce *ClosedError
	if !errors.As(err, &ce) || ce.State != Failed {
		t.Fatalf("complete: %v", err)
	}
	if exists(filepath.Join(en.dir, "public", "a.bin")) {
		t.Error("the file was placed without its intent logged")
	}
	if evs := en.bus.of(events.UploadFailed); len(evs) != 1 {
		t.Errorf("events %+v", evs)
	}
}

func TestADamagedStagedFileFailsTheSession(t *testing.T) {
	en := newEnv(t)
	f := newFile(2 * testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	en.sendAll(alice, c.UploadID, f)
	if err := os.Truncate(en.staged(c.UploadID, dataName), 10); err != nil {
		t.Fatal(err)
	}
	_, err := en.e.Complete(as(alice), c.UploadID, f.composite())
	var ce *ClosedError
	if !errors.As(err, &ce) || ce.State != Failed || en.files.adopts != 0 {
		t.Fatalf("complete: %v, %d adopts", err, en.files.adopts)
	}
}

func TestAnUnrecordedCompletionIsStillDone(t *testing.T) {
	for _, cause := range []error{events.ErrNotRecorded, events.ErrNotConfirmed} {
		t.Run(fmt.Sprint(cause), func(t *testing.T) {
			en := newEnv(t)
			f := newFile(2 * testPartSize)
			c := en.create(alice, "public", "a.bin", f)
			en.sendAll(alice, c.UploadID, f)
			en.audit.recErr = fmt.Errorf("%w: disk full", cause)
			res, err := en.e.Complete(as(alice), c.UploadID, f.composite())
			if !errors.Is(err, cause) || res.Path != "public/a.bin" {
				t.Fatalf("%+v, %v", res, err)
			}
			if !exists(filepath.Join(en.dir, "public", "a.bin")) || en.state(c.UploadID) != Completed {
				t.Errorf("placed %v, state %s", exists(filepath.Join(en.dir, "public", "a.bin")), en.state(c.UploadID))
			}
			if got := ops(en.logLines(c.UploadID)); got[len(got)-1] != opCompleted {
				t.Errorf("log %v", got)
			}
			again, err2 := en.e.Complete(as(alice), c.UploadID, f.composite())
			if again != res || !errors.Is(err2, cause) || len(en.audit.recorded) != 1 {
				t.Errorf("again: %+v, %v; %d records", again, err2, len(en.audit.recorded))
			}
		})
	}
}

func TestACompletionWhoseLogFailsAfterPlacingIsDone(t *testing.T) {
	en := newEnv(t)
	f := newFile(2 * testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	en.sendAll(alice, c.UploadID, f)
	syncs := 0
	en.e.syncFile = func(f *os.File) error {
		if strings.HasSuffix(f.Name(), logName) {
			if syncs++; syncs == 2 {
				return &os.PathError{Op: "sync", Path: f.Name(), Err: syscall.EIO}
			}
		}
		return f.Sync()
	}
	res, err := en.e.Complete(as(alice), c.UploadID, f.composite())
	if err != nil || res.Path != "public/a.bin" {
		t.Fatalf("%+v, %v", res, err)
	}
	if got := ops(en.logLines(c.UploadID)); slices.Contains(got, opRecorded) {
		t.Errorf("recorded after a completed line that may be lost: %v", got)
	}
	if en.state(c.UploadID) != Completed {
		t.Errorf("state %s", en.state(c.UploadID))
	}
}

func TestCompleteAsksTheGuardBeforeLookingAtTheParts(t *testing.T) {
	en := newEnv(t)
	f := newFile(2 * testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	en.audit.paused = errors.New("the audit log failed")
	if _, err := en.e.Complete(as(alice), c.UploadID, f.composite()); !errors.Is(err, events.ErrChangesPaused) {
		t.Errorf("complete with parts missing while paused: %v", err)
	}
}

func TestATombstoneAnswersWhileChangesArePaused(t *testing.T) {
	en := newEnv(t)
	f := newFile(testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	en.sendAll(alice, c.UploadID, f)
	res, err := en.e.Complete(as(alice), c.UploadID, f.composite())
	if err != nil {
		t.Fatal(err)
	}
	en.audit.paused = errors.New("the audit log failed")
	if again, err := en.e.Complete(as(alice), c.UploadID, f.composite()); err != nil || again != res {
		t.Errorf("again while paused: %+v, %v", again, err)
	}
}

func TestStagedDataThatIsntAFileFailsTheSession(t *testing.T) {
	en := newEnv(t)
	f := newFile(testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	en.sendAll(alice, c.UploadID, f)
	s := en.session(c.UploadID)
	s.mu.Lock()
	s.closeFiles()
	s.mu.Unlock()
	data := en.staged(c.UploadID, dataName)
	os.Remove(data)
	if err := os.Mkdir(data, 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := en.e.Complete(as(alice), c.UploadID, f.composite())
	var ce *ClosedError
	if !errors.As(err, &ce) || ce.State != Failed || en.files.adopts != 0 {
		t.Errorf("complete: %v, %d adopts", err, en.files.adopts)
	}
}

func TestAFullDiskForTheFinishingLineLeavesTheSessionReceiving(t *testing.T) {
	en := newEnv(t)
	f := newFile(2 * testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	en.sendAll(alice, c.UploadID, f)
	before, _ := os.ReadFile(en.staged(c.UploadID, logName))
	en.e.writeLog = func(file *os.File, b []byte, off int64) (int, error) {
		n, _ := file.WriteAt(b[:len(b)/2], off)
		return n, &os.PathError{Op: "write", Path: file.Name(), Err: errDiskFull}
	}
	if _, err := en.e.Complete(as(alice), c.UploadID, f.composite()); !errors.Is(err, space.ErrInsufficient) {
		t.Fatalf("complete: %v", err)
	}
	after, _ := os.ReadFile(en.staged(c.UploadID, logName))
	if en.state(c.UploadID) != Receiving || !bytes.Equal(before, after) || exists(filepath.Join(en.dir, "public", "a.bin")) {
		t.Errorf("state %s, log %q", en.state(c.UploadID), after[len(before):])
	}
	en.e.writeLog = (*os.File).WriteAt
	if _, err := en.e.Complete(as(alice), c.UploadID, f.composite()); err != nil {
		t.Errorf("once there is room: %v", err)
	}
}

func TestTheRecordsWaitWithinTheRequest(t *testing.T) {
	en := newEnv(t)
	f := newFile(testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	en.sendAll(alice, c.UploadID, f)
	if _, err := en.e.Complete(as(alice), c.UploadID, f.composite()); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(en.audit.requests, []string{"req-" + alice}) {
		t.Errorf("records waited for in requests %v", en.audit.requests)
	}
}

func TestACompletionAppliesTheCapOnTombstones(t *testing.T) {
	en := newEnv(t)
	en.e.Close(context.Background())
	e2, err := New(Config{Root: en.root, Staging: &sandbox.Staging{Links: true}, Files: en.files, Registry: en.reg, Events: en.bus,
		Audit: en.audit, Limits: Limits{MaxTombstones: 1}, JanitorEvery: time.Hour, Now: en.clock.now})
	if err != nil {
		t.Fatal(err)
	}
	e2.partSize = en.e.partSize
	t.Cleanup(func() { closeWithin(t, e2, context.Background()) })
	en.e = e2
	f := newFile(10)
	aborted := en.create(alice, "public", "a.bin", f)
	en.e.Abort(as(alice), aborted.UploadID)
	time.Sleep(20 * time.Millisecond) // the janitor woken by the abort finds one tombstone
	c := en.create(alice, "public", "b.bin", f)
	en.sendAll(alice, c.UploadID, f)
	if _, err := en.e.Complete(as(alice), c.UploadID, f.composite()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for en.e.lookup(aborted.UploadID) != nil {
		if time.Now().After(deadline) {
			t.Fatal("the completion didn't wake the janitor")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if en.e.lookup(c.UploadID) == nil {
		t.Error("the completed tombstone went first")
	}
}
