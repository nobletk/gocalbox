package transfer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nobletk/gocalbox/internal/events"
)

func TestStatus(t *testing.T) {
	en := newEnv(t)
	f := newFile(5 * testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	for _, n := range []int{1, 2, 4} {
		if _, err := en.send(alice, c.UploadID, f, n); err != nil {
			t.Fatal(err)
		}
	}
	g := newGate(f.part(5))
	done := make(chan error)
	go func() {
		_, err := en.e.Part(as(alice), PartRequest{ID: c.UploadID, N: 5, SHA256: f.sum(5), Length: -1, Body: g})
		done <- err
	}()
	within(t, g.reached)
	defer func() { g.open(); <-done }()

	st, err := en.e.Status(as(alice), c.UploadID, []int{1, 3, 99})
	if err != nil {
		t.Fatal(err)
	}
	if st.State != Receiving || st.Dir != "public" || st.Name != "a.bin" || st.Size != int64(len(f.data)) || st.PartCount != 5 ||
		!slices.Equal(st.Received, []Range{{1, 2}, {4, 4}}) || !slices.Equal(st.InFlight, []int{5}) || st.Owner != nil ||
		!st.Created.Equal(en.clock.now()) || !st.ExpiresAt.Equal(en.clock.now().Add(DefaultLimits.IdleTTL)) {
		t.Errorf("status %+v", st)
	}
	if h := st.Hashes; len(h) != 3 || h["1"] == nil || *h["1"] != f.sum(1) || h["3"] != nil || h["99"] != nil {
		t.Errorf("hashes %v", h)
	}
	st, err = en.e.Status(as(admin), c.UploadID, nil)
	if err != nil || st.Owner == nil || *st.Owner != (Owner{ID: alice, Username: "alice"}) || st.Hashes != nil {
		t.Errorf("an admin's status %+v, %v", st, err)
	}
	en.bus.reset()
	if _, err := en.e.Status(as(bob), c.UploadID, nil); !errors.Is(err, ErrUploadNotFound) {
		t.Errorf("another user: %v", err)
	}
	if _, err := en.e.Status(as(bob), strings.Repeat("a", 32), nil); !errors.Is(err, ErrUploadNotFound) {
		t.Errorf("an unknown ID: %v", err)
	}
	evs := en.bus.all()
	if len(evs) != 2 || evs[0].Outcome != events.OutcomeDenied || evs[1].Outcome != events.OutcomeNotFound {
		t.Errorf("events %+v", evs)
	}
	if _, err := en.e.Status(as(alice), c.UploadID, make([]int, MaxHashes+1)); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("17 hashes: %v", err)
	}
}

func TestAbort(t *testing.T) {
	en := newEnv(t, withFree(1<<30))
	f := newFile(2 * testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	en.send(alice, c.UploadID, f, 1)
	if _, err := en.e.Abort(as(bob), c.UploadID); !errors.Is(err, ErrUploadNotFound) {
		t.Errorf("another user: %v", err)
	}
	en.bus.reset()
	syncs := 0
	en.e.syncFile = func(f *os.File) error {
		if strings.HasSuffix(f.Name(), logName) {
			syncs++
		}
		return f.Sync()
	}
	res, err := en.e.Abort(as(alice), c.UploadID)
	if err != nil || res != (AbortResult{UploadID: c.UploadID, State: Aborted}) {
		t.Fatalf("%+v, %v", res, err)
	}
	if syncs != 1 {
		t.Errorf("the aborted line was flushed %d times", syncs)
	}
	if exists(en.staged(c.UploadID, dataName)) || !exists(en.staged(c.UploadID, logName)) {
		t.Error("abort removes the data and keeps the log")
	}
	if ls := en.logLines(c.UploadID); ls[len(ls)-1].Op != opAborted || ls[len(ls)-1].By != alice {
		t.Errorf("log %+v", ls)
	}
	evs := en.bus.all()
	if len(evs) != 1 || evs[0].Type != events.UploadAborted || evs[0].Actor.ID != alice || evs[0].Size != testPartSize ||
		evs[0].Upload.Received != 1 || evs[0].Upload.OwnerName != "" {
		t.Errorf("events %+v", evs)
	}
	if en.e.openTotal != 0 || en.ledger.Reserved() != 0 {
		t.Errorf("open %d, reserved %d", en.e.openTotal, en.ledger.Reserved())
	}
	if res, err := en.e.Abort(as(alice), c.UploadID); err != nil || res.State != Aborted {
		t.Errorf("abort again: %+v, %v", res, err)
	}
	if _, err := en.e.Complete(as(alice), c.UploadID, f.composite()); !errors.Is(err, ErrClosed) {
		t.Errorf("complete: %v", err)
	}
	if st, err := en.e.Status(as(alice), c.UploadID, nil); err != nil || st.State != Aborted ||
		!st.ExpiresAt.Equal(en.clock.now().Add(DefaultLimits.TombstoneTTL)) {
		t.Errorf("status %+v, %v", st, err)
	}

	d := en.create(bob, "public", "b.bin", f)
	en.bus.reset()
	if res, err := en.e.Abort(as(admin), d.UploadID); err != nil || res.State != Aborted {
		t.Fatalf("an admin aborts: %+v, %v", res, err)
	}
	if evs := en.bus.all(); len(evs) != 1 || evs[0].Actor.ID != admin || evs[0].Upload.Owner != bob || evs[0].Upload.OwnerName != "bob" {
		t.Errorf("events %+v", evs)
	}
	if ls := en.logLines(d.UploadID); ls[0].By != admin {
		t.Errorf("log %+v", ls)
	}
}

func TestAnAbortOnAFullDiskMakesRoomForItsLine(t *testing.T) {
	en := newEnv(t)
	f := newFile(2 * testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	en.send(alice, c.UploadID, f, 1)
	data := en.staged(c.UploadID, dataName)
	en.e.writeLog = func(file *os.File, b []byte, off int64) (int, error) {
		if exists(data) {
			return 0, &os.PathError{Op: "write", Path: file.Name(), Err: errDiskFull}
		}
		return file.WriteAt(b, off)
	}
	if _, err := en.e.Abort(as(alice), c.UploadID); err != nil {
		t.Fatal(err)
	}
	if got := ops(en.logLines(c.UploadID)); !slices.Equal(got, []string{opPart, opAborted}) || exists(data) {
		t.Errorf("log %v, data %v", got, exists(data))
	}
}

func TestAnAbortOnAFullDiskLogsItsLineOnceTheLastPartIsOut(t *testing.T) {
	en := newEnv(t)
	f := newFile(2 * testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	en.send(alice, c.UploadID, f, 1)
	data := en.staged(c.UploadID, dataName)
	en.e.writeLog = func(file *os.File, b []byte, off int64) (int, error) {
		if exists(data) {
			return 0, &os.PathError{Op: "write", Path: file.Name(), Err: errDiskFull}
		}
		return file.WriteAt(b, off)
	}
	g := newGate(f.part(2))
	errs := make(chan error, 1)
	go func() {
		_, err := en.e.Part(as(alice), PartRequest{ID: c.UploadID, N: 2, SHA256: f.sum(2), Length: -1, Body: g})
		errs <- err
	}()
	within(t, g.reached)
	if res, err := en.e.Abort(as(alice), c.UploadID); err != nil || res.State != Aborted {
		t.Fatalf("abort: %+v, %v", res, err)
	}
	if got := ops(en.logLines(c.UploadID)); !slices.Equal(got, []string{opPart}) || !exists(data) {
		t.Fatalf("with the part in flight: log %v, data %v", got, exists(data))
	}
	logSyncs := 0
	en.e.syncFile = func(f *os.File) error {
		if filepath.Base(f.Name()) == logName {
			logSyncs++
		}
		return f.Sync()
	}
	g.open()
	if err := within(t, errs); !errors.Is(err, ErrClosed) {
		t.Errorf("the part: %v", err)
	}
	ls := en.logLines(c.UploadID)
	if got := ops(ls); !slices.Equal(got, []string{opPart, opAborted}) || ls[1].By != alice || exists(data) || logSyncs != 1 {
		t.Errorf("log %+v, data %v, %d flushes of the log", ls, exists(data), logSyncs)
	}
}

func TestList(t *testing.T) {
	en := newEnv(t)
	var ids []string
	for i, u := range []string{alice, bob, alice} {
		ids = append(ids, en.create(u, "public", "x", newFile(i+1)).UploadID)
		en.clock.add(time.Second)
	}
	en.e.Abort(as(alice), ids[0])
	ids_ := func(l []Status) []string {
		var out []string
		for _, s := range l {
			out = append(out, s.UploadID)
		}
		return out
	}
	l, err := en.e.List(as(alice), false)
	if err != nil || !slices.Equal(ids_(l), []string{ids[2], ids[0]}) || l[0].Owner != nil {
		t.Errorf("alice's list %v, %v", ids_(l), err)
	}
	if l, _ := en.e.List(as(alice), true); !slices.Equal(ids_(l), []string{ids[2], ids[0]}) {
		t.Errorf("alice asks for all: %v", ids_(l))
	}
	l, err = en.e.List(as(admin), true)
	if err != nil || !slices.Equal(ids_(l), []string{ids[2], ids[1], ids[0]}) || l[1].Owner == nil || l[1].Owner.Username != "bob" {
		t.Errorf("all %v, %v", ids_(l), err)
	}
	if l, _ := en.e.List(as(admin), false); len(l) != 0 {
		t.Errorf("the admin's own %v", ids_(l))
	}
	if _, err := en.e.List(as("u-nobody"), false); !errors.Is(err, ErrNoAccount) {
		t.Errorf("no account: %v", err)
	}
}

func TestEveryCallHasItsOwnerRule(t *testing.T) {
	// The owner, an admin who isn't the owner, another user, a disabled
	// owner, a deleted owner and no account, for every call on a session.
	callers := []string{alice, admin, bob, "disabled", "deleted", "u-nobody"}
	want := map[string][]bool{
		"part":     {true, false, false, false, false, false},
		"complete": {true, false, false, false, false, false},
		"status":   {true, true, false, false, false, false},
		"abort":    {true, true, false, false, false, false},
	}
	for call, allowed := range want {
		for i, who := range callers {
			en := newEnv(t)
			f := newFile(testPartSize)
			c := en.create(alice, "public", "a.bin", f)
			if call == "complete" {
				en.sendAll(alice, c.UploadID, f)
			}
			switch who {
			case "disabled":
				who = alice
				en.files.set(func(ff *fakeFiles) { ff.users[alice].enabled = false })
			case "deleted":
				who = alice
				en.files.set(func(ff *fakeFiles) { delete(ff.users, alice) })
			}
			en.bus.reset()
			var err error
			switch call {
			case "part":
				_, err = en.send(who, c.UploadID, f, 1)
			case "complete":
				_, err = en.e.Complete(as(who), c.UploadID, f.composite())
			case "status":
				_, err = en.e.Status(as(who), c.UploadID, nil)
			case "abort":
				_, err = en.e.Abort(as(who), c.UploadID)
			}
			if allowed[i] != (err == nil) || (err != nil && !errors.Is(err, ErrUploadNotFound)) {
				t.Errorf("%s by %s: %v", call, callers[i], err)
			}
			if !allowed[i] {
				evs := en.bus.of(events.UploadRejected)
				if len(evs) != 1 || evs[0].Outcome != events.OutcomeDenied || evs[0].Upload.ID != c.UploadID {
					t.Errorf("%s by %s: records %+v", call, callers[i], evs)
				}
			}
		}
	}
}

func TestAnAdminSeesTheOwnerOfTheirOwnSession(t *testing.T) {
	en := newEnv(t)
	c := en.create(admin, "public", "a.bin", newFile(10))
	st, err := en.e.Status(as(admin), c.UploadID, nil)
	if err != nil || st.Owner == nil || *st.Owner != (Owner{ID: admin, Username: "root"}) {
		t.Errorf("%+v, %v", st, err)
	}
}

func TestALongIDIsCutShortInTheRecord(t *testing.T) {
	en := newEnv(t)
	long := strings.Repeat("a", 1<<20)
	for _, call := range []func() error{
		func() error { _, err := en.e.Status(as(alice), long, nil); return err },
		func() error { _, err := en.e.Abort(as(alice), long); return err },
		func() error { _, err := en.e.Complete(as(alice), long, newFile(1).composite()); return err },
	} {
		en.bus.reset()
		if err := call(); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("%v", err)
		}
		if evs := en.bus.all(); len(evs) != 1 || len(evs[0].Upload.ID) > 100 {
			t.Errorf("recorded an ID of %d bytes", len(evs[0].Upload.ID))
		}
	}
}

func TestASessionOutlivesTheLoginThatMadeIt(t *testing.T) {
	en := newEnv(t)
	f := newFile(2 * testPartSize)
	first := events.WithActor(context.Background(), events.Actor{ID: alice, Session: "login-1"})
	c, err := en.e.Create(first, CreateRequest{Dir: "public", Name: "a", Size: int64(len(f.data)), ClientKey: "k"})
	if err != nil {
		t.Fatal(err)
	}
	if en.reg.recs[c.UploadID].Session != "login-1" {
		t.Errorf("record %+v", en.reg.recs[c.UploadID])
	}
	later := events.WithActor(context.Background(), events.Actor{ID: alice, Session: "login-2"})
	again, err := en.e.Create(later, CreateRequest{Dir: "public", Name: "a", Size: int64(len(f.data)), ClientKey: "k"})
	if err != nil || again.UploadID != c.UploadID {
		t.Fatalf("resume from a new login: %+v, %v", again, err)
	}
	for n := 1; n <= 2; n++ {
		b := f.part(n)
		if _, err := en.e.Part(later, PartRequest{ID: c.UploadID, N: n, SHA256: f.sum(n), Length: int64(len(b)), Body: strings.NewReader(string(b))}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := en.e.Complete(later, c.UploadID, f.composite()); err != nil {
		t.Fatal(err)
	}
}
