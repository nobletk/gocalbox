package transfer

import (
	"bytes"
	"cmp"
	"errors"
	"io"
	"os"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/space"
)

func TestPartsAreWrittenAtTheirOffsetsInAnyOrder(t *testing.T) {
	en := newEnv(t)
	f := newFile(3*testPartSize + 100)
	c := en.create(alice, "public", "a.bin", f)
	for _, n := range []int{4, 2, 1, 3} {
		res, err := en.send(alice, c.UploadID, f, n)
		if err != nil {
			t.Fatalf("part %d: %v", n, err)
		}
		if res.Part != n || res.Size != int64(len(f.part(n))) || res.SHA256 != f.sum(n) || res.PartCount != 4 || res.Duplicate {
			t.Errorf("part %d: %+v", n, res)
		}
	}
	got, err := os.ReadFile(en.staged(c.UploadID, dataName))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, f.data) {
		t.Error("the staged data differs from the file")
	}
	ls := en.logLines(c.UploadID)
	if len(ls) != 4 {
		t.Fatalf("log %+v", ls)
	}
	for i, n := range []int{4, 2, 1, 3} {
		if l := ls[i]; l.Op != opPart || l.N != n || l.SHA256 != f.sum(n) || l.IP != "192.0.2.7" || l.At.IsZero() {
			t.Errorf("line %d: %+v", i, l)
		}
	}
	evs := en.bus.of(events.UploadPartReceived)
	if en.bus.tried != 4 || len(evs) != 4 {
		t.Fatalf("%d tried, %d events", en.bus.tried, len(evs))
	}
	if ev := evs[3]; ev.Upload.Part != 3 || ev.Upload.Received != 4 || ev.Upload.SHA256 != f.sum(3) || ev.Size != testPartSize ||
		ev.Outcome != events.OutcomeOK || len(ev.Upload.Clients) != 1 || ev.Upload.Clients[0] != "192.0.2.7" {
		t.Errorf("event %+v %+v", ev, ev.Upload)
	}
	st, err := en.e.Status(as(alice), c.UploadID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Received) != 1 || st.Received[0] != (Range{1, 4}) {
		t.Errorf("received %v", st.Received)
	}
}

func TestPartRefusals(t *testing.T) {
	en := newEnv(t)
	f := newFile(2*testPartSize + 10)
	c := en.create(alice, "public", "a.bin", f)
	if _, err := en.send(alice, c.UploadID, f, 1); err != nil {
		t.Fatal(err)
	}
	other := newFile(len(f.data))
	other.data[0] ^= 1
	part := func(n int, sum string, length int64, body string) PartRequest {
		return PartRequest{ID: c.UploadID, N: n, SHA256: sum, Length: length, Body: strings.NewReader(body)}
	}
	full := string(f.part(2))
	for _, tc := range []struct {
		name     string
		user     string
		req      PartRequest
		want     error
		recorded events.Outcome
		logged   bool
	}{
		{"malformed ID", alice, PartRequest{ID: "../x", N: 2, SHA256: f.sum(2)}, ErrInvalidPart, events.OutcomeInvalid, false},
		{"part 0", alice, part(0, f.sum(2), -1, full), ErrInvalidPart, events.OutcomeInvalid, false},
		{"no hash", alice, part(2, "", -1, full), ErrMissingChecksum, events.OutcomeInvalid, false},
		{"upper-case hash", alice, part(2, strings.ToUpper(f.sum(2)), -1, full), ErrMissingChecksum, events.OutcomeInvalid, false},
		{"unknown upload", alice, PartRequest{ID: strings.Repeat("0", 32), N: 1, SHA256: f.sum(1), Length: -1}, ErrUploadNotFound, events.OutcomeNotFound, false},
		{"another user", bob, part(2, f.sum(2), -1, full), ErrUploadNotFound, events.OutcomeDenied, false},
		{"an admin", admin, part(2, f.sum(2), -1, full), ErrUploadNotFound, events.OutcomeDenied, false},
		{"past the last part", alice, part(4, f.sum(2), -1, full), ErrInvalidPart, events.OutcomeInvalid, true},
		{"declared length", alice, part(2, f.sum(2), testPartSize-1, full), ErrPartSizeMismatch, events.OutcomeInvalid, true},
		{"short body", alice, part(2, f.sum(2), -1, full[:100]), ErrPartSizeMismatch, events.OutcomeInvalid, true},
		{"long body", alice, part(2, f.sum(2), -1, full+"x"), ErrPartSizeMismatch, events.OutcomeInvalid, true},
		{"wrong hash", alice, part(2, f.sum(1), -1, full), ErrChecksumMismatch, events.OutcomeInvalid, true},
		{"another hash for a received part", alice, part(1, other.sum(1), -1, string(other.part(1))), ErrPartConflict, events.OutcomeInvalid, true},
	} {
		en.bus.reset()
		before := len(en.logLines(c.UploadID))
		_, err := en.e.Part(as(tc.user), tc.req)
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
			continue
		}
		evs := en.bus.all()
		if len(evs) != 1 || evs[0].Type != events.UploadRejected || evs[0].Outcome != tc.recorded || evs[0].Actor.ID != tc.user {
			t.Errorf("%s: events %+v", tc.name, evs)
		} else if tc.user != alice && (evs[0].Upload.Owner != alice || evs[0].Upload.OwnerName != "alice") {
			t.Errorf("%s: the refusal doesn't name the owner: %+v", tc.name, evs[0].Upload)
		}
		ls := en.logLines(c.UploadID)
		if tc.logged != (len(ls) == before+1) {
			t.Errorf("%s: log %+v", tc.name, ls[before:])
		} else if tc.logged && (ls[before].Op != opReject || ls[before].Reason == "") {
			t.Errorf("%s: line %+v", tc.name, ls[before])
		}
	}
	got, _ := os.ReadFile(en.staged(c.UploadID, dataName))
	if !bytes.Equal(got[:testPartSize], f.part(1)) {
		t.Error("a refused part changed part 1")
	}
	if len(got) > 2*testPartSize {
		t.Errorf("the long body wrote past its part: %d bytes staged", len(got))
	}
	s := en.session(c.UploadID)
	if s.has(2) || s.nReceived != 1 || s.rejected != 6 {
		t.Errorf("part 2 received %v, %d received, %d rejected", s.has(2), s.nReceived, s.rejected)
	}
	if _, err := en.send(alice, c.UploadID, f, 2); err != nil {
		t.Errorf("part 2 sent again after its refusals: %v", err)
	}
}

func TestALongPartLeavesTheNextPartAlone(t *testing.T) {
	en := newEnv(t)
	f := newFile(3 * testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	if _, err := en.send(alice, c.UploadID, f, 2); err != nil {
		t.Fatal(err)
	}
	long := append(append([]byte(nil), f.part(1)...), 0xff, 0xff)
	_, err := en.e.Part(as(alice), PartRequest{ID: c.UploadID, N: 1, SHA256: f.sum(1), Length: -1, Body: bytes.NewReader(long)})
	if !errors.Is(err, ErrPartSizeMismatch) {
		t.Fatalf("a part 2 bytes too long: %v", err)
	}
	got, _ := os.ReadFile(en.staged(c.UploadID, dataName))
	if !bytes.Equal(got[testPartSize:2*testPartSize], f.part(2)) {
		t.Error("the long part 1 overwrote part 2")
	}
}

func TestADuplicatePartIsReadAndDiscarded(t *testing.T) {
	en := newEnv(t)
	f := newFile(2 * testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	if _, err := en.send(alice, c.UploadID, f, 1); err != nil {
		t.Fatal(err)
	}
	s := en.session(c.UploadID)
	last := s.lastPart
	en.clock.add(time.Hour)
	body := bytes.NewReader(f.part(1))
	res, err := en.e.Part(as(alice), PartRequest{ID: c.UploadID, N: 1, SHA256: f.sum(1), Length: -1, Body: body})
	if err != nil || !res.Duplicate || res.Received != 1 {
		t.Fatalf("%+v, %v", res, err)
	}
	if body.Len() != 0 {
		t.Errorf("%d bytes of the duplicate were left unread", body.Len())
	}
	if !s.lastPart.Equal(last) || s.retries != 1 || len(en.logLines(c.UploadID)) != 1 {
		t.Errorf("a duplicate counted as activity: last %v, retries %d, log %v", s.lastPart, s.retries, en.logLines(c.UploadID))
	}
	if evs := en.bus.of(events.UploadPartReceived); len(evs) != 1 {
		t.Errorf("part events %+v", evs)
	}
}

func TestAPartIsRefusedOnceTheOwnerMayNoLongerUpload(t *testing.T) {
	en := newEnv(t)
	f := newFile(2 * testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	en.files.set(func(ff *fakeFiles) { ff.deny["key:public"] = true })
	if _, err := en.send(alice, c.UploadID, f, 1); !errors.Is(err, errForbidden) {
		t.Fatalf("part after the right was taken: %v", err)
	}
	if ev := en.bus.of(events.UploadRejected); len(ev) != 1 || ev[0].Outcome != events.OutcomeDenied {
		t.Errorf("events %+v", ev)
	}
	en.files.set(func(ff *fakeFiles) { ff.users[alice].enabled = false })
	if _, err := en.send(alice, c.UploadID, f, 1); !errors.Is(err, ErrUploadNotFound) {
		t.Errorf("part from a disabled owner: %v", err)
	}
}

func TestPartsInFlightAreLimited(t *testing.T) {
	en := newEnv(t, withLimits(Limits{MaxInflight: 3, MaxInflightUser: 2}))
	f := newFile(4 * testPartSize)
	a := en.create(alice, "public", "a.bin", f)
	b := en.create(bob, "public", "b.bin", f)
	var gates []*gate
	var wg sync.WaitGroup
	hold := func(user, id string, n int) {
		g := newGate(f.part(n))
		gates = append(gates, g)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := en.e.Part(as(user), PartRequest{ID: id, N: n, SHA256: f.sum(n), Length: -1, Body: g}); err != nil {
				t.Errorf("held part: %v", err)
			}
		}()
		within(t, g.reached)
	}
	hold(alice, a.UploadID, 1)
	hold(alice, a.UploadID, 2)
	en.bus.reset()
	if _, err := en.send(alice, a.UploadID, f, 3); !errors.Is(err, ErrTooManyRequests) {
		t.Errorf("alice's third part: %v", err)
	}
	hold(bob, b.UploadID, 1)
	if _, err := en.send(bob, b.UploadID, f, 2); !errors.Is(err, ErrBusy) {
		t.Errorf("the server's fourth part: %v", err)
	}
	if evs := en.bus.of(events.UploadRejected); len(evs) != 0 {
		t.Errorf("admission refusals were recorded: %+v", evs)
	}
	for _, g := range gates {
		g.open()
	}
	wg.Wait()
	if _, err := en.send(alice, a.UploadID, f, 3); err != nil {
		t.Errorf("once the parts ended: %v", err)
	}
}

func TestTheSamePartTwiceAtOnce(t *testing.T) {
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
	if _, err := en.send(alice, c.UploadID, f, 1); !errors.Is(err, ErrPartInProgress) {
		t.Errorf("the second copy: %v", err)
	}
	if evs := en.bus.of(events.UploadRejected); len(evs) != 0 {
		t.Errorf("recorded %+v", evs)
	}
	g.open()
	if err := within(t, done); err != nil {
		t.Fatal(err)
	}
	if res, err := en.send(alice, c.UploadID, f, 1); err != nil || !res.Duplicate {
		t.Errorf("after the first copy: %+v, %v", res, err)
	}
}

func TestAPartGrowsTheWindowOrIsRefusedWithoutSpace(t *testing.T) {
	en := newEnv(t, withFree(1<<20), withLimits(Limits{Window: 8 << 10, MaxParallel: 1}))
	f := newFile(6 * testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	s := en.session(c.UploadID)
	if s.window.Left() != 8<<10 {
		t.Fatalf("window %d", s.window.Left())
	}
	for n := 1; n <= 3; n++ {
		if _, err := en.send(alice, c.UploadID, f, n); err != nil {
			t.Fatal(err)
		}
		en.setFree(int64(1<<20 - n*testPartSize))
	}
	if left := s.window.Left(); left != 8<<10-testPartSize {
		t.Errorf("window %d after three parts", left)
	}
	en.setFree(testPartSize)
	en.bus.reset()
	if _, err := en.send(alice, c.UploadID, f, 4); err != nil {
		t.Fatalf("part 4 within the window: %v", err)
	}
	if _, err := en.send(alice, c.UploadID, f, 5); !errors.Is(err, space.ErrInsufficient) {
		t.Fatalf("part 5 beyond the space: %v", err)
	}
	if evs := en.bus.of(events.UploadRejected); len(evs) != 1 || evs[0].Outcome != events.OutcomeNoSpace {
		t.Errorf("events %+v", evs)
	}
	if ls := en.logLines(c.UploadID); ls[len(ls)-1].Reason != "insufficient_storage" {
		t.Errorf("last line %+v", ls[len(ls)-1])
	}
	en.setFree(1 << 20)
	if _, err := en.send(alice, c.UploadID, f, 5); err != nil {
		t.Errorf("part 5 once space was freed: %v", err)
	}
	if en.state(c.UploadID) != Receiving {
		t.Errorf("state %s", en.state(c.UploadID))
	}
}

// fullWriter takes room bytes, then fails with err, or with a full disk.
type fullWriter struct {
	w    io.Writer
	room int
	err  error
}

func (f *fullWriter) Write(p []byte) (int, error) {
	if len(p) <= f.room {
		f.room -= len(p)
		return f.w.Write(p)
	}
	n, _ := f.w.Write(p[:f.room])
	f.room = 0
	return n, &os.PathError{Op: "write", Path: "data", Err: cmp.Or(f.err, errDiskFull)}
}

func TestADiskFullWhileWritingRefusesOnlyThePart(t *testing.T) {
	en := newEnv(t)
	f := newFile(2 * testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	en.e.writeAt = func(file *os.File, off int64) io.Writer {
		return &fullWriter{w: io.NewOffsetWriter(file, off), room: 100}
	}
	en.bus.reset()
	if _, err := en.send(alice, c.UploadID, f, 1); !errors.Is(err, space.ErrInsufficient) {
		t.Fatalf("part on a full disk: %v", err)
	}
	if en.state(c.UploadID) != Receiving {
		t.Errorf("state %s", en.state(c.UploadID))
	}
	if evs := en.bus.all(); len(evs) != 1 || evs[0].Type != events.UploadRejected || evs[0].Outcome != events.OutcomeNoSpace {
		t.Errorf("events %+v", evs)
	}
	en.e.writeAt = func(file *os.File, off int64) io.Writer { return io.NewOffsetWriter(file, off) }
	if _, err := en.send(alice, c.UploadID, f, 1); err != nil {
		t.Errorf("resent: %v", err)
	}
}

func TestAFileTooLargeForTheVolumeRefusesOnlyThePart(t *testing.T) {
	if errFileTooBig == nil {
		t.Skip("no file-size error is known on this system")
	}
	en := newEnv(t)
	f := newFile(2 * testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	en.e.writeAt = func(file *os.File, off int64) io.Writer {
		return &fullWriter{w: io.NewOffsetWriter(file, off), room: 100, err: errFileTooBig}
	}
	en.bus.reset()
	if _, err := en.send(alice, c.UploadID, f, 1); !errors.Is(err, ErrTooLargeForVolume) {
		t.Fatalf("part: %v", err)
	}
	if en.state(c.UploadID) != Receiving || !exists(en.staged(c.UploadID, dataName)) {
		t.Errorf("state %s, data %v", en.state(c.UploadID), exists(en.staged(c.UploadID, dataName)))
	}
	if evs := en.bus.all(); len(evs) != 1 || evs[0].Type != events.UploadRejected || evs[0].Outcome != events.OutcomeInvalid {
		t.Errorf("events %+v", evs)
	}
}

func TestAFlushThatFailsFailsTheSessionEvenForAFullDisk(t *testing.T) {
	en := newEnv(t)
	f := newFile(2 * testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	en.e.syncFile = func(f *os.File) error {
		if strings.HasSuffix(f.Name(), dataName) {
			return &os.PathError{Op: "sync", Path: f.Name(), Err: errDiskFull}
		}
		return f.Sync()
	}
	_, err := en.send(alice, c.UploadID, f, 1)
	var ce *ClosedError
	if !errors.As(err, &ce) || ce.State != Failed {
		t.Fatalf("part whose flush failed: %v", err)
	}
}

func TestAFullDiskForTheLogRefusesOnlyThePart(t *testing.T) {
	en := newEnv(t)
	f := newFile(2 * testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	en.e.writeLog = func(file *os.File, b []byte, off int64) (int, error) {
		n, _ := file.WriteAt(b[:len(b)/2], off)
		return n, &os.PathError{Op: "write", Path: file.Name(), Err: errDiskFull}
	}
	if _, err := en.send(alice, c.UploadID, f, 1); !errors.Is(err, space.ErrInsufficient) {
		t.Fatalf("part whose line didn't fit: %v", err)
	}
	if en.state(c.UploadID) != Receiving || !exists(en.staged(c.UploadID, dataName)) {
		t.Errorf("state %s", en.state(c.UploadID))
	}
	if b, _ := os.ReadFile(en.staged(c.UploadID, logName)); len(b) != 0 {
		t.Errorf("the log holds %q", b)
	}
	en.e.writeLog = (*os.File).WriteAt
	for n := 1; n <= 2; n++ {
		if _, err := en.send(alice, c.UploadID, f, n); err != nil {
			t.Fatal(err)
		}
	}
	if got := ops(en.logLines(c.UploadID)); !slices.Equal(got, []string{opPart, opPart}) {
		t.Errorf("log %v", got)
	}
}

func TestAWriteThatFailsFailsTheSession(t *testing.T) {
	for _, which := range []string{dataName, logName} {
		t.Run(which, func(t *testing.T) {
			en := newEnv(t, withFree(1<<30))
			f := newFile(2 * testPartSize)
			c := en.create(alice, "public", "a.bin", f)
			en.e.syncFile = func(f *os.File) error {
				if strings.HasSuffix(f.Name(), which) {
					return &os.PathError{Op: "sync", Path: f.Name(), Err: syscall.EIO}
				}
				return f.Sync()
			}
			_, err := en.send(alice, c.UploadID, f, 1)
			var ce *ClosedError
			if !errors.As(err, &ce) || ce.State != Failed {
				t.Fatalf("part with a failing %s: %v", which, err)
			}
			if exists(en.staged(c.UploadID, dataName)) {
				t.Error("the data of a failed session is still there")
			}
			if evs := en.bus.of(events.UploadFailed); len(evs) != 1 || evs[0].Actor.ID != alice || evs[0].RequestID != "req-"+alice ||
				evs[0].Outcome != events.OutcomeError {
				t.Errorf("events %+v", evs)
			}
			if en.e.openTotal != 0 || en.ledger.Reserved() != 0 {
				t.Errorf("open %d, reserved %d", en.e.openTotal, en.ledger.Reserved())
			}
			if _, err := en.send(alice, c.UploadID, f, 2); !errors.Is(err, ErrClosed) {
				t.Errorf("a part of the failed session: %v", err)
			}
		})
	}
}

func TestABodyThatBreaksIsNotRecorded(t *testing.T) {
	en := newEnv(t)
	f := newFile(2 * testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	body := io.MultiReader(bytes.NewReader(f.part(1)[:100]), &failingReader{})
	_, err := en.e.Part(as(alice), PartRequest{ID: c.UploadID, N: 1, SHA256: f.sum(1), Length: -1, Body: body})
	if !errors.Is(err, ErrPartAborted) {
		t.Fatalf("broken body: %v", err)
	}
	if evs := en.bus.of(events.UploadRejected); len(evs) != 0 {
		t.Errorf("recorded %+v", evs)
	}
	if s := en.session(c.UploadID); s.has(1) || len(s.inflight) != 0 || s.state != Receiving {
		t.Errorf("session after a broken body: has %v, in flight %v, %s", s.has(1), s.inflight, s.state)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("connection reset") }

func TestAPartOfAnUploadAbortedMeanwhileIsNotLogged(t *testing.T) {
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
	if _, err := en.e.Abort(as(admin), c.UploadID); err != nil {
		t.Fatal(err)
	}
	if !exists(en.staged(c.UploadID, dataName)) {
		t.Error("the data was removed while a part was being written")
	}
	g.open()
	if err := within(t, done); !errors.Is(err, ErrClosed) {
		t.Errorf("the part: %v", err)
	}
	if exists(en.staged(c.UploadID, dataName)) {
		t.Error("the last part to leave didn't remove the data")
	}
	if got := ops(en.logLines(c.UploadID)); len(got) != 1 || got[0] != opAborted {
		t.Errorf("log %v", got)
	}
	evs := en.bus.of(events.UploadAborted)
	if len(evs) != 1 || evs[0].Actor.ID != admin || evs[0].Upload.OwnerName != "alice" {
		t.Errorf("events %+v", evs)
	}
}

func TestPartEventsWaitOnlyWithAuditParts(t *testing.T) {
	en := newEnv(t)
	en.bus.full = true
	f := newFile(2 * testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	if _, err := en.send(alice, c.UploadID, f, 1); err != nil {
		t.Fatalf("a part while the bus is full: %v", err)
	}
	if evs := en.bus.of(events.UploadPartReceived); len(evs) != 0 || en.bus.tried != 1 {
		t.Errorf("%d tried, events %+v", en.bus.tried, evs)
	}
	en.e.auditParts = true
	if _, err := en.send(alice, c.UploadID, f, 2); err != nil {
		t.Fatal(err)
	}
	if evs := en.bus.of(events.UploadPartReceived); len(evs) != 1 || en.bus.tried != 1 {
		t.Errorf("with -audit-parts: %d tried, events %+v", en.bus.tried, evs)
	}
}

func TestAPartIsCheckedAgainOnceAdmitted(t *testing.T) {
	en := newEnv(t)
	f := newFile(2 * testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	var once sync.Once
	held, release := make(chan struct{}), make(chan struct{})
	en.e.admitted = func(PartRequest) {
		hold := false
		once.Do(func() { hold = true })
		if hold {
			close(held)
			<-release
		}
	}
	type answer struct {
		res PartResult
		err error
	}
	first := make(chan answer)
	go func() {
		res, err := en.send(alice, c.UploadID, f, 1)
		first <- answer{res, err}
	}()
	within(t, held)
	if res, err := en.send(alice, c.UploadID, f, 1); err != nil || res.Duplicate {
		t.Fatalf("the second request: %+v, %v", res, err)
	}
	close(release)
	if a := within(t, first); a.err != nil || !a.res.Duplicate {
		t.Errorf("the first request, admitted before the part arrived: %+v, %v", a.res, a.err)
	}
	if n := len(en.logLines(c.UploadID)); n != 1 {
		t.Errorf("%d part lines", n)
	}
}

func TestTheWindowCoversEveryPartInFlight(t *testing.T) {
	en := newEnv(t, withFree(1<<30), withLimits(Limits{Window: testPartSize, MaxParallel: 1}))
	f := newFile(3 * testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	var gates []*gate
	done := make(chan error, 2)
	for n := 1; n <= 2; n++ {
		g := newGate(f.part(n))
		gates = append(gates, g)
		go func() {
			_, err := en.e.Part(as(alice), PartRequest{ID: c.UploadID, N: n, SHA256: f.sum(n), Length: -1, Body: g})
			done <- err
		}()
		within(t, g.reached)
	}
	if got := en.ledger.Reserved(); got != 2*testPartSize {
		t.Errorf("reserved %d with two parts in flight", got)
	}
	for _, g := range gates {
		g.open()
	}
	for range 2 {
		if err := within(t, done); err != nil {
			t.Fatal(err)
		}
	}
	if got := en.ledger.Reserved(); got != 0 {
		t.Errorf("reserved %d once both are written", got)
	}
}

func TestAPartWhoseDataIsGoneFailsTheSession(t *testing.T) {
	en := newEnv(t)
	f := newFile(2 * testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	s := en.session(c.UploadID)
	s.mu.Lock()
	s.closeFiles()
	s.mu.Unlock()
	if err := os.Remove(en.staged(c.UploadID, dataName)); err != nil {
		t.Fatal(err)
	}
	_, err := en.send(alice, c.UploadID, f, 1)
	var ce *ClosedError
	if !errors.As(err, &ce) || ce.State != Failed {
		t.Fatalf("part: %v", err)
	}
	if evs := en.bus.of(events.UploadFailed); len(evs) != 1 || en.e.openTotal != 0 {
		t.Errorf("events %+v, open %d", evs, en.e.openTotal)
	}
}

func TestRejectLinesNameOnlyPartsTheSessionHas(t *testing.T) {
	en := newEnv(t)
	f := newFile(2 * testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	if _, err := en.e.Part(as(alice), PartRequest{ID: c.UploadID, N: 1 << 40, SHA256: f.sum(1), Length: -1, Body: bytes.NewReader(nil)}); !errors.Is(err, ErrInvalidPart) {
		t.Fatalf("part 2^40: %v", err)
	}
	en.e.Complete(as(alice), c.UploadID, f.composite())
	ls := en.logLines(c.UploadID)
	if len(ls) != 2 || ls[0].Op != opReject || ls[0].N != 0 || ls[0].Reason != "invalid_part" || ls[1].N != 0 || ls[1].Reason != "parts_missing" {
		t.Errorf("log %+v", ls)
	}
}

func TestTheHashIsCheckedBeforeTheOwner(t *testing.T) {
	en := newEnv(t)
	f := newFile(testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	if _, err := en.e.Part(as(bob), PartRequest{ID: c.UploadID, N: 1, Length: -1, Body: bytes.NewReader(f.part(1))}); !errors.Is(err, ErrMissingChecksum) {
		t.Errorf("another user's part without a hash: %v", err)
	}
}

func TestAPartWhoseDataCantBeOpenedIsRefused(t *testing.T) {
	en := newEnv(t)
	f := newFile(2 * testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	s := en.session(c.UploadID)
	s.mu.Lock()
	s.closeFiles()
	s.mu.Unlock()
	data := en.staged(c.UploadID, dataName)
	os.Remove(data)
	if err := os.Mkdir(data, 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := en.send(alice, c.UploadID, f, 1)
	if err == nil || errors.Is(err, ErrClosed) {
		t.Fatalf("part: %v", err)
	}
	if en.state(c.UploadID) != Receiving {
		t.Errorf("state %s", en.state(c.UploadID))
	}
}

func TestADuplicateOfAnUploadAbortedMeanwhileIsClosed(t *testing.T) {
	en := newEnv(t)
	f := newFile(2 * testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	en.send(alice, c.UploadID, f, 1)
	g := newGate(f.part(1))
	done := make(chan error)
	go func() {
		_, err := en.e.Part(as(alice), PartRequest{ID: c.UploadID, N: 1, SHA256: f.sum(1), Length: -1, Body: g})
		done <- err
	}()
	within(t, g.reached)
	en.e.Abort(as(alice), c.UploadID)
	g.open()
	if err := within(t, done); !errors.Is(err, ErrClosed) {
		t.Errorf("the duplicate: %v", err)
	}
}

func TestADuplicateIsReadOneByteBeyondItsPart(t *testing.T) {
	en := newEnv(t)
	f := newFile(testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	en.send(alice, c.UploadID, f, 1)
	body := bytes.NewReader(append(append([]byte(nil), f.part(1)...), 1, 2, 3, 4, 5))
	if res, err := en.e.Part(as(alice), PartRequest{ID: c.UploadID, N: 1, SHA256: f.sum(1), Length: -1, Body: body}); err != nil || !res.Duplicate {
		t.Fatalf("%+v, %v", res, err)
	}
	if body.Len() != 4 {
		t.Errorf("%d bytes left unread, want 4", body.Len())
	}
}

func TestAnEndedUploadLogsNoRefusal(t *testing.T) {
	en := newEnv(t)
	f := newFile(testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	en.e.Abort(as(alice), c.UploadID)
	en.files.set(func(ff *fakeFiles) { ff.deny["key:public"] = true })
	if _, err := en.send(alice, c.UploadID, f, 1); !errors.Is(err, errForbidden) {
		t.Fatalf("part: %v", err)
	}
	if got := ops(en.logLines(c.UploadID)); !slices.Equal(got, []string{opAborted}) {
		t.Errorf("log %v", got)
	}
}

func TestAWriteThatFailsOtherwiseFailsTheSession(t *testing.T) {
	en := newEnv(t)
	f := newFile(2 * testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	en.e.writeAt = func(file *os.File, off int64) io.Writer { return failingWriter{} }
	_, err := en.send(alice, c.UploadID, f, 1)
	var ce *ClosedError
	if !errors.As(err, &ce) || ce.State != Failed {
		t.Errorf("part whose write failed: %v", err)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, syscall.EIO }
