package transfer

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/nobletk/gocalbox/internal/events"
)

// admission is what admit returned on another goroutine.
type admission struct {
	release func()
	waited  bool
	err     error
}

// admitAsync calls admit on a goroutine and returns once the call is
// waiting in the queue, so that waiters join it in a known order.
func (en *env) admitAsync(ctx context.Context, user string) <-chan admission {
	en.t.Helper()
	before := en.waiting()
	out := make(chan admission, 1)
	go func() {
		rel, waited, err := en.e.admit(ctx, user, nil)
		out <- admission{rel, waited, err}
	}()
	en.until(func() bool { return en.waiting() == before+1 }, "the part to join the queue")
	return out
}

func (en *env) waiting() int {
	en.e.mu.Lock()
	defer en.e.mu.Unlock()
	return en.e.queue.Len()
}

func (en *env) until(cond func() bool, what string) {
	en.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			en.t.Fatalf("waited ten seconds for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// idle fails the test unless no slot is taken and nothing is counted.
func (en *env) idle() {
	en.t.Helper()
	e := en.e
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.slots != 0 || e.queue.Len() != 0 || len(e.userParts) != 0 {
		en.t.Errorf("admission not idle: %d slots, %d waiting, parts %v", e.slots, e.queue.Len(), e.userParts)
	}
}

// fill takes n slots for user and returns the functions that give them back.
func (en *env) fill(user string, n int) []func() {
	en.t.Helper()
	var rels []func()
	for range n {
		rel, waited, err := en.e.admit(context.Background(), user, nil)
		if err != nil || waited {
			en.t.Fatalf("taking a slot: waited %v, %v", waited, err)
		}
		rels = append(rels, rel)
	}
	return rels
}

func withWait(d time.Duration) option { return withEngine(func(e *Engine) { e.admitWait = d }) }

func TestWaitingPartsAreAdmittedInArrivalOrder(t *testing.T) {
	en := newEnv(t, withLimits(Limits{MaxInflight: 4, MaxInflightUser: 8}), withWait(10*time.Second))
	held := en.fill(alice, 4)
	var queued []<-chan admission
	for _, u := range []string{bob, alice, bob} {
		queued = append(queued, en.admitAsync(context.Background(), u))
	}
	for i := 0; i < len(queued); i++ {
		held[0]()
		held = held[1:]
		a := within(t, queued[i])
		if a.err != nil || !a.waited {
			t.Fatalf("waiter %d: waited %v, %v", i, a.waited, a.err)
		}
		for j := i + 1; j < len(queued); j++ {
			select {
			case b := <-queued[j]:
				t.Fatalf("waiter %d was admitted before waiter %d: %+v", j, i, b)
			default:
			}
		}
		if i == 0 {
			// The slot passed straight on: a part arriving now waits behind the
			// queue instead of taking it.
			queued = append(queued, en.admitAsync(context.Background(), alice))
		}
		if s := en.e.Stats(); s.PartsInFlight != 4 {
			t.Errorf("after waiter %d: %d parts in flight", i, s.PartsInFlight)
		}
		held = append(held, a.release)
	}
	for _, rel := range held {
		rel()
		rel() // a second call gives nothing back
	}
	en.idle()
	if s := en.e.Stats(); s.Waited != 4 || s.Busy != 0 {
		t.Errorf("stats: %+v", s)
	}
}

func TestAWaitThatRunsOutAnswersBusy(t *testing.T) {
	en := newEnv(t, withLimits(Limits{MaxInflight: 1, MaxInflightUser: 8}), withWait(50*time.Millisecond))
	rel, _, err := en.e.admit(context.Background(), alice, nil)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, waited, err := en.e.admit(context.Background(), bob, nil); !errors.Is(err, ErrBusy) || !waited {
		t.Fatalf("a part that waited in vain: waited %v, %v", waited, err)
	}
	if took := time.Since(start); took < 50*time.Millisecond {
		t.Errorf("it waited only %v", took)
	}
	if s := en.e.Stats(); s.Busy != 1 || s.WaitTimeouts != 1 || s.QueueFull != 0 || s.Waited != 1 || s.Waiting != 0 {
		t.Errorf("stats: %+v", s)
	}
	rel()
	en.idle()
}

func TestAFullQueueAnswersBusyAtOnce(t *testing.T) {
	en := newEnv(t, withLimits(Limits{MaxInflight: 2, MaxInflightUser: 8}), withWait(10*time.Second))
	var rels []func()
	for range 2 {
		rel, _, err := en.e.admit(context.Background(), alice, nil)
		if err != nil {
			t.Fatal(err)
		}
		rels = append(rels, rel)
	}
	w1 := en.admitAsync(context.Background(), bob)
	w2 := en.admitAsync(context.Background(), bob)
	if s := en.e.Stats(); s.Waiting != 2 {
		t.Errorf("waiting: %+v", s)
	}
	if _, waited, err := en.e.admit(context.Background(), bob, nil); !errors.Is(err, ErrBusy) || waited {
		t.Fatalf("a part finding the queue full: waited %v, %v", waited, err)
	}
	if s := en.e.Stats(); s.Busy != 1 || s.QueueFull != 1 || s.WaitTimeouts != 0 {
		t.Errorf("stats: %+v", s)
	}
	for _, rel := range rels {
		rel()
	}
	within(t, w1).release()
	within(t, w2).release()
	en.idle()
}

func TestAUsersWaitingPartsCountInTheirLimit(t *testing.T) {
	en := newEnv(t, withLimits(Limits{MaxInflight: 2, MaxInflightUser: 2}), withWait(10*time.Second))
	rels := append(en.fill(alice, 1), en.fill(bob, 1)...)
	waiting := en.admitAsync(context.Background(), alice)
	if _, waited, err := en.e.admit(context.Background(), alice, nil); !errors.Is(err, ErrTooManyRequests) || waited {
		t.Fatalf("alice's third part: waited %v, %v", waited, err)
	}
	other := en.admitAsync(context.Background(), bob)
	for _, rel := range rels {
		rel()
	}
	within(t, waiting).release()
	within(t, other).release()
	en.idle()
}

func TestAPartWhoseRequestEndsLeavesTheQueue(t *testing.T) {
	en := newEnv(t, withLimits(Limits{MaxInflight: 2, MaxInflightUser: 8}), withWait(10*time.Second))
	rels := en.fill(alice, 2)
	rel := func() {
		for _, r := range rels {
			r()
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	gone := en.admitAsync(ctx, bob)
	next := en.admitAsync(context.Background(), bob)
	cancel()
	if a := within(t, gone); !errors.Is(a.err, ErrPartAborted) || !a.waited {
		t.Fatalf("a part whose client left: %+v", a)
	}
	if n := en.waiting(); n != 1 {
		t.Errorf("%d waiting after the client left, want 1", n)
	}
	rel()
	a := within(t, next)
	if a.err != nil {
		t.Fatalf("the next part: %v", a.err)
	}
	a.release()
	en.idle()
}

func TestBeginShutdownAnswersWaitingParts(t *testing.T) {
	en := newEnv(t, withLimits(Limits{MaxInflight: 1, MaxInflightUser: 8}), withWait(10*time.Second))
	rel, _, err := en.e.admit(context.Background(), alice, nil)
	if err != nil {
		t.Fatal(err)
	}
	waiting := en.admitAsync(context.Background(), bob)
	start := time.Now()
	en.e.BeginShutdown()
	// The slot comes free at once, and must not go to the part in the queue.
	rel()
	if a := within(t, waiting); !errors.Is(a.err, ErrShuttingDown) {
		t.Fatalf("a waiting part at shutdown: %+v", a)
	}
	if took := time.Since(start); took > time.Second {
		t.Errorf("the waiting part was answered after %v", took)
	}
	en.idle()

	hold, _, err := en.e.admit(context.Background(), alice, nil)
	if err != nil {
		t.Fatalf("a part that finds a free slot during shutdown: %v", err)
	}
	if _, waited, err := en.e.admit(context.Background(), bob, nil); !errors.Is(err, ErrShuttingDown) || waited {
		t.Fatalf("a part that finds no slot during shutdown: waited %v, %v", waited, err)
	}
	en.e.BeginShutdown()
	hold()
	en.idle()
}

func TestCloseAnswersAWaitingPart(t *testing.T) {
	en := newEnv(t, withLimits(Limits{MaxInflight: 1, MaxInflightUser: 8}), withWait(10*time.Second))
	f := newFile(2 * testPartSize)
	a := en.create(alice, "public", "a.bin", f)
	b := en.create(bob, "public", "b.bin", f)
	g := newGate(f.part(1))
	held := make(chan error, 1)
	go func() {
		_, err := en.e.Part(as(alice), PartRequest{ID: a.UploadID, N: 1, SHA256: f.sum(1), Length: -1, Body: g})
		held <- err
	}()
	within(t, g.reached)
	waiting := make(chan error, 1)
	go func() {
		_, err := en.send(bob, b.UploadID, f, 1)
		waiting <- err
	}()
	en.until(func() bool { return en.waiting() == 1 }, "bob's part to wait")
	closed := make(chan error, 1)
	go func() { closed <- en.e.Close(context.Background()) }()
	if err := within(t, waiting); !errors.Is(err, ErrShuttingDown) {
		t.Errorf("a part waiting as the engine closes: %v", err)
	}
	g.open()
	if err := within(t, held); err != nil {
		t.Errorf("the part in flight: %v", err)
	}
	if err := within(t, closed); err != nil {
		t.Fatal(err)
	}
	en.idle()
}

func TestASlotPassedAsTheClientLeavesGoesToTheNext(t *testing.T) {
	en := newEnv(t, withLimits(Limits{MaxInflight: 2, MaxInflightUser: 8}), withWait(10*time.Second))
	rels := en.fill(alice, 2)
	ctx, cancel := context.WithCancel(context.Background())
	first := en.admitAsync(ctx, bob)
	second := en.admitAsync(context.Background(), alice)

	// The slot reaches the first waiter while its client is leaving: it must
	// pass on, not be lost.
	en.e.mu.Lock()
	cancel()
	time.Sleep(20 * time.Millisecond)
	en.e.handOff(alice)
	en.e.mu.Unlock()

	if a := within(t, first); !errors.Is(a.err, ErrPartAborted) {
		t.Fatalf("the waiter whose client left: %+v", a)
	}
	a := within(t, second)
	if a.err != nil {
		t.Fatalf("the next waiter: %v", a.err)
	}
	if s := en.e.Stats(); s.PartsInFlight != 2 || s.Waiting != 0 {
		t.Errorf("stats: %+v", s)
	}
	a.release()
	rels[1]() // rels[0]'s slot went by handOff above
	en.idle()
}

func TestASlotPassedAsTheWaitRunsOutIsTaken(t *testing.T) {
	en := newEnv(t, withLimits(Limits{MaxInflight: 1, MaxInflightUser: 8}), withWait(50*time.Millisecond))
	if _, _, err := en.e.admit(context.Background(), alice, nil); err != nil {
		t.Fatal(err)
	}
	waiter := en.admitAsync(context.Background(), bob)
	en.e.mu.Lock()
	time.Sleep(200 * time.Millisecond) // the waiter's timer fires meanwhile
	en.e.handOff(alice)
	en.e.mu.Unlock()
	a := within(t, waiter)
	if a.err != nil || !a.waited {
		t.Fatalf("a waiter passed a slot as its wait ran out: %+v", a)
	}
	if s := en.e.Stats(); s.PartsInFlight != 1 || s.Busy != 0 {
		t.Errorf("stats: %+v", s)
	}
	a.release()
	a.release()
	en.idle()
}

// holdSlot starts a part of bob's that takes the only slot and holds it
// until the returned function is called.
func (en *env) holdSlot(f file) (open func()) {
	en.t.Helper()
	b := en.create(bob, "users/bob", "held.bin", f)
	g := newGate(f.part(1))
	done := make(chan error, 1)
	go func() {
		_, err := en.e.Part(as(bob), PartRequest{ID: b.UploadID, N: 1, SHA256: f.sum(1), Length: -1, Body: g})
		done <- err
	}()
	within(en.t, g.reached)
	return func() {
		en.t.Helper()
		g.open()
		if err := within(en.t, done); err != nil {
			en.t.Errorf("the held part: %v", err)
		}
	}
}

// partAsync sends a part on a goroutine and returns once it waits for a
// slot.
func (en *env) partAsync(user string, req PartRequest) <-chan error {
	en.t.Helper()
	before := en.waiting()
	out := make(chan error, 1)
	go func() {
		_, err := en.e.Part(as(user), req)
		out <- err
	}()
	en.until(func() bool { return en.waiting() == before+1 }, "the part to wait")
	return out
}

// countingReader records whether anything read it.
type countingReader struct {
	r    *bytes.Reader
	mu   sync.Mutex
	read int
}

func (c *countingReader) Read(p []byte) (int, error) {
	c.mu.Lock()
	c.read++
	c.mu.Unlock()
	return c.r.Read(p)
}

func (c *countingReader) reads() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.read
}

func TestAPartIsCheckedAgainAfterItWaits(t *testing.T) {
	f := newFile(2 * testPartSize)
	t.Run("its owner lost the right to upload", func(t *testing.T) {
		en := newEnv(t, withLimits(Limits{MaxInflight: 1, MaxInflightUser: 8}), withWait(10*time.Second))
		a := en.create(alice, "public", "a.bin", f)
		open := en.holdSlot(f)
		body := &countingReader{r: bytes.NewReader(f.part(1))}
		res := en.partAsync(alice, PartRequest{ID: a.UploadID, N: 1, SHA256: f.sum(1), Length: testPartSize, Body: body})
		en.files.mu.Lock()
		en.files.deny["key:public"] = true
		en.files.mu.Unlock()
		en.bus.reset()
		open()
		if err := within(t, res); !errors.Is(err, errForbidden) {
			t.Fatalf("a part whose owner was demoted while it waited: %v", err)
		}
		if body.reads() != 0 {
			t.Error("its body was read")
		}
		if s := en.session(a.UploadID); s.has(1) {
			t.Error("the part was kept")
		}
		if ls := en.logLines(a.UploadID); len(ls) != 1 || ls[0].Op != opReject {
			t.Errorf("parts.log: %+v", ls)
		}
		if evs := en.bus.of(events.UploadRejected); len(evs) != 1 {
			t.Errorf("records: %+v", evs)
		}
		en.idle()
	})
	t.Run("its session ended", func(t *testing.T) {
		en := newEnv(t, withLimits(Limits{MaxInflight: 1, MaxInflightUser: 8}), withWait(10*time.Second))
		a := en.create(alice, "public", "a.bin", f)
		open := en.holdSlot(f)
		body := &countingReader{r: bytes.NewReader(f.part(1))}
		res := en.partAsync(alice, PartRequest{ID: a.UploadID, N: 1, SHA256: f.sum(1), Length: testPartSize, Body: body})
		if _, err := en.e.Abort(as(alice), a.UploadID); err != nil {
			t.Fatal(err)
		}
		open()
		if err := within(t, res); !errors.Is(err, ErrClosed) {
			t.Fatalf("a part whose session was aborted while it waited: %v", err)
		}
		if body.reads() != 0 {
			t.Error("its body was read")
		}
		en.idle()
	})
	t.Run("another request delivered it", func(t *testing.T) {
		en := newEnv(t, withLimits(Limits{MaxInflight: 2, MaxInflightUser: 8}), withWait(10*time.Second))
		a := en.create(alice, "public", "a.bin", f)
		openFirst := en.holdSlot(f)
		openSecond := en.holdSlot(f)
		first := en.partAsync(alice, PartRequest{ID: a.UploadID, N: 2, SHA256: f.sum(2), Length: -1, Body: bytes.NewReader(f.part(2))})
		res := make(chan PartResult, 1)
		before := en.waiting()
		go func() {
			r, err := en.e.Part(as(alice), PartRequest{ID: a.UploadID, N: 2, SHA256: f.sum(2), Length: -1, Body: bytes.NewReader(f.part(2))})
			if err != nil {
				t.Errorf("the second copy: %v", err)
			}
			res <- r
		}()
		en.until(func() bool { return en.waiting() == before+1 }, "the second copy to wait")
		// One slot at a time: with both free at once, the second copy could
		// find the first still being received, and be answered in progress.
		openFirst()
		if err := within(t, first); err != nil {
			t.Fatalf("the first copy: %v", err)
		}
		openSecond()
		if r := within(t, res); !r.Duplicate {
			t.Errorf("the second copy, delivered by the first while it waited: %+v", r)
		}
		en.idle()
	})
}

func TestAWaitPausesTheCallersClock(t *testing.T) {
	en := newEnv(t, withLimits(Limits{MaxInflight: 1, MaxInflightUser: 8}), withWait(10*time.Second))
	f := newFile(2 * testPartSize)
	a := en.create(alice, "public", "a.bin", f)
	var mu sync.Mutex
	var calls []bool
	var locked bool
	hook := func(waiting bool) {
		if en.e.mu.TryLock() {
			en.e.mu.Unlock()
		} else {
			locked = true
		}
		mu.Lock()
		calls = append(calls, waiting)
		mu.Unlock()
	}
	if _, err := en.e.Part(as(alice), PartRequest{ID: a.UploadID, N: 1, SHA256: f.sum(1), Length: -1, Body: bytes.NewReader(f.part(1)), Wait: hook}); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 0 {
		t.Errorf("a part that didn't wait called the hook: %v", calls)
	}
	open := en.holdSlot(f)
	res := en.partAsync(alice, PartRequest{ID: a.UploadID, N: 2, SHA256: f.sum(2), Length: -1, Body: bytes.NewReader(f.part(2)), Wait: hook})
	mu.Lock()
	if len(calls) != 1 || !calls[0] {
		t.Errorf("while waiting: %v", calls)
	}
	mu.Unlock()
	open()
	if err := within(t, res); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || calls[1] {
		t.Errorf("after the wait: %v", calls)
	}
	if locked {
		t.Error("the hook ran with the engine's lock held")
	}
	en.idle()
}

func TestAWaitingDuplicateOfAnEndedSessionIsNotRead(t *testing.T) {
	f := newFile(2 * testPartSize)
	en := newEnv(t, withLimits(Limits{MaxInflight: 1, MaxInflightUser: 8}), withWait(10*time.Second))
	a := en.create(alice, "public", "a.bin", f)
	if _, err := en.send(alice, a.UploadID, f, 1); err != nil {
		t.Fatal(err)
	}
	open := en.holdSlot(f)
	body := &countingReader{r: bytes.NewReader(f.part(1))}
	res := en.partAsync(alice, PartRequest{ID: a.UploadID, N: 1, SHA256: f.sum(1), Length: testPartSize, Body: body})
	en.until(func() bool { return en.waiting() == 1 }, "the duplicate to wait")
	if _, err := en.e.Abort(as(alice), a.UploadID); err != nil {
		t.Fatal(err)
	}
	open()
	if err := within(t, res); !errors.Is(err, ErrClosed) {
		t.Fatalf("a duplicate of a session aborted while it waited: %v", err)
	}
	if body.reads() != 0 {
		t.Errorf("its body was read %d times", body.reads())
	}
}

func TestPartLeavesTheQueueWhenItsRequestEnds(t *testing.T) {
	f := newFile(2 * testPartSize)
	en := newEnv(t, withLimits(Limits{MaxInflight: 1, MaxInflightUser: 8}), withWait(10*time.Second))
	a := en.create(alice, "public", "a.bin", f)
	open := en.holdSlot(f)
	defer open()
	ctx, cancel := context.WithCancel(as(alice))
	out := make(chan error, 1)
	go func() {
		_, err := en.e.Part(ctx, PartRequest{ID: a.UploadID, N: 1, SHA256: f.sum(1), Length: -1, Body: bytes.NewReader(f.part(1))})
		out <- err
	}()
	en.until(func() bool { return en.waiting() == 1 }, "the part to wait")
	cancel()
	select {
	case err := <-out:
		if !errors.Is(err, ErrPartAborted) {
			t.Errorf("%v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("the part still waits 2 s after its request ended")
	}
}

func TestTheWaitForASlotIsTenSecondsUnlessConfigured(t *testing.T) {
	en := newEnv(t, func(c *Config, _ *env) { c.prepare = nil; c.AdmitWait = 0 })
	if en.e.admitWait != 10*time.Second {
		t.Errorf("by default: %v", en.e.admitWait)
	}
	en = newEnv(t, func(c *Config, _ *env) { c.prepare = nil; c.AdmitWait = 300 * time.Millisecond })
	if en.e.admitWait != 300*time.Millisecond {
		t.Errorf("configured 300ms: %v", en.e.admitWait)
	}
}

// A user's parts count together across their uploads.
func TestAUsersPartsCountAcrossTheirUploads(t *testing.T) {
	f := newFile(2 * testPartSize)
	en := newEnv(t, withLimits(Limits{MaxInflight: 2, MaxInflightUser: 2}), withWait(10*time.Second))
	a := en.create(alice, "public", "a.bin", f)
	b := en.create(alice, "public", "b.bin", f)
	openFirst := en.holdSlot(f)
	openSecond := en.holdSlot(f)
	first := en.partAsync(alice, PartRequest{ID: a.UploadID, N: 1, SHA256: f.sum(1), Length: -1, Body: bytes.NewReader(f.part(1))})
	second := en.partAsync(alice, PartRequest{ID: b.UploadID, N: 1, SHA256: f.sum(1), Length: -1, Body: bytes.NewReader(f.part(1))})
	if _, err := en.e.Part(as(alice), PartRequest{ID: a.UploadID, N: 2, SHA256: f.sum(2), Length: -1, Body: bytes.NewReader(f.part(2))}); !errors.Is(err, ErrTooManyRequests) {
		t.Errorf("alice's third part, with two waiting in two uploads: %v", err)
	}
	openFirst()
	openSecond()
	for _, res := range []<-chan error{first, second} {
		if err := within(t, res); err != nil {
			t.Error(err)
		}
	}
	en.idle()
}

// A wait runs out after the time it is given, not later.
func TestAWaitRunsOutOnTime(t *testing.T) {
	f := newFile(2 * testPartSize)
	en := newEnv(t, withLimits(Limits{MaxInflight: 1, MaxInflightUser: 8}), withWait(400*time.Millisecond))
	a := en.create(alice, "public", "a.bin", f)
	open := en.holdSlot(f)
	defer open()
	start := time.Now()
	_, err := en.e.Part(as(alice), PartRequest{ID: a.UploadID, N: 1, SHA256: f.sum(1), Length: -1, Body: bytes.NewReader(f.part(1))})
	took := time.Since(start)
	if !errors.Is(err, ErrBusy) || took < 400*time.Millisecond || took > 700*time.Millisecond {
		t.Errorf("a wait of 400 ms: %v after %v", err, took)
	}
}
