package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nobletk/gocalbox/internal/events"
)

type lostLines struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *lostLines) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

type lostLine struct {
	Audit string       `json:"audit"`
	Error string       `json:"error"`
	Event events.Event `json:"event"`
}

func (l *lostLines) lines(t *testing.T) []lostLine {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []lostLine
	for _, s := range strings.Split(strings.TrimSpace(l.buf.String()), "\n") {
		if s == "" {
			continue
		}
		var ll lostLine
		if err := json.Unmarshal([]byte(s), &ll); err != nil {
			t.Fatalf("not a JSON line: %q: %v", s, err)
		}
		out = append(out, ll)
	}
	return out
}

func captureLost(t *testing.T) *lostLines {
	l := &lostLines{}
	t.Cleanup(events.SetLostOutput(l))
	return l
}

func acked(i int) events.Event {
	e := ev(i)
	e.Ack = events.NewAck()
	return e
}

func answer(t *testing.T, e events.Event) error {
	t.Helper()
	done, err := e.Ack.Wait(0)
	if !done {
		t.Fatalf("event %d not answered", e.Seq)
	}
	return err
}

// syncCheck fails the test if an Ack was answered before the file was synced.
type syncCheck struct {
	*os.File
	t     *testing.T
	acks  []*events.Ack
	syncs int
}

func (f *syncCheck) Sync() error {
	for _, a := range f.acks {
		if done, _ := a.Wait(0); done && f.syncs == 0 {
			f.t.Error("Ack answered before the fsync")
		}
	}
	f.syncs++
	return f.File.Sync()
}

func TestWriterAnswersAcksAfterTheSync(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	w, _ := Open(path)
	batch := []events.Event{acked(1), ev(2), acked(3)}
	f := &syncCheck{File: w.f.(*os.File), t: t, acks: []*events.Ack{batch[0].Ack, batch[2].Ack}}
	w.f = f

	w.HandleBatch(batch)
	if err := answer(t, batch[0]); err != nil {
		t.Errorf("Ack = %v", err)
	}
	if err := answer(t, batch[2]); err != nil {
		t.Errorf("Ack = %v", err)
	}
	if f.syncs != 1 {
		t.Errorf("%d syncs for one batch", f.syncs)
	}
	w.Close()
	if rep, err := Verify(path); err != nil || rep.Records != 3 {
		t.Errorf("log = %+v, %v", rep, err)
	}
}

func TestAFailedBatchIsAnsweredWithTheErrorAndPrinted(t *testing.T) {
	lost := captureLost(t)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	w, _ := Open(path)
	w.Handle(ev(1))
	w.f = &flakyFile{File: w.f.(*os.File), failWrites: 1}

	batch := []events.Event{acked(2), ev(3)}
	w.HandleBatch(batch)
	if err := answer(t, batch[0]); err == nil || !strings.Contains(err.Error(), "no space left") {
		t.Errorf("Ack = %v, want the write error", err)
	}
	got := lost.lines(t)
	if len(got) != 2 || got[0].Event.Seq != 2 || got[1].Event.Seq != 3 || got[0].Audit != "not_recorded" {
		t.Fatalf("printed = %+v; want both events of the failed batch", got)
	}

	next := acked(4)
	w.Handle(next)
	if err := answer(t, next); err != nil {
		t.Errorf("Ack after a rolled-back write = %v", err)
	}
	w.Close()
}

func TestABrokenOrClosedWriterAnswersAtOnce(t *testing.T) {
	lost := captureLost(t)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	w, _ := Open(path)
	w.f = &flakyFile{File: w.f.(*os.File), failWrites: 1, failTruncate: true}
	w.Handle(ev(1))
	if !errors.Is(w.Err(), ErrBroken) {
		t.Fatalf("Err = %v", w.Err())
	}

	e := acked(2)
	w.Handle(e)
	if err := answer(t, e); !errors.Is(err, ErrBroken) {
		t.Errorf("broken writer: Ack = %v", err)
	}
	w.Close()
	e = acked(3)
	w.Handle(e)
	if err := answer(t, e); !errors.Is(err, ErrClosed) {
		t.Errorf("closed writer: Ack = %v", err)
	}
	if n := len(lost.lines(t)); n != 3 {
		t.Errorf("%d events printed, want 3", n)
	}
}

func TestTheFilterNeverDropsAnAcknowledgedEvent(t *testing.T) {
	f := Filter(false)
	listed := events.Event{Type: events.FileListed, Outcome: events.OutcomeOK}
	if f(listed) {
		t.Fatal("a successful listing passed without -audit-listings")
	}
	listed.Ack = events.NewAck()
	if !f(listed) {
		t.Error("an acknowledged event was dropped")
	}
}

func TestTheCoalescerPassesAcknowledgedEvents(t *testing.T) {
	lost := captureLost(t)
	c, path := newCoalescer(t, time.Minute)
	first := dl(0, "anon", "10.0.0.1:1", "a", "bytes=0-", 5, events.OutcomeOK)
	second := dl(1, "anon", "10.0.0.1:1", "a", "bytes=1-", 4, events.OutcomeOK)
	second.Ack = events.NewAck()
	c.HandleBatch([]events.Event{first, second})
	if err := answer(t, second); err != nil {
		t.Errorf("Ack = %v", err)
	}
	c.Close()
	if evs := readBack(t, path); len(evs) != 2 || evs[1].Range != "bytes=1-" {
		t.Errorf("records = %+v", evs)
	}

	late := acked(9)
	c.HandleBatch([]events.Event{late})
	if err := answer(t, late); !errors.Is(err, ErrClosed) {
		t.Errorf("Ack after Close = %v", err)
	}
	if got := lost.lines(t); len(got) != 1 || got[0].Event.Seq != 9 {
		t.Errorf("printed = %+v", got)
	}
}

func TestTheGuardTripsOnceAndKeepsTheFirstReason(t *testing.T) {
	var logErr error
	g := NewGuard(func() error { return logErr })
	if g.Err() != nil {
		t.Fatal("tripped from the start")
	}
	logErr = errors.New("disk full")
	if err := g.Err(); err != logErr {
		t.Fatalf("Err = %v, want the log's error", err)
	}
	g.Trip(errors.New("later"))
	logErr = nil
	if err := g.Err(); err == nil || err.Error() != "disk full" {
		t.Errorf("Err = %v, want the first reason kept until restart", err)
	}

	g = NewGuard(nil)
	first := errors.New("first")
	g.Trip(first)
	g.Trip(errors.New("second"))
	if g.Err() != first {
		t.Errorf("Err = %v", g.Err())
	}
}

// stack is a bus, a coalescer and a writer wired as the server wires them,
// with the recorder's timeout as the stall limit.
type stack struct {
	bus  *events.Bus
	w    *Writer
	g    *Guard
	r    *Recorder
	path string
}

func newStack(t *testing.T, opts RecorderOptions) *stack {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	w, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	c := NewCoalescer(w, time.Minute, time.Minute)
	bus := events.New()
	g := NewGuard(w.Err)
	Subscribe(bus, c, g, false, opts.Timeout)
	s := &stack{bus: bus, w: w, g: g, r: NewRecorder(bus, g, opts), path: path}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		bus.Close(ctx)
		c.Close()
		w.Close()
	})
	return s
}

var bg = context.Background()

func change(path string) events.Event {
	return events.Event{Type: events.FileUploaded, Outcome: events.OutcomeOK, Path: path}
}

func TestAChangeReturnsOnceItsRecordIsOnDisk(t *testing.T) {
	s := newStack(t, RecorderOptions{Wait: true, Timeout: 10 * time.Second})
	if err := s.r.Allow(); err != nil {
		t.Fatalf("Allow = %v", err)
	}
	if err := s.r.Record(bg, change("a"), change("b")); err != nil {
		t.Fatalf("Record = %v", err)
	}
	if rep, err := Verify(s.path); err != nil || rep.Records != 2 {
		t.Errorf("after Record returned: %+v, %v; want both records on disk", rep, err)
	}
}

func TestAnInjectedWriteErrorIsNotRecordedAndPausesChanges(t *testing.T) {
	lost := captureLost(t)
	s := newStack(t, RecorderOptions{Wait: true, Timeout: 10 * time.Second})
	s.w.mu.Lock()
	s.w.f = &flakyFile{File: s.w.f.(*os.File), failWrites: 1}
	s.w.mu.Unlock()

	err := s.r.Record(bg, change("a"))
	if !errors.Is(err, events.ErrNotRecorded) || !events.IsUnrecorded(err) {
		t.Fatalf("Record = %v, want ErrNotRecorded", err)
	}
	if got := lost.lines(t); len(got) != 1 || got[0].Event.Path != "a" || got[0].Audit != "not_recorded" {
		t.Errorf("printed = %+v", got)
	}
	if err := s.r.Allow(); !errors.Is(err, events.ErrChangesPaused) || events.IsUnrecorded(err) || !s.r.Paused() {
		t.Errorf("Allow after the failure = %v, Paused = %v", err, s.r.Paused())
	}

	// The writer recovered, but changes stay paused until a restart.
	if err := s.r.Record(bg, change("b")); err != nil {
		t.Errorf("Record of a change made before the guard tripped = %v", err)
	}
	if !s.r.Paused() {
		t.Error("the guard reset itself")
	}
}

func TestAWriterThatStoppedAnswersAtOnce(t *testing.T) {
	captureLost(t)
	s := newStack(t, RecorderOptions{Wait: true, Timeout: time.Minute})
	s.w.mu.Lock()
	s.w.f = &flakyFile{File: s.w.f.(*os.File), failWrites: 1, failTruncate: true}
	s.w.mu.Unlock()
	s.r.Record(bg, change("a"))

	start := time.Now()
	err := s.r.Record(bg, change("b"))
	if !errors.Is(err, events.ErrNotRecorded) || !errors.Is(err, ErrBroken) {
		t.Errorf("Record on a broken writer = %v", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("a broken writer made the change wait %s", d)
	}
}

// silent is a bus nobody answers.
type silent struct{ evs []events.Event }

func (s *silent) Publish(ev events.Event) { s.evs = append(s.evs, ev) }

func TestARecordNotConfirmedInTimeIsReportedAndPausesChanges(t *testing.T) {
	lost := captureLost(t)
	g := NewGuard(nil)
	r := NewRecorder(&silent{}, g, RecorderOptions{Wait: true, Timeout: 50 * time.Millisecond})

	err := r.Record(bg, change("a"))
	if !errors.Is(err, events.ErrNotConfirmed) || errors.Is(err, events.ErrNotRecorded) {
		t.Fatalf("Record = %v, want ErrNotConfirmed only", err)
	}
	if got := lost.lines(t); len(got) != 1 || got[0].Audit != "unconfirmed" || got[0].Event.Path != "a" || got[0].Event.Time.IsZero() {
		t.Errorf("printed = %+v", got)
	}
	if !r.Paused() {
		t.Error("a timeout didn't pause changes")
	}
}

func TestProtectiveChangesDontWaitWhileChangesArePaused(t *testing.T) {
	captureLost(t)
	g := NewGuard(nil)
	short := NewRecorder(&silent{}, g, RecorderOptions{Wait: true, Timeout: 50 * time.Millisecond})
	if err := short.RecordProtective(bg, change("before")); !errors.Is(err, events.ErrNotConfirmed) {
		t.Fatalf("protective change while not paused = %v; it waits like any other", err)
	}

	bus := &silent{}
	r := NewRecorder(bus, g, RecorderOptions{Wait: true, Timeout: time.Minute})
	start := time.Now()
	if err := r.RecordProtective(bg, change("after")); err != nil {
		t.Errorf("protective change while paused = %v", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("waited %s", d)
	}
	if len(bus.evs) != 1 || bus.evs[0].Path != "after" {
		t.Errorf("published = %+v", bus.evs)
	}
}

func TestWithoutWaitingAChangeIsOnlyPublished(t *testing.T) {
	bus := &silent{}
	r := NewRecorder(bus, NewGuard(nil), RecorderOptions{Wait: false, Timeout: time.Minute})
	if err := r.Record(bg, change("a")); err != nil || len(bus.evs) != 1 || bus.evs[0].Ack != nil {
		t.Errorf("Record = %v, published %+v", err, bus.evs)
	}
}

func TestFailOpenKeepsAcceptingChanges(t *testing.T) {
	g := NewGuard(nil)
	g.Trip(errors.New("disk full"))
	r := NewRecorder(&silent{}, g, RecorderOptions{FailOpen: true})
	if err := r.Allow(); err != nil || r.Paused() {
		t.Errorf("Allow = %v, Paused = %v", err, r.Paused())
	}
	closed := NewRecorder(&silent{}, g, RecorderOptions{})
	if err := closed.Allow(); !errors.Is(err, events.ErrChangesPaused) || !strings.Contains(err.Error(), "disk full") {
		t.Errorf("Allow = %v", err)
	}
}

// stuckSync blocks every fsync until release is closed, as a hung disk does.
type stuckSync struct {
	*os.File
	release chan struct{}
}

func (f *stuckSync) Sync() error {
	<-f.release
	return f.File.Sync()
}

func TestAStuckDiskDoesntHoldChangesPastTheirTimeout(t *testing.T) {
	captureLost(t)
	s := newStack(t, RecorderOptions{Wait: true, Timeout: 200 * time.Millisecond})
	release := make(chan struct{})
	s.w.mu.Lock()
	s.w.f = &stuckSync{File: s.w.f.(*os.File), release: release}
	s.w.mu.Unlock()
	defer close(release)

	done := make(chan error, 2)
	go func() { done <- s.r.Record(bg, change("a")) }()
	time.Sleep(50 * time.Millisecond)
	go func() { done <- s.r.Allow() }()
	for range 2 {
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, events.ErrNotConfirmed) {
				t.Errorf("got %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("a change or Allow waited for the stuck fsync")
		}
	}
	if !s.r.Paused() {
		t.Error("a record not confirmed in time didn't pause changes")
	}
}

// scripted answers the Acks of the events published to it, in turn, with
// the errors it was given.
type scripted struct{ answers []error }

func (p *scripted) Publish(ev events.Event) {
	if len(p.answers) > 0 {
		ev.Ack.Done(p.answers[0])
		p.answers = p.answers[1:]
	}
}

func TestEveryEventOfAChangeIsWaitedFor(t *testing.T) {
	r := NewRecorder(&scripted{answers: []error{nil, errors.New("disk full")}}, NewGuard(nil), RecorderOptions{Wait: true, Timeout: time.Second})
	if err := r.Record(bg, change("a"), change("b")); !errors.Is(err, events.ErrNotRecorded) {
		t.Errorf("Record = %v; the second event's record failed", err)
	}
}

func TestARequestWaitsOnceForAllItsRecords(t *testing.T) {
	captureLost(t)
	r := NewRecorder(&silent{}, NewGuard(nil), RecorderOptions{Wait: true, Timeout: 300 * time.Millisecond})
	ctx := events.WithWaitBudget(bg)
	start := time.Now()
	for range 3 {
		if err := r.Record(ctx, change("a")); !errors.Is(err, events.ErrNotConfirmed) {
			t.Fatalf("Record = %v", err)
		}
	}
	if d := time.Since(start); d > 600*time.Millisecond {
		t.Errorf("three records of one request waited %s; their wait is shared", d)
	}
}

// slowBus takes delay to accept each event, as a bus with full queues does.
type slowBus struct{ delay time.Duration }

func (b slowBus) Publish(events.Event) { time.Sleep(b.delay) }

func TestTheWaitIncludesTheTimeToPublish(t *testing.T) {
	captureLost(t)
	r := NewRecorder(slowBus{500 * time.Millisecond}, NewGuard(nil), RecorderOptions{Wait: true, Timeout: 500 * time.Millisecond})
	start := time.Now()
	if err := r.Record(bg, change("a")); !errors.Is(err, events.ErrNotConfirmed) {
		t.Fatalf("Record = %v", err)
	}
	if d := time.Since(start); d > 800*time.Millisecond {
		t.Errorf("Record took %s with a timeout of 500ms", d)
	}
}

func TestWorkBetweenRecordsDoesntUseUpTheWait(t *testing.T) {
	s := newStack(t, RecorderOptions{Wait: true, Timeout: 300 * time.Millisecond})
	ctx := events.WithWaitBudget(bg)
	if err := s.r.Record(ctx, change("a")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(400 * time.Millisecond)
	if err := s.r.Record(ctx, change("b")); err != nil || s.r.Paused() {
		t.Errorf("second record of a request on a healthy log = %v, paused %v", err, s.r.Paused())
	}
}

func TestAStalledLogPausesChanges(t *testing.T) {
	captureLost(t)
	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)
	s := newStack(t, RecorderOptions{Wait: true, Timeout: 200 * time.Millisecond})
	release := make(chan struct{})
	s.w.mu.Lock()
	s.w.f = &stuckSync{File: s.w.f.(*os.File), release: release}
	s.w.mu.Unlock()
	defer close(release)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range 3000 {
			s.bus.Publish(events.Event{Type: events.FileDownloaded, Outcome: events.OutcomeOK, Path: fmt.Sprint(i)})
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("reads waited for the stalled log")
	}
	if err := s.r.Allow(); !errors.Is(err, events.ErrChangesPaused) || !strings.Contains(err.Error(), events.ErrStalled.Error()) {
		t.Errorf("Allow after the log stalled = %v", err)
	}
}
