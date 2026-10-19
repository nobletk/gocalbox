package events

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// lostLines collects what PrintLost writes during the test.
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
	Audit string `json:"audit"`
	Error string `json:"error"`
	Event Event  `json:"event"`
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
	t.Cleanup(SetLostOutput(l))
	return l
}

func TestAckKeepsTheFirstAnswer(t *testing.T) {
	a := NewAck()
	if done, _ := a.Wait(time.Millisecond); done {
		t.Fatal("answered before Done")
	}
	boom := errors.New("boom")
	a.Done(boom)
	a.Done(nil)
	if done, err := a.Wait(0); !done || err != boom {
		t.Errorf("Wait = %v, %v; want the first answer", done, err)
	}
	var none *Ack
	none.Done(nil) // Done is called on events that carry no Ack
}

func TestAckWaitReturnsWhenAnswered(t *testing.T) {
	a := NewAck()
	go func() {
		time.Sleep(20 * time.Millisecond)
		a.Done(nil)
	}()
	start := time.Now()
	if done, err := a.Wait(10 * time.Second); !done || err != nil {
		t.Fatalf("Wait = %v, %v", done, err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("Wait took %s", d)
	}
}

func TestPrintLostWritesOneJSONLine(t *testing.T) {
	lost := captureLost(t)
	ev := Event{Seq: 7, Type: FileUploaded, Outcome: OutcomeOK, Path: "a\nb.txt", Ack: NewAck()}
	PrintLost(ev, LostNotRecorded, errors.New("disk full"))
	PrintLost(ev, LostUnconfirmed, ErrNotConfirmed)

	got := lost.lines(t)
	if len(got) != 2 {
		t.Fatalf("%d lines, want 2: %q", len(got), lost.buf.String())
	}
	if got[0].Audit != "not_recorded" || got[0].Error != "disk full" || got[0].Event.Path != "a\nb.txt" || got[0].Event.Seq != 7 {
		t.Errorf("first line = %+v", got[0])
	}
	if got[1].Audit != "unconfirmed" {
		t.Errorf("second line = %+v", got[1])
	}
}

func TestPublishAfterCloseAnswersTheAckAndPrintsTheEvent(t *testing.T) {
	lost := captureLost(t)
	b := New()
	closeBus(t, b)

	ack := NewAck()
	b.Publish(Event{Type: FileDeleted, Path: "x", Ack: ack})
	if done, err := ack.Wait(0); !done || !errors.Is(err, ErrClosed) {
		t.Errorf("Ack after Close = %v, %v; want ErrClosed at once", done, err)
	}
	got := lost.lines(t)
	if len(got) != 1 || got[0].Event.Path != "x" || got[0].Event.Time.IsZero() {
		t.Errorf("printed = %+v", got)
	}
}

func TestEveryRecipientSeesTheSameAck(t *testing.T) {
	b := New()
	var x, y collector
	b.Subscribe("x", x.handle, Options{})
	b.Subscribe("y", y.handle, Options{Mode: Drop})
	ack := NewAck()
	b.Publish(Event{Type: FileDeleted, Ack: ack})
	closeBus(t, b)
	if ex, ey := x.events(), y.events(); len(ex) != 1 || len(ey) != 1 || ex[0].Ack != ack || ey[0].Ack != ack {
		t.Errorf("subscribers got %+v and %+v", ex, ey)
	}
	if done, _ := ack.Wait(0); done {
		t.Error("the bus answered an Ack it delivered")
	}
}

func TestIsUnrecorded(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{nil, false},
		{ErrChangesPaused, false},
		{ErrNotRecorded, true},
		{ErrNotConfirmed, true},
		{errors.Join(errors.New("x"), ErrNotRecorded), true},
	} {
		if got := IsUnrecorded(tc.err); got != tc.want {
			t.Errorf("IsUnrecorded(%v) = %v", tc.err, got)
		}
	}
}

func TestAStalledSubscriberDoesntHoldPublishersUp(t *testing.T) {
	lost := captureLost(t)
	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)

	b := NewWithQueue(4)
	release := make(chan struct{})
	var got collector
	var stalls atomic.Int32
	b.Subscribe("audit", func(ev Event) {
		<-release
		got.handle(ev)
	}, Options{Buffer: 4, StallAfter: 100 * time.Millisecond, OnStall: func(err error) {
		if errors.Is(err, ErrStalled) {
			stalls.Add(1)
		}
	}})

	acks := make([]*Ack, 40)
	finished := make(chan struct{})
	go func() {
		for i := range acks {
			acks[i] = NewAck()
			b.Publish(Event{Type: FileListed, Path: fmt.Sprint(i), Ack: acks[i]})
		}
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("publishers waited for a stalled subscriber")
	}
	stalled := 0
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		stalled = 0
		for _, a := range acks {
			if done, err := a.Wait(0); done && errors.Is(err, ErrStalled) {
				stalled++
			}
		}
		// The stalled handler holds one event and its buffer is full: every
		// other event has had its Ack answered once it was dropped.
		if stalled+b.Stats().Subscribers[0].Queued+1 == len(acks) && b.Dropped("audit") == uint64(stalled) {
			break
		}
	}
	if stalled == 0 || len(lost.lines(t)) != stalled || b.Dropped("audit") != uint64(stalled) {
		t.Errorf("%d answered ErrStalled, %d printed, %d dropped", stalled, len(lost.lines(t)), b.Dropped("audit"))
	}
	if !strings.Contains(logs.String(), "took no event") {
		t.Errorf("stall not logged: %q", logs.String())
	}
	if n := stalls.Load(); n != 1 {
		t.Errorf("OnStall called %d times", n)
	}

	close(release)
	for deadline := time.Now().Add(5 * time.Second); b.Stats().Subscribers[0].Queued > 0 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	ack := NewAck()
	b.Publish(Event{Type: FileDeleted, Path: "after", Ack: ack})
	closeBus(t, b)
	if evs := got.events(); evs[len(evs)-1].Path != "after" {
		t.Error("the subscriber got no events after it took one again")
	}
	if done, _ := ack.Wait(0); done {
		t.Error("an event delivered after the stall was answered by the bus")
	}
}

func TestOnlyWaitingCountsAgainstTheBudget(t *testing.T) {
	ctx := WithWaitBudget(context.Background())
	if left := WaitLeft(ctx, time.Second); left != time.Second {
		t.Fatalf("left at first = %s", left)
	}
	Waited(ctx, 300*time.Millisecond)
	time.Sleep(10 * time.Millisecond)
	if left := WaitLeft(ctx, time.Second); left != 700*time.Millisecond {
		t.Errorf("left after waiting 300ms = %s", left)
	}
	Waited(ctx, time.Hour)
	if left := WaitLeft(ctx, time.Second); left != 0 {
		t.Errorf("left after waiting too long = %s", left)
	}
	Waited(context.Background(), time.Hour)
	if left := WaitLeft(context.Background(), time.Second); left != time.Second {
		t.Errorf("without a budget: %s", left)
	}
}

func TestEventsLeftQueuedWhenCloseGivesUpArePrinted(t *testing.T) {
	lost := captureLost(t)
	b := NewWithQueue(4)
	release := make(chan struct{})
	defer close(release)
	b.Subscribe("audit", func(Event) { <-release }, Options{Buffer: 1, StallAfter: time.Hour})

	acks := make([]*Ack, 7)
	for i := range acks {
		acks[i] = NewAck()
		b.Publish(Event{Type: FileDeleted, Path: fmt.Sprint(i), Ack: acks[i]})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := b.Close(ctx); err == nil {
		t.Fatal("Close finished with a subscriber that never returns")
	}
	for deadline := time.Now().Add(5 * time.Second); len(lost.lines(t)) < 5 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	for _, i := range []int{2, 3, 4, 5, 6} {
		if done, err := acks[i].Wait(0); !done || !errors.Is(err, ErrClosed) {
			t.Errorf("event %d, on its way or queued: %v, %v", i, done, err)
		}
	}
	if got := lost.lines(t); len(got) != 5 || got[0].Event.Path != "2" {
		t.Errorf("printed = %+v", got)
	}
}
