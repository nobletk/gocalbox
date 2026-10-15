package events

import (
	"bytes"
	"context"
	"log"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

type collector struct {
	mu  sync.Mutex
	evs []Event
}

func (c *collector) handle(ev Event) {
	c.mu.Lock()
	c.evs = append(c.evs, ev)
	c.mu.Unlock()
}

func (c *collector) events() []Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Event(nil), c.evs...)
}

func closeBus(t *testing.T, b *Bus) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := b.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestPublishAssignsSeqAndTime(t *testing.T) {
	b := New()
	var c collector
	b.Subscribe("c", c.handle, Options{})

	fixed := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	b.Publish(Event{Type: FileDeleted})
	b.Publish(Event{Type: FileMoved, Time: fixed})
	closeBus(t, b)

	evs := c.events()
	if len(evs) != 2 {
		t.Fatalf("got %d events", len(evs))
	}
	if evs[0].Seq != 1 || evs[1].Seq != 2 {
		t.Errorf("seqs = %d, %d; want 1, 2", evs[0].Seq, evs[1].Seq)
	}
	if evs[0].Time.IsZero() || evs[0].Time.Location() != time.UTC {
		t.Errorf("time not stamped in UTC: %v", evs[0].Time)
	}
	if !evs[1].Time.Equal(fixed) {
		t.Errorf("explicit time overwritten: %v", evs[1].Time)
	}
}

func TestAllSubscribersSeeTheSameOrder(t *testing.T) {
	b := New()
	var a, c collector
	b.Subscribe("a", a.handle, Options{})
	b.Subscribe("c", c.handle, Options{Mode: Drop, Buffer: 10000})

	const publishers, each = 8, 200
	var wg sync.WaitGroup
	for p := 0; p < publishers; p++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < each; i++ {
				b.Publish(Event{Type: FileUploaded})
			}
		}()
	}
	wg.Wait()
	closeBus(t, b)

	for name, c := range map[string]*collector{"a": &a, "c": &c} {
		evs := c.events()
		if len(evs) != publishers*each {
			t.Fatalf("%s got %d events, want %d", name, len(evs), publishers*each)
		}
		for i, ev := range evs {
			if ev.Seq != uint64(i+1) {
				t.Fatalf("%s: event %d has seq %d (out of order)", name, i, ev.Seq)
			}
		}
	}
}

func TestFilter(t *testing.T) {
	b := New()
	var c collector
	b.Subscribe("c", c.handle, Options{Filter: func(ev Event) bool { return ev.Type != FileListed }})

	b.Publish(Event{Type: FileListed})
	b.Publish(Event{Type: FileDeleted})
	b.Publish(Event{Type: FileListed})
	closeBus(t, b)

	evs := c.events()
	if len(evs) != 1 || evs[0].Type != FileDeleted {
		t.Errorf("filter not applied: %+v", evs)
	}
	// Seq is global, so filtered-out events still consume numbers.
	if evs[0].Seq != 2 {
		t.Errorf("seq = %d, want 2", evs[0].Seq)
	}
}

func TestDropModeDoesNotBlockAndCountsDrops(t *testing.T) {
	b := New()
	release := make(chan struct{})
	var got collector
	b.Subscribe("slow", func(ev Event) { <-release; got.handle(ev) }, Options{Mode: Drop, Buffer: 2})
	var fast collector
	b.Subscribe("fast", fast.handle, Options{Buffer: 100})

	done := make(chan struct{})
	go func() {
		for i := 0; i < 50; i++ {
			b.Publish(Event{Type: FileUploaded})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Publish blocked on a Drop-mode subscriber")
	}
	// "fast" is served after "slow" for every event, so once it has all 50
	// the dispatcher has decided about each of them for "slow" too.
	waitFor(t, func() bool { return len(fast.events()) == 50 })

	if d := b.Dropped("slow"); d == 0 || d > 50 {
		t.Errorf("Dropped(slow) = %d, want 1..50", d)
	}
	if d := b.Dropped("fast"); d != 0 {
		t.Errorf("Dropped(fast) = %d, want 0", d)
	}
	close(release)
	closeBus(t, b)

	if n := len(got.events()); n+int(b.Dropped("slow")) != 50 {
		t.Errorf("slow got %d + dropped %d != 50", n, b.Dropped("slow"))
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached in time")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestBlockModeAppliesBackpressureAndLosesNothing(t *testing.T) {
	b := NewWithQueue(1)
	release := make(chan struct{})
	var c collector
	b.Subscribe("audit", func(ev Event) { <-release; c.handle(ev) }, Options{Buffer: 1})

	const total = 10
	published := make(chan int, total)
	go func() {
		for i := 0; i < total; i++ {
			b.Publish(Event{Type: FileDeleted})
			published <- i
		}
	}()

	// Handler, subscriber queue, dispatcher and bus queue hold one event
	// each; the fifth Publish must wait for the handler.
	time.Sleep(100 * time.Millisecond)
	if n := len(published); n >= total {
		t.Fatalf("Publish never blocked (%d published) despite a full Block-mode queue", n)
	}

	close(release)
	for i := 0; i < total; i++ {
		select {
		case <-published:
		case <-time.After(5 * time.Second):
			t.Fatalf("Publish stuck after releasing the subscriber (%d/%d)", i, total)
		}
	}
	closeBus(t, b)
	if n := len(c.events()); n != total {
		t.Errorf("got %d events, want %d (Block mode must not lose events)", n, total)
	}
}

func TestCloseDrainsQueuedEvents(t *testing.T) {
	b := New()
	var c collector
	b.Subscribe("slow", func(ev Event) { time.Sleep(5 * time.Millisecond); c.handle(ev) }, Options{Buffer: 100})

	for i := 0; i < 20; i++ {
		b.Publish(Event{Type: FileUploaded})
	}
	closeBus(t, b)

	if n := len(c.events()); n != 20 {
		t.Errorf("got %d events after Close, want 20", n)
	}
}

func TestCloseHonoursContextDeadline(t *testing.T) {
	b := New()
	stuck := make(chan struct{})
	defer close(stuck)
	b.Subscribe("stuck", func(Event) { <-stuck }, Options{})
	b.Publish(Event{Type: FileUploaded})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := b.Close(ctx); err == nil {
		t.Error("Close returned nil although a subscriber was stuck")
	}
}

// Close must keep its deadline even while publishers wait on a stuck
// subscriber.
func TestCloseReturnsAtDeadlineWhilePublishersAreBlocked(t *testing.T) {
	b := NewWithQueue(1)
	stuck := make(chan struct{})
	defer close(stuck)
	b.Subscribe("audit", func(Event) { <-stuck }, Options{Buffer: 1})

	var publishers sync.WaitGroup
	for i := 0; i < 10; i++ {
		publishers.Add(1)
		go func() { defer publishers.Done(); b.Publish(Event{Type: FileListed}) }()
	}
	time.Sleep(50 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	closed := make(chan error, 1)
	go func() { closed <- b.Close(ctx) }()
	select {
	case err := <-closed:
		if err == nil {
			t.Error("Close reported success although events were stuck")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close ignored its deadline")
	}

	released := make(chan struct{})
	go func() { publishers.Wait(); close(released) }()
	select {
	case <-released:
	case <-time.After(2 * time.Second):
		t.Fatal("blocked publishers were not released when Close gave up")
	}
}

func TestPublishConcurrentWithCloseIsSafe(t *testing.T) {
	captureLost(t)
	for i := 0; i < 50; i++ {
		b := New()
		var c collector
		b.Subscribe("c", c.handle, Options{})
		var wg sync.WaitGroup
		for p := 0; p < 4; p++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 50; j++ {
					b.Publish(Event{Type: FileUploaded})
				}
			}()
		}
		closeBus(t, b)
		wg.Wait()
		for i, ev := range c.events() {
			if ev.Seq != uint64(i+1) {
				t.Fatalf("gap or reorder at %d: seq %d", i, ev.Seq)
			}
		}
	}
}

func TestBatchSubscriberReceivesQueuedEventsTogether(t *testing.T) {
	b := New()
	release := make(chan struct{})
	var mu sync.Mutex
	var sizes []int
	var total int
	b.SubscribeBatch("batch", func(evs []Event) {
		<-release
		mu.Lock()
		sizes = append(sizes, len(evs))
		total += len(evs)
		mu.Unlock()
	}, Options{MaxBatch: 50})

	for i := 0; i < 120; i++ {
		b.Publish(Event{Type: FileUploaded})
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	closeBus(t, b)

	if total != 120 {
		t.Fatalf("delivered %d events, want 120", total)
	}
	if len(sizes) >= 120 {
		t.Errorf("no batching happened: %v", sizes)
	}
	for _, n := range sizes {
		if n > 50 {
			t.Errorf("batch of %d exceeds MaxBatch 50", n)
		}
	}
}

func TestStats(t *testing.T) {
	b := New()
	var c collector
	b.Subscribe("all", c.handle, Options{})
	b.Subscribe("none", c.handle, Options{Filter: func(Event) bool { return false }})
	for i := 0; i < 7; i++ {
		b.Publish(Event{Type: FileDeleted})
	}
	closeBus(t, b)

	st := b.Stats()
	if st.Published != 7 || st.Pending != 0 || len(st.Subscribers) != 2 {
		t.Fatalf("stats = %+v", st)
	}
	if s := st.Subscribers[0]; s.Name != "all" || s.Delivered != 7 || s.Queued != 0 {
		t.Errorf("all = %+v", s)
	}
	if s := st.Subscribers[1]; s.Delivered != 0 {
		t.Errorf("none = %+v", s)
	}
}

func TestPublishAndSubscribeAfterCloseAreNoOps(t *testing.T) {
	captureLost(t)
	b := New()
	var c collector
	b.Subscribe("c", c.handle, Options{})
	closeBus(t, b)

	b.Publish(Event{Type: FileDeleted})
	b.Subscribe("late", c.handle, Options{})
	closeBus(t, b)

	if n := len(c.events()); n != 0 {
		t.Errorf("event delivered after Close: %d", n)
	}
}

func TestPanickingHandlerDoesNotKillSubscriber(t *testing.T) {
	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)

	b := New()
	var c collector
	b.Subscribe("flaky", func(ev Event) {
		if ev.Seq == 1 {
			panic("boom")
		}
		c.handle(ev)
	}, Options{})

	b.Publish(Event{Type: FileDeleted})
	b.Publish(Event{Type: FileDeleted})
	closeBus(t, b)

	if evs := c.events(); len(evs) != 1 || evs[0].Seq != 2 {
		t.Errorf("subscriber did not survive the panic: %+v", evs)
	}
	if !strings.Contains(logs.String(), "panicked") {
		t.Errorf("panic not logged: %q", logs.String())
	}
}

func TestContextHelpers(t *testing.T) {
	ctx := context.Background()
	if a := ActorFrom(ctx); a.ID != AnonymousID {
		t.Errorf("default actor = %+v", a)
	}
	if id := RequestIDFrom(ctx); id != "" {
		t.Errorf("default request id = %q", id)
	}

	ctx = WithActor(ctx, Actor{ID: "alice", Role: "admin", RemoteAddr: "1.2.3.4:5"})
	ctx = WithRequestID(ctx, "abc123")
	if a := ActorFrom(ctx); a.ID != "alice" || a.Role != "admin" || a.RemoteAddr != "1.2.3.4:5" {
		t.Errorf("actor = %+v", a)
	}
	if id := RequestIDFrom(ctx); id != "abc123" {
		t.Errorf("request id = %q", id)
	}
}

func TestLogHandlerFormat(t *testing.T) {
	var logs bytes.Buffer
	log.SetOutput(&logs)
	log.SetFlags(0)
	defer func() { log.SetOutput(os.Stderr); log.SetFlags(log.LstdFlags) }()

	LogHandler(Event{
		Type: FileMoved, Outcome: OutcomeNotFound,
		Actor: Actor{ID: "anonymous", RemoteAddr: "127.0.0.1:5000"}, RequestID: "r1",
		Path: "dog4.jpg", Target: "dog3.jpg", Range: "bytes=0-9", Detail: "not found",
	})
	line := logs.String()
	for _, want := range []string{
		"Event [file.moved]", "outcome=not_found", "actor=anonymous@127.0.0.1:5000",
		"req=r1", `path="dog4.jpg"`, `target="dog3.jpg"`, `range="bytes=0-9"`, `detail="not found"`,
	} {
		if !strings.Contains(line, want) {
			t.Errorf("log line %q is missing %q", line, want)
		}
	}
}
