package events

import (
	"context"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// Handler must not Publish to the same bus: with full queues that deadlocks.
type Handler func(Event)

// BatchHandler must not retain the slice; it is reused after the call.
type BatchHandler func([]Event)

type Mode int

const (
	Block Mode = iota
	Drop
)

const (
	defaultBuffer   = 256
	defaultQueue    = 1024
	defaultMaxBatch = 256
)

type Options struct {
	Buffer int  // 256 default
	Mode   Mode // Block (default) or Drop
	// Filter is called only from the dispatcher goroutine, so it may keep
	// state without locking.
	Filter   func(Event) bool
	MaxBatch int // 256 default
	// StallAfter, for the Block subscriber that answers Acks, is how long it
	// may take no event before it counts as stalled. Until it takes one
	// again, the events it has no room for are printed on the console and
	// their Acks answered with ErrStalled, so that publishers don't wait for
	// it. 0 waits for ever.
	StallAfter time.Duration
	// OnStall is called each time the subscriber stalls. It runs on the
	// dispatcher, so it must neither block nor publish.
	OnStall func(error)
}

type Bus struct {
	in    chan Event
	abort chan struct{}
	now   func() time.Time

	mu         sync.Mutex
	closed     bool
	publishers sync.WaitGroup
	abortOnce  sync.Once

	subs           atomic.Pointer[[]*subscriber]
	published      atomic.Uint64
	dispatcherDone chan struct{}
}

type subscriber struct {
	name      string
	handle    BatchHandler
	ch        chan Event
	mode      Mode
	filter    func(Event) bool
	maxBatch  int
	stall     time.Duration
	onStall   func(error)
	stalled   bool // used by the dispatcher only
	delivered atomic.Uint64
	dropped   atomic.Uint64
	done      chan struct{}
}

func New() *Bus { return NewWithQueue(defaultQueue) }

// NewWithQueue sets the length of the shared publish queue.
func NewWithQueue(n int) *Bus {
	if n < 1 {
		n = 1
	}
	b := &Bus{
		in:             make(chan Event, n),
		abort:          make(chan struct{}),
		now:            func() time.Time { return time.Now().UTC() },
		dispatcherDone: make(chan struct{}),
	}
	b.subs.Store(&[]*subscriber{})
	go b.dispatch()
	return b
}

func (b *Bus) Subscribe(name string, h Handler, opts Options) {
	opts.MaxBatch = 1
	b.add(name, func(evs []Event) {
		for _, ev := range evs {
			h(ev)
		}
	}, opts)
}

func (b *Bus) SubscribeBatch(name string, h BatchHandler, opts Options) {
	if opts.MaxBatch <= 0 {
		opts.MaxBatch = defaultMaxBatch
	}
	b.add(name, h, opts)
}

func (b *Bus) add(name string, h BatchHandler, opts Options) {
	if opts.Buffer <= 0 {
		opts.Buffer = defaultBuffer
	}
	s := &subscriber{
		name:     name,
		handle:   h,
		ch:       make(chan Event, opts.Buffer),
		mode:     opts.Mode,
		filter:   opts.Filter,
		maxBatch: opts.MaxBatch,
		stall:    opts.StallAfter,
		onStall:  opts.OnStall,
		done:     make(chan struct{}),
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	old := *b.subs.Load()
	next := append(append(make([]*subscriber, 0, len(old)+1), old...), s)
	b.subs.Store(&next)
	go s.run()
}

// Publish queues ev for every subscriber. An event published after Close
// reaches none of them: it is printed on the console and its Ack answered.
func (b *Bus) Publish(ev Event) {
	if ev.Time.IsZero() {
		ev.Time = b.now()
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		lose(ev, ErrClosed)
		return
	}
	b.publishers.Add(1)
	b.mu.Unlock()
	defer b.publishers.Done()

	select {
	case b.in <- ev:
	case <-b.abort:
		lose(ev, ErrClosed)
	}
}

func (b *Bus) dispatch() {
	defer close(b.dispatcherDone)
	defer func() {
		for _, s := range *b.subs.Load() {
			close(s.ch)
		}
	}()
	defer func() {
		select {
		case <-b.abort:
			b.loseQueued()
		default:
		}
	}()

	var seq uint64
	for {
		var ev Event
		select {
		case e, ok := <-b.in:
			if !ok {
				return
			}
			ev = e
		case <-b.abort:
			return
		}
		seq++
		ev.Seq = seq
		b.published.Store(seq)
		for _, s := range *b.subs.Load() {
			if s.filter != nil && !s.filter(ev) {
				continue
			}
			if s.mode == Drop {
				select {
				case s.ch <- ev:
				default:
					s.dropped.Add(1)
				}
				continue
			}
			if !b.offer(s, ev) {
				if s.stall > 0 {
					lose(ev, ErrClosed)
				}
				return
			}
		}
	}
}

// offer hands ev to the Block subscriber s, waiting for room unless s has
// stalled. It returns false once the bus gives up.
func (b *Bus) offer(s *subscriber, ev Event) bool {
	if s.stall == 0 {
		select {
		case s.ch <- ev:
			return true
		case <-b.abort:
			return false
		}
	}
	select {
	case s.ch <- ev:
		s.stalled = false
		return true
	default:
	}
	if s.stalled {
		s.dropped.Add(1)
		lose(ev, ErrStalled)
		return true
	}
	t := time.NewTimer(s.stall)
	defer t.Stop()
	select {
	case s.ch <- ev:
	case <-t.C:
		s.stalled = true
		s.dropped.Add(1)
		log.Printf("events: subscriber %q took no event for %s; until it takes one, events it has no room for are printed instead", s.name, s.stall)
		if s.onStall != nil {
			s.onStall(fmt.Errorf("%w for %s", ErrStalled, s.stall))
		}
		lose(ev, ErrStalled)
	case <-b.abort:
		return false
	}
	return true
}

// loseQueued prints the events left in the queue when the bus gives up.
func (b *Bus) loseQueued() {
	for {
		select {
		case ev, ok := <-b.in:
			if !ok {
				return
			}
			lose(ev, ErrClosed)
		default:
			return
		}
	}
}

func (b *Bus) Close(ctx context.Context) error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	b.mu.Unlock()

	if err := wait(ctx, waitGroupDone(&b.publishers)); err != nil {
		b.giveUp()
		return err
	}
	close(b.in)

	if err := wait(ctx, b.dispatcherDone); err != nil {
		b.giveUp()
		return err
	}
	for _, s := range *b.subs.Load() {
		if err := wait(ctx, s.done); err != nil {
			b.giveUp()
			return err
		}
	}
	return nil
}

func (b *Bus) giveUp() { b.abortOnce.Do(func() { close(b.abort) }) }

func wait(ctx context.Context, done <-chan struct{}) error {
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func waitGroupDone(wg *sync.WaitGroup) <-chan struct{} {
	ch := make(chan struct{})
	go func() { wg.Wait(); close(ch) }()
	return ch
}

// Dropped returns how many events subscribers named name have discarded.
func (b *Bus) Dropped(name string) uint64 {
	var n uint64
	for _, s := range *b.subs.Load() {
		if s.name == name {
			n += s.dropped.Load()
		}
	}
	return n
}

type SubscriberStats struct {
	Name      string
	Queued    int
	Delivered uint64
	Dropped   uint64
}

type Stats struct {
	Published   uint64
	Pending     int
	Subscribers []SubscriberStats
}

func (b *Bus) Stats() Stats {
	st := Stats{Published: b.published.Load(), Pending: len(b.in)}
	for _, s := range *b.subs.Load() {
		st.Subscribers = append(st.Subscribers, SubscriberStats{
			Name:      s.name,
			Queued:    len(s.ch),
			Delivered: s.delivered.Load(),
			Dropped:   s.dropped.Load(),
		})
	}
	return st
}

func (s *subscriber) run() {
	defer close(s.done)
	batch := make([]Event, 0, s.maxBatch)
	for ev := range s.ch {
		batch = append(batch[:0], ev)
	fill:
		for len(batch) < s.maxBatch {
			select {
			case ev, ok := <-s.ch:
				if !ok {
					break fill
				}
				batch = append(batch, ev)
			default:
				break fill
			}
		}
		s.deliver(batch)
	}
}

func (s *subscriber) deliver(batch []Event) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("events: subscriber %q panicked on %s seq=%d: %v", s.name, batch[0].Type, batch[0].Seq, r)
		}
		s.delivered.Add(uint64(len(batch)))
	}()
	s.handle(batch)
}
