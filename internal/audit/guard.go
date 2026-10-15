package audit

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/nobletk/gocalbox/internal/events"
)

// Guard reports whether changes may proceed. It trips at the audit log's
// first failure and stays tripped until restart, so a person has to look.
type Guard struct {
	logErr func() error

	mu     sync.Mutex
	reason error
}

// NewGuard returns a guard that also trips once logErr reports an error.
func NewGuard(logErr func() error) *Guard { return &Guard{logErr: logErr} }

// Trip pauses changes for reason; only the first reason is kept.
func (g *Guard) Trip(reason error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.trip(reason)
}

func (g *Guard) trip(reason error) {
	if g.reason == nil && reason != nil {
		g.reason = reason
		log.Printf("AUDIT ERROR: changes are paused until the server restarts: %v", reason)
	}
}

// Err returns why changes are paused, or nil.
func (g *Guard) Err() error {
	if g.logErr != nil {
		if err := g.logErr(); err != nil {
			g.Trip(err)
		}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.reason
}

type Publisher interface {
	Publish(events.Event)
}

type RecorderOptions struct {
	// Wait makes a change reply only once its record is on disk.
	Wait bool
	// Timeout bounds the wait; a record not confirmed by then trips the
	// guard all the same.
	Timeout time.Duration
	// FailOpen lets changes proceed after the log has failed.
	FailOpen bool
}

// Recorder refuses changes once the audit log has failed, and makes a change
// wait until its record is on disk.
type Recorder struct {
	pub   Publisher
	guard *Guard
	opts  RecorderOptions
	now   func() time.Time
}

func NewRecorder(pub Publisher, guard *Guard, opts RecorderOptions) *Recorder {
	return &Recorder{pub: pub, guard: guard, opts: opts, now: func() time.Time { return time.Now().UTC() }}
}

// Paused reports whether changes are refused.
func (r *Recorder) Paused() bool { return !r.opts.FailOpen && r.guard.Err() != nil }

func (r *Recorder) Allow() error {
	if r.opts.FailOpen {
		return nil
	}
	if err := r.guard.Err(); err != nil {
		// The reason is not wrapped: a paused change made nothing, even
		// when what paused changes was a record that failed.
		return fmt.Errorf("%w: %v", events.ErrChangesPaused, err)
	}
	return nil
}

func (r *Recorder) Record(ctx context.Context, evs ...events.Event) error {
	return r.record(ctx, evs, false)
}

func (r *Recorder) RecordProtective(ctx context.Context, evs ...events.Event) error {
	return r.record(ctx, evs, true)
}

func (r *Recorder) record(ctx context.Context, evs []events.Event, protective bool) error {
	if !r.opts.Wait || (protective && r.Paused()) {
		for _, ev := range evs {
			r.pub.Publish(ev)
		}
		return nil
	}
	start := time.Now()
	deadline := start.Add(events.WaitLeft(ctx, r.opts.Timeout))
	defer func() { events.Waited(ctx, time.Since(start)) }()
	acks := make([]*events.Ack, len(evs))
	for i := range evs {
		acks[i] = events.NewAck()
		evs[i].Ack = acks[i]
		if evs[i].Time.IsZero() {
			evs[i].Time = r.now()
		}
		r.pub.Publish(evs[i])
	}
	var first error
	for i, ack := range acks {
		done, err := ack.Wait(time.Until(deadline))
		switch {
		case !done:
			// The record may still be written, so the event is marked as
			// unconfirmed rather than lost.
			err = fmt.Errorf("%w within %s", events.ErrNotConfirmed, r.opts.Timeout)
			events.PrintLost(evs[i], events.LostUnconfirmed, err)
		case err != nil:
			err = fmt.Errorf("%w: %w", events.ErrNotRecorded, err)
		}
		if first == nil {
			first = err
		}
	}
	if first != nil {
		r.guard.Trip(first)
	}
	return first
}
