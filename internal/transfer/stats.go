package transfer

import (
	"sync/atomic"
	"time"
)

// Stats is what the engine is doing, and what it has done since it started.
// Admission refusals are counted here; the audit log doesn't record them.
type Stats struct {
	Sessions      int // open: receiving or being completed
	PartsInFlight int // parts being received, duplicates included
	Waiting       int // parts waiting for a server-wide slot

	PartsReceived int64 // parts accepted, each counted once
	BytesReceived int64 // the bytes of those parts
	Duplicates    int64 // parts sent again with the SHA-256 they were accepted with
	Completed     int64 // files placed by Complete

	Busy            int64 // ErrBusy: the server-wide limits on parts in flight and open sessions
	TooManyRequests int64 // ErrTooManyRequests: a user's parts in flight or waiting
	TooManyUploads  int64 // ErrTooManyUploads: a user's open sessions

	Waited       int64         // parts that waited for a slot, however the wait ended
	WaitTime     time.Duration // their waits together
	WaitTimeouts int64         // waits that ran out, answered ErrBusy (counted in Busy)
	QueueFull    int64         // parts refused because the queue was full (counted in Busy)
}

type counters struct {
	parts, bytes, duplicates, completed       atomic.Int64
	busy, tooManyRequests, tooManyUploads     atomic.Int64
	waited, waitTime, waitTimeouts, queueFull atomic.Int64
}

// Stats returns the engine's counters.
func (e *Engine) Stats() Stats {
	e.mu.Lock()
	sessions, inflight, waiting := e.openTotal, e.slots, e.queue.Len()
	e.mu.Unlock()
	c := &e.counters
	return Stats{
		Sessions:        sessions,
		PartsInFlight:   inflight,
		Waiting:         waiting,
		PartsReceived:   c.parts.Load(),
		BytesReceived:   c.bytes.Load(),
		Duplicates:      c.duplicates.Load(),
		Completed:       c.completed.Load(),
		Busy:            c.busy.Load(),
		TooManyRequests: c.tooManyRequests.Load(),
		TooManyUploads:  c.tooManyUploads.Load(),
		Waited:          c.waited.Load(),
		WaitTime:        time.Duration(c.waitTime.Load()),
		WaitTimeouts:    c.waitTimeouts.Load(),
		QueueFull:       c.queueFull.Load(),
	}
}
