package transfer

import "sync/atomic"

// Stats is what the engine is doing, and what it has done since it started.
// Admission refusals are counted here; the audit log doesn't record them.
type Stats struct {
	Sessions      int // open: receiving or being completed
	PartsInFlight int // parts being received, duplicates included

	PartsReceived int64 // parts accepted, each counted once
	BytesReceived int64 // the bytes of those parts
	Duplicates    int64 // parts sent again with the SHA-256 they were accepted with
	Completed     int64 // files placed by Complete

	Busy            int64 // ErrBusy: the server-wide limits on parts in flight and open sessions
	TooManyRequests int64 // ErrTooManyRequests: a user's parts in flight
	TooManyUploads  int64 // ErrTooManyUploads: a user's open sessions
}

type counters struct {
	parts, bytes, duplicates, completed   atomic.Int64
	busy, tooManyRequests, tooManyUploads atomic.Int64
}

// Stats returns the engine's counters.
func (e *Engine) Stats() Stats {
	e.mu.Lock()
	sessions, inflight := e.openTotal, len(e.inflight)
	e.mu.Unlock()
	c := &e.counters
	return Stats{
		Sessions:        sessions,
		PartsInFlight:   inflight,
		PartsReceived:   c.parts.Load(),
		BytesReceived:   c.bytes.Load(),
		Duplicates:      c.duplicates.Load(),
		Completed:       c.completed.Load(),
		Busy:            c.busy.Load(),
		TooManyRequests: c.tooManyRequests.Load(),
		TooManyUploads:  c.tooManyUploads.Load(),
	}
}
