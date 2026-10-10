package audit

import (
	"net"
	"sync"
	"time"

	"github.com/nobletk/gocalbox/internal/events"
)

// Coalescer sits between the bus and a Writer and collapses ranged
// downloads, of which media players issue one per seek, abandoning the
// previous one.
type Coalescer struct {
	w      *Writer
	window time.Duration
	now    func() time.Time

	mu       sync.Mutex
	sessions map[sessionKey]*session
	closed   bool

	stop chan struct{}
	done chan struct{}
}

type sessionKey struct{ actor, ip, file string }

type session struct {
	start   time.Time
	summary events.Event
}

func NewCoalescer(w *Writer, window time.Duration) *Coalescer {
	c := &Coalescer{
		w: w, window: window,
		now:      func() time.Time { return time.Now().UTC() },
		sessions: map[sessionKey]*session{},
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	go c.loop(min(max(window/2, time.Second), 30*time.Second))
	return c
}

func (c *Coalescer) loop(every time.Duration) {
	defer close(c.done)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			c.flushExpired(c.now())
		case <-c.stop:
			return
		}
	}
}

func (c *Coalescer) HandleBatch(evs []events.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}

	out := make([]events.Event, 0, len(evs))
	for _, ev := range evs {
		if !collapsible(ev) {
			out = append(out, ev)
			continue
		}
		k := sessionKey{ev.Actor.ID, clientIP(ev.Actor.RemoteAddr), ev.Resolved}
		if s, ok := c.sessions[k]; ok {
			if ev.Time.Sub(s.start) < c.window {
				s.add(ev)
				continue
			}
			out = appendSummary(out, s)
		}
		out = append(out, ev)
		c.sessions[k] = &session{start: ev.Time, summary: summaryOf(ev)}
	}
	c.w.HandleBatch(out)
}

func (c *Coalescer) flushExpired(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []events.Event
	for k, s := range c.sessions {
		if now.Sub(s.start) >= c.window {
			out = appendSummary(out, s)
			delete(c.sessions, k)
		}
	}
	c.w.HandleBatch(out)
}

func (c *Coalescer) Close() {
	close(c.stop)
	<-c.done

	c.mu.Lock()
	defer c.mu.Unlock()
	var out []events.Event
	for _, s := range c.sessions {
		out = appendSummary(out, s)
	}
	clear(c.sessions)
	c.closed = true
	c.w.HandleBatch(out)
}

func collapsible(ev events.Event) bool {
	return ev.Type == events.FileDownloaded && ev.Range != "" &&
		(ev.Outcome == events.OutcomeOK || ev.Outcome == events.OutcomeAborted)
}

func summaryOf(first events.Event) events.Event {
	return events.Event{
		Type:     events.FileReadSummary,
		Actor:    first.Actor,
		Outcome:  events.OutcomeOK,
		Path:     first.Path,
		Resolved: first.Resolved,
	}
}

func (s *session) add(ev events.Event) {
	if s.summary.Count == 0 {
		s.summary.Since = ev.Time
	}
	s.summary.Count++
	if ev.Outcome == events.OutcomeAborted {
		s.summary.Aborted++
	}
	s.summary.Size += ev.Size
	s.summary.Time = ev.Time
	s.summary.RequestID = ev.RequestID // the last one
}

func appendSummary(out []events.Event, s *session) []events.Event {
	if s.summary.Count == 0 {
		return out
	}
	return append(out, s.summary)
}

func clientIP(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}
