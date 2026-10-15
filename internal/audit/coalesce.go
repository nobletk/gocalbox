package audit

import (
	"fmt"
	"maps"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/nobletk/gocalbox/internal/events"
)

// LoginWindow is how long the failed logins of one client are collapsed.
const LoginWindow = 5 * time.Minute

// Failed logins are collapsed per address, for each account apart and for
// all other typed names together. Beyond maxAddressesPerAccount addresses
// of an account, or maxOtherPairs pairs of other names, the failures share
// one summary for the account, or one for all other names. A flood of
// attempts with made-up names or changing addresses so adds a bounded
// number of records, and can't push an attack on an account out of view.
const (
	maxAddressesPerAccount = 10
	maxOtherPairs          = 100
)

// Coalescer sits between the bus and a Writer. It collapses ranged
// downloads, of which media players issue one per seek, abandoning the
// previous one, and failed logins, of which a guessing attack makes many.
// The first of each is written at once; the rest within the window become
// one summary record.
type Coalescer struct {
	w           *Writer
	window      time.Duration // ranged downloads; 0 writes each
	loginWindow time.Duration
	now         func() time.Time

	mu       sync.Mutex
	sessions map[sessionKey]*session
	logins   map[loginKey]*session
	open     map[string]int      // open login keys by account; "" for other names
	overflow map[string]*session // by account; "" for other names
	closed   bool

	stop chan struct{}
	done chan struct{}
}

type sessionKey struct{ actor, ip, file string }

// loginKey names a known account by its ID, any other typed name by itself.
type loginKey struct{ account, name, ip string }

type session struct {
	start   time.Time
	summary events.Event
	reasons map[string]int // failed logins only
}

func NewCoalescer(w *Writer, window, loginWindow time.Duration) *Coalescer {
	c := &Coalescer{
		w: w, window: window, loginWindow: loginWindow,
		now:      func() time.Time { return time.Now().UTC() },
		sessions: map[sessionKey]*session{},
		logins:   map[loginKey]*session{},
		open:     map[string]int{},
		overflow: map[string]*session{},
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	shortest := loginWindow
	if window > 0 {
		shortest = min(window, loginWindow)
	}
	go c.loop(min(max(shortest/2, time.Second), 30*time.Second))
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
		lose(evs, ErrClosed)
		return
	}

	out := make([]events.Event, 0, len(evs))
	for _, ev := range evs {
		switch {
		case ev.Ack != nil:
			out = append(out, ev)
		case c.window > 0 && collapsible(ev):
			out = c.addDownload(out, ev)
		case failedLogin(ev):
			out = c.addFailedLogin(out, ev)
		case ev.Type == events.AuthLogin:
			// A success ends the client's window, so its next failure is
			// written at once.
			k := loginKeyOf(ev)
			if s, ok := c.logins[k]; ok {
				out = appendSummary(out, s)
				c.closeLogin(k)
			}
			out = append(out, ev)
		default:
			out = append(out, ev)
		}
	}
	c.w.HandleBatch(out)
}

func (c *Coalescer) addDownload(out []events.Event, ev events.Event) []events.Event {
	k := sessionKey{ev.Actor.ID, clientIP(ev.Actor.RemoteAddr), ev.Resolved}
	if s, ok := c.sessions[k]; ok {
		if ev.Time.Sub(s.start) < c.window {
			s.add(ev)
			return out
		}
		out = appendSummary(out, s)
	}
	c.sessions[k] = &session{start: ev.Time, summary: summaryOf(ev)}
	return append(out, ev)
}

func (c *Coalescer) addFailedLogin(out []events.Event, ev events.Event) []events.Event {
	k := loginKeyOf(ev)
	if s, ok := c.logins[k]; ok {
		if ev.Time.Sub(s.start) < c.loginWindow {
			s.addLogin(ev)
			return out
		}
		out = appendSummary(out, s)
		c.closeLogin(k)
	}
	limit := maxOtherPairs
	if k.account != "" {
		limit = maxAddressesPerAccount
	}
	if c.open[k.account] < limit {
		c.logins[k] = &session{start: ev.Time, summary: events.Event{
			Type: events.AuthLoginSummary, Actor: ev.Actor, Outcome: events.OutcomeDenied, Path: ev.Path, Resolved: ev.Resolved,
		}, reasons: map[string]int{}}
		c.open[k.account]++
		return append(out, ev)
	}
	o := c.overflow[k.account]
	if o != nil && ev.Time.Sub(o.start) >= c.loginWindow {
		out = appendSummary(out, o)
		o = nil
	}
	if o == nil {
		o = &session{start: ev.Time, summary: events.Event{
			Type: events.AuthLoginSummary, Actor: events.Actor{ID: events.AnonymousID}, Outcome: events.OutcomeDenied, Resolved: k.account,
		}, reasons: map[string]int{}}
		if k.account != "" {
			o.summary.Path = ev.Path
		}
		c.overflow[k.account] = o
	}
	o.addLogin(ev)
	return out
}

func (c *Coalescer) closeLogin(k loginKey) {
	delete(c.logins, k)
	if c.open[k.account]--; c.open[k.account] <= 0 {
		delete(c.open, k.account)
	}
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
	for k, s := range c.logins {
		if now.Sub(s.start) >= c.loginWindow {
			out = appendSummary(out, s)
			c.closeLogin(k)
		}
	}
	for k, o := range c.overflow {
		if now.Sub(o.start) >= c.loginWindow {
			out = appendSummary(out, o)
			delete(c.overflow, k)
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
	for _, s := range c.logins {
		out = appendSummary(out, s)
	}
	for _, o := range c.overflow {
		out = appendSummary(out, o)
	}
	clear(c.sessions)
	clear(c.logins)
	clear(c.open)
	clear(c.overflow)
	c.closed = true
	c.w.HandleBatch(out)
}

func collapsible(ev events.Event) bool {
	return ev.Type == events.FileDownloaded && ev.Range != "" &&
		(ev.Outcome == events.OutcomeOK || ev.Outcome == events.OutcomeAborted)
}

func failedLogin(ev events.Event) bool {
	return ev.Type == events.AuthLogin && ev.Outcome != events.OutcomeOK
}

func loginKeyOf(ev events.Event) loginKey {
	if ev.Resolved != "" {
		return loginKey{account: ev.Resolved, ip: clientIP(ev.Actor.RemoteAddr)}
	}
	return loginKey{name: ev.Path, ip: clientIP(ev.Actor.RemoteAddr)}
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

// addLogin counts a failed login under the first word of its detail.
func (s *session) addLogin(ev events.Event) {
	if s.summary.Count == 0 {
		s.summary.Since = ev.Time
	}
	s.summary.Count++
	s.summary.Time = ev.Time
	s.summary.RequestID = ev.RequestID
	reason, _, _ := strings.Cut(ev.Detail, " ")
	if reason == "" {
		reason = string(ev.Outcome)
	}
	s.reasons[reason]++
	var b strings.Builder
	for _, r := range slices.Sorted(maps.Keys(s.reasons)) {
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%s=%d", r, s.reasons[r])
	}
	s.summary.Detail = b.String()
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
