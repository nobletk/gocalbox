package transfer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/space"
)

type State string

const (
	Receiving  State = "receiving"
	Completing State = "completing"
	Completed  State = "completed"
	Aborted    State = "aborted"
	Expired    State = "expired"
	Failed     State = "failed"
)

// Over reports whether a session in state s has ended.
func (s State) Over() bool { return s != Receiving && s != Completing }

// hashChunk is how many parts' bits and hashes are allocated at once, when
// the first of them arrives, so that memory follows what was received rather
// than the declared size.
const hashChunk = 1024

type chunk struct {
	bits   [hashChunk / 64]uint64
	hashes [hashChunk][sha256.Size]byte
}

const maxClients = 8

type session struct {
	rec Record

	// counted is guarded by Engine.mu: whether the session counts as open.
	counted bool

	mu        sync.Mutex
	state     State
	reason    string
	chunks    []*chunk
	nReceived int
	recvBytes int64
	inflight  map[int]int64 // part number → its length
	inBytes   int64
	window    *space.Reservation
	data      *os.File
	log       *os.File
	lastPart  time.Time // the last part accepted for the first time
	retries   int
	rejected  int
	clients   []string
	over      time.Time // when it ended
	result    *Result
	resultErr error
	dataGone  bool
	// unlogged are the lines the disk had no room for, in order. They are
	// written once there is room, and any later line waits behind them.
	unlogged []line
	removing bool
}

func newSession(rec Record) *session {
	return &session{
		rec:      rec,
		state:    Receiving,
		chunks:   make([]*chunk, (rec.PartCount+hashChunk-1)/hashChunk),
		inflight: map[int]int64{},
	}
}

func (s *session) path() string { return logicalJoin(s.rec.Dir, s.rec.Name) }

func (s *session) has(n int) bool {
	c, i := s.chunks[(n-1)/hashChunk], (n-1)%hashChunk
	return c != nil && c.bits[i/64]&(1<<(i%64)) != 0
}

func (s *session) hash(n int) [sha256.Size]byte {
	c := s.chunks[(n-1)/hashChunk]
	if c == nil {
		return [sha256.Size]byte{}
	}
	return c.hashes[(n-1)%hashChunk]
}

func (s *session) keep(n int, h [sha256.Size]byte) {
	c, i := s.chunks[(n-1)/hashChunk], (n-1)%hashChunk
	if c == nil {
		c = new(chunk)
		s.chunks[(n-1)/hashChunk] = c
	}
	c.hashes[i] = h
	c.bits[i/64] |= 1 << (i % 64)
}

// ranges lists the parts received, or with missing set those not received,
// as inclusive ranges.
func (s *session) ranges(missing bool) []Range {
	out := []Range{}
	start := 0
	for n := 1; n <= s.rec.PartCount+1; n++ {
		in := n <= s.rec.PartCount && s.has(n) != missing
		switch {
		case in && start == 0:
			start = n
		case !in && start != 0:
			out = append(out, Range{start, n - 1})
			start = 0
		}
	}
	return out
}

func (s *session) composite() string {
	h := sha256.New()
	for n := 1; n <= s.rec.PartCount; n++ {
		p := s.hash(n)
		h.Write(p[:])
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (s *session) inFlight() []int {
	l := make([]int, 0, len(s.inflight))
	for n := range s.inflight {
		l = append(l, n)
	}
	slices.Sort(l)
	return l
}

func (s *session) seen(addr string) {
	if addr != "" && len(s.clients) < maxClients && !slices.Contains(s.clients, addr) {
		s.clients = append(s.clients, addr)
	}
}

// info is a new snapshot of the session's counters for an event.
func (s *session) info(part int, sum string) *events.UploadInfo {
	return &events.UploadInfo{
		ID:       s.rec.ID,
		Owner:    s.rec.Owner,
		Part:     part,
		PartSize: s.rec.PartSize,
		Parts:    s.rec.PartCount,
		Received: s.nReceived,
		Retries:  s.retries,
		Rejected: s.rejected,
		Clients:  slices.Clone(s.clients),
		Started:  s.rec.Created,
		SHA256:   sum,
	}
}

// totals is info for an event that ends the session.
func (s *session) totals(now time.Time, sum string) *events.UploadInfo {
	up := s.info(0, sum)
	up.DurationMS = now.Sub(s.rec.Created).Milliseconds()
	return up
}

func (s *session) releaseWindow() {
	if s.window != nil {
		s.window.Release()
	}
}

func (s *session) closeFiles() {
	if s.data != nil {
		s.data.Close()
		s.data = nil
	}
	if s.log != nil {
		s.log.Close()
		s.log = nil
	}
}

// line is one line of parts.log.
type line struct {
	Op      string        `json:"op"`
	N       int           `json:"n,omitempty"`
	SHA256  string        `json:"sha256,omitempty"`
	Reason  string        `json:"reason,omitempty"`
	Path    string        `json:"path,omitempty"`
	Size    *int64        `json:"size,omitempty"`
	MTime   *int64        `json:"mtime,omitempty"`
	At      time.Time     `json:"at"`
	IP      string        `json:"ip,omitempty"`
	Actor   *events.Actor `json:"actor,omitempty"`
	Request string        `json:"request,omitempty"`
	By      string        `json:"by,omitempty"`
}

const (
	opPart      = "part"
	opReject    = "reject"
	opFinishing = "finishing"
	opCompleted = "completed"
	opRecorded  = "recorded"
	opAborted   = "aborted"
	opExpired   = "expired"
	opFailed    = "failed"
)

// appendLine adds l to the session's log, and with durable set waits until
// it is on disk. A line the file system had no room for is cut back, so the
// log holds only whole lines, and the error then wraps space.ErrInsufficient:
// the session can go on once space is freed. The caller holds s.mu, which
// keeps lines from being written over each other: the log isn't opened to
// append, since Windows doesn't let a file opened that way be cut back.
func (e *Engine) appendLine(s *session, l line, durable bool) error {
	if s.log == nil {
		f, err := e.root.OpenFile(native(uploadsDir, s.rec.ID, logName), os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		s.log = f
	}
	if l.At.IsZero() {
		l.At = e.now()
	}
	b, err := json.Marshal(l)
	if err != nil {
		return err
	}
	info, err := s.log.Stat()
	if err != nil {
		return err
	}
	if _, err := e.writeLog(s.log, append(b, '\n'), info.Size()); err != nil {
		if terr := s.log.Truncate(info.Size()); terr != nil {
			return fmt.Errorf("%w; cutting the line back: %v", err, terr)
		}
		if isNoSpace(err) {
			return noSpace(err)
		}
		return err
	}
	if durable {
		return e.syncFile(s.log)
	}
	return nil
}

// openData opens the session's data for writing parts. The caller holds
// s.mu.
func (e *Engine) openData(s *session) error {
	if s.data != nil {
		return nil
	}
	f, err := e.root.OpenFile(native(uploadsDir, s.rec.ID, dataName), os.O_RDWR, 0)
	if err != nil {
		return err
	}
	s.data = f
	return nil
}

// dropData removes the data of a session that ended, once no part is being
// written to it. A failure is tried again by the janitor. The caller holds
// s.mu.
func (e *Engine) dropData(s *session) {
	if s.dataGone || len(s.inflight) > 0 {
		return
	}
	if s.data != nil {
		s.data.Close()
		s.data = nil
	}
	err := e.root.Remove(native(uploadsDir, s.rec.ID, dataName))
	if err == nil || errors.Is(err, fs.ErrNotExist) {
		s.dataGone = true
		e.logPending(s)
		return
	}
	logf("cannot remove the data of upload %s: %v", s.rec.ID, err)
}

// durable reports whether a line is flushed as it is written. Losing the
// others loses at most a counter, a republish or a reason.
func durable(op string) bool {
	switch op {
	case opReject, opRecorded, opFailed:
		return false
	}
	return true
}

// logOrKeep appends l, or keeps it for logPending when the disk has no
// room for it or a line is already waiting. It reports false when l is
// lost. The caller holds s.mu.
func (e *Engine) logOrKeep(s *session, l line) bool {
	if l.At.IsZero() {
		l.At = e.now()
	}
	if len(s.unlogged) > 0 {
		s.unlogged = append(s.unlogged, l)
		return true
	}
	switch err := e.appendLine(s, l, durable(l.Op)); {
	case errors.Is(err, space.ErrInsufficient):
		s.unlogged = append(s.unlogged, l)
	case err != nil:
		logf("cannot log the %s line of upload %s: %v", l.Op, s.rec.ID, err)
		return false
	}
	return true
}

// logPending writes the lines that had no room, in order. One that still has
// no room waits for the next try; after any other failure the rest are
// dropped, since they can't be written out of order. The caller holds s.mu.
func (e *Engine) logPending(s *session) {
	for len(s.unlogged) > 0 {
		l := s.unlogged[0]
		err := e.appendLine(s, l, durable(l.Op))
		if errors.Is(err, space.ErrInsufficient) {
			break
		}
		if err != nil {
			logf("cannot log the %s line of upload %s, nor the %d after it: %v", l.Op, s.rec.ID, len(s.unlogged)-1, err)
			s.unlogged = nil
			break
		}
		s.unlogged = s.unlogged[1:]
	}
	if s.state.Over() && s.log != nil {
		s.log.Close()
		s.log = nil
	}
}

// end moves a session to a final state other than completed, logging why,
// and wakes the janitor to apply the owner's cap on tombstones. The caller
// holds s.mu and publishes the event, then calls closeSlot.
func (e *Engine) end(s *session, st State, l line) {
	l.At = e.now()
	s.state, s.reason, s.over = st, l.Reason, l.At
	// A line with no room is written once the data is removed, which may
	// make room, or by the janitor.
	e.logOrKeep(s, l)
	e.wakeJanitor()
	s.releaseWindow()
	if s.log != nil {
		s.log.Close()
		s.log = nil
	}
	e.dropData(s)
}

// fail ends a session whose staged data or log can no longer be trusted
// during the request of ctx, and returns its upload.failed event and the
// answer to the request. The caller holds s.mu, then calls failed.
func (e *Engine) fail(ctx context.Context, s *session, reason string) (events.Event, error) {
	logf("upload %s failed: %s", s.rec.ID, reason)
	reason = truncate(reason)
	e.end(s, Failed, line{Op: opFailed, Reason: reason})
	ev := events.Event{
		Type:      events.UploadFailed,
		Actor:     events.ActorFrom(ctx),
		RequestID: events.RequestIDFrom(ctx),
		Outcome:   events.OutcomeError,
		Path:      truncate(s.path()),
		Size:      s.recvBytes,
		Detail:    truncate(reason),
		Upload:    s.totals(e.now(), ""),
	}
	return ev, closed(Failed, reason)
}

// failed stops counting a session that fail ended, and publishes its
// event. The caller holds no lock.
func (e *Engine) failed(s *session, ev events.Event) {
	e.closeSlot(s)
	e.publish(ev)
}

// expiresAt is when a receiving session expires, or when the record of a
// finished one is removed. The caller holds s.mu.
func (e *Engine) expiresAt(s *session) time.Time {
	if s.state.Over() {
		return s.over.Add(e.lim.TombstoneTTL)
	}
	t := s.rec.Created.Add(e.lim.FirstPartTTL)
	if s.nReceived > 0 {
		t = s.lastPart.Add(e.lim.IdleTTL)
	}
	return minTime(t, s.rec.Created.Add(e.lim.MaxAge))
}

func minTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}
