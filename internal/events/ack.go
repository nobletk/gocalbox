package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

var (
	ErrChangesPaused = errors.New("changes are paused because the audit log failed")
	ErrNotRecorded   = errors.New("the change was made but could not be recorded in the audit log")
	ErrNotConfirmed  = errors.New("the change was made but the audit log did not confirm its record in time")
	ErrClosed        = errors.New("the event bus is closed")
	ErrStalled       = errors.New("the audit log took no event")
	ErrQueueFull     = errors.New("the event bus's queue was full")
)

// IsUnrecorded reports whether err is the answer to a change that was made
// but whose record is not known to be on disk. The caller still has the
// change's result to report.
func IsUnrecorded(err error) bool {
	return errors.Is(err, ErrNotRecorded) || errors.Is(err, ErrNotConfirmed)
}

// Ack carries the audit log's answer about one event back to the request
// that made the change. Every subscriber sees the same Ack; only the audit
// log answers it.
type Ack struct {
	once sync.Once
	done chan struct{}
	err  error
}

func NewAck() *Ack { return &Ack{done: make(chan struct{})} }

// Done gives the answer: nil once the event's record is on disk. Only the
// first answer counts.
func (a *Ack) Done(err error) {
	if a == nil {
		return
	}
	a.once.Do(func() {
		a.err = err
		close(a.done)
	})
}

// Wait waits up to timeout for the answer; done is false if none came.
func (a *Ack) Wait(timeout time.Duration) (done bool, err error) {
	t := time.NewTimer(max(timeout, 0))
	defer t.Stop()
	select {
	case <-a.done:
		return true, a.err
	case <-t.C:
	}
	select {
	case <-a.done:
		return true, a.err
	default:
		return false, nil
	}
}

// Auditor applies the audit log's policies to changes.
type Auditor interface {
	// Allow returns an error wrapping ErrChangesPaused once the audit log has
	// failed; a change asks before it does anything.
	Allow() error
	// Record publishes the events of a change that was made and returns once
	// their records are on disk; otherwise its error wraps ErrNotRecorded or
	// ErrNotConfirmed. The waits of one request share one limit.
	Record(ctx context.Context, evs ...Event) error
	// RecordProtective is Record for a change that only takes access away,
	// which Allow never refuses. While changes are paused it doesn't wait.
	RecordProtective(ctx context.Context, evs ...Event) error
}

type waitBudgetKey struct{}

type waitBudget struct {
	mu     sync.Mutex
	waited time.Duration
}

// WithWaitBudget makes the records a request waits for share one limit,
// however many changes it makes. Only the time spent waiting counts.
func WithWaitBudget(ctx context.Context) context.Context {
	return context.WithValue(ctx, waitBudgetKey{}, &waitBudget{})
}

// WaitLeft returns how long the request of ctx may still wait for records,
// of the limit d.
func WaitLeft(ctx context.Context, d time.Duration) time.Duration {
	b, ok := ctx.Value(waitBudgetKey{}).(*waitBudget)
	if !ok {
		return d
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return max(d-b.waited, 0)
}

// Waited counts d against the request's limit.
func Waited(ctx context.Context, d time.Duration) {
	if b, ok := ctx.Value(waitBudgetKey{}).(*waitBudget); ok {
		b.mu.Lock()
		b.waited += d
		b.mu.Unlock()
	}
}

// How a line on the console names an event the audit log lacks.
const (
	LostNotRecorded = "not_recorded" // never written
	LostUnconfirmed = "unconfirmed"  // not confirmed in time; it may still be written
)

var lost = struct {
	sync.Mutex
	out io.Writer
}{out: os.Stderr}

// PrintLost writes ev to standard error as one JSON line. For an event the
// audit log doesn't hold, the line is the only copy.
func PrintLost(ev Event, status string, cause error) {
	line, err := json.Marshal(struct {
		Audit string `json:"audit"`
		Error string `json:"error"`
		Event Event  `json:"event"`
	}{status, fmt.Sprint(cause), ev})
	if err != nil {
		line = fmt.Appendf(nil, `{"audit":%q,"error":%q}`, status, err.Error())
	}
	lost.Lock()
	defer lost.Unlock()
	lost.out.Write(append(line, '\n'))
}

// SetLostOutput sends the lines of PrintLost to w until restore is called.
func SetLostOutput(w io.Writer) (restore func()) {
	lost.Lock()
	defer lost.Unlock()
	prev := lost.out
	lost.out = w
	return func() {
		lost.Lock()
		defer lost.Unlock()
		lost.out = prev
	}
}

func lose(ev Event, cause error) {
	PrintLost(ev, LostNotRecorded, cause)
	ev.Ack.Done(cause)
}
