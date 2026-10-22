package load

import (
	"context"
	"errors"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/nobletk/gocalbox/internal/transfer"
)

// pool holds the places a user's parts in flight take, across their files.
// Its size drops by one when the server refuses a part for its load, never
// below one and at most once per window, the parts sent since the last
// drop; it grows by one again once as many parts in a row of the current
// window as it holds are accepted, up to its cap. A part waiting out a
// refusal holds no place, and takes the next one before parts not yet sent.
type pool struct {
	mu    sync.Mutex
	cond  *sync.Cond
	cap   int
	limit int
	inUse int
	ahead int // parts sent again after a refusal, waiting for a place
	drops int // how many times the pool dropped: the window a send belongs to
	run   int // parts accepted in a row since the last refusal or growth
}

func newPool(n int) *pool {
	p := &pool{cap: n, limit: n}
	p.cond = sync.NewCond(&p.mu)
	return p
}

// acquire waits for a place, and returns the window the part is sent in;
// again marks a part sent again after a refusal, which goes first.
func (p *pool) acquire(ctx context.Context, again bool) (window int, err error) {
	stop := context.AfterFunc(ctx, func() {
		p.mu.Lock()
		p.cond.Broadcast()
		p.mu.Unlock()
	})
	defer stop()
	p.mu.Lock()
	defer p.mu.Unlock()
	if again {
		p.ahead++
		defer func() { p.ahead--; p.cond.Broadcast() }()
	}
	for p.inUse >= p.limit || !again && p.ahead > 0 {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		p.cond.Wait()
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	p.inUse++
	return p.drops, nil
}

// release gives a place back; accepted says whether the server took the
// part or already had it, and refused whether it refused it for its load.
func (p *pool) release(window int, accepted, refused bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.inUse--
	switch {
	case refused:
		p.run = 0
		if window == p.drops {
			p.limit = max(1, p.limit-1)
			p.drops++
		}
	case accepted && window == p.drops:
		if p.run++; p.run >= p.limit && p.limit < p.cap {
			p.limit++
			p.run = 0
		}
	}
	p.cond.Broadcast()
}

// size is how many places the pool has now.
func (p *pool) size() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.limit
}

// loadRefusal reports whether the server refused a call for its load, which
// it answers with how long to wait.
func loadRefusal(err error) bool {
	return errors.Is(err, transfer.ErrBusy) || errors.Is(err, transfer.ErrTooManyRequests) ||
		errors.Is(err, transfer.ErrTooManyUploads)
}

// noRetryAfter is the wait when a refusal says none: in process, and for
// too_many_uploads.
var noRetryAfter = time.Second

// retryAfter is the wait a refusal asks for.
func retryAfter(err error) time.Duration {
	var rf *Refused
	if errors.As(err, &rf) && rf.RetryAfter > 0 {
		return rf.RetryAfter
	}
	return noRetryAfter
}

// spread is d times a random factor from 0.5 to 1.5, so that clients
// refused at the same moment don't all come back together.
func spread(d time.Duration) time.Duration {
	return time.Duration(float64(d) * (0.5 + rand.Float64()))
}

// pause waits d, or less if ctx ends first, and reports whether it waited.
func pause(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
