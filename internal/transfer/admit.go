package transfer

import (
	"container/list"
	"context"
	"time"
)

// admitWait is how long a part waits for a server-wide slot.
const admitWait = 10 * time.Second

// waiter is a part waiting for a server-wide slot.
type waiter struct {
	user    string
	elem    *list.Element
	granted chan struct{} // closed when a slot is passed to it
	got     bool
}

// admit takes a slot for one part being received. When every server-wide
// slot is taken, the part waits for one, in arrival order, up to admitWait;
// onWait, when set, is called with no lock held as the wait begins and as it
// ends. waited says whether it waited.
//
// A user's parts in flight and waiting together are held to MaxInflightUser,
// and at most MaxInflight parts wait: a waiting part's body is unread and
// holds its share of its connection's flow-control window.
func (e *Engine) admit(ctx context.Context, user string, onWait func(waiting bool)) (release func(), waited bool, err error) {
	e.mu.Lock()
	if e.userParts[user] >= e.lim.MaxInflightUser {
		e.mu.Unlock()
		e.counters.tooManyRequests.Add(1)
		return nil, false, ErrTooManyRequests
	}
	if e.slots < e.lim.MaxInflight && e.queue.Len() == 0 {
		e.slots++
		e.userParts[user]++
		e.mu.Unlock()
		return e.releaser(user), false, nil
	}
	if e.stopping {
		e.mu.Unlock()
		return nil, false, ErrShuttingDown
	}
	if e.queue.Len() >= e.lim.MaxInflight {
		e.mu.Unlock()
		e.counters.busy.Add(1)
		e.counters.queueFull.Add(1)
		return nil, false, ErrBusy
	}
	w := &waiter{user: user, granted: make(chan struct{})}
	w.elem = e.queue.PushBack(w)
	e.userParts[user]++
	stop := e.stopWaiting
	wait := e.admitWait
	e.mu.Unlock()

	if onWait != nil {
		onWait(true)
		defer onWait(false)
	}
	start := time.Now()
	timer := time.NewTimer(wait)
	select {
	case <-w.granted:
	case <-ctx.Done():
	case <-timer.C:
	case <-stop:
	}
	timer.Stop()
	e.counters.waited.Add(1)
	e.counters.waitTime.Add(int64(time.Since(start)))

	e.mu.Lock()
	defer e.mu.Unlock()
	if w.got {
		if ctx.Err() != nil {
			e.handOff(user)
			return nil, true, ErrPartAborted
		}
		return e.releaser(user), true, nil
	}
	e.queue.Remove(w.elem)
	e.uncountPart(user)
	switch {
	case e.stopping:
		return nil, true, ErrShuttingDown
	case ctx.Err() != nil:
		return nil, true, ErrPartAborted
	}
	e.counters.busy.Add(1)
	e.counters.waitTimeouts.Add(1)
	return nil, true, ErrBusy
}

// releaser returns the function that gives a part's slot back, once.
func (e *Engine) releaser(user string) func() {
	var done bool
	return func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		if !done {
			done = true
			e.handOff(user)
		}
	}
}

// handOff gives back a slot user held: to the part that has waited longest,
// or to the pool. Once shutdown has begun no part takes a slot from the
// queue, so none starts a body it can't finish. The caller holds e.mu.
func (e *Engine) handOff(user string) {
	e.uncountPart(user)
	if front := e.queue.Front(); front != nil && !e.stopping {
		w := e.queue.Remove(front).(*waiter)
		w.got = true
		close(w.granted)
		return
	}
	e.slots--
}

// uncountPart stops counting one of user's parts. The caller holds e.mu.
func (e *Engine) uncountPart(user string) {
	if e.userParts[user]--; e.userParts[user] <= 0 {
		delete(e.userParts, user)
	}
}

// BeginShutdown stops parts from waiting for a slot: those waiting answer
// ErrShuttingDown at once, as does every part that finds no free slot from
// now on. It is called as the server's shutdown begins, before the HTTP
// server waits for its handlers; Close calls it too.
func (e *Engine) BeginShutdown() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.stopping {
		e.stopping = true
		close(e.stopWaiting)
	}
}
