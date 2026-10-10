package httpapi

import (
	"context"
	"net/http"
	"slices"
	"sync"

	"github.com/nobletk/gocalbox/internal/events"
)

// Tracker counts file operations in progress.
type Tracker struct {
	mu      sync.Mutex
	closing bool
	wg      sync.WaitGroup
	next    uint64
	running map[uint64]string // "METHOD path (request ID)"
}

func NewTracker() *Tracker { return &Tracker{running: map[uint64]string{}} }

func (t *Tracker) track(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.mu.Lock()
		if t.closing {
			t.mu.Unlock()
			writeErrorJSON(w, r, http.StatusServiceUnavailable, "unavailable", "The server is shutting down")
			return
		}
		t.wg.Add(1)
		t.next++
		id := t.next
		t.running[id] = r.Method + " " + r.URL.Path + " (" + events.RequestIDFrom(r.Context()) + ")"
		t.mu.Unlock()

		defer func() {
			t.mu.Lock()
			delete(t.running, id)
			t.mu.Unlock()
			t.wg.Done()
		}()
		next.ServeHTTP(w, r)
	})
}

func (t *Tracker) Drain(ctx context.Context) ([]string, error) {
	t.mu.Lock()
	t.closing = true
	t.mu.Unlock()

	done := make(chan struct{})
	go func() { t.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil, nil
	case <-ctx.Done():
		select {
		case <-done:
			return nil, nil
		default:
		}
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	left := make([]string, 0, len(t.running))
	for _, op := range t.running {
		left = append(left, op)
	}
	slices.Sort(left)
	return left, ctx.Err()
}
