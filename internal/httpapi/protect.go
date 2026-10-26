package httpapi

import (
	"context"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// Scripts and styles come from files only, so markup injected into the UI
// can't run as the user.
const uiCSP = "default-src 'self'; script-src 'self'; style-src 'self'; " +
	"img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

func isResourcePath(p string) bool {
	return p == "/api" || p == "/files" || strings.HasPrefix(p, "/api/") || strings.HasPrefix(p, "/files/")
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		if p := r.URL.Path; p == "/api" || strings.HasPrefix(p, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		if isResourcePath(r.URL.Path) {
			h.Set("Cross-Origin-Resource-Policy", "same-origin")
			h.Set("X-Frame-Options", "SAMEORIGIN")
		} else {
			h.Set("Content-Security-Policy", uiCSP)
			h.Set("X-Frame-Options", "DENY")
		}
		next.ServeHTTP(w, r)
	})
}

func isolateResources(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isResourcePath(r.URL.Path) && !sameOriginOrNavigation(r) {
			log.Printf("SECURITY ALERT: Blocked cross-origin %s %s (Sec-Fetch-Site %q, Sec-Fetch-Mode %q, Sec-Fetch-Dest %q)",
				r.Method, r.URL.Path, r.Header.Get("Sec-Fetch-Site"), r.Header.Get("Sec-Fetch-Mode"), r.Header.Get("Sec-Fetch-Dest"))
			writeErrorJSON(w, r, http.StatusForbidden, "cross_origin", "Cross-origin requests are not allowed")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func sameOriginOrNavigation(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "", "same-origin", "none":
		return true
	}
	return r.Method == http.MethodGet &&
		r.Header.Get("Sec-Fetch-Mode") == "navigate" &&
		r.Header.Get("Sec-Fetch-Dest") == "document"
}

const bodyProgress = 64 << 10

func limitBodyStalls(timeout time.Duration, next http.Handler) http.Handler {
	if timeout <= 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil && r.Body != http.NoBody {
			rc := http.NewResponseController(w)
			deadline := time.Now().Add(timeout)
			if rc.SetReadDeadline(deadline) == nil {
				clock := &stallClock{rc: rc, timeout: timeout, deadline: deadline}
				r.Body = &stallLimitedBody{ReadCloser: r.Body, clock: clock}
				r = r.WithContext(context.WithValue(r.Context(), stallClockKey{}, clock))
			}
		}
		next.ServeHTTP(w, r)
	})
}

type stallClockKey struct{}

// stallClock is the read deadline of one request's body, used only from its
// handler's goroutine.
type stallClock struct {
	rc       *http.ResponseController
	timeout  time.Duration
	deadline time.Time
	paused   bool
}

func (c *stallClock) restart() {
	c.deadline = time.Now().Add(c.timeout)
	c.rc.SetReadDeadline(c.deadline)
}

// pauseStalls returns the function that stops the request's body-stall
// clock while its handler chooses not to read, and starts it again when it
// is called with false; nil when no clock runs.
func pauseStalls(r *http.Request) func(paused bool) {
	c, _ := r.Context().Value(stallClockKey{}).(*stallClock)
	if c == nil {
		return nil
	}
	return func(paused bool) {
		switch {
		// A deadline already passed stays passed: over HTTP/1.1 the body is cut
		// only at its next read.
		case paused && time.Now().Before(c.deadline):
			c.paused = true
			c.rc.SetReadDeadline(time.Time{})
		case !paused && c.paused:
			c.paused = false
			c.restart()
		}
	}
}

type stallLimitedBody struct {
	io.ReadCloser
	clock *stallClock
	got   int64
}

func (b *stallLimitedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.got += int64(n)
	// Never once the body has ended: net/http then clears the deadline for its
	// background read, and a new one would cancel the request's context.
	if b.got >= bodyProgress && err == nil {
		b.got = 0
		b.clock.restart()
	}
	return n, err
}
