// Package space keeps uploads from filling the volume the server writes to.
// A Ledger admits a write only if the volume's free space, minus what other
// writes in progress were promised, keeps a configured reserve free.
package space

import (
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"sync"
)

var ErrInsufficient = errors.New("insufficient storage")

const defaultCheckEvery = 64 << 20

type Ledger struct {
	free    func() (int64, error)
	minFree int64

	// CheckEvery is how many bytes a write may add beyond its reservation
	// before free space is measured again. Set it before the first Reserve.
	CheckEvery int64

	mu       sync.Mutex
	reserved int64 // promised to writes in progress and not yet written
	lastErr  string
}

// NewLedger uses free to measure the bytes available on the volume. minFree
// is the reserve every write must leave; 0 still refuses writes that do not
// fit.
func NewLedger(free func() (int64, error), minFree int64) *Ledger {
	return &Ledger{free: free, minFree: max(minFree, 0), CheckEvery: defaultCheckEvery}
}

// Reserve admits a write of size bytes, or of unknown size when size < 0. A
// write of unknown size is admitted while the reserve is intact, and is
// measured again as it grows. Release the reservation when the write ends.
func (l *Ledger) Reserve(size int64) (*Reservation, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	promised := max(size, 0)
	if avail, ok := l.available(); ok && avail < promised {
		return nil, fmt.Errorf("%w: %d bytes needed, %d available above the %d-byte reserve",
			ErrInsufficient, promised, max(avail, 0), l.minFree)
	}
	l.reserved += promised
	return &Reservation{l: l, left: promised}, nil
}

func (l *Ledger) Reserved() int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.reserved
}

// available is what a new write may still use. ok is false when free space
// cannot be measured; writes are then admitted rather than refused, and a
// full disk still surfaces as an error from the write itself.
func (l *Ledger) available() (avail int64, ok bool) {
	free, err := l.free()
	if err != nil {
		if msg := err.Error(); msg != l.lastErr {
			l.lastErr = msg
			log.Printf("space: cannot measure free space, not limiting uploads: %v", err)
		}
		return 0, false
	}
	l.lastErr = ""
	return free - l.reserved - l.minFree, true
}

func (l *Ledger) check() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if avail, ok := l.available(); ok && avail < 0 {
		return fmt.Errorf("%w: the %d-byte reserve is in use", ErrInsufficient, l.minFree)
	}
	return nil
}

func (l *Ledger) consume(n int64) {
	l.mu.Lock()
	l.reserved -= n
	l.mu.Unlock()
}

// Reservation is used by the one goroutine performing the write.
type Reservation struct {
	l         *Ledger
	left      int64 // reserved and not yet written
	unchecked int64 // written beyond the reservation since the last measurement
}

// Writer counts what passes through to w against the reservation. Beyond
// it, free space is measured every CheckEvery bytes, so a write fails with
// ErrInsufficient up to CheckEvery bytes into the reserve, and each
// concurrent write can go that far.
func (r *Reservation) Writer(w io.Writer) io.Writer { return &countingWriter{w: w, r: r} }

// Release returns what the write did not use. Calling it again does nothing.
func (r *Reservation) Release() {
	if r.left > 0 {
		r.l.consume(r.left)
		r.left = 0
	}
}

type countingWriter struct {
	w io.Writer
	r *Reservation
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	if err != nil {
		return n, err
	}
	r := c.r
	used := min(int64(n), r.left)
	if used > 0 {
		r.left -= used
		r.l.consume(used)
	}
	if r.unchecked += int64(n) - used; r.unchecked >= r.l.CheckEvery {
		r.unchecked = 0
		if err := r.l.check(); err != nil {
			return n, err
		}
	}
	return n, nil
}

func clamp(blocks uint64, blockSize int64) int64 {
	if blockSize <= 0 {
		return 0
	}
	if blocks > uint64(math.MaxInt64/blockSize) {
		return math.MaxInt64
	}
	return int64(blocks) * blockSize
}
