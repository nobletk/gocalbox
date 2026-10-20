//go:build bench

package benchmode

import (
	"os"
	"sync"
)

// A lineWriter appends to a file, one Write at a time.
type lineWriter struct {
	mu sync.Mutex
	f  *os.File
}

func openLineWriter(path string) (*lineWriter, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	return &lineWriter{f: f}, nil
}

func (w *lineWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.f.Write(p)
}
