//go:build bench

package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/nobletk/gocalbox/internal/benchmode"
)

// logRequests logs every request to the benchmark build's request log, if it
// has one: what the server received and sent, when its first byte left, and
// how long the request took.
func logRequests(h http.Handler) http.Handler {
	out := benchmode.RequestLog()
	if out == nil {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		body := &countingBody{ReadCloser: r.Body}
		// A request without a body keeps http.NoBody: the stall limit tells
		// such requests by it, and must leave them alone.
		if r.Body != nil && r.Body != http.NoBody {
			r.Body = body
		}
		cw := &countingWriter{ResponseWriter: w}
		defer func() {
			e := requestEntry{
				Start: start.UTC(), Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, Proto: r.Proto,
				Status: cw.status, In: body.n, Out: cw.n, TotalMS: millis(time.Since(start)),
				Remote: r.RemoteAddr, Canceled: r.Context().Err() != nil,
			}
			if e.Status == 0 {
				e.Status = http.StatusOK
			}
			if !cw.first.IsZero() {
				e.FirstMS = millis(cw.first.Sub(start))
			}
			if b, err := json.Marshal(e); err == nil {
				out.Write(append(b, '\n'))
			}
		}()
		h.ServeHTTP(cw, r)
	})
}

// requestEntry is a line of the request log. Times are from the moment the
// server's handler got the request.
type requestEntry struct {
	Start    time.Time `json:"start"`
	Method   string    `json:"method"`
	Path     string    `json:"path"`
	Query    string    `json:"query,omitempty"`
	Proto    string    `json:"proto"`
	Status   int       `json:"status"`
	In       int64     `json:"in"`
	Out      int64     `json:"out"`
	FirstMS  float64   `json:"first_byte_ms"`
	TotalMS  float64   `json:"total_ms"`
	Remote   string    `json:"remote"`
	Canceled bool      `json:"canceled,omitempty"`
}

func millis(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

type countingBody struct {
	io.ReadCloser
	n int64
}

func (b *countingBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.n += int64(n)
	return n, err
}

// countingWriter counts the body bytes a handler writes and notes when the
// header left. It unwraps for http.ResponseController, and passes ReadFrom
// on, so that a download keeps the copy path it has without the log.
type countingWriter struct {
	http.ResponseWriter
	first  time.Time
	status int
	n      int64
}

func (w *countingWriter) started() {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	if w.first.IsZero() {
		w.first = time.Now()
	}
}

func (w *countingWriter) WriteHeader(code int) {
	if w.status == 0 && code >= 200 {
		w.status = code
		w.first = time.Now()
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *countingWriter) Write(p []byte) (int, error) {
	w.started()
	n, err := w.ResponseWriter.Write(p)
	w.n += int64(n)
	return n, err
}

func (w *countingWriter) ReadFrom(r io.Reader) (int64, error) {
	w.started()
	var n int64
	var err error
	if rf, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		n, err = rf.ReadFrom(r)
	} else {
		n, err = io.Copy(struct{ io.Writer }{w.ResponseWriter}, r)
	}
	w.n += n
	return n, err
}

func (w *countingWriter) Flush() {
	w.started()
	http.NewResponseController(w.ResponseWriter).Flush()
}

func (w *countingWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
