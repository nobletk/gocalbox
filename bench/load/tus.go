package load

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// TusVersion is the version of the tus protocol the client speaks.
const TusVersion = "1.0.0"

// Tus is a tus server reached over HTTPS, such as tusd: the core protocol
// with the creation extension.
type Tus struct {
	// Endpoint is where uploads are created, such as
	// https://localhost:18080/files/.
	Endpoint string
	// CA is the PEM certificate of the server's CA, or nil to trust the
	// system's.
	CA    []byte
	HTTP1 bool // HTTP/1.1 rather than HTTP/2
}

// TusConfig is one upload of a file to a tus server, one request at a time,
// as the core protocol has it.
type TusConfig struct {
	Server Tus
	File   string
	// Chunk is the bytes of each PATCH; 0 sends the file in one.
	Chunk int64
	// ResumeAt, between 0 and 1, stops the upload once that share of the
	// file is accepted, and resumes it as tus-js-client does after a reload:
	// HEAD for the offset the server has, then PATCH from there. It needs
	// chunks, as a stop comes between two. 0 doesn't stop.
	ResumeAt float64
	// RetryFor is how long requests are tried again while they get no
	// answer; a PATCH goes on from the offset a HEAD then finds. 0 doesn't.
	RetryFor time.Duration
}

// TusRun uploads cfg.File and returns when the upload has ended. The result
// counts the file as 201 once the server holds all of it; its parts are the
// PATCH requests answered. The error is for a configuration that can't run.
func TusRun(ctx context.Context, cfg TusConfig) (Result, error) {
	res := Result{Codes: map[string]int{}, Retried: map[string]int{}, Files: 1, UserRates: []float64{0}, CPU: -1}
	endpoint, err := url.Parse(cfg.Server.Endpoint)
	switch {
	case err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "":
		return res, fmt.Errorf("the tus endpoint must be https://host:port/path, not %q", cfg.Server.Endpoint)
	case cfg.Chunk < 0:
		return res, errors.New("the chunk size can't be negative")
	case !(cfg.ResumeAt >= 0 && cfg.ResumeAt < 1):
		return res, errors.New("the share to resume at must be at least 0 and below 1")
	case cfg.ResumeAt > 0 && cfg.Chunk == 0:
		return res, errors.New("resuming needs chunks, as a stop comes between two")
	case cfg.RetryFor < 0:
		return res, errors.New("the time to try requests again can't be negative")
	}
	roots, err := rootsOf(cfg.Server.CA)
	if err != nil {
		return res, err
	}
	f, err := os.Open(cfg.File)
	if err != nil {
		return res, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return res, err
	}
	if !fi.Mode().IsRegular() {
		return res, fmt.Errorf("%s is no regular file", cfg.File)
	}
	tr := newTransport(roots, cfg.Server.HTTP1)
	defer tr.CloseIdleConnections()
	t := &tusUpload{
		cfg:    cfg,
		client: &http.Client{Transport: tr},
		file:   f,
		size:   fi.Size(),
		st:     &userState{res: Result{Codes: map[string]int{}, Retried: map[string]int{}}},
	}
	if cfg.ResumeAt > 0 {
		t.stopAt = max(1, int64(cfg.ResumeAt*float64(t.size)))
		// The stop comes at the end of the chunk that reaches it, which mustn't be the file's end.
		if end := (t.stopAt + cfg.Chunk - 1) / cfg.Chunk * cfg.Chunk; end >= t.size {
			return res, fmt.Errorf("a stop at %g of %d bytes falls in the last chunk of %d bytes, so the upload would never stop", cfg.ResumeAt, t.size, cfg.Chunk)
		}
	}
	res.Bytes = t.size

	// The connection is made before the clock starts, as the engine's is by its login.
	t.connect(ctx, endpoint)
	cpu := processCPU()
	res.Start = time.Now()
	code := t.run(ctx, endpoint)
	res.Duration = time.Since(res.Start)
	if end := processCPU(); cpu >= 0 && end >= 0 {
		res.CPU = end - cpu
	}
	if !t.st.downSince.IsZero() {
		t.st.res.Stalled += time.Since(t.st.downSince)
	}
	res.Codes[code]++
	res.Retried = t.st.res.Retried
	res.Parts = t.st.res.Parts
	res.Stalled = t.st.res.Stalled
	res.Resent = t.resent
	if code == "201" {
		res.UserRates = []float64{float64(t.size) / (1 << 20) / res.Duration.Seconds()}
		if !t.stopped.IsZero() {
			res.Resumes = []time.Duration{time.Since(t.stopped)}
		}
	}
	return res, nil
}

type tusUpload struct {
	cfg      TusConfig
	client   *http.Client
	file     *os.File
	size     int64
	st       *userState
	location string
	stopAt   int64 // the offset after which the upload stops once; 0 never
	stopped  time.Time
	resent   int64
}

// run creates the upload and sends the file, and returns the status the
// upload ended with: 201 once the server holds the whole file.
func (t *tusUpload) run(ctx context.Context, endpoint *url.URL) string {
	if err := t.create(ctx, endpoint); err != nil {
		return status(err)
	}
	var off int64
	for off < t.size {
		n := t.size - off
		if t.cfg.Chunk > 0 {
			n = min(n, t.cfg.Chunk)
		}
		perr := t.patch(ctx, off, n)
		if perr == nil {
			off += n
			// After a HEAD the chunks no longer end where they began, and one can end the file.
			if t.stopAt > 0 && off >= t.stopAt && off < t.size && t.stopped.IsZero() {
				t.stopped = time.Now()
				var err error
				if off, err = t.offset(ctx); err != nil {
					return status(err)
				}
			}
			continue
		}
		var rf *Refused
		conflict := errors.As(perr, &rf) && rf.Status == http.StatusConflict
		lost := errors.Is(perr, ErrNoAnswer) && ctx.Err() == nil
		if !conflict && !(lost && t.retrying(ctx)) {
			return status(perr)
		}
		t.st.retried(perr)
		got, err := t.offset(ctx)
		if err != nil {
			return status(err)
		}
		// A server that refuses the offset it has just given would be asked forever.
		if conflict && got == off {
			return status(perr)
		}
		// A PATCH that may have carried bytes the server didn't keep sends them again.
		if lost && !errors.Is(perr, ErrNotConnected) && got < off+n {
			t.resent += off + n - max(got, off)
		}
		off = got
	}
	return "201"
}

// connect opens the connection to the server with an OPTIONS request, which
// tus servers answer with the protocol's versions. A failure is left to the
// upload's first request.
func (t *tusUpload) connect(ctx context.Context, endpoint *url.URL) {
	req, err := http.NewRequestWithContext(ctx, http.MethodOptions, endpoint.String(), nil)
	if err != nil {
		return
	}
	if resp, err := t.client.Do(req); err == nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

// retrying says whether a request that got no answer is tried again: while
// the server has given none for at most RetryFor, after a pause.
func (t *tusUpload) retrying(ctx context.Context) bool {
	t.st.mu.Lock()
	down := t.st.downSince
	t.st.mu.Unlock()
	if t.cfg.RetryFor <= 0 || down.IsZero() || time.Since(down) > t.cfg.RetryFor {
		return false
	}
	return pause(ctx, 100*time.Millisecond)
}

// create makes the upload and keeps its URL.
func (t *tusUpload) create(ctx context.Context, endpoint *url.URL) error {
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), nil)
		if err != nil {
			return err
		}
		req.Header.Set("Tus-Resumable", TusVersion)
		req.Header.Set("Upload-Length", strconv.FormatInt(t.size, 10))
		req.Header.Set("Upload-Metadata", "filename "+base64.StdEncoding.EncodeToString([]byte(filepath.Base(t.file.Name()))))
		resp, err := t.do(req, http.StatusCreated)
		if err == nil {
			loc := resp.Header.Get("Location")
			u, perr := endpoint.Parse(loc)
			if loc == "" || perr != nil {
				return fmt.Errorf("the server's answer to the creation has no upload URL: %q", loc)
			}
			t.location = u.String()
			return nil
		}
		// An upload whose creation lost its answer may exist; another is made, as tus-js-client does.
		if !errors.Is(err, ErrNoAnswer) || !t.retrying(ctx) {
			return err
		}
		t.st.retried(err)
	}
}

// patch sends n bytes from off, which the server must then have taken.
func (t *tusUpload) patch(ctx context.Context, off, n int64) error {
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, t.location, io.NewSectionReader(t.file, off, n))
	if err != nil {
		return err
	}
	req.ContentLength = n
	req.Header.Set("Tus-Resumable", TusVersion)
	req.Header.Set("Upload-Offset", strconv.FormatInt(off, 10))
	req.Header.Set("Content-Type", "application/offset+octet-stream")
	resp, err := t.do(req, http.StatusNoContent)
	if err != nil {
		return err
	}
	if got := resp.Header.Get("Upload-Offset"); got != strconv.FormatInt(off+n, 10) {
		return fmt.Errorf("the server answered a PATCH of %d bytes at %d with the offset %q", n, off, got)
	}
	t.st.mu.Lock()
	t.st.res.Parts = append(t.st.res.Parts, time.Since(start))
	t.st.mu.Unlock()
	return nil
}

// offset asks the server how much of the upload it has.
func (t *tusUpload) offset(ctx context.Context) (int64, error) {
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, t.location, nil)
		if err != nil {
			return 0, err
		}
		req.Header.Set("Tus-Resumable", TusVersion)
		resp, err := t.do(req, http.StatusOK)
		if err == nil {
			off, perr := strconv.ParseInt(resp.Header.Get("Upload-Offset"), 10, 64)
			if perr != nil || off < 0 || off > t.size {
				return 0, fmt.Errorf("the server answered HEAD with the offset %q", resp.Header.Get("Upload-Offset"))
			}
			return off, nil
		}
		if !errors.Is(err, ErrNoAnswer) || !t.retrying(ctx) {
			return 0, err
		}
		t.st.retried(err)
	}
}

// do sends req and reads its answer, which must have the status want. It
// notes whether the server answered, for the time it gave no answer.
func (t *tusUpload) do(req *http.Request, want int) (*http.Response, error) {
	resp, err := t.client.Do(req)
	if err != nil {
		if req.Context().Err() == nil {
			t.st.answered(false)
		}
		if op := (*net.OpError)(nil); errors.As(err, &op) && op.Op == "dial" {
			return nil, fmt.Errorf("%w: %w: %v", ErrNoAnswer, ErrNotConnected, err)
		}
		return nil, fmt.Errorf("%w: %v", ErrNoAnswer, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		t.st.answered(false)
		return nil, fmt.Errorf("%w: %v", ErrNoAnswer, err)
	}
	t.st.answered(true)
	if resp.StatusCode != want {
		return nil, &Refused{Status: resp.StatusCode, Code: "tus", Message: strings.TrimSpace(string(body))}
	}
	return resp, nil
}
