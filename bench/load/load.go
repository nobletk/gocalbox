// Package load drives the resumable upload protocol the way the browser
// does: one session per file, hashed parts sent with a fixed number in
// flight per user across all of their files, lowest part numbers first, and
// a completion with the composite hash. It measures the time and writes the
// CSV columns of the benchmark scripts.
package load

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/fsops"
	"github.com/nobletk/gocalbox/internal/sandbox"
	"github.com/nobletk/gocalbox/internal/space"
	"github.com/nobletk/gocalbox/internal/transfer"
)

// API is the upload protocol as one simulated user reaches it.
type API interface {
	Create(ctx context.Context, req transfer.CreateRequest) (transfer.Created, error)
	Part(ctx context.Context, req transfer.PartRequest) (transfer.PartResult, error)
	Complete(ctx context.Context, id, composite string) (transfer.Result, error)
}

// User is one simulated user: its own way to the server, and the folder its
// files go to.
type User struct {
	API API
	Dir string
}

type Config struct {
	Users    []User
	Files    int   // files per user
	Size     int64 // bytes per file
	Parallel int   // parts in flight per user, across their files
}

type Result struct {
	// Files and Bytes count every file attempted, as the scripts do;
	// Codes tells how many of them were uploaded.
	Files    int
	Bytes    int64
	Duration time.Duration
	// Codes counts the files by the HTTP status their upload ended with:
	// 201 for a file uploaded, otherwise the status of the refusal that
	// stopped it, or 000 for a request that got no answer.
	Codes map[string]int
	// Retried counts the refusals that were tried again, by their status:
	// 503 busy, 429 too_many_requests and 409 part_in_progress.
	Retried map[string]int
	Parts   []time.Duration // the latency of every part accepted, its last try only
}

// Uploaded is how many files were uploaded.
func (r Result) Uploaded() int { return r.Codes["201"] }

// Run uploads cfg.Files files of cfg.Size bytes for every user at once and
// returns when all have ended.
func Run(ctx context.Context, cfg Config) Result {
	res := Result{Codes: map[string]int{}, Retried: map[string]int{}}
	var mu sync.Mutex
	var wg sync.WaitGroup
	start := time.Now()
	for i, u := range cfg.Users {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := runUser(ctx, u, cfg, i)
			mu.Lock()
			defer mu.Unlock()
			for k, v := range r.Codes {
				res.Codes[k] += v
			}
			for k, v := range r.Retried {
				res.Retried[k] += v
			}
			res.Parts = append(res.Parts, r.Parts...)
		}()
	}
	wg.Wait()
	res.Duration = time.Since(start)
	res.Files = len(cfg.Users) * cfg.Files
	res.Bytes = int64(res.Files) * cfg.Size
	return res
}

type upload struct {
	seed   byte
	c      transfer.Created
	hashes [][sha256.Size]byte
	left   int
	failed error
}

type job struct {
	up *upload
	n  int
}

func runUser(ctx context.Context, u User, cfg Config, user int) Result {
	res := Result{Codes: map[string]int{}, Retried: map[string]int{}}
	var mu sync.Mutex
	retried := func(err error) {
		mu.Lock()
		res.Retried[status(err)]++
		mu.Unlock()
	}
	jobs := make(chan job)
	var workers sync.WaitGroup
	for range max(cfg.Parallel, 1) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			var buf []byte
			for j := range jobs {
				mu.Lock()
				skip := j.up.failed != nil
				mu.Unlock()
				var d time.Duration
				var err error
				if !skip {
					if ps := j.up.c.PartSize; int64(len(buf)) < ps {
						buf = make([]byte, ps)
					}
					d, err = sendPart(ctx, u.API, cfg.Size, j, buf, retried)
				}
				mu.Lock()
				if err != nil && j.up.failed == nil {
					j.up.failed = err
				}
				if err == nil && !skip {
					res.Parts = append(res.Parts, d)
				}
				j.up.left--
				last := j.up.left == 0
				mu.Unlock()
				if last {
					status := finish(ctx, u.API, j.up, retried)
					mu.Lock()
					res.Codes[status]++
					mu.Unlock()
				}
			}
		}()
	}
	for f := range cfg.Files {
		up := &upload{seed: byte(user*31 + f)}
		name := fmt.Sprintf("load-%03d-%04d.bin", user, f)
		c, _, err := retry(ctx, func() (transfer.Created, error) {
			return u.API.Create(ctx, transfer.CreateRequest{Dir: u.Dir, Name: name, Size: cfg.Size})
		}, retried)
		if err != nil {
			mu.Lock()
			res.Codes[status(err)]++
			mu.Unlock()
			continue
		}
		up.c, up.hashes, up.left = c, make([][sha256.Size]byte, c.PartCount), c.PartCount
		if c.PartCount == 0 {
			code := finish(ctx, u.API, up, retried)
			mu.Lock()
			res.Codes[code]++
			mu.Unlock()
			continue
		}
		for n := 1; n <= c.PartCount; n++ {
			jobs <- job{up: up, n: n}
		}
	}
	close(jobs)
	workers.Wait()
	return res
}

// fill writes into b the bytes of the file with the given seed that start
// at off: the same bytes every time, without reading a file.
func fill(b []byte, off int64, seed byte) {
	for i := range b {
		b[i] = byte((off+int64(i))%251) + seed
	}
}

// sendPart sends part j.n, as the server's answer to create cut the file,
// and returns how long its last try took.
func sendPart(ctx context.Context, api API, size int64, j job, buf []byte, retried func(error)) (time.Duration, error) {
	c := j.up.c
	off := int64(j.n-1) * c.PartSize
	b := buf[:min(c.PartSize, size-off)]
	fill(b, off, j.up.seed)
	h := sha256.Sum256(b)
	j.up.hashes[j.n-1] = h
	sum := hex.EncodeToString(h[:])
	_, d, err := retry(ctx, func() (transfer.PartResult, error) {
		return api.Part(ctx, transfer.PartRequest{ID: c.UploadID, N: j.n, SHA256: sum, Length: int64(len(b)), Body: bytes.NewReader(b)})
	}, retried)
	return d, err
}

func finish(ctx context.Context, api API, up *upload, retried func(error)) string {
	if up.failed != nil {
		return status(up.failed)
	}
	_, _, err := retry(ctx, func() (transfer.Result, error) {
		return api.Complete(ctx, up.c.UploadID, transfer.Composite(up.hashes))
	}, retried)
	if err != nil {
		return status(err)
	}
	return "201"
}

// retry repeats a call the server refused for being busy, with growing
// pauses, telling retried of each refusal, and returns how long its last
// try took.
func retry[T any](ctx context.Context, call func() (T, error), retried func(error)) (T, time.Duration, error) {
	wait := 5 * time.Millisecond
	for {
		start := time.Now()
		v, err := call()
		took := time.Since(start)
		if !errors.Is(err, transfer.ErrBusy) && !errors.Is(err, transfer.ErrTooManyRequests) && !errors.Is(err, transfer.ErrPartInProgress) {
			return v, took, err
		}
		select {
		case <-ctx.Done():
			return v, took, err
		case <-time.After(wait):
		}
		retried(err)
		wait = min(2*wait, time.Second)
	}
}

// statuses are the HTTP statuses the server answers the errors of fsops,
// the ledger and the audit guard with, in the order it checks them.
var statuses = []struct {
	err    error
	status string
}{
	{events.ErrChangesPaused, "503"},
	{sandbox.ErrReserved, "403"},
	{fsops.ErrForbidden, "403"},
	{fsops.ErrBoundFolder, "409"},
	{sandbox.ErrTraversal, "403"},
	{sandbox.ErrRootTarget, "400"},
	{sandbox.ErrBrokenLink, "400"},
	{sandbox.ErrInvalidPath, "400"},
	{fsops.ErrNotFound, "404"},
	{fsops.ErrParentNotFound, "400"},
	{fsops.ErrNotDir, "400"},
	{fsops.ErrInvalidName, "400"},
	{fsops.ErrMoveIntoSelf, "400"},
	{fsops.ErrExists, "409"},
	{fsops.ErrUploadMoved, "409"},
	{fsops.ErrBodyAborted, "400"},
	{fsops.ErrCrossDevice, "409"},
	{space.ErrInsufficient, "507"},
	{fs.ErrPermission, "403"},
}

// status is the HTTP status the server answers err with.
func status(err error) string {
	var te *transfer.Error
	var rf *Refused
	switch {
	case errors.As(err, &rf):
		return strconv.Itoa(rf.Status)
	case errors.Is(err, ErrNoAnswer):
		return "000"
	case events.IsUnrecorded(err):
		return "500"
	case errors.As(err, &te):
		return strconv.Itoa(te.Status)
	}
	for _, s := range statuses {
		if errors.Is(err, s.err) {
			return s.status
		}
	}
	return "500"
}

// CodeColumn formats the answers as the scripts do: "201" when every file got
// it, otherwise each status with its count, such as "201x97 507x3".
func (r Result) CodeColumn() string {
	if len(r.Codes) == 1 && r.Codes["201"] > 0 {
		return "201"
	}
	keys := make([]string, 0, len(r.Codes))
	for k := range r.Codes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%sx%d", k, r.Codes[k]))
	}
	return strings.Join(parts, " ")
}

// Percentile returns the p-th percentile of the part latencies, p in [0, 1].
func (r Result) Percentile(p float64) time.Duration {
	if len(r.Parts) == 0 {
		return 0
	}
	l := slices.Clone(r.Parts)
	slices.Sort(l)
	return l[min(int(p*float64(len(l))), len(l)-1)]
}

// Header is the first line of the benchmark scripts' CSV files.
const Header = "commit,dirty,scenario,size_bytes,files,concurrency,rep,seconds,mib_per_s,durable_upper_seconds,server_cpu_s,http_code,transport"

// Row is one line of that CSV. A completion answers only once the file is
// on disk, so the durable time is the time itself. The server's CPU time
// isn't measured, and is left empty: in one process it can't be told apart
// from the client's.
func (r Result) Row(commit string, dirty bool, scenario string, size int64, concurrency, rep int, transport string) string {
	secs := r.Duration.Seconds()
	mibs := 0.0
	if secs > 0 {
		mibs = float64(r.Bytes) / (1 << 20) / secs
	}
	d := 0
	if dirty {
		d = 1
	}
	return fmt.Sprintf("%s,%d,%s,%d,%d,%d,%d,%.6f,%.3f,%.6f,,%s,%s",
		commit, d, scenario, size, r.Files, concurrency, rep, secs, mibs, secs, r.CodeColumn(), transport)
}
