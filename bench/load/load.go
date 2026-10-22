// Package load drives the resumable upload protocol the way the browser
// does: one session per file, hashed parts sent with a fixed number in
// flight per user across all of their files, lowest part numbers first, and
// a completion with the composite hash. It measures the time, and writes
// the benchmark scripts' CSV columns followed by its own.
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
	// ResumeAt, between 0 and 1, stops each file once that share of its
	// parts is accepted, dropping the parts in flight, and resumes it as a
	// browser does after a reload: create again with the file's client key,
	// then send the parts the server lacks. 0 doesn't stop.
	ResumeAt float64
	// RetryFor is how long a call is tried again while it gets no answer,
	// or 503 unavailable from a server shutting down; 0 doesn't.
	RetryFor time.Duration
}

type Result struct {
	// Files and Bytes count every file attempted, as the scripts do;
	// Codes tells how many of them were uploaded.
	Files    int
	Bytes    int64
	Start    time.Time
	Duration time.Duration
	// Codes counts the files by the HTTP status their upload ended with:
	// 201 for a file uploaded, otherwise the status of the refusal that
	// stopped it, or 000 for a request that got no answer.
	Codes map[string]int
	// Retried counts the calls that were tried again, by the status that
	// refused them: 503 busy or unavailable, 429 too_many_requests, 409
	// part_in_progress, or 000 for no answer.
	Retried   map[string]int
	Parts     []time.Duration // the latency of every part accepted, its last try only
	Completes []time.Duration // the time of every completion answered, its last try only
	// Resent counts the bytes of parts sent more than once. A try counts as
	// sent if it was answered with the part taken or already had, got no
	// answer once connected, or was cut off when its file stopped; refusals
	// don't, as the server answers them without taking the part, and nor do
	// tries that couldn't connect.
	Resent int64
	// Resumes is the time from each file's stop to its end, for the files
	// that stopped and were resumed with the session the server kept.
	Resumes []time.Duration
	// Stalled is how long the calls of a user got no answer, at most over
	// the users.
	Stalled time.Duration
	// UserRates is each user's uploaded bytes over the time to its last
	// file's end, in MiB/s.
	UserRates []float64
	// CPU is this process's CPU time over the run, or -1 where it can't be
	// read. In process, it is the engine's and the users' together.
	CPU time.Duration
}

// Uploaded is how many files were uploaded.
func (r Result) Uploaded() int { return r.Codes["201"] }

// Run uploads cfg.Files files of cfg.Size bytes for every user at once and
// returns when all have ended.
func Run(ctx context.Context, cfg Config) Result {
	res := Result{Codes: map[string]int{}, Retried: map[string]int{}}
	var mu sync.Mutex
	var wg sync.WaitGroup
	cpu := processCPU()
	start := time.Now()
	for i, u := range cfg.Users {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := runUser(ctx, u, cfg, i, start)
			mu.Lock()
			defer mu.Unlock()
			for k, v := range r.Codes {
				res.Codes[k] += v
			}
			for k, v := range r.Retried {
				res.Retried[k] += v
			}
			res.Parts = append(res.Parts, r.Parts...)
			res.Completes = append(res.Completes, r.Completes...)
			res.Resumes = append(res.Resumes, r.Resumes...)
			res.Resent += r.Resent
			res.Stalled = max(res.Stalled, r.Stalled)
			res.UserRates = append(res.UserRates, r.UserRates...)
		}()
	}
	wg.Wait()
	res.Start, res.Duration = start, time.Since(start)
	res.CPU = -1
	if end := processCPU(); cpu >= 0 && end >= 0 {
		res.CPU = end - cpu
	}
	res.Files = len(cfg.Users) * cfg.Files
	res.Bytes = int64(res.Files) * cfg.Size
	return res
}

type upload struct {
	name    string
	key     string
	seed    byte
	c       transfer.Created
	hashes  [][sha256.Size]byte
	left    int // jobs not yet done
	failed  error
	ctx     context.Context
	cancel  context.CancelFunc
	stopAt  int // accepted parts after which the file stops; 0 never
	done    int // parts accepted since the file's session was made
	stopped time.Time
	resumed bool
	sends   map[int]int // tries that may have carried each part
}

type job struct {
	up *upload
	n  int
	// again marks a part sent again after the server refused it for its
	// load; it waits until notBefore without holding a place.
	again     bool
	notBefore time.Time
}

// queue holds a user's parts to send, in the order they go out, and how many
// of the user's files haven't ended.
type queue struct {
	mu       sync.Mutex
	cond     *sync.Cond
	jobs     []job
	open     int
	producer bool // the files are still being created
}

func newQueue() *queue {
	q := &queue{producer: true}
	q.cond = sync.NewCond(&q.mu)
	return q
}

// push adds jobs at the back, or at the front.
func (q *queue) push(front bool, js ...job) {
	q.mu.Lock()
	if front {
		q.jobs = append(slices.Clone(js), q.jobs...)
	} else {
		q.jobs = append(q.jobs, js...)
	}
	q.mu.Unlock()
	q.cond.Broadcast()
}

// pop waits for the first job whose time has come; it returns false once no
// job is left and none can come.
func (q *queue) pop() (job, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for {
		now := time.Now()
		var next time.Time
		for i, j := range q.jobs {
			if !j.notBefore.After(now) {
				q.jobs = slices.Delete(q.jobs, i, i+1)
				q.cond.Broadcast()
				return j, true
			}
			if next.IsZero() || j.notBefore.Before(next) {
				next = j.notBefore
			}
		}
		if len(q.jobs) == 0 && !q.producer && q.open == 0 {
			return job{}, false
		}
		if !next.IsZero() {
			t := time.AfterFunc(next.Sub(now), func() {
				q.mu.Lock()
				q.cond.Broadcast()
				q.mu.Unlock()
			})
			q.cond.Wait()
			t.Stop()
			continue
		}
		q.cond.Wait()
	}
}

// drained waits until every job queued has been taken.
func (q *queue) drained() {
	q.mu.Lock()
	for len(q.jobs) > 0 {
		q.cond.Wait()
	}
	q.mu.Unlock()
}

func (q *queue) opened() { q.mu.Lock(); q.open++; q.mu.Unlock() }

func (q *queue) ended() {
	q.mu.Lock()
	q.open--
	q.mu.Unlock()
	q.cond.Broadcast()
}

func (q *queue) finished() {
	q.mu.Lock()
	q.producer = false
	q.mu.Unlock()
	q.cond.Broadcast()
}

// userState is what a user's workers share.
type userState struct {
	mu        sync.Mutex
	res       Result
	downSince time.Time
	uploaded  int64
}

func (st *userState) retried(err error) {
	st.mu.Lock()
	st.res.Retried[status(err)]++
	st.mu.Unlock()
}

// answered notes whether a call got an answer, for the time the server
// gave none.
func (st *userState) answered(ok bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	switch {
	case !ok && st.downSince.IsZero():
		st.downSince = time.Now()
	case ok && !st.downSince.IsZero():
		st.res.Stalled += time.Since(st.downSince)
		st.downSince = time.Time{}
	}
}

func runUser(ctx context.Context, u User, cfg Config, user int, start time.Time) Result {
	st := &userState{res: Result{Codes: map[string]int{}, Retried: map[string]int{}}}
	q := newQueue()
	r := retrier{cfg: cfg, st: st, pool: newPool(max(cfg.Parallel, 1))}
	end := func(up *upload, code string) {
		if up.cancel != nil {
			up.cancel()
		}
		st.mu.Lock()
		st.res.Codes[code]++
		for n, k := range up.sends {
			if k > 1 {
				st.res.Resent += int64(k-1) * partLen(cfg.Size, up.c.PartSize, n)
			}
		}
		if code == "201" {
			st.uploaded += cfg.Size
			if !up.stopped.IsZero() && up.resumed {
				st.res.Resumes = append(st.res.Resumes, time.Since(up.stopped))
			}
		}
		st.mu.Unlock()
		q.ended()
	}
	var workers sync.WaitGroup
	for range max(cfg.Parallel, 1) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			var buf []byte
			for {
				j, ok := q.pop()
				if !ok {
					return
				}
				st.mu.Lock()
				skip := j.up.failed != nil || !j.up.stopped.IsZero() && !j.up.resumed
				upCtx := j.up.ctx
				st.mu.Unlock()
				var d time.Duration
				var err error
				if !skip {
					if ps := j.up.c.PartSize; int64(len(buf)) < ps {
						buf = make([]byte, ps)
					}
					var window int
					if window, err = r.pool.acquire(upCtx, j.again); err == nil {
						d, err = r.sendPart(upCtx, u.API, cfg.Size, j, buf)
						refused := err != nil && upCtx.Err() == nil && loadRefusal(err)
						r.pool.release(window, err == nil, refused)
						if refused {
							st.retried(err)
							j.again, j.notBefore = true, time.Now().Add(spread(retryAfter(err)))
							q.push(true, j)
							continue
						}
					}
				}
				st.mu.Lock()
				switch {
				case skip:
				case err != nil && !j.up.stopped.IsZero() && !j.up.resumed:
					// Cut off by its file's stop, to be resumed.
				case err != nil:
					if j.up.failed == nil {
						j.up.failed = err
					}
				default:
					st.res.Parts = append(st.res.Parts, d)
					j.up.done++
					if j.up.stopAt > 0 && j.up.done >= j.up.stopAt && j.up.stopped.IsZero() {
						// Under the lock, so that no part fails unnoticed between the
						// stop and the cut, and no resumed session is cancelled.
						j.up.stopped = time.Now()
						j.up.cancel()
					}
				}
				j.up.left--
				last := j.up.left == 0
				st.mu.Unlock()
				if !last {
					continue
				}
				st.mu.Lock()
				resume := j.up.failed == nil && !j.up.stopped.IsZero() && !j.up.resumed
				st.mu.Unlock()
				if resume {
					if code, ok := r.resume(ctx, u, cfg, j.up, q); !ok {
						end(j.up, code)
					}
					continue
				}
				end(j.up, r.finish(ctx, u.API, j.up))
			}
		}()
	}
	for f := range cfg.Files {
		name := fmt.Sprintf("load-%03d-%04d.bin", user, f)
		up := &upload{name: name, seed: byte(user*31 + f), sends: map[int]int{}}
		up.key = clientKey(u.Dir, name, cfg.Size, up.seed)
		q.opened()
		c, err := r.create(ctx, u, cfg, up)
		if err != nil {
			end(up, status(err))
			continue
		}
		r.start(ctx, up, c, cfg)
		if c.PartCount == 0 {
			end(up, r.finish(ctx, u.API, up))
			continue
		}
		q.push(false, jobsFor(up, nil)...)
		q.drained()
	}
	q.finished()
	workers.Wait()
	if !st.downSince.IsZero() {
		st.res.Stalled += time.Since(st.downSince)
	}
	if st.uploaded > 0 {
		st.res.UserRates = []float64{float64(st.uploaded) / (1 << 20) / time.Since(start).Seconds()}
	} else {
		st.res.UserRates = []float64{0}
	}
	return st.res
}

// clientKey identifies a file for resuming it, as the browser's key does.
func clientKey(dir, name string, size int64, seed byte) string {
	h := sha256.Sum256(fmt.Appendf(nil, "%s\n%s\n%d\n%d", dir, name, size, seed))
	return hex.EncodeToString(h[:])
}

// jobsFor returns a job for each part of up, or for the parts in need only.
func jobsFor(up *upload, need []int) []job {
	if need == nil {
		need = make([]int, up.c.PartCount)
		for i := range need {
			need[i] = i + 1
		}
	}
	js := make([]job, len(need))
	for i, n := range need {
		js[i] = job{up: up, n: n}
	}
	return js
}

// retrier makes the calls of one user, tried again as cfg says, its parts
// within its pool.
type retrier struct {
	cfg  Config
	st   *userState
	pool *pool
}

func (r retrier) create(ctx context.Context, u User, cfg Config, up *upload) (transfer.Created, error) {
	c, _, err := retry(ctx, r, true, func() (transfer.Created, error) {
		return u.API.Create(ctx, transfer.CreateRequest{Dir: u.Dir, Name: up.name, Size: cfg.Size, ClientKey: up.key})
	})
	return c, err
}

// start gives up the session c: its parts go out under a context of their
// own, which the file's stop cancels. A file stops only once.
func (r retrier) start(ctx context.Context, up *upload, c transfer.Created, cfg Config) {
	r.st.mu.Lock()
	defer r.st.mu.Unlock()
	if up.hashes == nil || len(up.hashes) != c.PartCount {
		up.hashes = make([][sha256.Size]byte, c.PartCount)
	}
	up.c, up.left = c, c.PartCount
	if up.cancel != nil {
		up.cancel()
	}
	up.ctx, up.cancel = context.WithCancel(ctx)
	up.stopAt = 0
	if cfg.ResumeAt > 0 && !up.resumed {
		up.stopAt = max(1, int(cfg.ResumeAt*float64(c.PartCount)))
	}
}

// resume makes the file's session again with its client key and queues the
// parts the server lacks, first. It returns false, with the status that
// ended the file, if it couldn't.
func (r retrier) resume(ctx context.Context, u User, cfg Config, up *upload, q *queue) (string, bool) {
	c, err := r.create(ctx, u, cfg, up)
	if err != nil {
		return status(err), false
	}
	r.st.mu.Lock()
	up.resumed = true
	r.st.mu.Unlock()
	var need []int
	if c.Resumed {
		have := map[int]bool{}
		for _, rg := range c.Received {
			for n := rg[0]; n <= rg[1]; n++ {
				have[n] = true
			}
		}
		for n := 1; n <= c.PartCount; n++ {
			if !have[n] {
				need = append(need, n)
			}
		}
	} else {
		r.st.mu.Lock()
		up.stopped = time.Time{}
		r.st.mu.Unlock()
	}
	r.start(ctx, up, c, cfg)
	if c.Resumed {
		r.st.mu.Lock()
		up.left = len(need)
		r.st.mu.Unlock()
		if len(need) == 0 {
			return r.finish(ctx, u.API, up), false
		}
		q.push(true, jobsFor(up, need)...)
		return "", true
	}
	q.push(true, jobsFor(up, nil)...)
	return "", true
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
func (r retrier) sendPart(ctx context.Context, api API, size int64, j job, buf []byte) (time.Duration, error) {
	c := j.up.c
	off := int64(j.n-1) * c.PartSize
	b := buf[:min(c.PartSize, size-off)]
	fill(b, off, j.up.seed)
	h := sha256.Sum256(b)
	r.st.mu.Lock()
	j.up.hashes[j.n-1] = h
	r.st.mu.Unlock()
	sum := hex.EncodeToString(h[:])
	_, d, err := retry(ctx, r, false, func() (transfer.PartResult, error) {
		if ctx.Err() != nil {
			return transfer.PartResult{}, ctx.Err()
		}
		res, err := api.Part(ctx, transfer.PartRequest{ID: c.UploadID, N: j.n, SHA256: sum, Length: int64(len(b)), Body: bytes.NewReader(b)})
		if err == nil || errors.Is(err, ErrNoAnswer) && !errors.Is(err, ErrNotConnected) || ctx.Err() != nil {
			r.st.mu.Lock()
			j.up.sends[j.n]++
			r.st.mu.Unlock()
		}
		return res, err
	})
	return d, err
}

// finish completes up, unless one of its parts failed, and returns the
// status its upload ended with.
func (r retrier) finish(ctx context.Context, api API, up *upload) string {
	r.st.mu.Lock()
	failed := up.failed
	hashes := slices.Clone(up.hashes)
	r.st.mu.Unlock()
	if failed != nil {
		return status(failed)
	}
	_, d, err := retry(ctx, r, true, func() (transfer.Result, error) {
		return api.Complete(ctx, up.c.UploadID, transfer.Composite(hashes))
	})
	if err != nil {
		return status(err)
	}
	r.st.mu.Lock()
	r.st.res.Completes = append(r.st.res.Completes, d)
	r.st.mu.Unlock()
	return "201"
}

// partLen is the length of part n of a file of size bytes.
func partLen(size, partSize int64, n int) int64 {
	off := int64(n-1) * partSize
	return min(partSize, size-off)
}

// maxBackOff bounds the growing pauses after refusals for the server's load.
var maxBackOff = 8 * time.Second

// retry repeats a call that found its part in progress, with growing
// pauses, and, for up to RetryFor, one that got no answer or found the
// server shutting down. With load set, it also repeats a call the server
// refused for its load, after the wait the refusal asks for, doubled for
// each refusal in a row; without it, such a refusal is returned, for the
// part's pool to deal with. It tells r of each try repeated, and returns how
// long the last try took.
func retry[T any](ctx context.Context, r retrier, load bool, call func() (T, error)) (T, time.Duration, error) {
	wait := 5 * time.Millisecond
	var backOff time.Duration
	var down time.Time
	for {
		start := time.Now()
		v, err := call()
		took := time.Since(start)
		gone := errors.Is(err, ErrNoAnswer) || errors.Is(err, transfer.ErrShuttingDown)
		if ctx.Err() == nil {
			r.st.answered(!gone)
		}
		switch {
		case err == nil:
			return v, took, nil
		case ctx.Err() != nil:
			return v, took, err
		case gone:
			if r.cfg.RetryFor <= 0 {
				return v, took, err
			}
			if down.IsZero() {
				down = start
			}
			if time.Since(down) > r.cfg.RetryFor {
				return v, took, err
			}
		case loadRefusal(err):
			if !load {
				return v, took, err
			}
			backOff = min(max(2*backOff, retryAfter(err)), maxBackOff)
			if !pause(ctx, spread(backOff)) {
				return v, took, err
			}
			r.st.retried(err)
			continue
		case errors.Is(err, transfer.ErrPartInProgress):
		default:
			return v, took, err
		}
		if !pause(ctx, wait) {
			return v, took, err
		}
		r.st.retried(err)
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
func (r Result) Percentile(p float64) time.Duration { return Percentile(r.Parts, p) }

// Percentile returns the p-th percentile of ds, p in [0, 1], or 0 for none.
func Percentile(ds []time.Duration, p float64) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	l := slices.Clone(ds)
	slices.Sort(l)
	return l[min(int(p*float64(len(l))), len(l)-1)]
}

// ScriptColumns are the columns of the benchmark scripts' CSV files.
const ScriptColumns = "commit,dirty,scenario,size_bytes,files,concurrency,rep,seconds,mib_per_s,durable_upper_seconds,server_cpu_s,http_code,transport"

// Header is the first line of the load client's CSV files: the scripts'
// columns, then its own.
const Header = ScriptColumns + ",part_p50_ms,part_p99_ms,complete_p50_ms,complete_max_ms,retried,resent_bytes," +
	"user_min_mib_s,user_max_mib_s,client_cpu_s,resumed,resume_p50_s,resume_max_s,stalled_s,started_unix"

// Row is one line of that CSV. A completion answers only once the file is
// on disk, so the durable time is the time itself. The server's CPU time
// isn't measured, and is left empty, and so is the client's in process,
// where the two can't be told apart.
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
	ms := func(d time.Duration) string { return fmt.Sprintf("%.3f", float64(d)/float64(time.Millisecond)) }
	var lo, hi float64
	if len(r.UserRates) > 0 {
		lo, hi = slices.Min(r.UserRates), slices.Max(r.UserRates)
	}
	cpu := ""
	if transport != "inprocess" && r.CPU >= 0 {
		cpu = fmt.Sprintf("%.3f", r.CPU.Seconds())
	}
	return fmt.Sprintf("%s,%d,%s,%d,%d,%d,%d,%.6f,%.3f,%.6f,,%s,%s,%s,%s,%s,%s,%s,%d,%.3f,%.3f,%s,%d,%.3f,%.3f,%.3f,%.6f",
		commit, d, scenario, size, r.Files, concurrency, rep, secs, mibs, secs, r.CodeColumn(), transport,
		ms(Percentile(r.Parts, 0.5)), ms(Percentile(r.Parts, 0.99)),
		ms(Percentile(r.Completes, 0.5)), ms(Percentile(r.Completes, 1)),
		Counts(r.Retried), r.Resent, lo, hi, cpu,
		len(r.Resumes), Percentile(r.Resumes, 0.5).Seconds(), Percentile(r.Resumes, 1).Seconds(), r.Stalled.Seconds(),
		float64(r.Start.UnixMicro())/1e6)
}

// Counts lists a count of each status, such as "429x1 503x2", or nothing
// for none.
func Counts(m map[string]int) string {
	var keys []string
	for k, v := range m {
		if v > 0 {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for i, k := range keys {
		keys[i] = fmt.Sprintf("%sx%d", k, m[k])
	}
	return strings.Join(keys, " ")
}
