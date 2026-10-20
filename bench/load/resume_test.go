package load

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nobletk/gocalbox/internal/transfer"
)

// keyedServer keeps an upload's parts by its client key, as the engine
// keeps a session: a create with a key it knows answers resumed, with the
// parts it has, and a part it has is answered as a duplicate.
type keyedServer struct {
	partSize int64
	mu       sync.Mutex
	files    map[string]map[int][]byte // by client key
	ids      map[string]string         // upload ID to client key
	creates  int
	down     int          // calls left that get no answer
	shutdown int          // calls left answered 503 unavailable
	lostAns  map[int]bool // parts taken whose first answer is lost
	lose     bool         // forget the sessions, as an expired one is
	// hold, in the first session, answers its hold-th part only once
	// another part has come, which then waits until it is cut off and
	// answers with the context's error, as the engine in process does, or
	// with ErrNoAnswer if noAnswer is set, as the HTTPS client does.
	hold     int
	noAnswer bool
	held     chan struct{}
	heldOne  sync.Once
	// downUntil makes every call get no answer until then.
	downUntil time.Time
	calls     []string // part calls as upload ID and part number
}

func newKeyed(partSize int64) *keyedServer {
	return &keyedServer{partSize: partSize, files: map[string]map[int][]byte{}, ids: map[string]string{}, lostAns: map[int]bool{}, held: make(chan struct{})}
}

func (f *keyedServer) gone() error {
	if time.Now().Before(f.downUntil) {
		return fmt.Errorf("%w: connection reset", ErrNoAnswer)
	}
	if f.down > 0 {
		f.down--
		return fmt.Errorf("%w: connection refused", ErrNoAnswer)
	}
	if f.shutdown > 0 {
		f.shutdown--
		return &Refused{Status: 503, Code: "unavailable"}
	}
	return nil
}

func (f *keyedServer) Create(_ context.Context, req transfer.CreateRequest) (transfer.Created, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.gone(); err != nil {
		return transfer.Created{}, err
	}
	f.creates++
	c := transfer.Created{PartSize: f.partSize, PartCount: transfer.PartCount(req.Size, f.partSize)}
	parts, ok := f.files[req.ClientKey]
	if f.lose {
		ok = false
	}
	if ok {
		c.Resumed = true
		var ns []int
		for n := range parts {
			ns = append(ns, n)
		}
		sort.Ints(ns)
		for _, n := range ns {
			c.Received = append(c.Received, transfer.Range{n, n})
		}
	} else {
		f.files[req.ClientKey] = map[int][]byte{}
	}
	c.UploadID = fmt.Sprintf("u%d", f.creates)
	f.ids[c.UploadID] = req.ClientKey
	return c, nil
}

func (f *keyedServer) Part(ctx context.Context, req transfer.PartRequest) (transfer.PartResult, error) {
	b, _ := io.ReadAll(req.Body)
	f.mu.Lock()
	if err := f.gone(); err != nil {
		f.mu.Unlock()
		return transfer.PartResult{}, err
	}
	parts := f.files[f.ids[req.ID]]
	f.calls = append(f.calls, fmt.Sprintf("%s:%d", req.ID, req.N))
	first := f.hold > 0 && req.ID == "u1"
	if first && len(parts) >= f.hold {
		f.mu.Unlock()
		f.heldOne.Do(func() { close(f.held) })
		<-ctx.Done()
		if f.noAnswer {
			return transfer.PartResult{}, fmt.Errorf("%w: %v", ErrNoAnswer, ctx.Err())
		}
		return transfer.PartResult{}, ctx.Err()
	}
	if _, ok := parts[req.N]; ok {
		f.mu.Unlock()
		return transfer.PartResult{Part: req.N, Duplicate: true}, nil
	}
	parts[req.N] = b
	if f.lostAns[req.N] {
		delete(f.lostAns, req.N)
		f.mu.Unlock()
		return transfer.PartResult{}, fmt.Errorf("%w: reset", ErrNoAnswer)
	}
	if first && len(parts) == f.hold {
		f.mu.Unlock()
		<-f.held
		return transfer.PartResult{Part: req.N}, nil
	}
	f.mu.Unlock()
	return transfer.PartResult{Part: req.N}, nil
}

func (f *keyedServer) Complete(_ context.Context, id, composite string) (transfer.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.gone(); err != nil {
		return transfer.Result{}, err
	}
	parts := f.files[f.ids[id]]
	var hs [][sha256.Size]byte
	for n := 1; n <= len(parts); n++ {
		hs = append(hs, sha256.Sum256(parts[n]))
	}
	if composite != transfer.Composite(hs) {
		return transfer.Result{}, transfer.ErrChecksumMismatch
	}
	return transfer.Result{Path: id}, nil
}

// whole returns the bytes the server holds for the upload with client key.
func (f *keyedServer) whole(key string) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	var b []byte
	for n := 1; n <= len(f.files[key]); n++ {
		b = append(b, f.files[key][n]...)
	}
	return b
}

func want(size int64, seed byte) []byte {
	b := make([]byte, size)
	fill(b, 0, seed)
	return b
}

// A file stopped halfway is resumed with its client key: the parts the
// server has aren't sent again, the parts cut off are, and the file arrives
// whole.
func TestAStoppedFileIsResumedByItsClientKey(t *testing.T) {
	srv := newKeyed(4)
	srv.hold = 5 // the stop comes with a part in flight
	const size = 40
	done := make(chan Result)
	go func() {
		done <- Run(context.Background(), Config{Users: []User{{API: srv, Dir: "x"}}, Files: 1, Size: size, Parallel: 2, ResumeAt: 0.5})
	}()
	var res Result
	select {
	case res = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run didn't return")
	}
	key := clientKey("x", "load-000-0000.bin", size, 0)
	if res.CodeColumn() != "201" || len(res.Resumes) != 1 || srv.creates != 2 {
		t.Fatalf("codes %s, resumes %v, creates %d", res.CodeColumn(), res.Resumes, srv.creates)
	}
	if !bytes.Equal(srv.whole(key), want(size, 0)) {
		t.Error("the file arrived with other bytes")
	}
	if res.Resent != 4 {
		t.Errorf("resent %d bytes; the part cut off has 4", res.Resent)
	}
	if len(res.Completes) != 1 || len(res.Parts) != 10 || res.Stalled != 0 || res.CodeColumn() != "201" {
		t.Errorf("completes %v, %d parts accepted, stalled %v", res.Completes, len(res.Parts), res.Stalled)
	}
}

// Over HTTPS, a part cut off gets no answer; it is sent twice all the same.
func TestAPartCutOffWithoutAnAnswerIsSentTwice(t *testing.T) {
	srv := newKeyed(4)
	srv.hold, srv.noAnswer = 5, true
	res := Run(context.Background(), Config{Users: []User{{API: srv, Dir: "x"}}, Files: 1, Size: 40, Parallel: 2, ResumeAt: 0.5})
	if res.CodeColumn() != "201" || res.Resent != 4 || len(res.Resumes) != 1 || res.Stalled != 0 {
		t.Errorf("codes %s, resent %d, resumes %v, stalled %v: a cut isn't the server's silence", res.CodeColumn(), res.Resent, res.Resumes, res.Stalled)
	}
}

// A file of fewer parts than the stop's share asks for still stops once, at
// its first part, and resumes.
func TestASmallFileStopsAtItsFirstPart(t *testing.T) {
	srv := newKeyed(4)
	res := Run(context.Background(), Config{Users: []User{{API: srv, Dir: "x"}}, Files: 1, Size: 4, Parallel: 1, ResumeAt: 0.5})
	if res.CodeColumn() != "201" || len(res.Resumes) != 1 || srv.creates != 2 {
		t.Errorf("codes %s, resumes %v, creates %d", res.CodeColumn(), res.Resumes, srv.creates)
	}
}

// A resumed file's parts go before those of the files queued since.
func TestAResumedFilesPartsGoFirst(t *testing.T) {
	srv := &orderedCreates{keyedServer: newKeyed(4)}
	res := Run(context.Background(), Config{Users: []User{{API: srv, Dir: "x"}}, Files: 2, Size: 16, Parallel: 1, ResumeAt: 0.5})
	if res.CodeColumn() != "201" {
		t.Fatalf("codes %s", res.CodeColumn())
	}
	// u1 is the first file, u2 the second, u3 the first again; u4 the second again.
	srv.keyedServer.mu.Lock()
	defer srv.keyedServer.mu.Unlock()
	got := strings.Join(srv.calls, " ")
	if !strings.HasPrefix(got, "u1:1 u1:2 u3:3 u3:4 u2:1") {
		t.Errorf("part calls %s", got)
	}
}

// orderedCreates answers the first file's second create only once the
// second file has been created, and its parts queued.
type orderedCreates struct {
	*keyedServer
	mu      sync.Mutex
	creates map[string]int
	second  chan struct{}
}

func (o *orderedCreates) Create(ctx context.Context, req transfer.CreateRequest) (transfer.Created, error) {
	o.mu.Lock()
	if o.creates == nil {
		o.creates, o.second = map[string]int{}, make(chan struct{})
	}
	o.creates[req.Name]++
	n := o.creates[req.Name]
	o.mu.Unlock()
	switch {
	case strings.HasSuffix(req.Name, "0001.bin") && n == 1:
		defer close(o.second)
	case strings.HasSuffix(req.Name, "0000.bin") && n == 2:
		<-o.second
		time.Sleep(50 * time.Millisecond)
	}
	return o.keyedServer.Create(ctx, req)
}

// A file whose session the server lost is sent again whole, under a new
// session, and isn't stopped twice.
func TestAFileWhoseSessionIsGoneIsSentAgain(t *testing.T) {
	srv := newKeyed(4)
	srv.lose = true
	res := Run(context.Background(), Config{Users: []User{{API: srv, Dir: "x"}}, Files: 1, Size: 40, Parallel: 1, ResumeAt: 0.5})
	if res.CodeColumn() != "201" || len(res.Resumes) != 0 || srv.creates != 2 || res.Resent != 5*4 {
		t.Errorf("codes %s, resumes %v, creates %d, resent %d", res.CodeColumn(), res.Resumes, srv.creates, res.Resent)
	}
	if !bytes.Equal(srv.whole(clientKey("x", "load-000-0000.bin", 40, 0)), want(40, 0)) {
		t.Error("the file arrived with other bytes")
	}
}

// Within RetryFor, calls that get no answer, or find the server shutting
// down, are tried again; the time without answers is counted, and so are the
// bytes of parts sent again.
func TestAServerThatIsGoneForAWhileIsWaitedFor(t *testing.T) {
	srv := newKeyed(4)
	srv.down, srv.shutdown = 3, 2
	res := Run(context.Background(), Config{Users: []User{{API: srv, Dir: "x"}}, Files: 1, Size: 40, Parallel: 1, RetryFor: 10 * time.Second})
	if res.CodeColumn() != "201" || res.Retried["000"] != 3 || res.Retried["503"] != 2 {
		t.Fatalf("codes %s, retried %v", res.CodeColumn(), res.Retried)
	}
	if res.Stalled <= 0 {
		t.Errorf("stalled %v", res.Stalled)
	}
	if !bytes.Equal(srv.whole(clientKey("x", "load-000-0000.bin", 40, 0)), want(40, 0)) {
		t.Error("the file arrived with other bytes")
	}

	part := newKeyed(4)
	res = Run(context.Background(), Config{Users: []User{{API: &partsDown{keyedServer: part, n: 2}, Dir: "x"}}, Files: 1, Size: 40, Parallel: 1, RetryFor: 10 * time.Second})
	if res.CodeColumn() != "201" || res.Resent != 2*4 {
		t.Errorf("parts without an answer: codes %s, resent %d", res.CodeColumn(), res.Resent)
	}
}

// partsDown answers no part for the first n part calls, after reading them.
type partsDown struct {
	*keyedServer
	n int
}

func (p *partsDown) Part(ctx context.Context, req transfer.PartRequest) (transfer.PartResult, error) {
	p.keyedServer.mu.Lock()
	if p.n > 0 {
		p.n--
		p.keyedServer.mu.Unlock()
		io.Copy(io.Discard, req.Body)
		return transfer.PartResult{}, fmt.Errorf("%w: reset", ErrNoAnswer)
	}
	p.keyedServer.mu.Unlock()
	return p.keyedServer.Part(ctx, req)
}

// Without RetryFor, a call without an answer ends the file, as before; with
// it, a server gone for longer than RetryFor does too.
func TestAServerGoneTooLongEndsTheFile(t *testing.T) {
	srv := newKeyed(4)
	srv.down = 1
	if res := Run(context.Background(), Config{Users: []User{{API: srv, Dir: "x"}}, Files: 1, Size: 40, Parallel: 1}); res.CodeColumn() != "000x1" {
		t.Errorf("without RetryFor: %s", res.CodeColumn())
	}
	srv = newKeyed(4)
	srv.down = 1 << 30
	start := time.Now()
	res := Run(context.Background(), Config{Users: []User{{API: srv, Dir: "x"}}, Files: 1, Size: 40, Parallel: 1, RetryFor: 300 * time.Millisecond})
	if res.CodeColumn() != "000x1" || time.Since(start) > 5*time.Second || res.Stalled < 300*time.Millisecond {
		t.Errorf("gone for good: %s after %v, stalled %v", res.CodeColumn(), time.Since(start), res.Stalled)
	}
}

// Tries that couldn't connect sent nothing, so they aren't sent twice.
func TestATryThatNeverConnectedIsNotSent(t *testing.T) {
	srv := &notConnected{keyedServer: newKeyed(4), n: 3}
	res := Run(context.Background(), Config{Users: []User{{API: srv, Dir: "x"}}, Files: 1, Size: 40, Parallel: 1, RetryFor: 10 * time.Second})
	if res.CodeColumn() != "201" || res.Resent != 0 || res.Retried["000"] != 3 {
		t.Errorf("codes %s, resent %d, retried %v", res.CodeColumn(), res.Resent, res.Retried)
	}
}

// notConnected fails the first n part calls without connecting.
type notConnected struct {
	*keyedServer
	n int
}

func (p *notConnected) Part(ctx context.Context, req transfer.PartRequest) (transfer.PartResult, error) {
	p.keyedServer.mu.Lock()
	if p.n > 0 {
		p.n--
		p.keyedServer.mu.Unlock()
		return transfer.PartResult{}, fmt.Errorf("%w: %w: dial tcp: connection refused", ErrNoAnswer, ErrNotConnected)
	}
	p.keyedServer.mu.Unlock()
	return p.keyedServer.Part(ctx, req)
}

// The time without answers is a user's, and the run's is the longest of its
// users', not their sum; each user's rate is its bytes over its time.
func TestStallsAndRatesArePerUser(t *testing.T) {
	until := time.Now().Add(300 * time.Millisecond)
	a, b := newKeyed(4), newKeyed(4)
	a.downUntil, b.downUntil = until, until
	res := Run(context.Background(), Config{Users: []User{{API: a, Dir: "a"}, {API: b, Dir: "b"}}, Files: 1, Size: 40, Parallel: 1, RetryFor: 10 * time.Second})
	if res.CodeColumn() != "201" || res.Stalled < 250*time.Millisecond || res.Stalled > 500*time.Millisecond {
		t.Errorf("codes %s, stalled %v: each user waited about 300ms", res.CodeColumn(), res.Stalled)
	}
	one := Run(context.Background(), Config{Users: []User{{API: newKeyed(1 << 20), Dir: "x"}}, Files: 2, Size: 8 << 20, Parallel: 2})
	want := float64(one.Bytes) / (1 << 20) / one.Duration.Seconds()
	if len(one.UserRates) != 1 || one.UserRates[0] < want*0.8 || one.UserRates[0] > want*1.2 {
		t.Errorf("one user's rate %v, the run's %.1f MiB/s", one.UserRates, want)
	}
}

// A part taken whose answer was lost is sent again, and answered as a
// duplicate: sent twice, counted once.
func TestAPartWhoseAnswerWasLostIsSentTwice(t *testing.T) {
	srv := newKeyed(4)
	srv.lostAns[3] = true
	res := Run(context.Background(), Config{Users: []User{{API: srv, Dir: "x"}}, Files: 1, Size: 40, Parallel: 1, RetryFor: 10 * time.Second})
	if res.CodeColumn() != "201" || res.Resent != 4 || res.Retried["000"] != 1 || len(res.Parts) != 10 {
		t.Errorf("codes %s, resent %d, retried %v, %d parts", res.CodeColumn(), res.Resent, res.Retried, len(res.Parts))
	}
}

// Refusals aren't sends: a part refused as busy and then taken is sent once.
func TestARefusedPartIsNotSentTwice(t *testing.T) {
	srv := newKeyed(4)
	busy := &busyParts{keyedServer: srv, n: 3}
	res := Run(context.Background(), Config{Users: []User{{API: busy, Dir: "x"}}, Files: 1, Size: 40, Parallel: 1})
	if res.CodeColumn() != "201" || res.Resent != 0 || res.Retried["503"] != 3 {
		t.Errorf("codes %s, resent %d, retried %v", res.CodeColumn(), res.Resent, res.Retried)
	}
}

// busyParts refuses the first n part calls as busy.
type busyParts struct {
	*keyedServer
	n int
}

func (p *busyParts) Part(ctx context.Context, req transfer.PartRequest) (transfer.PartResult, error) {
	p.keyedServer.mu.Lock()
	if p.n > 0 {
		p.n--
		p.keyedServer.mu.Unlock()
		return transfer.PartResult{}, &Refused{Status: 503, Code: "busy"}
	}
	p.keyedServer.mu.Unlock()
	return p.keyedServer.Part(ctx, req)
}

// Every user's rate is reported, and every completion's time.
func TestEachUsersRateAndEachCompletionAreCounted(t *testing.T) {
	a, b := newKeyed(4), newKeyed(4)
	res := Run(context.Background(), Config{Users: []User{{API: a, Dir: "a"}, {API: b, Dir: "b"}}, Files: 3, Size: 40, Parallel: 2})
	if res.CodeColumn() != "201" || len(res.UserRates) != 2 || len(res.Completes) != 6 {
		t.Fatalf("codes %s, rates %v, completes %d", res.CodeColumn(), res.UserRates, len(res.Completes))
	}
	for _, r := range res.UserRates {
		if r <= 0 {
			t.Errorf("rates %v", res.UserRates)
		}
	}
	srv := newKeyed(4)
	srv.down = 1 << 30
	res = Run(context.Background(), Config{Users: []User{{API: srv, Dir: "x"}}, Files: 1, Size: 40, Parallel: 1})
	if len(res.UserRates) != 1 || res.UserRates[0] != 0 || len(res.Completes) != 0 {
		t.Errorf("a user who uploaded nothing: rates %v, completes %v", res.UserRates, res.Completes)
	}
}

// Against the real engine, in process, a stopped file resumes the session
// the engine kept, and the stored files are whole.
func TestResumingAgainstTheEngine(t *testing.T) {
	work := t.TempDir()
	stack, err := NewStack(StackOptions{Work: work, Users: 1, AuditWait: true})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	const size = 5*(8<<20) + 3
	res := Run(context.Background(), Config{Users: stack.Users, Files: 2, Size: size, Parallel: 2, ResumeAt: 0.5})
	if res.CodeColumn() != "201" || len(res.Resumes) != 2 {
		t.Fatalf("codes %s, resumes %v", res.CodeColumn(), res.Resumes)
	}
	if st := stack.Engine.Stats(); st.PartsReceived != 12 {
		t.Errorf("the engine took %d parts, want each of the 12 once", st.PartsReceived)
	}
	for f := range 2 {
		got, err := os.ReadFile(filepath.Join(stack.Root, "users", "load00", fmt.Sprintf("load-000-%04d.bin", f)))
		if err != nil || !bytes.Equal(got, want(size, byte(f))) {
			t.Errorf("file %d: %d bytes, %v", f, len(got), err)
		}
	}
}

// A part the resumed session refuses ends the file with that refusal: only
// the parts of the session before the stop are cut off.
func TestARefusalAfterTheResumeEndsTheFile(t *testing.T) {
	srv := &refuseResumed{keyedServer: newKeyed(4)}
	res := Run(context.Background(), Config{Users: []User{{API: srv, Dir: "x"}}, Files: 1, Size: 40, Parallel: 1, ResumeAt: 0.5})
	if res.CodeColumn() != "409x1" || len(res.Completes) != 0 {
		t.Errorf("codes %s, completes %v", res.CodeColumn(), res.Completes)
	}
}

// refuseResumed refuses every part of a second session.
type refuseResumed struct{ *keyedServer }

func (p *refuseResumed) Part(ctx context.Context, req transfer.PartRequest) (transfer.PartResult, error) {
	if req.ID != "u1" {
		return transfer.PartResult{}, transfer.ErrPartConflict
	}
	return p.keyedServer.Part(ctx, req)
}
