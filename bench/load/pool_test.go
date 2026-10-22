package load

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/nobletk/gocalbox/internal/transfer"
)

// fastRetries shortens the wait after a refusal that says none.
func fastRetries(t *testing.T, d time.Duration) {
	prev := noRetryAfter
	noRetryAfter = d
	t.Cleanup(func() { noRetryAfter = prev })
}

func TestThePoolDropsOnARefusalAndGrowsBack(t *testing.T) {
	ctx := context.Background()
	p := newPool(4)
	take := func() int {
		t.Helper()
		w, err := p.acquire(ctx, false)
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	// Four parts sent in one window; three refused: the pool drops once.
	ws := []int{take(), take(), take(), take()}
	p.release(ws[0], false, true)
	p.release(ws[1], false, true)
	p.release(ws[2], false, true)
	if got := p.size(); got != 3 {
		t.Fatalf("after three refusals in one window: %d places, want 3", got)
	}
	p.release(ws[3], true, false)
	// A part sent after the drop and refused drops it again; and again, but
	// never below one.
	for _, want := range []int{2, 1, 1} {
		p.release(take(), false, true)
		if got := p.size(); got != want {
			t.Fatalf("a refusal in a new window: %d places, want %d", got, want)
		}
	}
	// Growing back: one place needs one part accepted, two need two, and so
	// on, up to the cap; a refusal starts the count again.
	accept := func(n int) {
		for range n {
			p.release(take(), true, false)
		}
	}
	accept(1)
	if p.size() != 2 {
		t.Fatalf("after one part accepted at one place: %d", p.size())
	}
	accept(1)
	if p.size() != 2 {
		t.Fatalf("after one more part accepted at two places: %d", p.size())
	}
	w := take()
	p.release(w, false, true) // a refusal: down to 1, the run lost
	accept(1)
	if p.size() != 2 {
		t.Fatalf("after a refusal and one part accepted: %d", p.size())
	}
	for _, step := range []struct{ accept, want int }{{1, 2}, {1, 3}, {2, 3}, {1, 4}, {8, 4}} {
		accept(step.accept)
		if p.size() != step.want {
			t.Fatalf("after %d more parts accepted: %d, want %d", step.accept, p.size(), step.want)
		}
	}
	// A part accepted or answered otherwise leaves the size alone.
	p.release(take(), false, false)
	if p.size() != 4 {
		t.Fatalf("after a part that failed otherwise: %d", p.size())
	}
}

// A part sent again takes the place before a new part, whichever came to
// wait first. Of goroutines woken together the scheduler tends to run the
// last first, so both orders are tried, many times.
func TestAPartSentAgainGoesFirst(t *testing.T) {
	ctx := context.Background()
	for i := range 40 {
		againFirst := i%2 == 0
		p := newPool(1)
		w, _ := p.acquire(ctx, false)
		order := make(chan string, 2)
		var wg sync.WaitGroup
		wait := func(again bool) {
			wg.Add(1)
			go func() {
				defer wg.Done()
				w, err := p.acquire(ctx, again)
				if err == nil {
					order <- map[bool]string{false: "new", true: "again"}[again]
					p.release(w, true, false)
				}
			}()
			time.Sleep(5 * time.Millisecond)
		}
		wait(againFirst)
		wait(!againFirst)
		p.release(w, true, false)
		wg.Wait()
		if first := <-order; first != "again" {
			t.Fatalf("again waiting first %v: %q took the place first, want the part sent again", againFirst, first)
		}
	}
}

// Parts accepted from a window before the last drop don't grow the pool,
// and a refusal from one still ends the run of parts accepted.
func TestOnlyTheCurrentWindowGrowsThePool(t *testing.T) {
	ctx := context.Background()
	p := newPool(4)
	take := func() int {
		t.Helper()
		w, err := p.acquire(ctx, false)
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	old := []int{take(), take(), take(), take()}
	p.release(old[0], false, true)
	p.release(old[2], true, false)
	p.release(old[3], true, false)
	if got := p.size(); got != 3 {
		t.Fatalf("after a refusal and two parts of its window accepted: %d places, want 3", got)
	}
	p.release(take(), true, false)
	p.release(take(), true, false)
	p.release(old[1], false, true)
	if got := p.size(); got != 3 {
		t.Fatalf("after a refusal from an old window: %d places, want 3", got)
	}
	p.release(take(), true, false)
	p.release(take(), true, false)
	if got := p.size(); got != 3 {
		t.Fatalf("two parts accepted since the old window's refusal grew the pool to %d", got)
	}
	p.release(take(), true, false)
	if got := p.size(); got != 4 {
		t.Fatalf("three in a row: %d places, want 4", got)
	}
}

// A server that takes c of a user's parts at a time and refuses the rest at
// once, as a full queue does, before the ones it took end: the pool settles
// within one place of c, and costs a refusal at most every other window.
func TestThePoolSettlesUnderSteadyOverload(t *testing.T) {
	for _, c := range []int{1, 2, 3} {
		p := newPool(4)
		refused := 0 // windows with a refusal
		var sizes []int
		for range 20 {
			n := p.size()
			ws := make([]int, n)
			for i := range n {
				ws[i], _ = p.acquire(context.Background(), false)
			}
			if n > c {
				refused++
			}
			for i := c; i < n; i++ {
				p.release(ws[i], false, true)
			}
			for i := range min(c, n) {
				p.release(ws[i], true, false)
			}
			sizes = append(sizes, n)
		}
		for i, n := range sizes[4:] {
			if n > c+1 {
				t.Errorf("capacity %d: %d places in window %d; sizes %v", c, n, i+4, sizes)
			}
		}
		if refused > 12 {
			t.Errorf("capacity %d: refusals in %d of 20 windows; sizes %v", c, refused, sizes)
		}
	}
}

func TestAWaitForAPlaceWithAnEndedContextTakesNone(t *testing.T) {
	p := newPool(1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.acquire(ctx, false); !errors.Is(err, context.Canceled) {
		t.Fatalf("%v", err)
	}
	if _, err := p.acquire(context.Background(), false); err != nil {
		t.Fatalf("the place was taken by the ended wait: %v", err)
	}
}

// A part sent again that takes the one place left free lets the new parts
// waiting behind it look again at once.
func TestNewPartsTakeAPlaceLeftFreeAfterAPartSentAgain(t *testing.T) {
	ctx := context.Background()
	for range 20 {
		p := newPool(2)
		a, _ := p.acquire(ctx, false)
		b, _ := p.acquire(ctx, false)
		again := make(chan int, 1)
		go func() { w, _ := p.acquire(ctx, true); again <- w }()
		time.Sleep(2 * time.Millisecond)
		fresh := make(chan struct{})
		go func() { p.acquire(ctx, false); close(fresh) }()
		time.Sleep(2 * time.Millisecond)
		p.mu.Lock()
		p.inUse -= 2
		p.cond.Broadcast()
		p.mu.Unlock()
		_, _ = a, b
		<-again
		select {
		case <-fresh:
		case <-time.After(time.Second):
			t.Fatal("a new part still waits with a place free")
		}
	}
}

func TestAPauseCutShortByItsContextSaysSo(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if pause(ctx, time.Hour) {
		t.Error("a pause whose context ended reported it waited")
	}
	if !pause(context.Background(), time.Millisecond) {
		t.Error("a pause that ran its time reported it didn't")
	}
}

func TestAWaitForAPlaceEndsWithItsContext(t *testing.T) {
	p := newPool(1)
	if _, err := p.acquire(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := p.acquire(ctx, false); done <- err }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("%v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the wait didn't end")
	}
}

func TestTheWaitARefusalAsksForIsSpread(t *testing.T) {
	if noRetryAfter != time.Second {
		t.Fatalf("without Retry-After the wait is %v, want 1 s", noRetryAfter)
	}
	fastRetries(t, 40*time.Millisecond)
	if got := retryAfter(&Refused{Status: 503, Code: "busy", RetryAfter: 3 * time.Second}); got != 3*time.Second {
		t.Errorf("Retry-After: 3: %v", got)
	}
	for _, err := range []error{transfer.ErrBusy, &Refused{Status: 429, Code: "too_many_uploads"}} {
		if got := retryAfter(err); got != 40*time.Millisecond {
			t.Errorf("%v without Retry-After: %v", err, got)
		}
	}
	lo, hi := time.Hour, time.Duration(0)
	for range 2000 {
		d := spread(time.Second)
		lo, hi = min(lo, d), max(hi, d)
	}
	if lo < 500*time.Millisecond || hi >= 1500*time.Millisecond || lo > 520*time.Millisecond || hi < 1480*time.Millisecond {
		t.Errorf("1 s spread over %v to %v, want 0.5 to 1.5 s", lo, hi)
	}
}

// busyServer refuses the first parts it is sent for its load, and records
// the order of the parts it takes.
type busyServer struct {
	partSize int64
	refuse   map[int]int // part → refusals left
	mu       sync.Mutex
	taken    []int
	inFlight int
	most     int
	parts    map[int][]byte
	creates  int
	refuseC  int // creates left to refuse with too_many_uploads
	gate     chan struct{}
	hold     time.Duration // how long a part taken stays in flight
	refused  int           // parts refused so far
	// mostSince is the most parts in flight at once since the last refusal.
	mostSince int
}

func (f *busyServer) Create(_ context.Context, req transfer.CreateRequest) (transfer.Created, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.creates++
	if f.refuseC > 0 {
		f.refuseC--
		return transfer.Created{}, &Refused{Status: 429, Code: "too_many_uploads"}
	}
	return transfer.Created{UploadID: "id", PartSize: f.partSize, PartCount: transfer.PartCount(req.Size, f.partSize)}, nil
}

func (f *busyServer) Part(_ context.Context, req transfer.PartRequest) (transfer.PartResult, error) {
	f.mu.Lock()
	if f.refuse[req.N] > 0 {
		f.refuse[req.N]--
		f.refused++
		f.mostSince = 0
		f.mu.Unlock()
		return transfer.PartResult{}, &Refused{Status: 503, Code: "busy", RetryAfter: 0}
	}
	f.inFlight++
	f.most = max(f.most, f.inFlight)
	f.mostSince = max(f.mostSince, f.inFlight)
	gate := f.gate
	f.mu.Unlock()
	if gate != nil {
		<-gate
	}
	time.Sleep(f.hold)
	b, _ := io.ReadAll(req.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.inFlight--
	f.taken = append(f.taken, req.N)
	f.parts[req.N] = b
	return transfer.PartResult{Part: req.N}, nil
}

func (f *busyServer) Complete(context.Context, string, string) (transfer.Result, error) {
	return transfer.Result{}, nil
}

func TestARefusedPartWaitsWithoutItsPlaceAndThenGoesFirst(t *testing.T) {
	fastRetries(t, 200*time.Millisecond)
	srv := &busyServer{partSize: 4, refuse: map[int]int{1: 1}, parts: map[int][]byte{}}
	res := Run(context.Background(), Config{Users: []User{{API: srv, Dir: "x"}}, Files: 1, Size: 4 * 6, Parallel: 2})
	if res.CodeColumn() != "201" || res.Retried["503"] != 1 {
		t.Fatalf("codes %s, retried %v", res.CodeColumn(), res.Retried)
	}
	// While part 1 waited out its refusal, its place went to the next parts.
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.taken) != 6 || srv.taken[0] == 1 {
		t.Errorf("parts taken in the order %v", srv.taken)
	}
}

func TestAPoolNeverSendsMoreThanItsSize(t *testing.T) {
	fastRetries(t, 10*time.Millisecond)
	// Parts 1 and 2 are refused, each once and in one window: the pool of 3
	// drops to 2 and grows back after two parts in a row.
	srv := &busyServer{partSize: 4, refuse: map[int]int{1: 1, 2: 1}, parts: map[int][]byte{}}
	res := Run(context.Background(), Config{Users: []User{{API: srv, Dir: "x"}}, Files: 1, Size: 4 * 20, Parallel: 3})
	if res.CodeColumn() != "201" || res.Retried["503"] != 2 {
		t.Fatalf("codes %s, retried %v", res.CodeColumn(), res.Retried)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.most > 3 {
		t.Errorf("%d parts in flight at once, more than -parallel 3", srv.most)
	}
}

func TestCreatesRefusalsLeaveThePoolAlone(t *testing.T) {
	fastRetries(t, 50*time.Millisecond)
	srv := &busyServer{partSize: 4, parts: map[int][]byte{}, refuseC: 2}
	start := time.Now()
	res := Run(context.Background(), Config{Users: []User{{API: srv, Dir: "x"}}, Files: 1, Size: 8, Parallel: 2})
	if res.CodeColumn() != "201" || res.Retried["429"] != 2 || srv.creates != 3 {
		t.Fatalf("codes %s, retried %v, %d creates", res.CodeColumn(), res.Retried, srv.creates)
	}
	// 50 ms, then 100 ms, each spread over half to one and a half times.
	if took := time.Since(start); took < 75*time.Millisecond {
		t.Errorf("the two refusals were waited out in %v", took)
	}
}

func TestAPartRefusedForItsLoadIsSentAgainAfterRetryAfter(t *testing.T) {
	calls := 0
	srv := &retryAfterAPI{refusals: 1, wait: time.Second, calls: &calls}
	start := time.Now()
	res := Run(context.Background(), Config{Users: []User{{API: srv, Dir: "x"}}, Files: 1, Size: 4, Parallel: 1})
	if res.CodeColumn() != "201" || calls != 2 || res.Retried["503"] != 1 {
		t.Fatalf("codes %s after %d calls, retried %v", res.CodeColumn(), calls, res.Retried)
	}
	if took := time.Since(start); took < 500*time.Millisecond || took > 2*time.Second {
		t.Errorf("Retry-After: 1 waited %v, want 0.5 to 1.5 s", took)
	}
}

// retryAfterAPI refuses its first parts busy with a Retry-After.
type retryAfterAPI struct {
	refusals int
	wait     time.Duration
	calls    *int
}

func (a *retryAfterAPI) Create(_ context.Context, req transfer.CreateRequest) (transfer.Created, error) {
	return transfer.Created{UploadID: "id", PartSize: 4, PartCount: transfer.PartCount(req.Size, 4)}, nil
}

func (a *retryAfterAPI) Part(_ context.Context, req transfer.PartRequest) (transfer.PartResult, error) {
	*a.calls++
	if a.refusals > 0 {
		a.refusals--
		return transfer.PartResult{}, &Refused{Status: 503, Code: "busy", RetryAfter: a.wait}
	}
	io.Copy(io.Discard, req.Body)
	return transfer.PartResult{Part: req.N}, nil
}

func (a *retryAfterAPI) Complete(context.Context, string, string) (transfer.Result, error) {
	return transfer.Result{}, nil
}

// With one place, a refused part gives it up: the next part goes out while
// the refused one waits, and the refused one goes before the parts not yet
// sent once its wait is over.
func TestARefusedPartGivesUpItsOnlyPlace(t *testing.T) {
	fastRetries(t, 200*time.Millisecond)
	srv := &busyServer{partSize: 4, refuse: map[int]int{1: 1}, parts: map[int][]byte{}}
	res := Run(context.Background(), Config{Users: []User{{API: srv, Dir: "x"}}, Files: 1, Size: 4 * 3, Parallel: 1})
	if res.CodeColumn() != "201" {
		t.Fatalf("codes %s", res.CodeColumn())
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.taken) == 0 || srv.taken[0] == 1 {
		t.Errorf("parts taken in the order %v: part 1 kept its place while it waited", srv.taken)
	}
}

func TestARefusedPartGoesBeforeThePartsNotYetSent(t *testing.T) {
	fastRetries(t, time.Millisecond)
	srv := &busyServer{partSize: 4, refuse: map[int]int{1: 1}, parts: map[int][]byte{}, hold: 20 * time.Millisecond}
	res := Run(context.Background(), Config{Users: []User{{API: srv, Dir: "x"}}, Files: 1, Size: 4 * 6, Parallel: 1})
	if res.CodeColumn() != "201" {
		t.Fatalf("codes %s", res.CodeColumn())
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if i := slices.Index(srv.taken, 1); i < 0 || i > 1 {
		t.Errorf("parts taken in the order %v: part 1 went behind parts not yet sent", srv.taken)
	}
}

// After a refusal the user's pool is one smaller while the other parts are
// still in flight, and it grows back once parts sent since are accepted.
func TestARefusalShrinksTheUsersPool(t *testing.T) {
	fastRetries(t, time.Second)
	gate := make(chan struct{})
	srv := &busyServer{partSize: 4, refuse: map[int]int{1: 1}, parts: map[int][]byte{}, gate: gate}
	done := make(chan Result, 1)
	go func() {
		done <- Run(context.Background(), Config{Users: []User{{API: srv, Dir: "x"}}, Files: 1, Size: 4 * 8, Parallel: 4})
	}()
	inFlight := func() int { srv.mu.Lock(); defer srv.mu.Unlock(); return srv.inFlight }
	for deadline := time.Now().Add(5 * time.Second); inFlight() < 3; {
		if time.Now().After(deadline) {
			t.Fatal("the parts didn't go out")
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	n := inFlight()
	close(gate)
	if res := <-done; res.CodeColumn() != "201" {
		t.Fatalf("codes %s", res.CodeColumn())
	}
	if n != 3 {
		t.Errorf("%d parts in flight after one refusal, with -parallel 4; want 3", n)
	}
}

func TestThePoolGrowsBackDuringARun(t *testing.T) {
	fastRetries(t, time.Millisecond)
	srv := &busyServer{partSize: 4, refuse: map[int]int{1: 1}, parts: map[int][]byte{}, hold: 5 * time.Millisecond}
	res := Run(context.Background(), Config{Users: []User{{API: srv, Dir: "x"}}, Files: 1, Size: 4 * 20, Parallel: 2})
	if res.CodeColumn() != "201" || res.Retried["503"] != 1 {
		t.Fatalf("codes %s, retried %v", res.CodeColumn(), res.Retried)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.mostSince != 2 {
		t.Errorf("at most %d parts in flight at once after the refusal, with -parallel 2", srv.mostSince)
	}
}

// A part refused for the server's load just as its file stops is cut off
// with its file, not sent again on its own.
func TestARefusalOfAPartCutByItsFilesStopIsNotARetry(t *testing.T) {
	srv := newKeyed(4)
	srv.hold, srv.cutBusy = 5, true
	res := Run(context.Background(), Config{Users: []User{{API: srv, Dir: "x"}}, Files: 1, Size: 40, Parallel: 2, ResumeAt: 0.5})
	if res.CodeColumn() != "201" || len(res.Resumes) != 1 || len(res.Retried) != 0 {
		t.Errorf("codes %s, resumes %v, retried %v", res.CodeColumn(), res.Resumes, res.Retried)
	}
}

// The queue wakes for its earliest job, wherever it stands.
func TestTheQueueWakesForItsEarliestJob(t *testing.T) {
	q := newQueue()
	now := time.Now()
	q.push(false, job{n: 1, notBefore: now.Add(time.Hour)}, job{n: 2, notBefore: now.Add(20 * time.Millisecond)}, job{n: 3, notBefore: now.Add(time.Hour)})
	got := make(chan job, 1)
	go func() { j, _ := q.pop(); got <- j }()
	select {
	case j := <-got:
		if j.n != 2 {
			t.Errorf("popped part %d", j.n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("still waiting 5 s on, for a job due in 20 ms")
	}
}

// A job pushed while the queue waits for a later one is taken at once.
func TestAJobPushedWhileTheQueueWaitsIsTakenAtOnce(t *testing.T) {
	q := newQueue()
	q.push(false, job{n: 1, notBefore: time.Now().Add(time.Hour)})
	got := make(chan job, 1)
	go func() { j, _ := q.pop(); got <- j }()
	time.Sleep(20 * time.Millisecond)
	pushed := make(chan struct{})
	go func() { q.push(true, job{n: 2}); close(pushed) }()
	select {
	case j := <-got:
		if j.n != 2 {
			t.Errorf("popped part %d", j.n)
		}
	case <-time.After(5 * time.Second):
		select {
		case <-pushed:
			t.Fatal("the job pushed wasn't taken")
		default:
			t.Fatal("the push couldn't take the queue's lock")
		}
	}
}

// refusing answers its first calls busy with a Retry-After of wait, and
// records when each call came.
func refusing(n int, wait time.Duration, calls *[]time.Time) func() (int, error) {
	return func() (int, error) {
		*calls = append(*calls, time.Now())
		if len(*calls) <= n {
			return 0, &Refused{Status: 503, Code: "busy", RetryAfter: wait}
		}
		return 1, nil
	}
}

func TestRefusalsInARowDoubleTheWaitUpToItsCap(t *testing.T) {
	if maxBackOff != 8*time.Second {
		t.Fatalf("the cap is %v, want 8 s", maxBackOff)
	}
	var calls []time.Time
	if _, _, err := retry(context.Background(), retrier{st: newState()}, true, refusing(4, 20*time.Millisecond, &calls)); err != nil {
		t.Fatal(err)
	}
	// 20, 40, 80 and 160 ms, each spread over half to one and a half times.
	if took := calls[4].Sub(calls[0]); took < 150*time.Millisecond {
		t.Errorf("four refusals waited out in %v; doubling, at least 150 ms", took)
	}
	prev := maxBackOff
	maxBackOff = 30 * time.Millisecond
	t.Cleanup(func() { maxBackOff = prev })
	calls = nil
	if _, _, err := retry(context.Background(), retrier{st: newState()}, true, refusing(5, 20*time.Millisecond, &calls)); err != nil {
		t.Fatal(err)
	}
	// 20 ms, then 30 ms four times, spread: at most 210 ms.
	if took := calls[5].Sub(calls[0]); took > 300*time.Millisecond {
		t.Errorf("five refusals with a 30 ms cap waited out in %v", took)
	}
}

func TestTheWaitAfterARefusedCreateIsSpread(t *testing.T) {
	shortest := time.Hour
	for range 30 {
		var calls []time.Time
		if _, _, err := retry(context.Background(), retrier{st: newState()}, true, refusing(1, 40*time.Millisecond, &calls)); err != nil {
			t.Fatal(err)
		}
		shortest = min(shortest, calls[1].Sub(calls[0]))
	}
	if shortest >= 36*time.Millisecond {
		t.Errorf("of 30 waits of Retry-After 40 ms spread, the shortest was %v", shortest)
	}
}

// scriptServer answers each try of a part as its script says, by file and
// part ("f1:2"), and records the parts it takes in order; tries past the
// script are taken at once. A create of a file it has a gate for, by the
// order of creates, waits for it.
type scriptServer struct {
	mu          sync.Mutex
	creates     int
	createGates map[int]chan struct{}
	script      map[string][]step
	arrived     int
	taken       []string
}

type step struct {
	gate   chan struct{} // waited for first, when set
	refuse bool          // busy, asking to wait 1 ns
}

func (f *scriptServer) Create(_ context.Context, req transfer.CreateRequest) (transfer.Created, error) {
	f.mu.Lock()
	f.creates++
	n := f.creates
	gate := f.createGates[n]
	f.mu.Unlock()
	if gate != nil {
		<-gate
	}
	return transfer.Created{UploadID: fmt.Sprintf("f%d", n), PartSize: 4, PartCount: transfer.PartCount(req.Size, 4)}, nil
}

func (f *scriptServer) Part(_ context.Context, req transfer.PartRequest) (transfer.PartResult, error) {
	key := fmt.Sprintf("%s:%d", req.ID, req.N)
	f.mu.Lock()
	f.arrived++
	var st step
	if s := f.script[key]; len(s) > 0 {
		st, f.script[key] = s[0], s[1:]
	}
	f.mu.Unlock()
	if st.gate != nil {
		<-st.gate
	}
	if st.refuse {
		return transfer.PartResult{}, &Refused{Status: 503, Code: "busy", RetryAfter: time.Nanosecond}
	}
	io.Copy(io.Discard, req.Body)
	f.mu.Lock()
	f.taken = append(f.taken, key)
	f.mu.Unlock()
	return transfer.PartResult{Part: req.N}, nil
}

func (f *scriptServer) Complete(context.Context, string, string) (transfer.Result, error) {
	return transfer.Result{}, nil
}

func (f *scriptServer) until(t *testing.T, arrived int) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(time.Millisecond) {
		f.mu.Lock()
		n := f.arrived
		f.mu.Unlock()
		if n >= arrived {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d parts came, want %d", n, arrived)
		}
	}
}

// A part refused and waiting for a place takes it before a part of a file
// that came to wait after it. The pauses let each worker reach its wait.
func TestAPartSentAgainTakesAPlaceBeforeANewFilesPart(t *testing.T) {
	for range 10 {
		g0, g1, g2, g3 := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
		create2 := make(chan struct{})
		srv := &scriptServer{createGates: map[int]chan struct{}{2: create2}, script: map[string][]step{
			"f1:1": {{gate: g0, refuse: true}, {gate: g1, refuse: true}},
			"f1:2": {{gate: g2}},
			"f1:3": {{gate: g3}},
		}}
		done := make(chan Result, 1)
		go func() {
			done <- Run(context.Background(), Config{Users: []User{{API: srv, Dir: "x"}}, Files: 2, Size: 12, Parallel: 3})
		}()
		srv.until(t, 3)
		close(g0) // f1:1 refused, down to two places; f1:2 and f1:3 held
		time.Sleep(20 * time.Millisecond)
		close(g2) // f1:1 takes the place f1:2 leaves
		srv.until(t, 4)
		time.Sleep(20 * time.Millisecond)
		close(g1) // f1:1 refused again, down to one place, f1:3's
		time.Sleep(20 * time.Millisecond)
		close(create2) // f2:1 comes to wait behind f1:1
		time.Sleep(20 * time.Millisecond)
		close(g3)
		if res := <-done; res.CodeColumn() != "201,201" && res.CodeColumn() != "201" {
			t.Fatalf("codes %s", res.CodeColumn())
		}
		srv.mu.Lock()
		taken := srv.taken
		srv.mu.Unlock()
		if slices.Index(taken, "f1:1") > slices.Index(taken, "f2:1") {
			t.Fatalf("parts taken in the order %v: f2:1 took the place f1:1 waited for", taken)
		}
	}
}
