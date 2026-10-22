package load

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/nobletk/gocalbox/internal/transfer"
)

// gated holds every part call after its first after ones until open is
// closed, so that a fault called on another goroutine sees the parts it
// came after, and no more.
type gated struct {
	*keyedServer
	after int
	calls int
	open  chan struct{}
}

func (g *gated) Part(ctx context.Context, req transfer.PartRequest) (transfer.PartResult, error) {
	g.keyedServer.mu.Lock()
	g.calls++
	wait := g.calls > g.after
	g.keyedServer.mu.Unlock()
	if wait {
		<-g.open
	}
	return g.keyedServer.Part(ctx, req)
}

// The fault is called once, as soon as a file has its share of parts
// accepted, while the parts go on; the run waits for it to return.
func TestTheFaultIsCalledOnceAtItsShare(t *testing.T) {
	srv := &gated{keyedServer: newKeyed(4), after: 5, open: make(chan struct{})}
	var mu sync.Mutex
	calls, had := 0, 0
	key := clientKey("x", "load-000-0000.bin", 40, 0)
	fault := func() error {
		srv.mu.Lock()
		n := len(srv.files[key])
		srv.mu.Unlock()
		mu.Lock()
		calls++
		had = n
		mu.Unlock()
		time.Sleep(200 * time.Millisecond)
		close(srv.open)
		return nil
	}
	start := time.Now()
	res := Run(context.Background(), Config{Users: []User{{API: srv, Dir: "x"}}, Files: 2, Size: 40, Parallel: 1, FaultAt: 0.5, Fault: fault})
	if res.CodeColumn() != "201" || !res.Faulted || res.FaultErr != nil {
		t.Fatalf("codes %s, faulted %v, %v", res.CodeColumn(), res.Faulted, res.FaultErr)
	}
	if calls != 1 || had != 5 {
		t.Errorf("called %d times, the first file holding %d of its 10 parts", calls, had)
	}
	if time.Since(start) < 200*time.Millisecond {
		t.Errorf("the run returned after %v, before its fault", time.Since(start))
	}
	// One user sends its files one after another at parallel 1: only the first had begun.
	if len(res.Resumes) != 1 || res.Resumes[0] <= 0 || res.Resumes[0] > res.Duration {
		t.Errorf("resumes %v of a run of %v", res.Resumes, res.Duration)
	}
}

// Every file that had begun before the fault and is uploaded counts the time
// from the fault to its end; one begun after it doesn't.
func TestEachFileUnderwayAtTheFaultCountsItsTime(t *testing.T) {
	srv := &barrier{keyedServer: newKeyed(4), n: 2, all: make(chan struct{})}
	res := Run(context.Background(), Config{Users: []User{{API: srv, Dir: "x"}, {API: srv, Dir: "y"}}, Files: 1, Size: 40, Parallel: 2,
		FaultAt: 0.1, Fault: func() error { return nil }})
	if res.CodeColumn() != "201" || len(res.Resumes) != 2 {
		t.Errorf("both begun before it: codes %s, resumes %v", res.CodeColumn(), res.Resumes)
	}
	one := newKeyed(4)
	res = Run(context.Background(), Config{Users: []User{{API: one, Dir: "x"}}, Files: 2, Size: 40, Parallel: 1,
		FaultAt: 0.1, Fault: func() error { return nil }})
	if res.CodeColumn() != "201" || len(res.Resumes) != 1 {
		t.Errorf("the second begun after it: codes %s, resumes %v", res.CodeColumn(), res.Resumes)
	}
}

// barrier answers no create until n have come.
type barrier struct {
	*keyedServer
	n    int
	all  chan struct{}
	once sync.Once
}

func (b *barrier) Create(ctx context.Context, req transfer.CreateRequest) (transfer.Created, error) {
	b.keyedServer.mu.Lock()
	b.n--
	last := b.n == 0
	b.keyedServer.mu.Unlock()
	if last {
		b.once.Do(func() { close(b.all) })
	}
	<-b.all
	return b.keyedServer.Create(ctx, req)
}

// What the fault returns is the run's; the files go on all the same.
func TestTheFaultsErrorIsKept(t *testing.T) {
	boom := errors.New("boom")
	res := Run(context.Background(), Config{Users: []User{{API: newKeyed(4), Dir: "x"}}, Files: 1, Size: 40, Parallel: 1, FaultAt: 0.5,
		Fault: func() error { return boom }})
	if res.CodeColumn() != "201" || !res.Faulted || !errors.Is(res.FaultErr, boom) {
		t.Errorf("codes %s, faulted %v, %v", res.CodeColumn(), res.Faulted, res.FaultErr)
	}
}

// A fault that takes the server away is waited out with RetryFor, and the
// file arrives whole.
func TestAFaultThatTakesTheServerAwayIsWaitedOut(t *testing.T) {
	srv := &gated{keyedServer: newKeyed(4), after: 5, open: make(chan struct{})}
	res := Run(context.Background(), Config{Users: []User{{API: srv, Dir: "x"}}, Files: 1, Size: 40, Parallel: 1, RetryFor: 10 * time.Second,
		FaultAt: 0.5, Fault: func() error {
			srv.mu.Lock()
			srv.downUntil = time.Now().Add(300 * time.Millisecond)
			srv.mu.Unlock()
			close(srv.open)
			return nil
		}})
	if res.CodeColumn() != "201" || res.Retried["000"] == 0 || res.Stalled <= 0 {
		t.Fatalf("codes %s, retried %v, stalled %v", res.CodeColumn(), res.Retried, res.Stalled)
	}
	if len(res.Resumes) != 1 || res.Resumes[0] < 300*time.Millisecond {
		t.Errorf("resumes %v", res.Resumes)
	}
	if !bytes.Equal(srv.whole(clientKey("x", "load-000-0000.bin", 40, 0)), want(40, 0)) {
		t.Error("the file arrived with other bytes")
	}
}

// A file of one part reaches any share with it; without FaultAt, or without
// a fault, nothing is called.
func TestTheFaultsShareRoundsDownButToOnePart(t *testing.T) {
	called := false
	res := Run(context.Background(), Config{Users: []User{{API: newKeyed(64), Dir: "x"}}, Files: 1, Size: 40, Parallel: 1, FaultAt: 0.9,
		Fault: func() error { called = true; return nil }})
	if !called || !res.Faulted {
		t.Errorf("one part: called %v, faulted %v", called, res.Faulted)
	}
	srv := &gated{keyedServer: newKeyed(4), after: 9, open: make(chan struct{})}
	var at int
	key := clientKey("x", "load-000-0000.bin", 40, 0)
	Run(context.Background(), Config{Users: []User{{API: srv, Dir: "x"}}, Files: 1, Size: 40, Parallel: 1, FaultAt: 0.99,
		Fault: func() error { srv.mu.Lock(); at = len(srv.files[key]); srv.mu.Unlock(); close(srv.open); return nil }})
	if at != 9 {
		t.Errorf("at 0.99 of 10 parts: called with %d in", at)
	}
	called = false
	res = Run(context.Background(), Config{Users: []User{{API: newKeyed(4), Dir: "x"}}, Files: 1, Size: 40, Parallel: 1,
		Fault: func() error { called = true; return nil }})
	if called || res.Faulted || len(res.Resumes) != 0 {
		t.Errorf("without FaultAt: called %v, faulted %v, resumes %v", called, res.Faulted, res.Resumes)
	}
	res = Run(context.Background(), Config{Users: []User{{API: newKeyed(4), Dir: "x"}}, Files: 1, Size: 40, Parallel: 1, FaultAt: 0.5})
	if res.Faulted || res.CodeColumn() != "201" {
		t.Errorf("without a fault: faulted %v, codes %s", res.Faulted, res.CodeColumn())
	}
}

// slowFirst takes delay over each of its first n part calls.
type slowFirst struct {
	*keyedServer
	n     int
	delay time.Duration
}

func (s *slowFirst) Part(ctx context.Context, req transfer.PartRequest) (transfer.PartResult, error) {
	s.keyedServer.mu.Lock()
	slow := s.n > 0
	s.n--
	s.keyedServer.mu.Unlock()
	if slow {
		time.Sleep(s.delay)
	}
	return s.keyedServer.Part(ctx, req)
}

// The time counted runs from the fault, not from the file's start.
func TestTheResumeTimeRunsFromTheFault(t *testing.T) {
	srv := &slowFirst{keyedServer: newKeyed(4), n: 5, delay: 80 * time.Millisecond}
	res := Run(context.Background(), Config{Users: []User{{API: srv, Dir: "x"}}, Files: 1, Size: 40, Parallel: 1, FaultAt: 0.5,
		Fault: func() error { return nil }})
	if len(res.Resumes) != 1 || res.Resumes[0] > res.Duration-350*time.Millisecond {
		t.Errorf("resumes %v of a run of %v, whose first 400 ms came before the fault", res.Resumes, res.Duration)
	}
}

// The parts go on while the fault runs.
func TestThePartsGoOnDuringTheFault(t *testing.T) {
	srv := &gated{keyedServer: newKeyed(4), after: 5, open: make(chan struct{})}
	key := clientKey("x", "load-000-0000.bin", 40, 0)
	held := func() int { srv.mu.Lock(); defer srv.mu.Unlock(); return len(srv.files[key]) }
	res := Run(context.Background(), Config{Users: []User{{API: srv, Dir: "x"}}, Files: 1, Size: 40, Parallel: 1, FaultAt: 0.5,
		Fault: func() error {
			at := held()
			close(srv.open)
			for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
				if held() > at {
					return nil
				}
			}
			return errors.New("no part came while the fault ran")
		}})
	if res.CodeColumn() != "201" || res.FaultErr != nil {
		t.Errorf("codes %s, %v", res.CodeColumn(), res.FaultErr)
	}
}

// A fault that never came, because no file reached its share, isn't waited for.
func TestAFaultThatNeverCameIsNotWaitedFor(t *testing.T) {
	srv := newKeyed(4)
	srv.down = 1
	done := make(chan Result, 1)
	go func() {
		done <- Run(context.Background(), Config{Users: []User{{API: srv, Dir: "x"}}, Files: 1, Size: 40, Parallel: 1, FaultAt: 0.5,
			Fault: func() error { return nil }})
	}()
	select {
	case res := <-done:
		if res.Faulted || res.CodeColumn() != "000x1" {
			t.Errorf("faulted %v, codes %s", res.Faulted, res.CodeColumn())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the run waited for a fault that never came")
	}
}
