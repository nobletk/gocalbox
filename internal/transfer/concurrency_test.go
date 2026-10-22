package transfer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nobletk/gocalbox/internal/events"
)

func TestTheSamePartFromManyRequestsAtOnce(t *testing.T) {
	en := newEnv(t)
	f := newFile(2 * testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	start := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	written, dups, busy := 0, 0, 0
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			res, err := en.send(alice, c.UploadID, f, 1)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil && !res.Duplicate:
				written++
			case err == nil:
				dups++
			case errors.Is(err, ErrPartInProgress), errors.Is(err, ErrTooManyRequests):
				busy++
			default:
				t.Errorf("unexpected: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if written != 1 {
		t.Errorf("%d requests wrote the part (%d duplicates, %d refused)", written, dups, busy)
	}
	n := 0
	for _, l := range en.logLines(c.UploadID) {
		if l.Op == opPart {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d part lines", n)
	}
	got, _ := os.ReadFile(en.staged(c.UploadID, dataName))
	if !bytes.Equal(got, f.part(1)) {
		t.Error("the staged data differs")
	}
}

func TestCompleteRacingTheLastPart(t *testing.T) {
	en := newEnv(t)
	f := newFile(4 * testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	for n := 1; n <= 3; n++ {
		en.send(alice, c.UploadID, f, n)
	}
	done := make(chan error)
	go func() {
		_, err := en.send(alice, c.UploadID, f, 4)
		done <- err
	}()
	var res Result
	for {
		var err error
		res, err = en.e.Complete(as(alice), c.UploadID, f.composite())
		if err == nil {
			break
		}
		if !errors.Is(err, ErrPartsMissing) && !errors.Is(err, ErrPartsInFlight) {
			t.Fatalf("complete: %v", err)
		}
	}
	if err := within(t, done); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(filepath.Join(en.dir, res.Path))
	if !bytes.Equal(got, f.data) {
		t.Error("the placed file differs")
	}
}

func TestAbortWhilePartsAreInFlight(t *testing.T) {
	en := newEnv(t, withFree(1<<30))
	f := newFile(4 * testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	var gates []*gate
	errs := make(chan error, 4)
	for n := 1; n <= 4; n++ {
		g := newGate(f.part(n))
		gates = append(gates, g)
		go func() {
			_, err := en.e.Part(as(alice), PartRequest{ID: c.UploadID, N: n, SHA256: f.sum(n), Length: -1, Body: g})
			errs <- err
		}()
		within(t, g.reached)
	}
	if _, err := en.e.Abort(as(alice), c.UploadID); err != nil {
		t.Fatal(err)
	}
	for _, g := range gates {
		g.open()
	}
	for range 4 {
		if err := within(t, errs); !errors.Is(err, ErrClosed) {
			t.Errorf("a part: %v", err)
		}
	}
	if exists(en.staged(c.UploadID, dataName)) || en.ledger.Reserved() != 0 || len(en.bus.of(events.UploadFailed)) != 0 {
		t.Errorf("data %v, reserved %d, failed %v", exists(en.staged(c.UploadID, dataName)), en.ledger.Reserved(), en.bus.of(events.UploadFailed))
	}
}

func TestManyUsersAndSessionsAtOnce(t *testing.T) {
	en := newEnv(t, withFree(1<<40))
	users := make([]string, 16)
	for i := range users {
		users[i] = fmt.Sprintf("u-%02d", i)
		en.files.users[users[i]] = &user{name: users[i], enabled: true}
	}
	const sessions = 100
	var wg sync.WaitGroup
	for i := range sessions {
		wg.Add(1)
		go func() {
			defer wg.Done()
			u := users[i%len(users)]
			f := newFile(3*testPartSize + i)
			f.data[0] = byte(i)
			c, err := en.e.Create(as(u), CreateRequest{Dir: "public", Name: fmt.Sprintf("f%03d", i), Size: int64(len(f.data))})
			if err != nil {
				t.Errorf("create %d: %v", i, err)
				return
			}
			var pw sync.WaitGroup
			for n := 1; n <= f.parts(); n++ {
				pw.Add(1)
				go func() {
					defer pw.Done()
					for {
						_, err := en.send(u, c.UploadID, f, n)
						if errors.Is(err, ErrBusy) || errors.Is(err, ErrTooManyRequests) {
							time.Sleep(time.Millisecond)
							continue
						}
						if err != nil {
							t.Errorf("session %d part %d: %v", i, n, err)
						}
						return
					}
				}()
			}
			pw.Wait()
			res, err := en.e.Complete(as(u), c.UploadID, f.composite())
			if err != nil {
				t.Errorf("complete %d: %v", i, err)
				return
			}
			if got, _ := os.ReadFile(filepath.Join(en.dir, res.Path)); !bytes.Equal(got, f.data) {
				t.Errorf("file %d differs", i)
			}
		}()
	}
	wg.Wait()
	if en.e.openTotal != 0 || len(en.e.open) != 0 || len(en.e.userParts) != 0 || en.e.slots != 0 || en.e.queue.Len() != 0 || en.ledger.Reserved() != 0 {
		t.Errorf("open %d %v, parts %v %d, reserved %d", en.e.openTotal, en.e.open, en.e.userParts, en.e.slots, en.ledger.Reserved())
	}
}

func TestPartsKeepFlowingWhileTheAuditLogStalls(t *testing.T) {
	en := newEnv(t)
	bus := events.NewWithQueue(1)
	stall := make(chan struct{})
	bus.Subscribe("stalled", func(events.Event) { <-stall }, events.Options{Buffer: 1})
	defer bus.Close(context.Background())
	defer close(stall)

	f := newFile(20 * testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	en.e.pub = bus
	done := make(chan error)
	go func() {
		for n := 1; n <= f.parts(); n++ {
			if _, err := en.send(alice, c.UploadID, f, n); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("parts waited for the stalled subscriber")
	}
	if bus.Stats().Skipped == 0 {
		t.Error("no part event was skipped")
	}
}

func TestASlowLogHoldsUpOnlyItsOwnSession(t *testing.T) {
	en := newEnv(t)
	f := newFile(2 * testPartSize)
	slow := en.create(alice, "public", "slow.bin", f)
	held, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	en.e.syncFile = func(file *os.File) error {
		if strings.Contains(file.Name(), slow.UploadID) && strings.HasSuffix(file.Name(), logName) {
			once.Do(func() { close(held); <-release })
		}
		return file.Sync()
	}
	done := make(chan error)
	go func() {
		_, err := en.send(alice, slow.UploadID, f, 1)
		done <- err
	}()
	within(t, held)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		c := en.create(bob, "public", "fast.bin", f)
		en.sendAll(bob, c.UploadID, f)
		if _, err := en.e.Complete(as(bob), c.UploadID, f.composite()); err != nil {
			t.Error(err)
		}
		if _, err := en.e.List(as(bob), false); err != nil {
			t.Error(err)
		}
	}()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Error("another session waited for the slow log")
	}
	close(release)
	if err := within(t, done); err != nil {
		t.Fatal(err)
	}
}
