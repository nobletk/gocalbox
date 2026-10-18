package transfer

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/nobletk/gocalbox/internal/events"
)

func TestStatsCountWhatTheEngineDoes(t *testing.T) {
	en := newEnv(t, withLimits(Limits{MaxInflight: 2, MaxInflightUser: 2, MaxSessions: 2, MaxSessionsTotal: 3}))
	if s := en.e.Stats(); s != (Stats{}) {
		t.Errorf("a new engine: %+v", s)
	}
	f := newFile(2*testPartSize + 5)
	a := en.create(alice, "public", "a.bin", f)
	b := en.create(bob, "public", "b.bin", f)

	var wg sync.WaitGroup
	var gates []*gate
	hold := func(user, id string, n int) {
		g := newGate(f.part(n))
		gates = append(gates, g)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := en.e.Part(as(user), PartRequest{ID: id, N: n, SHA256: f.sum(n), Length: -1, Body: g}); err != nil {
				t.Errorf("held part: %v", err)
			}
		}()
		within(t, g.reached)
	}
	hold(alice, a.UploadID, 1)
	if s := en.e.Stats(); s.Sessions != 2 || s.PartsInFlight != 1 {
		t.Errorf("one part on its way: %+v", s)
	}
	hold(alice, a.UploadID, 2)
	if _, err := en.send(alice, a.UploadID, f, 3); !errors.Is(err, ErrTooManyRequests) {
		t.Fatalf("alice's third part: %v", err)
	}
	if _, err := en.send(bob, b.UploadID, f, 1); !errors.Is(err, ErrBusy) {
		t.Fatalf("the server's third part: %v", err)
	}
	if s := en.e.Stats(); s.PartsInFlight != 2 || s.PartsReceived != 0 || s.TooManyRequests != 1 || s.Busy != 1 {
		t.Errorf("two parts on their way: %+v", s)
	}
	for _, g := range gates {
		g.open()
	}
	wg.Wait()
	if _, err := en.send(bob, b.UploadID, f, 1); err != nil {
		t.Fatal(err)
	}

	if _, err := en.e.Create(as(alice), CreateRequest{Dir: "public", Name: "c.bin", Size: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := en.e.Create(as(alice), CreateRequest{Dir: "public", Name: "d.bin", Size: 1}); !errors.Is(err, ErrTooManyUploads) {
		t.Fatalf("alice's third upload: %v", err)
	}
	if _, err := en.e.Create(as(bob), CreateRequest{Dir: "public", Name: "e.bin", Size: 1}); !errors.Is(err, ErrBusy) {
		t.Fatalf("the server's fourth upload: %v", err)
	}

	en.sendAll(alice, a.UploadID, f)
	wrong := bytes.Repeat([]byte{1}, testPartSize)
	if _, err := en.e.Part(as(bob), PartRequest{ID: b.UploadID, N: 2, SHA256: f.sum(2), Length: testPartSize, Body: bytes.NewReader(wrong)}); !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("a part that doesn't match its hash: %v", err)
	}
	if _, err := en.e.Part(as(bob), PartRequest{ID: b.UploadID, N: 2, SHA256: strings.Repeat("0", 64), Length: 1, Body: bytes.NewReader([]byte{0})}); !errors.Is(err, ErrPartSizeMismatch) {
		t.Fatalf("a part of the wrong length: %v", err)
	}
	if _, err := en.e.Complete(as(alice), a.UploadID, f.composite()); err != nil {
		t.Fatal(err)
	}
	if _, err := en.e.Complete(as(alice), a.UploadID, f.composite()); err != nil {
		t.Fatalf("the completion asked again: %v", err)
	}
	want := Stats{
		Sessions:        2, // bob's, and alice's second
		PartsReceived:   4, // alice's 3 and bob's first
		BytesReceived:   int64(len(f.data)) + testPartSize,
		Duplicates:      2, // alice's first two, sent again by sendAll
		Completed:       1,
		Busy:            2,
		TooManyRequests: 1,
		TooManyUploads:  1,
	}
	if s := en.e.Stats(); s != want {
		t.Errorf("stats\n got %+v\nwant %+v", s, want)
	}
}

func TestAnUnrecordedCompletionIsCounted(t *testing.T) {
	en := newEnv(t)
	f := newFile(2 * testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	en.sendAll(alice, c.UploadID, f)
	en.audit.recErr = fmt.Errorf("%w: disk full", events.ErrNotRecorded)
	if _, err := en.e.Complete(as(alice), c.UploadID, f.composite()); !errors.Is(err, events.ErrNotRecorded) {
		t.Fatal(err)
	}
	if s := en.e.Stats(); s.Completed != 1 || s.Sessions != 0 {
		t.Errorf("a completion that placed the file without its records: %+v", s)
	}
}

func TestADuplicateOfAnUploadThatEndedIsNotCounted(t *testing.T) {
	en := newEnv(t)
	f := newFile(2 * testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	if _, err := en.send(alice, c.UploadID, f, 1); err != nil {
		t.Fatal(err)
	}
	g := newGate(f.part(1))
	done := make(chan error, 1)
	go func() {
		_, err := en.e.Part(as(alice), PartRequest{ID: c.UploadID, N: 1, SHA256: f.sum(1), Length: -1, Body: g})
		done <- err
	}()
	within(t, g.reached)
	if _, err := en.e.Abort(as(alice), c.UploadID); err != nil {
		t.Fatal(err)
	}
	g.open()
	if err := within(t, done); !errors.Is(err, ErrClosed) {
		t.Fatalf("the duplicate: %v", err)
	}
	if s := en.e.Stats(); s.Duplicates != 0 || s.PartsInFlight != 0 || s.PartsReceived != 1 {
		t.Errorf("a duplicate answered upload_closed: %+v", s)
	}
}
