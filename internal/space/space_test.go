package space

import (
	"bytes"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
)

func fixed(n int64) func() (int64, error) { return func() (int64, error) { return n, nil } }

func TestReserveAdmitsOnlyWhatFitsAboveTheFloor(t *testing.T) {
	l := NewLedger(fixed(100), 10)
	a, err := l.Reserve(90)
	if err != nil {
		t.Fatalf("90 of 100 with a floor of 10: %v", err)
	}
	if _, err := l.Reserve(1); !errors.Is(err, ErrInsufficient) {
		t.Fatalf("one byte more: %v, want ErrInsufficient", err)
	}
	if _, err := l.Reserve(-1); err != nil {
		t.Fatalf("unknown size while exactly at the floor: %v", err)
	}
	a.Release()
	a.Release()
	if l.Reserved() != 0 {
		t.Fatalf("reserved after release = %d", l.Reserved())
	}
	if _, err := l.Reserve(90); err != nil {
		t.Fatalf("after release: %v", err)
	}
}

func TestUnknownSizeNeedsTheFloorIntact(t *testing.T) {
	if _, err := NewLedger(fixed(9), 10).Reserve(-1); !errors.Is(err, ErrInsufficient) {
		t.Fatalf("below the floor: %v", err)
	}
	if _, err := NewLedger(fixed(0), 0).Reserve(-1); err != nil {
		t.Fatalf("no floor: %v", err)
	}
	if _, err := NewLedger(fixed(5), 0).Reserve(6); !errors.Is(err, ErrInsufficient) {
		t.Fatalf("no floor but larger than the free space: %v", err)
	}
}

func TestWritesUseUpTheReservation(t *testing.T) {
	l := NewLedger(fixed(1000), 0)
	r, _ := l.Reserve(100)
	var buf bytes.Buffer
	w := r.Writer(&buf)
	w.Write(make([]byte, 30))
	if got := l.Reserved(); got != 70 {
		t.Fatalf("reserved after writing 30 of 100 = %d", got)
	}
	w.Write(make([]byte, 200))
	if got := l.Reserved(); got != 0 {
		t.Fatalf("reserved after writing past the reservation = %d", got)
	}
	r.Release()
	if got := l.Reserved(); got != 0 || buf.Len() != 230 {
		t.Fatalf("reserved %d, written %d", got, buf.Len())
	}
}

type volume struct{ free atomic.Int64 }

func (v *volume) Free() (int64, error)        { return v.free.Load(), nil }
func (v *volume) Write(p []byte) (int, error) { v.free.Add(-int64(len(p))); return len(p), nil }

func TestWritesBeyondTheReservationStopAtTheFloor(t *testing.T) {
	for _, reserve := range []int64{-1, 1000} {
		v := &volume{}
		v.free.Store(10_000)
		l := NewLedger(v.Free, 4_000)
		l.CheckEvery = 500
		r, err := l.Reserve(reserve)
		if err != nil {
			t.Fatal(err)
		}
		w := r.Writer(v)
		var written int64
		for written < 20_000 {
			n, err := w.Write(make([]byte, 100))
			written += int64(n)
			if errors.Is(err, ErrInsufficient) {
				break
			}
		}
		r.Release()
		// The floor is crossed by at most one check interval.
		if left := v.free.Load(); left > 4_000 || left < 4_000-500 {
			t.Errorf("reserve %d: stopped with %d free (wrote %d), want just under the 4000 floor", reserve, left, written)
		}
	}
}

func TestUnmeasurableSpaceAdmitsWrites(t *testing.T) {
	l := NewLedger(func() (int64, error) { return 0, errors.New("statfs: I/O error") }, 1<<30)
	l.CheckEvery = 1
	r, err := l.Reserve(1 << 40)
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if _, err := r.Writer(&bytes.Buffer{}).Write(make([]byte, 10)); err != nil {
		t.Fatalf("Write: %v", err)
	}
}

func TestConcurrentReservationsBalance(t *testing.T) {
	l := NewLedger(fixed(1<<40), 0)
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				r, err := l.Reserve(1000)
				if err != nil {
					t.Error(err)
					return
				}
				r.Writer(&bytes.Buffer{}).Write(make([]byte, j*20))
				r.Release()
			}
		}()
	}
	wg.Wait()
	if got := l.Reserved(); got != 0 {
		t.Fatalf("reserved after all writes = %d", got)
	}
}

func TestFreeMeasuresTheServedVolume(t *testing.T) {
	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	free, err := Free(dir)
	if errors.Is(err, errors.ErrUnsupported) {
		t.Skip("not supported on this system")
	}
	if err != nil || free <= 0 {
		t.Fatalf("Free = %d, %v", free, err)
	}
}

func TestClamp(t *testing.T) {
	if got := clamp(1<<62, 4096); got != 1<<63-1 {
		t.Errorf("overflow not clamped: %d", got)
	}
	if got := clamp(10, 4096); got != 40960 {
		t.Errorf("clamp(10, 4096) = %d", got)
	}
	if got := clamp(10, 0); got != 0 {
		t.Errorf("zero block size = %d", got)
	}
}

func TestAdmitsReservesNothing(t *testing.T) {
	l := NewLedger(fixed(100), 10)
	if err := l.Admits(90); err != nil {
		t.Fatalf("90 of 100 with a floor of 10: %v", err)
	}
	if err := l.Admits(91); !errors.Is(err, ErrInsufficient) {
		t.Fatalf("91: %v, want ErrInsufficient", err)
	}
	if l.Reserved() != 0 {
		t.Fatalf("Admits reserved %d", l.Reserved())
	}
	r, _ := l.Reserve(50)
	if err := l.Admits(41); !errors.Is(err, ErrInsufficient) {
		t.Errorf("Admits ignores other reservations: %v", err)
	}
	r.Release()
	if err := NewLedger(func() (int64, error) { return 0, os.ErrInvalid }, 10).Admits(1 << 40); err != nil {
		t.Errorf("unmeasurable free space must admit: %v", err)
	}
}

// A window: hold some, give back what was written, grow again as needed,
// and drop it all while idle.
func TestGrowConsumeAndLeft(t *testing.T) {
	l := NewLedger(fixed(1000), 100)
	r, err := l.Reserve(300)
	if err != nil {
		t.Fatal(err)
	}
	r.Consume(120)
	if r.Left() != 180 || l.Reserved() != 180 {
		t.Fatalf("after consuming 120: left %d, reserved %d", r.Left(), l.Reserved())
	}
	r.Consume(500)
	r.Consume(-5)
	if r.Left() != 0 || l.Reserved() != 0 {
		t.Fatalf("consuming more than held: left %d, reserved %d", r.Left(), l.Reserved())
	}
	if err := r.Grow(900); err != nil {
		t.Fatalf("growing to the floor: %v", err)
	}
	other, _ := l.Reserve(0)
	if err := other.Grow(1); !errors.Is(err, ErrInsufficient) {
		t.Fatalf("growing past the floor: %v", err)
	}
	if other.Left() != 0 || l.Reserved() != 900 {
		t.Fatalf("a refused Grow held space: left %d, reserved %d", other.Left(), l.Reserved())
	}
	if err := r.Grow(0); err != nil || r.Left() != 900 {
		t.Fatalf("Grow(0): %v, left %d", err, r.Left())
	}
	r.Release()
	if r.Left() != 0 || l.Reserved() != 0 {
		t.Fatalf("after release: left %d, reserved %d", r.Left(), l.Reserved())
	}
	if err := r.Grow(50); err != nil || r.Left() != 50 || l.Reserved() != 50 {
		t.Fatalf("growing after release: %v, left %d, reserved %d", err, r.Left(), l.Reserved())
	}
}

func TestReservationsOfManySessionsAddUp(t *testing.T) {
	l := NewLedger(fixed(1<<30), 0)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, _ := l.Reserve(1 << 20)
			for j := 0; j < 100; j++ {
				r.Grow(1 << 10)
				r.Consume(1 << 10)
			}
			r.Release()
		}()
	}
	wg.Wait()
	if l.Reserved() != 0 {
		t.Errorf("reserved %d after every session released", l.Reserved())
	}
}
