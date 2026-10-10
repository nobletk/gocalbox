package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nobletk/gocalbox/internal/events"
)

var t0 = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

func dl(sec int, actor, addr, file, rng string, size int64, out events.Outcome) events.Event {
	return events.Event{
		Type: events.FileDownloaded, Outcome: out, Time: t0.Add(time.Duration(sec) * time.Second),
		Actor: events.Actor{ID: actor, RemoteAddr: addr}, Resolved: file, Path: file, Range: rng, Size: size,
	}
}

func readBack(t *testing.T, path string) []events.Event {
	t.Helper()
	if _, err := Verify(path); err != nil {
		t.Fatal(err)
	}
	var out []events.Event
	for _, line := range lines(t, path) {
		var rec struct{ Event events.Event }
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatal(err)
		}
		out = append(out, rec.Event)
	}
	return out
}

func newCoalescer(t *testing.T, window time.Duration) (*Coalescer, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	w, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.Close() })
	return NewCoalescer(w, window), path
}

func sentBytes(evs []events.Event, file string) (total int64) {
	for _, ev := range evs {
		if ev.Resolved == file && (ev.Type == events.FileDownloaded || ev.Type == events.FileReadSummary) {
			total += ev.Size
		}
	}
	return total
}

func TestCoalescerAccountsForEveryByte(t *testing.T) {
	c, path := newCoalescer(t, time.Minute)
	const ok = events.OutcomeOK

	c.HandleBatch([]events.Event{
		dl(0, "anon", "10.0.0.1:5000", "movie.mp4", "bytes=0-0", 1, ok),      // a probe...
		dl(1, "anon", "10.0.0.1:5001", "movie.mp4", "bytes=0-", 100_000, ok), // ...then the whole file
		dl(2, "anon", "10.0.0.1:5001", "movie.mp4", "bytes=50000-", 50_000, ok),
		dl(3, "anon", "10.0.0.1:5002", "movie.mp4", "bytes=60000-", 10, events.OutcomeAborted),
		dl(4, "anon", "10.0.0.1:5003", "movie.mp4", "", 100_000, ok),
		{Type: events.FileDeleted, Outcome: ok, Time: t0, Path: "x"},
	})
	c.Close()

	evs := readBack(t, path)
	var types []string
	for _, ev := range evs {
		types = append(types, string(ev.Type))
	}
	want := "file.downloaded,file.downloaded,file.deleted,file.read_summary"
	if strings.Join(types, ",") != want {
		t.Fatalf("records = %s\nwant      %s", strings.Join(types, ","), want)
	}
	sum := evs[3]
	if sum.Count != 3 || sum.Aborted != 1 || sum.Size != 150_010 || !sum.Since.Equal(t0.Add(time.Second)) || !sum.Time.Equal(t0.Add(3*time.Second)) || sum.Seq != 0 {
		t.Errorf("summary = %+v", sum)
	}
	if got := sentBytes(evs, "movie.mp4"); got != 1+150_000+10+100_000 {
		t.Errorf("bytes accounted = %d", got)
	}
}

func TestCoalescerKeysAndWindows(t *testing.T) {
	c, path := newCoalescer(t, time.Minute)
	const ok = events.OutcomeOK
	c.HandleBatch([]events.Event{
		dl(0, "anon", "10.0.0.1:1", "a", "bytes=0-", 5, ok),
		dl(1, "anon", "10.0.0.2:1", "a", "bytes=0-", 5, ok),  // other IP
		dl(2, "alice", "10.0.0.1:1", "a", "bytes=0-", 5, ok), // other actor
		dl(3, "anon", "10.0.0.1:1", "b", "bytes=0-", 5, ok),  // other file
		dl(4, "anon", "10.0.0.1:2", "a", "bytes=1-", 4, ok),  // collapsed
		dl(70, "anon", "10.0.0.1:3", "a", "bytes=2-", 3, ok), // new window: summary, then record
	})
	c.Close()

	evs := readBack(t, path)
	if len(evs) != 6 {
		t.Fatalf("%d records, want 6: %+v", len(evs), evs)
	}
	if evs[4].Type != events.FileReadSummary || evs[4].Size != 4 || evs[5].Range != "bytes=2-" {
		t.Errorf("window rollover: %+v / %+v", evs[4], evs[5])
	}
}

func TestCoalescerFlushesExpiredWindowsWithoutNewEvents(t *testing.T) {
	c, path := newCoalescer(t, time.Minute)
	c.HandleBatch([]events.Event{
		dl(0, "anon", "10.0.0.1:1", "a", "bytes=0-", 5, events.OutcomeOK),
		dl(1, "anon", "10.0.0.1:1", "a", "bytes=3-", 2, events.OutcomeOK),
	})
	c.flushExpired(t0.Add(30 * time.Second))
	if n := len(readBack(t, path)); n != 1 {
		t.Fatalf("summary written before its window ended: %d records", n)
	}
	c.flushExpired(t0.Add(61 * time.Second))
	if evs := readBack(t, path); len(evs) != 2 || evs[1].Type != events.FileReadSummary {
		t.Fatalf("expired window not flushed: %+v", evs)
	}
	c.Close()
	if n := len(readBack(t, path)); n != 2 {
		t.Errorf("Close wrote a second summary: %d records", n)
	}
	c.HandleBatch([]events.Event{{Type: events.FileDeleted}})
	if info, _ := os.Stat(path); info == nil || len(readBack(t, path)) != 2 {
		t.Error("events accepted after Close")
	}
}

func TestCoalescerCollapsesAbandonedSeeks(t *testing.T) {
	c, path := newCoalescer(t, time.Minute)
	const aborted = events.OutcomeAborted
	batch := []events.Event{dl(0, "anon", "10.0.0.1:1", "movie.mp4", "bytes=0-", 65536, aborted)}
	for i := 1; i <= 24; i++ {
		batch = append(batch, dl(i, "anon", "10.0.0.1:1", "movie.mp4", fmt.Sprintf("bytes=%d-", i<<20), 65536, aborted))
	}
	batch = append(batch, dl(25, "anon", "10.0.0.1:1", "movie.mp4", "bytes=999999999-", 0, events.OutcomeInvalid))
	c.HandleBatch(batch)
	c.Close()

	evs := readBack(t, path)
	if len(evs) != 3 {
		t.Fatalf("%d records for 25 abandoned seeks and one bad range, want 3: %+v", len(evs), evs)
	}
	if evs[0].Outcome != aborted || evs[0].Range != "bytes=0-" {
		t.Errorf("first request not written at once: %+v", evs[0])
	}
	if evs[1].Outcome != events.OutcomeInvalid {
		t.Errorf("failed ranged request was collapsed: %+v", evs[1])
	}
	if sum := evs[2]; sum.Type != events.FileReadSummary || sum.Count != 24 || sum.Aborted != 24 || sum.Size != 24*65536 {
		t.Errorf("summary = %+v", sum)
	}
}
