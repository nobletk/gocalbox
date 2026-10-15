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
	return NewCoalescer(w, window, window), path
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
	captureLost(t)
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

func login(sec int, name, addr string, out events.Outcome, detail string) events.Event {
	return events.Event{
		Type: events.AuthLogin, Outcome: out, Time: t0.Add(time.Duration(sec) * time.Second),
		Actor: events.Actor{ID: events.AnonymousID, RemoteAddr: addr}, Path: name, Detail: detail,
	}
}

func TestFailedLoginsAreWrittenOnceAndThenCounted(t *testing.T) {
	c, path := newCoalescer(t, time.Minute)
	const denied = events.OutcomeDenied
	batch := []events.Event{login(0, "alice", "10.0.0.1:1", denied, "invalid_credentials")}
	for i := 1; i <= 30; i++ {
		batch = append(batch, login(i, "alice", fmt.Sprintf("10.0.0.1:%d", i), denied, "invalid_credentials"))
	}
	for i := 31; i <= 50; i++ {
		batch = append(batch, login(i, "alice", "10.0.0.1:1", denied, "too_many_attempts"))
	}
	batch = append(batch, login(51, "alice", "10.0.0.1:1", denied, "busy"))
	c.HandleBatch(batch)
	c.Close()

	evs := readBack(t, path)
	if len(evs) != 2 {
		t.Fatalf("%d records for 52 failures of one pair, want 2: %+v", len(evs), evs)
	}
	if evs[0].Type != events.AuthLogin || evs[0].Detail != "invalid_credentials" {
		t.Errorf("first failure not written at once: %+v", evs[0])
	}
	sum := evs[1]
	if sum.Type != events.AuthLoginSummary || sum.Outcome != denied || sum.Path != "alice" || sum.Count != 51 ||
		sum.Detail != "busy=1 invalid_credentials=30 too_many_attempts=20" ||
		!sum.Since.Equal(t0.Add(time.Second)) || !sum.Time.Equal(t0.Add(51*time.Second)) {
		t.Errorf("summary = %+v", sum)
	}
}

func TestFailedLoginsAreKeyedByUsernameAndAddress(t *testing.T) {
	c, path := newCoalescer(t, time.Minute)
	const denied = events.OutcomeDenied
	c.HandleBatch([]events.Event{
		login(0, "alice", "10.0.0.1:1", denied, "invalid_credentials"),
		login(1, "bob", "10.0.0.1:1", denied, "invalid_credentials"),    // other username
		login(2, "alice", "10.0.0.2:1", denied, "invalid_credentials"),  // other address
		login(3, "alice", "10.0.0.1:2", denied, "invalid_credentials"),  // collapsed
		login(70, "alice", "10.0.0.1:3", denied, "invalid_credentials"), // new window: summary, then record
	})
	c.Close()

	evs := readBack(t, path)
	if len(evs) != 5 {
		t.Fatalf("%d records, want 5: %+v", len(evs), evs)
	}
	if evs[3].Type != events.AuthLoginSummary || evs[3].Count != 1 || evs[4].Type != events.AuthLogin {
		t.Errorf("window rollover: %+v / %+v", evs[3], evs[4])
	}
}

func TestASuccessfulLoginEndsThePairsWindow(t *testing.T) {
	c, path := newCoalescer(t, time.Minute)
	const denied = events.OutcomeDenied
	c.HandleBatch([]events.Event{
		login(0, "alice", "10.0.0.1:1", denied, "invalid_credentials"),
		login(1, "alice", "10.0.0.1:1", denied, "invalid_credentials"),
		login(2, "alice", "10.0.0.1:1", events.OutcomeOK, ""),
		login(3, "alice", "10.0.0.1:1", denied, "invalid_credentials"),
	})
	c.Close()

	var got []string
	for _, ev := range readBack(t, path) {
		got = append(got, fmt.Sprintf("%s/%s", ev.Type, ev.Outcome))
	}
	want := "auth.login/denied auth.login_summary/denied auth.login/ok auth.login/denied"
	if strings.Join(got, " ") != want {
		t.Errorf("records = %s\nwant      %s", strings.Join(got, " "), want)
	}
}

func TestFailedLoginsFromEverChangingPairsStayBounded(t *testing.T) {
	c, path := newCoalescer(t, time.Minute)
	var batch []events.Event
	for i := range 5000 {
		batch = append(batch, login(i%50, fmt.Sprintf("guess%d", i), fmt.Sprintf("10.0.%d.%d:1", i/250, i%250), events.OutcomeDenied, "too_many_attempts"))
	}
	c.HandleBatch(batch)
	c.Close()

	evs := readBack(t, path)
	if len(evs) != maxOtherPairs+1 {
		t.Fatalf("%d records for 5000 failures from 5000 pairs, want %d", len(evs), maxOtherPairs+1)
	}
	last := evs[len(evs)-1]
	if last.Type != events.AuthLoginSummary || last.Path != "" || last.Count != 5000-maxOtherPairs || last.Detail != fmt.Sprintf("too_many_attempts=%d", 5000-maxOtherPairs) {
		t.Errorf("summary of the other pairs = %+v", last)
	}
}

func account(ev events.Event, id string) events.Event {
	ev.Resolved = id
	return ev
}

func TestMadeUpNamesCantHideAnAttackOnAnAccount(t *testing.T) {
	c, path := newCoalescer(t, time.Minute)
	const denied = events.OutcomeDenied
	var batch []events.Event
	for i := range 500 {
		batch = append(batch, login(0, fmt.Sprintf("filler%d", i), "198.51.100.7:1", denied, "too_many_attempts"))
	}
	for i := range 50 {
		batch = append(batch, account(login(1+i, "alice", "203.0.113.9:1", denied, "invalid_credentials"), "u-alice"))
	}
	c.HandleBatch(batch)
	c.Close()

	var first, summary *events.Event
	evs := readBack(t, path)
	for i, ev := range evs {
		if ev.Path == "alice" && ev.Type == events.AuthLogin {
			first = &evs[i]
		}
		if ev.Path == "alice" && ev.Type == events.AuthLoginSummary {
			summary = &evs[i]
		}
	}
	if first == nil || first.Actor.RemoteAddr != "203.0.113.9:1" || first.Resolved != "u-alice" {
		t.Errorf("the first failure on alice = %+v", first)
	}
	if summary == nil || summary.Count != 49 || summary.Resolved != "u-alice" || summary.Actor.RemoteAddr != "203.0.113.9:1" {
		t.Errorf("the summary for alice = %+v", summary)
	}
}

func TestAnAccountKeepsTenAddressesApart(t *testing.T) {
	c, path := newCoalescer(t, time.Minute)
	var batch []events.Event
	for i := range 300 {
		batch = append(batch, account(login(i%60, "alice", fmt.Sprintf("10.1.%d.%d:1", i/250, i%250), events.OutcomeDenied, "too_many_attempts"), "u-alice"))
	}
	c.HandleBatch(batch)
	c.Close()

	evs := readBack(t, path)
	if len(evs) != maxAddressesPerAccount+1 {
		t.Fatalf("%d records for 300 addresses, want %d", len(evs), maxAddressesPerAccount+1)
	}
	last := evs[len(evs)-1]
	if last.Type != events.AuthLoginSummary || last.Path != "alice" || last.Resolved != "u-alice" || last.Actor.RemoteAddr != "" || last.Count != 300-maxAddressesPerAccount {
		t.Errorf("summary of alice's other addresses = %+v", last)
	}
}

func TestTheOverflowSummaryStartsAgainAfterItsWindow(t *testing.T) {
	c, path := newCoalescer(t, time.Minute)
	var batch []events.Event
	for i := range maxOtherPairs + 2 {
		batch = append(batch, login(0, fmt.Sprintf("name%d", i), "10.0.0.1:1", events.OutcomeDenied, "too_many_attempts"))
	}
	c.HandleBatch(batch)
	c.HandleBatch([]events.Event{
		login(30, "late1", "10.0.0.1:1", events.OutcomeDenied, "busy"),
		login(61, "late2", "10.0.0.1:1", events.OutcomeDenied, "busy"),
	})
	evs := readBack(t, path)
	last := evs[len(evs)-1]
	if len(evs) != maxOtherPairs+1 || last.Path != "" || last.Count != 3 || last.Detail != "busy=1 too_many_attempts=2" {
		t.Fatalf("after the overflow's window: %d records, last %+v", len(evs), last)
	}
	c.Close()
	evs = readBack(t, path)
	if last := evs[len(evs)-1]; len(evs) != maxOtherPairs+2 || last.Count != 1 || !last.Since.Equal(t0.Add(61*time.Second)) {
		t.Errorf("the next overflow summary = %+v", last)
	}
}

func TestFailuresInASessionAreCountedByReason(t *testing.T) {
	c, path := newCoalescer(t, time.Minute)
	const denied = events.OutcomeDenied
	c.HandleBatch([]events.Event{
		account(login(0, "alice", "10.0.0.1:1", denied, "wrong_password_in_session id=s1"), "u-alice"),
		account(login(1, "alice", "10.0.0.1:1", denied, "wrong_password_in_session id=s1"), "u-alice"),
		account(login(2, "alice", "10.0.0.1:1", denied, "wrong_password_in_session id=s2"), "u-alice"),
		account(login(3, "alice", "10.0.0.1:1", denied, "too_many_attempts_in_session id=s2"), "u-alice"),
	})
	c.Close()
	evs := readBack(t, path)
	if len(evs) != 2 || evs[1].Detail != "too_many_attempts_in_session=1 wrong_password_in_session=2" {
		t.Errorf("records = %+v", evs)
	}
}

func TestExpiredLoginWindowsAreFlushed(t *testing.T) {
	c, path := newCoalescer(t, time.Minute)
	const denied = events.OutcomeDenied
	batch := []events.Event{
		login(0, "alice", "10.0.0.1:1", denied, "invalid_credentials"),
		login(1, "alice", "10.0.0.1:1", denied, "invalid_credentials"),
	}
	for i := range maxOtherPairs {
		batch = append(batch, login(2, fmt.Sprintf("u%d", i), "10.0.0.9:1", denied, "invalid_credentials"))
	}
	c.HandleBatch(batch)
	c.flushExpired(t0.Add(30 * time.Second))
	if n := len(readBack(t, path)); n != maxOtherPairs {
		t.Fatalf("summaries written before their windows ended: %d records", n)
	}
	c.flushExpired(t0.Add(63 * time.Second))
	evs := readBack(t, path)
	if len(evs) != maxOtherPairs+2 {
		t.Fatalf("%d records after the windows ended, want %d", len(evs), maxOtherPairs+2)
	}
	for _, ev := range evs[maxOtherPairs:] {
		if ev.Type != events.AuthLoginSummary || ev.Count != 1 {
			t.Errorf("summary = %+v", ev)
		}
	}
	c.HandleBatch([]events.Event{login(64, "carol", "10.0.0.1:1", denied, "invalid_credentials")})
	if evs := readBack(t, path); len(evs) != maxOtherPairs+3 || evs[len(evs)-1].Path != "carol" {
		t.Error("a new pair wasn't written at once after the old ones expired")
	}
}

func TestFailedLoginsAreCollapsedWhenRangedDownloadsAreNot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	w, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	c := NewCoalescer(w, 0, time.Minute)
	c.HandleBatch([]events.Event{
		dl(0, "anon", "10.0.0.1:1", "a", "bytes=0-", 5, events.OutcomeOK),
		dl(1, "anon", "10.0.0.1:1", "a", "bytes=1-", 4, events.OutcomeOK),
		login(2, "x", "10.0.0.1:1", events.OutcomeDenied, "too_many_attempts"),
		login(3, "x", "10.0.0.1:1", events.OutcomeDenied, "too_many_attempts"),
	})
	c.Close()
	var got []string
	for _, ev := range readBack(t, path) {
		got = append(got, string(ev.Type))
	}
	if strings.Join(got, " ") != "file.downloaded file.downloaded auth.login auth.login_summary" {
		t.Errorf("records = %v", got)
	}
}
