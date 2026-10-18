package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/httpapi"
	"github.com/nobletk/gocalbox/internal/transfer"
)

// sendPart sends part n of data, cut into parts of c's size, to h, with the
// SHA-256 of sum when it is set, and returns the status.
func sendPart(t *testing.T, h http.Handler, c transfer.Created, data []byte, n int, sum []byte) int {
	t.Helper()
	off := int64(n-1) * c.PartSize
	part := data[off:min(off+c.PartSize, int64(len(data)))]
	req := partRequest(c.UploadID, n, bytes.NewReader(part), part)
	if sum != nil {
		req.Header.Set(httpapi.PartChecksumHeader, hex.EncodeToString(sum))
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func partSums(data []byte, partSize int64) [][sha256.Size]byte {
	var sums [][sha256.Size]byte
	for off := int64(0); off < int64(len(data)); off += partSize {
		sums = append(sums, sha256.Sum256(data[off:min(off+partSize, int64(len(data)))]))
	}
	return sums
}

func ofType(evs []events.Event, t events.Type) []events.Event {
	var out []events.Event
	for _, ev := range evs {
		if ev.Type == t {
			out = append(out, ev)
		}
	}
	return out
}

// -audit-parts records each part the first time it is accepted, and only
// then; refused parts are recorded either way.
func TestAuditPartsRecordsEveryAcceptedPart(t *testing.T) {
	for _, parts := range []bool{false, true} {
		a, cfg := newTestApp(t, func(c *config) { c.AuditParts = parts })
		data := bytes.Repeat([]byte("0123456789abcdef"), (8<<20+5)/16+1)[:8<<20+5]
		code, c := createUpload(t, a.Handler, transfer.CreateRequest{Dir: "public", Name: "a.bin", Size: int64(len(data))})
		if code != http.StatusCreated || c.PartCount != 2 {
			t.Fatalf("create: %d %+v", code, c)
		}
		sums := partSums(data, c.PartSize)
		wrong := sha256.Sum256([]byte("another part"))
		for _, step := range []struct {
			n    int
			sum  []byte
			want int
		}{{1, wrong[:], 400}, {2, nil, 200}, {1, nil, 200}, {2, nil, 200}} {
			if got := sendPart(t, a.Handler, c, data, step.n, step.sum); got != step.want {
				t.Fatalf("-audit-parts=%v: part %d: %d, want %d", parts, step.n, got, step.want)
			}
		}
		if code, body := call(t, a.Handler, "POST", "/api/upload/complete", httpapi.UploadCompleteRequest{UploadID: c.UploadID, CompositeSHA256: transfer.Composite(sums)}); code != http.StatusCreated {
			t.Fatalf("complete: %d %s", code, body)
		}
		closeApp(t, a)

		evs := auditEvents(t, cfg.AuditLog)
		if rejected := ofType(evs, events.UploadRejected); len(rejected) != 1 || rejected[0].Upload.Part != 1 {
			t.Errorf("-audit-parts=%v: refused parts recorded %+v", parts, rejected)
		}
		got := ofType(evs, events.UploadPartReceived)
		if !parts {
			if len(got) != 0 {
				t.Errorf("parts recorded without -audit-parts: %+v", got)
			}
			continue
		}
		if len(got) != 2 {
			t.Fatalf("-audit-parts recorded %d parts, want each of the 2 once: %+v", len(got), got)
		}
		for i, n := range []int{2, 1} {
			ev, want := got[i], int64(min(c.PartSize, int64(len(data))-int64(n-1)*c.PartSize))
			if ev.Upload.ID != c.UploadID || ev.Upload.Part != n || ev.Upload.SHA256 != hex.EncodeToString(sums[n-1][:]) || ev.Size != want || ev.Outcome != events.OutcomeOK || ev.Path != "public/a.bin" {
				t.Errorf("record of part %d: %+v (upload %+v)", n, ev, ev.Upload)
			}
		}
		completed := ofType(evs, events.UploadCompleted)
		if len(completed) != 1 || completed[0].Upload.Received != 2 || completed[0].Upload.Retries != 1 || completed[0].Upload.Rejected != 1 {
			t.Errorf("completion %+v", completed)
		}
	}
}

// With -audit-parts, a part goes on once the audit log has failed: its
// record is printed on the console instead, and the completion waits for a
// log that works.
func TestAPartGoesOnWhenTheLogFailed(t *testing.T) {
	var lost lockedBuffer
	t.Cleanup(events.SetLostOutput(&lost))
	a, cfg := newTestApp(t, func(c *config) { c.AuditParts = true })
	defer closeApp(t, a)
	data := []byte("a part sent while the log is down")
	_, c := createUpload(t, a.Handler, transfer.CreateRequest{Dir: "public", Name: "a.txt", Size: int64(len(data))})
	a.audit.Close()
	if code, body := do(t, a.Handler, "POST", "/api/fs/mkdir", `{"targetPath":"public","name":"during"}`); code != http.StatusInternalServerError || !strings.Contains(body, "not_recorded") {
		t.Fatalf("mkdir as the log stops = %d %s", code, body)
	}
	if code := sendPart(t, a.Handler, c, data, 1, nil); code != http.StatusOK {
		t.Fatalf("part: %d", code)
	}
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(lost.String(), `"type":"upload.part_received"`) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if out := lost.String(); !strings.Contains(out, `"type":"upload.part_received"`) || !strings.Contains(out, c.UploadID) {
		t.Errorf("console = %s", out)
	}
	code, body := call(t, a.Handler, "POST", "/api/upload/complete", httpapi.UploadCompleteRequest{UploadID: c.UploadID, CompositeSHA256: transfer.Composite(partSums(data, c.PartSize))})
	if code != http.StatusServiceUnavailable || !strings.Contains(body, "changes_paused") {
		t.Errorf("complete with the log down: %d %s", code, body)
	}
	if _, err := os.Stat(filepath.Join(cfg.RootDir, "public", "a.txt")); err == nil {
		t.Error("a completion was placed while changes are paused")
	}
}

func TestVerifyUpload(t *testing.T) {
	dir := t.TempDir()
	data := make([]byte, 1000)
	for i := range data {
		data[i] = byte(i % 251)
	}
	file, empty := filepath.Join(dir, "f.bin"), filepath.Join(dir, "empty")
	os.WriteFile(file, data, 0o644)
	os.WriteFile(empty, nil, 0o644)
	const want = "e6cec81163d2e289742636ba3b36a7b799773a56971c086fcd851aee99ccac17"
	for _, c := range []struct {
		path     string
		partSize int64
		sum      string
	}{
		{file, 256, want},
		{file, 256, strings.ToUpper(want)},
		{empty, 8 << 20, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
	} {
		if err := verifyUpload(c.path, c.partSize, c.sum); err != nil {
			t.Errorf("%s in parts of %d: %v", c.path, c.partSize, err)
		}
	}
	for _, c := range []struct {
		path     string
		partSize int64
		sum      string
		msg      string
	}{
		{file, 512, want, "doesn't match its record: its 2 parts of 512 bytes give the composite "},
		{file, 512, want, "; the server only cuts files into parts of a power of two from 8388608 to 67108864 bytes, so take -part-size from the record"},
		{file, 256, strings.Repeat("0", 64), "doesn't match its record: its 4 parts of 256 bytes give the composite " + want + ", not " + strings.Repeat("0", 64)},
		{"", 256, want, "needs the stored file's path"},
		{file, 0, want, "needs -part-size, part_size in the upload's record, at least 1; got 0"},
		{file, -1, want, "got -1"},
		{file, 256, want[:63], "needs -composite, sha256 in the upload's record: 64 hex digits"},
		{file, 256, want[:62] + "zz", "64 hex digits"},
		{file, 256, "", "64 hex digits"},
		{filepath.Join(dir, "missing"), 256, want, "missing"},
		{dir, 256, want, "is not a regular file"},
	} {
		err := verifyUpload(c.path, c.partSize, c.sum)
		var unchecked *uncheckedError
		if mismatch := strings.Contains(c.msg, "match its record") || strings.Contains(c.msg, "the server only cuts"); err == nil ||
			!strings.Contains(err.Error(), c.msg) || errors.As(err, &unchecked) == mismatch {
			t.Errorf("%q, %d, %q: %v, want %q (a mismatch %v)", c.path, c.partSize, c.sum, err, c.msg, mismatch)
		}
	}

	big := filepath.Join(dir, "big")
	os.WriteFile(big, bytes.Repeat([]byte("y"), 9<<20), 0o644)
	sum, _, _ := transfer.CompositeOf(bytes.NewReader(bytes.Repeat([]byte("y"), 9<<20)), 8<<20)
	if err := verifyUpload(big, 8<<20, strings.Repeat("0", 64)); err == nil || strings.Contains(err.Error(), "the server only cuts") {
		t.Errorf("a mismatch with a part size the server uses: %v", err)
	}
	if err := verifyUpload(big, 8<<20, sum); err != nil {
		t.Errorf("9 MiB in parts of 8 MiB: %v", err)
	}
}

// A file that changes while it is read can't be checked: its size and time
// are compared before and after.
func TestVerifyUploadNoticesAFileThatChanged(t *testing.T) {
	file := filepath.Join(t.TempDir(), "f")
	os.WriteFile(file, []byte("abc"), 0o644)
	const abc = "4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358"
	then := time.Now().Add(-time.Hour)
	for name, change := range map[string]func(){
		"grew":                    func() { os.WriteFile(file, []byte("abcd"), 0o644) },
		"grew with its time kept": func() { os.WriteFile(file, []byte("abcd"), 0o644); os.Chtimes(file, then, then) },
		"was touched":             func() { os.Chtimes(file, time.Now(), time.Now().Add(time.Hour)) },
	} {
		os.WriteFile(file, []byte("abc"), 0o644)
		os.Chtimes(file, then, then)
		afterVerifyRead = change
		err := verifyUpload(file, 8<<20, abc)
		afterVerifyRead = nil
		var unchecked *uncheckedError
		if err == nil || !strings.Contains(err.Error(), "changed while it was read") || !errors.As(err, &unchecked) {
			t.Errorf("a file that %s: %v", name, err)
		}
	}
	os.WriteFile(file, []byte("abc"), 0o644)
	if err := verifyUpload(file, 8<<20, abc); err != nil {
		t.Errorf("the file left alone: %v", err)
	}
}

// With -audit-parts a part waits for room on the bus, so its record is
// kept; without it a part never waits, and its event is skipped instead.
func TestAuditPartsDecidesWhetherAPartWaitsForTheBus(t *testing.T) {
	for _, parts := range []bool{true, false} {
		a, cfg := newTestApp(t, func(c *config) { c.AuditParts = parts })
		release := blockBus(t, a)
		data := []byte("one part")
		_, c := createUpload(t, a.Handler, transfer.CreateRequest{Dir: "public", Name: "a.bin", Size: int64(len(data))})
		fillBus(a)
		skipped := a.bus.Stats().Skipped
		codes := make(chan int, 1)
		go func() {
			rec := httptest.NewRecorder()
			a.Handler.ServeHTTP(rec, partRequest(c.UploadID, 1, bytes.NewReader(data), data))
			codes <- rec.Code
		}()
		answered := false
		select {
		case code := <-codes:
			answered = true
			if parts {
				t.Errorf("with -audit-parts the part answered %d while the bus was full", code)
			} else if code != http.StatusOK || a.bus.Stats().Skipped != skipped+1 {
				t.Errorf("without -audit-parts: part %d, skipped %d -> %d", code, skipped, a.bus.Stats().Skipped)
			}
		case <-time.After(500 * time.Millisecond):
			if !parts {
				t.Errorf("without -audit-parts the part waited for the bus")
			}
		}
		close(release)
		if !answered {
			if code := <-codes; code != http.StatusOK {
				t.Fatalf("part: %d", code)
			}
		}
		closeApp(t, a)
		if n, want := len(ofType(auditEvents(t, cfg.AuditLog), events.UploadPartReceived)), map[bool]int{true: 1}[parts]; n != want {
			t.Errorf("-audit-parts=%v: %d part records, want %d", parts, n, want)
		}
	}
}

// blockBus adds a subscriber that holds the bus's dispatcher at the first
// event fillBus publishes, until the returned channel is closed.
func blockBus(t *testing.T, a *app) chan struct{} {
	t.Helper()
	release, entered := make(chan struct{}), make(chan struct{}, 1)
	a.bus.Subscribe("blocker", func(events.Event) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
	}, events.Options{
		Mode: events.Block, Buffer: 1,
		Filter: func(ev events.Event) bool { return ev.Type == events.FileListed },
	})
	a.bus.Publish(events.Event{Type: events.FileListed, Outcome: events.OutcomeOK})
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the blocker never ran")
	}
	return release
}

// fillBus fills the bus's queue while blockBus holds its dispatcher.
func fillBus(a *app) {
	for a.bus.TryPublish(events.Event{Type: events.FileListed, Outcome: events.OutcomeOK}) {
	}
	time.Sleep(50 * time.Millisecond)
	for a.bus.TryPublish(events.Event{Type: events.FileListed, Outcome: events.OutcomeOK}) {
	}
}
