package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/httpapi"
	"github.com/nobletk/gocalbox/internal/transfer"
)

// fullLogServer starts a server whose audit log is alone on a tmpfs of
// 1 MiB, and returns it with alice's uploader.
func fullLogServer(t *testing.T, args ...string) (*liveServer, *uploader) {
	t.Helper()
	s := newLiveServer(t)
	dir := filepath.Dir(s.auditPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	mountAt(t, dir, "", "1m")
	tokens := addUsers(t, s, "alice:contributor")
	s.start(args...)
	return s, s.uploader(tokens["alice"])
}

// fillLog fills the audit log's tmpfs, and then the room left in the log's
// last page, which a record can take without a new page, with folders. A
// folder's record takes about 470 bytes and an upload's at least 570, so
// with less than 520 bytes left the next upload record fails. It returns a
// function that frees the space again.
func fillLog(t *testing.T, s *liveServer, u *uploader) func() {
	t.Helper()
	filler := filepath.Join(filepath.Dir(s.auditPath), "filler")
	f, err := os.Create(filler)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64<<10)
	for {
		if _, err := f.Write(buf); err != nil {
			break
		}
	}
	f.Close()
	page := int64(os.Getpagesize())
	for i := 0; ; i++ {
		info, err := os.Stat(s.auditPath)
		if err != nil {
			t.Fatal(err)
		}
		room := (page - info.Size()%page) % page
		if room < 520 {
			break
		}
		if err := u.call("/api/fs/mkdir", map[string]string{"targetPath": "users/alice", "name": fmt.Sprintf("p%03d", i)}, nil); err != nil {
			t.Fatalf("a folder made to fill the log's last page, %d bytes left in it: %v", room, err)
		}
	}
	return func() { os.Remove(filler) }
}

func (s *liveServer) waitOutput(t *testing.T, want ...string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		out := s.out.String()
		ok := true
		for _, w := range want {
			ok = ok && strings.Contains(out, w)
		}
		if ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the server never printed %q\n%s", want, out)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A completion whose records don't fit in the audit log is placed and
// answered 500 not_recorded, changes pause, and the next start records it
// as recovered: the chain verifies, and the file verifies from that record.
func TestE2EACompletionTheFullLogMissedIsRecordedAtTheNextStart(t *testing.T) {
	s, alice := fullLogServer(t)
	f := source{dir: "users/alice", name: "f.bin", data: randomData(t, 8<<20+5), modified: time.Now()}
	c, err := alice.create(f)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{1, 2} {
		if err := alice.part(c.UploadID, n, f.part(c, n)); err != nil {
			t.Fatalf("part %d: %v", n, err)
		}
	}
	awaitRecord(t, s.auditPath, func(ev events.Event) bool { return ev.Type == events.UploadCreated && ev.Upload.ID == c.UploadID })
	free := fillLog(t, s, alice)

	err = alice.call("/api/upload/complete", httpapi.UploadCompleteRequest{UploadID: c.UploadID, CompositeSHA256: f.composite(c)}, nil)
	if codeOf(err) != "not_recorded" || err.(*apiError).Status != 500 {
		t.Fatalf("complete with the log full: %v", err)
	}
	stored := filepath.Join(s.root, "users", "alice", "f.bin")
	if _, err := os.Stat(stored); err != nil {
		t.Fatalf("the file whose records failed wasn't placed: %v", err)
	}
	s.waitOutput(t, `"audit":"not_recorded"`, `"type":"upload.completed"`)
	if _, err := alice.create(source{dir: "users/alice", name: "g.bin", data: []byte("g"), modified: time.Now()}); codeOf(err) != "changes_paused" {
		t.Errorf("create once the log failed: %v", err)
	}

	free()
	s.stop(syscall.SIGTERM)
	s.restart()
	rec := awaitRecord(t, s.auditPath, func(ev events.Event) bool {
		return ev.Type == events.UploadCompleted && ev.Upload.ID == c.UploadID
	})
	if err := s.stop(syscall.SIGTERM); err != nil {
		t.Fatalf("exit: %v", err)
	}
	if rec.Detail != "recovered" || rec.Resolved != "users/alice/f.bin" || rec.Upload.SHA256 != f.composite(c) || rec.Upload.PartSize != c.PartSize {
		t.Errorf("the recovered record: %+v, %+v", rec, rec.Upload)
	}
	evs := recordsSoFar(t, s.auditPath)
	if n := len(ofType(evs, events.UploadCompleted)); n != 1 {
		t.Errorf("%d completion records, want the recovered one only", n)
	}
	if out, code := runToCompletion(t, "-verify-audit="+s.auditPath); code != 0 || !strings.Contains(out, "chain intact") {
		t.Errorf("-verify-audit: %d %s", code, out)
	}
	if out, code := verifyWith(t, stored, rec); code != 0 || !strings.Contains(out, "OK: ") {
		t.Errorf("-verify-upload from the recovered record: %d %s", code, out)
	}
}

// With -audit-parts and the audit log full, a part is still accepted and
// its record printed on the console; the completion waits for the next
// start, and then succeeds with every part kept.
func TestE2EPartsGoOnWhenTheFullLogStopsTheirRecords(t *testing.T) {
	s, alice := fullLogServer(t, "-audit-parts")
	f := source{dir: "users/alice", name: "f.bin", data: randomData(t, 8<<20+5), modified: time.Now()}
	c, err := alice.create(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := alice.part(c.UploadID, 1, f.part(c, 1)); err != nil {
		t.Fatal(err)
	}
	awaitRecord(t, s.auditPath, func(ev events.Event) bool { return ev.Type == events.UploadPartReceived && ev.Upload.Part == 1 })
	free := fillLog(t, s, alice)

	if err := alice.part(c.UploadID, 2, f.part(c, 2)); err != nil {
		t.Fatalf("a part with the log full: %v", err)
	}
	s.waitOutput(t, `"audit":"not_recorded"`, `"type":"upload.part_received"`)
	err = alice.call("/api/upload/complete", httpapi.UploadCompleteRequest{UploadID: c.UploadID, CompositeSHA256: f.composite(c)}, nil)
	if codeOf(err) != "changes_paused" {
		t.Fatalf("complete once the log failed: %v", err)
	}
	stored := filepath.Join(s.root, "users", "alice", "f.bin")
	if _, err := os.Stat(stored); err == nil {
		t.Fatal("a completion was placed while changes are paused")
	}

	free()
	s.stop(syscall.SIGTERM)
	s.restart("-audit-parts")
	var res transfer.Result
	if err := alice.call("/api/upload/complete", httpapi.UploadCompleteRequest{UploadID: c.UploadID, CompositeSHA256: f.composite(c)}, &res); err != nil {
		t.Fatalf("complete after the restart: %v", err)
	}
	if err := s.stop(syscall.SIGTERM); err != nil {
		t.Fatalf("exit: %v", err)
	}
	evs := recordsSoFar(t, s.auditPath)
	if parts := ofType(evs, events.UploadPartReceived); len(parts) != 1 || parts[0].Upload.Part != 1 {
		t.Errorf("part records: %+v", parts)
	}
	completed := ofType(evs, events.UploadCompleted)
	if len(completed) != 1 || completed[0].Upload.Received != 2 || completed[0].Detail != "" {
		t.Fatalf("completion records: %+v", completed)
	}
	if out, code := runToCompletion(t, "-verify-audit="+s.auditPath); code != 0 || !strings.Contains(out, "chain intact") {
		t.Errorf("-verify-audit: %d %s", code, out)
	}
	if out, code := verifyWith(t, stored, completed[0]); code != 0 {
		t.Errorf("-verify-upload: %d %s", code, out)
	}
}
