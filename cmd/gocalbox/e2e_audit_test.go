package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/httpapi"
	"github.com/nobletk/gocalbox/internal/transfer"
)

// recordsSoFar reads the whole records of an audit log that may still be
// written.
func recordsSoFar(t *testing.T, path string) []events.Event {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []events.Event
	for line := range strings.Lines(string(b)) {
		if !strings.HasSuffix(line, "\n") {
			break
		}
		var rec struct {
			Event events.Event `json:"event"`
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("bad audit line %q: %v", line, err)
		}
		out = append(out, rec.Event)
	}
	return out
}

// awaitRecord waits until the audit log holds a record that ok accepts.
func awaitRecord(t *testing.T, path string, ok func(events.Event) bool) events.Event {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		for _, ev := range recordsSoFar(t, path) {
			if ok(ev) {
				return ev
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no such record in %s", path)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// sendWrongPart sends part n with the SHA-256 of other bytes.
func (u *uploader) sendWrongPart(id string, n int, data []byte) error {
	sum := sha256.Sum256(append([]byte("not "), data...))
	return u.send("POST", "/api/upload/part?id="+id+"&n="+strconv.Itoa(n), "application/octet-stream",
		bytes.NewReader(data), int64(len(data)), map[string]string{httpapi.PartChecksumHeader: hex.EncodeToString(sum[:])}, nil)
}

func (f source) composite(c transfer.Created) string {
	var sums [][sha256.Size]byte
	for n := 1; n <= c.PartCount; n++ {
		sums = append(sums, digest(f.part(c, n)))
	}
	return transfer.Composite(sums)
}

// verifyWith runs the binary's -verify-upload on path with the part size
// and composite of rec.
func verifyWith(t *testing.T, path string, rec events.Event) (string, int) {
	t.Helper()
	return runToCompletion(t, "-verify-upload="+path, "-part-size="+strconv.FormatInt(rec.Upload.PartSize, 10), "-composite="+rec.Upload.SHA256)
}

// Every record of §9: a refused part, the totals of a completion, an admin's
// abort that names the owner, an expiry by the server itself, a failure
// found during the owner's call. The log's chain verifies, and the stored
// file verifies from its record.
func TestE2EAnUploadIsRecordedAsTheDesignSays(t *testing.T) {
	s := newLiveServer(t)
	tokens := addUsers(t, s, "alice:contributor")
	s.start()
	alice, admin := s.uploader(tokens["alice"]), s.uploader(sessionCookie(s.statePath).Value)

	f := source{dir: "users/alice", name: "f.bin", data: randomData(t, 8<<20+5), modified: time.Now()}
	c, err := alice.create(f)
	if err != nil || c.PartCount != 2 {
		t.Fatalf("create: %+v %v", c, err)
	}
	if err := alice.sendWrongPart(c.UploadID, 1, f.part(c, 1)); codeOf(err) != "checksum_mismatch" {
		t.Fatalf("a part that doesn't match its hash: %v", err)
	}
	for _, n := range []int{1, 1, 2} {
		if err := alice.part(c.UploadID, n, f.part(c, n)); err != nil {
			t.Fatalf("part %d: %v", n, err)
		}
	}
	var res transfer.Result
	if err := alice.call("/api/upload/complete", httpapi.UploadCompleteRequest{UploadID: c.UploadID, CompositeSHA256: f.composite(c)}, &res); err != nil || res.Path != "users/alice/f.bin" {
		t.Fatalf("complete: %+v %v", res, err)
	}
	g, err := alice.create(source{dir: "users/alice", name: "g.bin", data: []byte("g"), modified: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.call("/api/upload/abort", httpapi.UploadAbortRequest{UploadID: g.UploadID}, nil); err != nil {
		t.Fatalf("the admin aborts alice's upload: %v", err)
	}
	h, err := alice.create(source{dir: "users/alice", name: "h.bin", data: []byte("h"), modified: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	k := source{dir: "users/alice", name: "k.bin", data: []byte("k"), modified: time.Now()}
	kc, err := alice.create(k)
	if err != nil {
		t.Fatal(err)
	}
	if err := alice.part(kc.UploadID, 1, k.data); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(s.root, ".gocalbox", "uploads", kc.UploadID, "data")); err != nil {
		t.Fatal(err)
	}
	if err := alice.call("/api/upload/complete", httpapi.UploadCompleteRequest{UploadID: kc.UploadID, CompositeSHA256: k.composite(kc)}, nil); codeOf(err) != "upload_closed" {
		t.Fatalf("complete with its staged data gone: %v", err)
	}
	if err := s.stop(syscall.SIGTERM); err != nil {
		t.Fatalf("exit: %v", err)
	}
	time.Sleep(1100 * time.Millisecond)
	s.restart("-upload-first-part-ttl=1s")
	awaitRecord(t, s.auditPath, func(ev events.Event) bool { return ev.Type == events.UploadExpired })
	if err := s.stop(syscall.SIGTERM); err != nil {
		t.Fatalf("exit: %v", err)
	}

	evs := recordsSoFar(t, s.auditPath)
	byUpload := func(typ events.Type, id string) []events.Event {
		var out []events.Event
		for _, ev := range evs {
			if ev.Type == typ && ev.Upload != nil && ev.Upload.ID == id {
				out = append(out, ev)
			}
		}
		return out
	}
	created := byUpload(events.UploadCreated, c.UploadID)
	if len(created) != 1 || created[0].Actor.Name != "alice" || created[0].Upload.Owner != created[0].Actor.ID || created[0].Size != int64(len(f.data)) ||
		created[0].Path != "users/alice/f.bin" || created[0].Upload.PartSize != c.PartSize || created[0].Upload.Parts != 2 {
		t.Fatalf("upload.created: %+v", created)
	}
	aliceID := created[0].Actor.ID
	if rejected := byUpload(events.UploadRejected, c.UploadID); len(rejected) != 1 || rejected[0].Upload.Part != 1 || rejected[0].Outcome != events.OutcomeInvalid || rejected[0].Actor.ID != aliceID {
		t.Errorf("upload.rejected: %+v", rejected)
	}
	if parts := ofType(evs, events.UploadPartReceived); len(parts) != 0 {
		t.Errorf("parts recorded without -audit-parts: %+v", parts)
	}
	var completed events.Event
	for i, ev := range evs {
		if ev.Type == events.UploadCompleted && ev.Upload.ID == c.UploadID {
			if i == 0 || evs[i-1].Type != events.FileUploaded || evs[i-1].Resolved != "users/alice/f.bin" || evs[i-1].Upload == nil ||
				evs[i-1].Upload.ID != c.UploadID || evs[i-1].Upload.Owner != aliceID {
				t.Errorf("upload.completed doesn't follow its file.uploaded: %+v", evs[max(i-1, 0)])
			}
			completed = ev
		}
	}
	up := completed.Upload
	if up == nil || completed.Actor.ID != aliceID || completed.Resolved != "users/alice/f.bin" || completed.Size != int64(len(f.data)) ||
		up.Owner != aliceID || up.Parts != 2 || up.PartSize != c.PartSize || up.Received != 2 || up.Retries != 1 || up.Rejected != 1 ||
		len(up.Clients) != 1 || up.Clients[0] != "127.0.0.1" || up.Started.IsZero() || up.DurationMS < 0 || up.SHA256 != f.composite(c) ||
		completed.Detail != "" {
		t.Errorf("upload.completed: %+v, totals %+v", completed, up)
	}
	if aborted := byUpload(events.UploadAborted, g.UploadID); len(aborted) != 1 || aborted[0].Actor.Name != "admin" ||
		aborted[0].Upload.Owner != aliceID || aborted[0].Upload.OwnerName != "alice" {
		t.Errorf("upload.aborted by the admin: %+v", aborted)
	}
	if expired := byUpload(events.UploadExpired, h.UploadID); len(expired) != 1 || expired[0].Actor.ID != events.SystemID ||
		expired[0].Detail == "" || expired[0].Upload.Owner != aliceID {
		t.Errorf("upload.expired: %+v", expired)
	}
	if failed := byUpload(events.UploadFailed, kc.UploadID); len(failed) != 1 || failed[0].Actor.ID != aliceID || failed[0].Outcome != events.OutcomeError ||
		!strings.HasPrefix(failed[0].Detail, "the staged data is gone") || failed[0].Upload.Received != 1 || failed[0].Upload.Owner != aliceID {
		t.Errorf("upload.failed: %+v", failed)
	}

	if out, code := runToCompletion(t, "-verify-audit="+s.auditPath); code != 0 || !strings.Contains(out, "chain intact") {
		t.Errorf("-verify-audit: %d %s", code, out)
	}
	stored := filepath.Join(s.root, "users", "alice", "f.bin")
	if out, code := verifyWith(t, stored, completed); code != 0 || !strings.Contains(out, "OK: "+stored+" matches its record: 8388613 bytes, 2 parts of 8388608 bytes") {
		t.Errorf("-verify-upload: %d %s", code, out)
	}
	changed := filepath.Join(t.TempDir(), "f.bin")
	data := bytes.Clone(f.data)
	data[len(data)-1] ^= 1
	os.WriteFile(changed, data, 0o644)
	if out, code := verifyWith(t, changed, completed); code != 1 || !strings.Contains(out, "doesn't match its record") {
		t.Errorf("-verify-upload of a changed file: %d %s", code, out)
	}
}

func TestE2EVerifyUploadsFlags(t *testing.T) {
	file := filepath.Join(t.TempDir(), "f")
	os.WriteFile(file, []byte("abc"), 0o644)
	const abc = "4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358"
	for _, c := range []struct {
		args []string
		code int
		out  string
	}{
		{[]string{"-verify-upload=" + file, "-part-size=8388608", "-composite=" + abc}, 0, "OK: " + file + " matches its record: 3 bytes, 1 parts of 8388608 bytes"},
		{[]string{"-verify-upload=" + file, "-part-size=8388608", "-composite=" + strings.Repeat("0", 64)}, 1, "doesn't match its record"},
		{[]string{"-verify-upload=" + file, "-composite=" + abc}, 2, "needs -part-size"},
		{[]string{"-verify-upload=" + file, "-part-size=8388608"}, 2, "needs -composite"},
		{[]string{"-verify-upload=", "-part-size=8388608", "-composite=" + abc}, 2, "needs the stored file's path"},
		{[]string{"-verify-upload=" + file + ".missing", "-part-size=8388608", "-composite=" + abc}, 2, "no such file"},
		{[]string{"-verify-upload=" + filepath.Dir(file), "-part-size=8388608", "-composite=" + abc}, 2, "is not a regular file"},
		{[]string{"-part-size=8388608"}, 1, "-part-size and -composite are only for -verify-upload"},
		{[]string{"-composite=" + abc}, 1, "-part-size and -composite are only for -verify-upload"},
		{[]string{"-verify-audit=" + file, "-verify-upload=" + file, "-part-size=1", "-composite=" + abc}, 2, "give one at a time"},
	} {
		out, code := runToCompletion(t, c.args...)
		if code != c.code || !strings.Contains(out, c.out) {
			t.Errorf("%q: %d %s", c.args, code, out)
		}
	}
	out, _ := runToCompletion(t, "-h")
	for _, want := range []string{"-audit-parts", "-verify-upload", "-part-size", "-composite"} {
		if !strings.Contains(out, "  "+want) {
			t.Errorf("-h doesn't list %s", want)
		}
	}
}

// With -audit-parts the binary records each part the first time it is
// accepted, and the log still verifies.
func TestE2EAuditPartsRecordsEveryPart(t *testing.T) {
	s := newLiveServer(t)
	tokens := addUsers(t, s, "alice:contributor")
	s.start("-audit-parts")
	alice := s.uploader(tokens["alice"])
	f := source{dir: "users/alice", name: "f.bin", data: randomData(t, 8<<20+5), modified: time.Now()}
	c, err := alice.create(f)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{2, 1, 2} {
		if err := alice.part(c.UploadID, n, f.part(c, n)); err != nil {
			t.Fatalf("part %d: %v", n, err)
		}
	}
	if err := alice.call("/api/upload/complete", httpapi.UploadCompleteRequest{UploadID: c.UploadID, CompositeSHA256: f.composite(c)}, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.stop(syscall.SIGTERM); err != nil {
		t.Fatalf("exit: %v", err)
	}
	parts := ofType(recordsSoFar(t, s.auditPath), events.UploadPartReceived)
	if len(parts) != 2 {
		t.Fatalf("%d part records, want one for each part: %+v", len(parts), parts)
	}
	for i, n := range []int{2, 1} {
		sum := digest(f.part(c, n))
		if ev := parts[i]; ev.Upload.ID != c.UploadID || ev.Upload.Part != n || ev.Upload.SHA256 != hex.EncodeToString(sum[:]) ||
			ev.Size != int64(len(f.part(c, n))) || ev.Actor.Name != "alice" {
			t.Errorf("record of part %d: %+v, %+v", n, ev, ev.Upload)
		}
	}
	if out, code := runToCompletion(t, "-verify-audit="+s.auditPath); code != 0 || !strings.Contains(out, "chain intact") {
		t.Errorf("-verify-audit: %d %s", code, out)
	}
}
