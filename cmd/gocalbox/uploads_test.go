package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/httpapi"
	"github.com/nobletk/gocalbox/internal/transfer"
)

// call sends a JSON call of the seeded admin to h.
func call(t *testing.T, h http.Handler, method, path string, in any) (int, string) {
	t.Helper()
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, body)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func partRequest(id string, n int, body io.Reader, data []byte) *http.Request {
	sum := sha256.Sum256(data)
	req := httptest.NewRequest(http.MethodPost, "/api/upload/part?id="+id+"&n="+strconv.Itoa(n), body)
	req.ContentLength = int64(len(data))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set(httpapi.PartChecksumHeader, hex.EncodeToString(sum[:]))
	return req
}

func createUpload(t *testing.T, h http.Handler, req transfer.CreateRequest) (int, transfer.Created) {
	t.Helper()
	code, body := call(t, h, "POST", "/api/upload/create", req)
	var c transfer.Created
	if code < 300 {
		if err := json.Unmarshal([]byte(body), &c); err != nil {
			t.Fatalf("%s: %v", body, err)
		}
	} else {
		t.Logf("create: %d %s", code, body)
	}
	return code, c
}

// The server serves the engine with its flags, and recovers its sessions at
// the next start, before it answers.
func TestTheServerResumesAnUploadAfterARestart(t *testing.T) {
	a, cfg := newTestApp(t, func(c *config) { c.Uploads.MaxSessions = 1; c.MaxUploadBytes = 1 << 20 })
	data := []byte("the uploaded file")
	req := transfer.CreateRequest{Dir: "public", Name: "a.txt", Size: int64(len(data)), ClientKey: "key"}
	code, c := createUpload(t, a.Handler, req)
	if code != http.StatusCreated || c.PartCount != 1 {
		t.Fatalf("create: %d %+v", code, c)
	}
	if code, _ := createUpload(t, a.Handler, transfer.CreateRequest{Dir: "public", Name: "b.txt", Size: 1}); code != http.StatusTooManyRequests {
		t.Errorf("a second upload with -upload-max-sessions=1: %d", code)
	}
	if code, _ := createUpload(t, a.Handler, transfer.CreateRequest{Dir: "public", Name: "b.txt", Size: 1<<20 + 1}); code != http.StatusRequestEntityTooLarge {
		t.Errorf("an upload above -max-upload-mb: %d", code)
	}
	rec := httptest.NewRecorder()
	a.Handler.ServeHTTP(rec, partRequest(c.UploadID, 1, bytes.NewReader(data), data))
	if rec.Code != http.StatusOK {
		t.Fatalf("part: %d %s", rec.Code, rec.Body)
	}
	closeApp(t, a)

	b, err := openTestApp(t, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer closeApp(t, b)
	code, again := createUpload(t, b.Handler, req)
	if code != http.StatusOK || !again.Resumed || again.UploadID != c.UploadID || len(again.Received) != 1 {
		t.Fatalf("after the restart: %d %+v", code, again)
	}
	sum := sha256.Sum256(data)
	code, body := call(t, b.Handler, "POST", "/api/upload/complete", httpapi.UploadCompleteRequest{
		UploadID: c.UploadID, CompositeSHA256: transfer.Composite([][sha256.Size]byte{sum}),
	})
	if code != http.StatusCreated || !strings.Contains(body, `"path":"public/a.txt"`) {
		t.Fatalf("complete: %d %s", code, body)
	}
	if got, err := os.ReadFile(filepath.Join(cfg.RootDir, "public", "a.txt")); err != nil || !bytes.Equal(got, data) {
		t.Errorf("the stored file: %q %v", got, err)
	}
}

// When a shutdown's deadline passes with a part still being received, the
// engine closes nothing, and the folder stays locked until the process
// exits: no other server may recover that upload while it is written.
func TestAShutdownCutShortKeepsTheLock(t *testing.T) {
	a, cfg := newTestApp(t)
	data := bytes.Repeat([]byte("x"), 1000)
	_, c := createUpload(t, a.Handler, transfer.CreateRequest{Dir: "public", Name: "a.bin", Size: int64(len(data))})
	pr, pw := io.Pipe()
	t.Cleanup(func() { pw.CloseWithError(errors.New("the test ended")) })
	answered := make(chan int, 1)
	go func() {
		rec := httptest.NewRecorder()
		a.Handler.ServeHTTP(rec, partRequest(c.UploadID, 1, pr, data))
		answered <- rec.Code
	}()
	go pw.Write(data[:1])
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(time.Millisecond) {
		_, body := call(t, a.Handler, "POST", "/api/upload/status", httpapi.UploadStatusRequest{UploadID: c.UploadID})
		if strings.Contains(body, `"inFlight":[1]`) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the part never started: %s", body)
		}
	}

	var out lockedBuffer
	log.SetOutput(&out)
	defer log.SetOutput(os.Stderr)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	closed := make(chan struct{})
	go func() { a.Close(ctx); close(closed) }()
	within(t, "the shutdown", closed)
	log.SetOutput(os.Stderr)
	if !strings.Contains(out.String(), " SHUTDOWN: upload calls still running at shutdown: context deadline exceeded. The lock of .gocalbox is kept") {
		t.Errorf("the console doesn't say why the lock is kept:\n%s", out.String())
	}
	if !a.kept {
		t.Fatal("the lock was released with a part still being received")
	}
	if _, err := a.volume.Stat(); err != nil {
		t.Errorf("the served volume was closed with a part still being received: %v", err)
	}
	second := cfg
	second.AuditLog = filepath.Join(t.TempDir(), "second.jsonl")
	second.StateFile = filepath.Join(t.TempDir(), "second.db")
	if b, err := newApp(second); err == nil || !strings.Contains(err.Error(), "another gocalbox serves this folder") {
		if err == nil {
			closeApp(t, b)
		}
		t.Errorf("a second server while the first one's part runs: %v", err)
	}

	go func() { pw.Write(data[1:]); pw.Close() }()
	if code := within(t, "the part that outlived the shutdown", answered); code != http.StatusOK {
		t.Errorf("the part that outlived the shutdown: %d", code)
	}
	log, err := os.ReadFile(filepath.Join(cfg.RootDir, ".gocalbox", "uploads", c.UploadID, "parts.log"))
	if err != nil || !strings.Contains(string(log), `"op":"part"`) {
		t.Errorf("the part isn't logged: %v\n%s", err, log)
	}
	// As the process's exit would.
	if err := a.uploads.Close(context.Background()); err != nil {
		t.Errorf("the engine once its part ended: %v", err)
	}
	a.volume.Close()
	a.staging.Close()
	a.sb.Close()
	b, err := openTestApp(t, cfg)
	if err != nil {
		t.Fatalf("the next start: %v", err)
	}
	defer closeApp(t, b)
	code, body := call(t, b.Handler, "POST", "/api/upload/status", httpapi.UploadStatusRequest{UploadID: c.UploadID})
	if code != 200 || !strings.Contains(body, `"received":[[1,1]]`) {
		t.Errorf("the next start: %d %s", code, body)
	}
}

func TestAShutdownInTimeReleasesTheLock(t *testing.T) {
	a, cfg := newTestApp(t)
	closeApp(t, a)
	if a.kept {
		t.Error("the lock was kept by a shutdown with nothing running")
	}
	b, err := openTestApp(t, cfg)
	if err != nil {
		t.Fatalf("the next start: %v", err)
	}
	closeApp(t, b)
}

func TestWithoutItsFolderTheServerRunsWithoutResumableUploads(t *testing.T) {
	a, cfg := newTestApp(t, func(c *config) {
		os.WriteFile(filepath.Join(c.RootDir, ".gocalbox"), []byte("not a folder"), 0o644)
	})
	defer closeApp(t, a)
	code, body := call(t, a.Handler, "POST", "/api/upload/create", transfer.CreateRequest{Dir: "public", Name: "a.txt", Size: 1})
	if code != http.StatusServiceUnavailable || !strings.Contains(body, `"uploads_unavailable"`) {
		t.Errorf("create: %d %s", code, body)
	}
	rec := httptest.NewRecorder()
	a.Handler.ServeHTTP(rec, uploadRequest(t, "b.txt", 10, false))
	if rec.Code != http.StatusCreated {
		t.Errorf("the single-request upload: %d %s", rec.Code, rec.Body)
	}
	if _, err := os.Stat(filepath.Join(cfg.RootDir, "b.txt")); err != nil {
		t.Error(err)
	}
}

func TestUploadLimits(t *testing.T) {
	good := transfer.DefaultLimits
	good.Window = 0
	if l, err := uploadLimits(1024, good); err != nil || l.Window != 1<<30 || l.MaxSessions != good.MaxSessions {
		t.Errorf("the defaults: %+v %v", l, err)
	}
	flags := []string{"-upload-window-mb", "-upload-idle-ttl", "-upload-first-part-ttl", "-upload-max-age", "-upload-tombstone-ttl",
		"-upload-max-sessions", "-upload-max-sessions-total", "-upload-max-inflight"}
	for _, tc := range []struct {
		flag string
		mb   int64
		mod  func(*transfer.Limits)
		got  string
	}{
		{"-upload-window-mb", 0, nil, "0"},
		{"-upload-window-mb", -1, nil, "-1"},
		{"-upload-window-mb", 1 << 43, nil, "8796093022208"},
		{"-upload-idle-ttl", 1, func(l *transfer.Limits) { l.IdleTTL = 0 }, "0s"},
		{"-upload-idle-ttl", 1, func(l *transfer.Limits) { l.IdleTTL = -time.Second }, "-1s"},
		{"-upload-first-part-ttl", 1, func(l *transfer.Limits) { l.FirstPartTTL = 0 }, "0s"},
		{"-upload-first-part-ttl", 1, func(l *transfer.Limits) { l.FirstPartTTL = -time.Second }, "-1s"},
		{"-upload-max-age", 1, func(l *transfer.Limits) { l.MaxAge = 0 }, "0s"},
		{"-upload-max-age", 1, func(l *transfer.Limits) { l.MaxAge = -time.Second }, "-1s"},
		{"-upload-tombstone-ttl", 1, func(l *transfer.Limits) { l.TombstoneTTL = 0 }, "0s"},
		{"-upload-tombstone-ttl", 1, func(l *transfer.Limits) { l.TombstoneTTL = -time.Second }, "-1s"},
		{"-upload-max-sessions", 1, func(l *transfer.Limits) { l.MaxSessions = 0 }, "0"},
		{"-upload-max-sessions", 1, func(l *transfer.Limits) { l.MaxSessions = -1 }, "-1"},
		{"-upload-max-sessions-total", 1, func(l *transfer.Limits) { l.MaxSessionsTotal = 0 }, "0"},
		{"-upload-max-sessions-total", 1, func(l *transfer.Limits) { l.MaxSessionsTotal = -1 }, "-1"},
		{"-upload-max-inflight", 1, func(l *transfer.Limits) { l.MaxInflight = 0 }, "0"},
		{"-upload-max-inflight", 1, func(l *transfer.Limits) { l.MaxInflight = -1 }, "-1"},
	} {
		l := good
		if tc.mod != nil {
			tc.mod(&l)
		}
		_, err := uploadLimits(tc.mb, l)
		if err == nil {
			t.Errorf("%s: a bad value accepted", tc.flag)
			continue
		}
		for _, f := range flags {
			if named := strings.Contains(err.Error(), f+" "); named != (f == tc.flag) {
				t.Errorf("%s: %q", tc.flag, err)
			}
		}
		if !strings.HasSuffix(err.Error(), "got "+tc.got) {
			t.Errorf("%s: %q, want the value %s", tc.flag, err, tc.got)
		}
	}
	if l, err := uploadLimits(1<<43-1, good); err != nil || l.Window != (1<<43-1)<<20 {
		t.Errorf("the largest window: %d %v", l.Window, err)
	}
}

func TestMaxUploadBytes(t *testing.T) {
	for mb, want := range map[int64]int64{0: 0, 1: 1 << 20, 67108864: 1 << 46} {
		if got, err := maxUploadBytes(mb); err != nil || got != want {
			t.Errorf("%d MiB: %d %v, want %d", mb, got, err, want)
		}
	}
	for _, mb := range []int64{67108865, -1, 1 << 43, 1 << 44, math.MaxInt64, math.MinInt64} {
		_, err := maxUploadBytes(mb)
		if err == nil || err.Error() != fmt.Sprintf("-max-upload-mb must be between 0 and 67108864, got %d", mb) {
			t.Errorf("%d MiB: %v", mb, err)
		}
	}
}

// While the server drains for shutdown, upload calls are refused like every
// other operation, before they reach the engine.
func TestUploadCallsAreRefusedWhileTheServerDrains(t *testing.T) {
	a, _ := newTestApp(t)
	data := bytes.Repeat([]byte("x"), 1000)
	_, c := createUpload(t, a.Handler, transfer.CreateRequest{Dir: "public", Name: "a.bin", Size: int64(len(data))})

	// A single-request upload whose body is held keeps the drain waiting.
	pr, pw := io.Pipe()
	t.Cleanup(func() { pw.CloseWithError(errors.New("the test ended")) })
	held := httptest.NewRequest(http.MethodPost, "/api/upload?path=public", pr)
	held.Header.Set("Content-Type", "multipart/form-data; boundary=B")
	answered := make(chan int, 1)
	go func() {
		rec := httptest.NewRecorder()
		a.Handler.ServeHTTP(rec, held)
		answered <- rec.Code
	}()
	read := make(chan struct{})
	go func() {
		io.WriteString(pw, "--B\r\nContent-Disposition: form-data; name=\"myFile\"; filename=\"held.bin\"\r\n\r\nx")
		close(read)
	}()
	within(t, "the held upload", read)
	closed := make(chan struct{})
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		a.Close(ctx)
		close(closed)
	}()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(time.Millisecond) {
		if code, _ := get(t, a.Handler, "/api/files?path="); code == http.StatusServiceUnavailable {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the server never began to drain")
		}
	}
	id := `{"uploadId":"` + c.UploadID + `"}`
	for _, rq := range []*http.Request{
		httptest.NewRequest("POST", "/api/upload/create", strings.NewReader(`{"dir":"public","name":"b","size":1}`)),
		partRequest(c.UploadID, 1, bytes.NewReader(data), data),
		httptest.NewRequest("POST", "/api/upload/status", strings.NewReader(id)),
		httptest.NewRequest("POST", "/api/upload/complete", strings.NewReader(`{"uploadId":"`+c.UploadID+`","compositeSha256":"`+strings.Repeat("0", 64)+`"}`)),
		httptest.NewRequest("POST", "/api/upload/abort", strings.NewReader(id)),
		httptest.NewRequest("GET", "/api/upload/list", nil),
	} {
		if rq.Header.Get("Content-Type") == "" && rq.Method == "POST" {
			rq.Header.Set("Content-Type", "application/json")
		}
		rec := httptest.NewRecorder()
		a.Handler.ServeHTTP(rec, rq)
		if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), `"unavailable"`) {
			t.Errorf("%s while draining: %d %s", rq.URL.Path, rec.Code, rec.Body)
		}
	}
	go func() { io.WriteString(pw, "\r\n--B--\r\n"); pw.Close() }()
	if code := within(t, "the upload under way", answered); code != http.StatusCreated {
		t.Errorf("the upload under way: %d", code)
	}
	<-closed
	if a.kept {
		t.Error("the shutdown kept the lock")
	}
}

// A completion replies once its records are on disk, and when they can't be
// written, it says so with the file it placed.
func TestACompletionRepliesOnceItsRecordsAreOnDisk(t *testing.T) {
	t.Cleanup(events.SetLostOutput(&lockedBuffer{}))
	a, cfg := newTestApp(t)
	defer closeApp(t, a)
	upload := func(name string) (int, string) {
		t.Helper()
		data := []byte("content of " + name)
		_, c := createUpload(t, a.Handler, transfer.CreateRequest{Dir: "public", Name: name, Size: int64(len(data))})
		rec := httptest.NewRecorder()
		a.Handler.ServeHTTP(rec, partRequest(c.UploadID, 1, bytes.NewReader(data), data))
		if rec.Code != http.StatusOK {
			t.Fatalf("part: %d %s", rec.Code, rec.Body)
		}
		sum := sha256.Sum256(data)
		return call(t, a.Handler, "POST", "/api/upload/complete", httpapi.UploadCompleteRequest{
			UploadID: c.UploadID, CompositeSHA256: transfer.Composite([][sha256.Size]byte{sum}),
		})
	}
	if code, body := upload("a.txt"); code != http.StatusCreated {
		t.Fatalf("complete: %d %s", code, body)
	}
	evs := auditEvents(t, cfg.AuditLog)
	if n := len(evs); n < 2 || evs[n-2].Type != events.FileUploaded || evs[n-1].Type != events.UploadCompleted || evs[n-1].Resolved != "public/a.txt" {
		t.Fatalf("after the reply the log ends with %+v", evs[max(len(evs)-2, 0):])
	}

	a.audit.Close()
	code, body := upload("b.txt")
	if code != http.StatusInternalServerError || !strings.Contains(body, `"not_recorded"`) || !strings.Contains(body, `"path":"public/b.txt"`) {
		t.Errorf("complete as the log stops: %d %s", code, body)
	}
	if _, err := os.Stat(filepath.Join(cfg.RootDir, "public", "b.txt")); err != nil {
		t.Error("the file whose records failed wasn't placed")
	}
	if code, body := call(t, a.Handler, "POST", "/api/upload/create", transfer.CreateRequest{Dir: "public", Name: "c.txt", Size: 1}); code != http.StatusServiceUnavailable ||
		!strings.Contains(body, `"changes_paused"`) {
		t.Errorf("create once the log failed: %d %s", code, body)
	}
}

func TestAnUploadKeepsTheFreeSpaceReserve(t *testing.T) {
	a, _ := newTestApp(t, func(c *config) { c.MinFreeBytes = 1 << 62 })
	defer closeApp(t, a)
	if a.space == nil {
		t.Skipf("free space cannot be measured here: %v", a.spaceErr)
	}
	code, body := call(t, a.Handler, "POST", "/api/upload/create", transfer.CreateRequest{Dir: "public", Name: "a.bin", Size: 10})
	if code != http.StatusInsufficientStorage || !strings.Contains(body, `"insufficient_storage"`) {
		t.Errorf("create below the reserve: %d %s", code, body)
	}
}

// A start that fails once the engine is made closes the engine: its janitor
// would otherwise go on in a process that lives on, with state.db closed
// beneath it.
func TestAFailedStartClosesTheEngine(t *testing.T) {
	janitors := func() int {
		buf := make([]byte, 1<<22)
		return strings.Count(string(buf[:runtime.Stack(buf, true)]), "transfer.(*Engine).janitor(")
	}
	before := janitors()
	cfg := seeded(t, testConfig(t))
	cfg.RecoverAdmin = "nobody"
	if a, err := newApp(cfg); err == nil {
		closeApp(t, a)
		t.Fatal("-recover-admin nobody started")
	}
	for deadline := time.Now().Add(5 * time.Second); janitors() > before; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the janitor runs on after a failed start")
		}
	}
}
