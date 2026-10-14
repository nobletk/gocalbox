package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nobletk/gocalbox/internal/audit"
	"github.com/nobletk/gocalbox/internal/auth"
	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/state"
)

func get(t *testing.T, h http.Handler, path string) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	b, _ := io.ReadAll(rec.Result().Body)
	return rec.Code, string(b)
}

func post(t *testing.T, h http.Handler, path, body string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

// seedAdmin gives a new state file an admin, "admin" with the password
// testPassword, and creates the folder layout setup would, so a server
// starts outside setup mode and creates nothing at start-up.
func seedAdmin(t *testing.T, statePath, root string) state.User {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(statePath), 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := state.Open(statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	hash, _ := auth.NewHasher(auth.Params{Memory: 64, Time: 1, Threads: 1}, 1, time.Second).Hash(context.Background(), testPassword)
	now := time.Now().UTC()
	admin := state.User{ID: state.NewUserID(), Username: "admin", Role: state.RoleAdmin, Hash: hash, CreatedAt: now, CreatedBy: events.ConsoleID, PasswordChangedAt: now}
	err = db.Update(func(tx *state.Tx) error {
		if err := tx.CreateUser(admin); err != nil {
			return err
		}
		if err := tx.PutBinding(state.Binding{ID: state.NewID(), Subject: admin.ID, Folder: "users/admin", Role: state.RoleContributor, Kind: state.KindHome, CreatedAt: now}); err != nil {
			return err
		}
		return tx.PutBinding(state.Binding{ID: state.NewID(), Subject: state.Everyone, Folder: "public", Role: state.RoleContributor, Kind: state.KindPublic, CreatedAt: now})
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"users/admin", "public"} {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(d)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return admin
}

const testPassword = "test password of some length"

// testConfig is a configuration with its own audit log and state file, and
// no admin yet.
func testConfig(t *testing.T) config {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "root")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	return config{RootDir: root, AuditLog: filepath.Join(base, "audit", "audit.jsonl"), StateFile: filepath.Join(base, "state", "state.db")}
}

// seeded gives cfg a new state file with an admin.
func seeded(t *testing.T, cfg config) config {
	t.Helper()
	cfg.StateFile = filepath.Join(t.TempDir(), "state.db")
	seedAdmin(t, cfg.StateFile, cfg.RootDir)
	return cfg
}

func newTestApp(t *testing.T, mutate ...func(*config)) (*app, config) {
	t.Helper()
	cfg := testConfig(t)
	seedAdmin(t, cfg.StateFile, cfg.RootDir)
	for _, m := range mutate {
		m(&cfg)
	}
	a, err := newApp(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return a, cfg
}

func uploadRequest(t *testing.T, name string, size int, chunked bool) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	w, _ := mw.CreateFormFile("myFile", name)
	w.Write(bytes.Repeat([]byte("x"), size))
	mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/api/upload", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if chunked {
		req.Body = io.NopCloser(req.Body)
		req.ContentLength = -1
	}
	return req
}

func closeApp(t *testing.T, a *app) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func auditEvents(t *testing.T, path string) []events.Event {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []events.Event
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line == "" {
			continue
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

// Each layer has its own tests; these check the wiring.
func TestAppServesUIAndAPI(t *testing.T) {
	a, cfg := newTestApp(t)
	defer closeApp(t, a)
	os.WriteFile(filepath.Join(cfg.RootDir, "hello.txt"), []byte("hi"), 0o644)

	if code, body := get(t, a.Handler, "/"); code != 200 || !strings.Contains(strings.ToLower(body), "<html") {
		t.Errorf("GET / = %d, %.60q", code, body)
	}
	if code, body := get(t, a.Handler, "/api/files?path="); code != 200 || !strings.Contains(body, "hello.txt") {
		t.Errorf("GET /api/files = %d, %q", code, body)
	}
	if code, body := get(t, a.Handler, "/files/hello.txt"); code != 200 || body != "hi" {
		t.Errorf("GET /files/hello.txt = %d, %q", code, body)
	}
	if code, _ := get(t, a.Handler, "/api/files?path=../"); code != 403 {
		t.Errorf("traversal = %d, want 403", code)
	}
}

func TestWebDirOverride(t *testing.T) {
	web := t.TempDir()
	os.WriteFile(filepath.Join(web, "index.html"), []byte("<html>custom</html>"), 0o644)
	a, _ := newTestApp(t, func(c *config) { c.WebDir = web })
	defer closeApp(t, a)

	if _, body := get(t, a.Handler, "/"); !strings.Contains(body, "custom") {
		t.Errorf("-web override not used: %q", body)
	}
}

func TestFailedRenameEndsUpInTheAuditLog(t *testing.T) {
	a, _ := newTestApp(t)

	if code := post(t, a.Handler, "/api/fs/rename", `{"oldPath":"dog4.jpg","newPath":"dog3.jpg"}`); code != 404 {
		t.Fatalf("status = %d, want 404", code)
	}
	if code := post(t, a.Handler, "/api/fs/delete", `{"path":""}`); code != 400 {
		t.Fatalf("delete root status = %d, want 400", code)
	}
	if code, _ := get(t, a.Handler, "/api/files?path=../outside"); code != 403 {
		t.Fatalf("traversal status = %d, want 403", code)
	}
	closeApp(t, a)

	if rep, err := audit.Verify(a.AuditPath); err != nil || rep.Records != 3 {
		t.Fatalf("Verify: %+v, %v", rep, err)
	}
	evs := auditEvents(t, a.AuditPath)
	if len(evs) != 3 {
		t.Fatalf("%d audit events, want 3: %+v", len(evs), evs)
	}

	mv, del, list := evs[0], evs[1], evs[2]
	if mv.Type != events.FileMoved || mv.Outcome != events.OutcomeNotFound || mv.Path != "dog4.jpg" || mv.Target != "dog3.jpg" || mv.RequestID == "" {
		t.Errorf("rename event = %+v", mv)
	}
	if del.Type != events.FileDeleted || del.Outcome != events.OutcomeDenied {
		t.Errorf("delete-root event = %+v", del)
	}
	if list.Type != events.FileListed || list.Outcome != events.OutcomeDenied || list.Path != "../outside" {
		t.Errorf("traversal event = %+v (the attempted path must be kept as sent)", list)
	}
}

func TestListingsAndFileChecksAreAuditedOnlyWhenEnabled(t *testing.T) {
	count := func(on bool) int {
		a, cfg := newTestApp(t, func(c *config) { c.AuditListings = on })
		os.WriteFile(filepath.Join(cfg.RootDir, "a.jpg"), []byte("x"), 0o644)
		get(t, a.Handler, "/api/files?path=")
		get(t, a.Handler, "/api/files?path=")

		rec := httptest.NewRecorder()
		a.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodHead, "/files/a.jpg", nil))
		req := httptest.NewRequest(http.MethodGet, "/files/a.jpg", nil)
		req.Header.Set("If-None-Match", rec.Header().Get("ETag"))
		rec = httptest.NewRecorder()
		a.Handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotModified {
			t.Fatalf("revalidation = %d", rec.Code)
		}
		closeApp(t, a)
		return len(auditEvents(t, a.AuditPath))
	}
	if n := count(false); n != 0 {
		t.Errorf("listings and file checks recorded by default: %d", n)
	}
	if n := count(true); n != 4 {
		t.Errorf("records with -audit-listings: %d, want 4 (2 listings, HEAD, 304)", n)
	}
}

func TestAuditLogContinuesAcrossRestarts(t *testing.T) {
	a, cfg := newTestApp(t)
	os.WriteFile(filepath.Join(cfg.RootDir, "a.txt"), []byte("x"), 0o644)
	post(t, a.Handler, "/api/fs/delete", `{"path":"a.txt"}`)
	closeApp(t, a)

	b, err := newApp(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if n := b.audit.Records(); n != 1 {
		t.Errorf("records after restart = %d, want 1", n)
	}
	post(t, b.Handler, "/api/fs/delete", `{"path":"missing"}`)
	closeApp(t, b)

	if rep, err := audit.Verify(b.AuditPath); err != nil || rep.Records != 2 {
		t.Errorf("after restart: %+v, %v", rep, err)
	}
}

func TestAuditLogInsideServedFolderIsRefused(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	os.Mkdir(root, 0o755)

	for _, p := range []string{
		filepath.Join(root, "audit.jsonl"),
		filepath.Join(root, "sub", "audit.jsonl"),
	} {
		if _, err := newApp(config{RootDir: root, AuditLog: p}); err == nil {
			t.Errorf("audit log %s inside the served folder was accepted", p)
		}
	}
}

func TestTamperedAuditLogBlocksStartup(t *testing.T) {
	a, cfg := newTestApp(t)
	post(t, a.Handler, "/api/fs/delete", `{"path":"x"}`)
	post(t, a.Handler, "/api/fs/delete", `{"path":"y"}`)
	closeApp(t, a)

	b, _ := os.ReadFile(a.AuditPath)
	os.WriteFile(a.AuditPath, []byte(strings.Replace(string(b), `"path":"x"`, `"path":"z"`, 1)), 0o600)

	_, err := newApp(cfg)
	if !errors.Is(err, audit.ErrTampered) {
		t.Errorf("startup err = %v, want ErrTampered", err)
	}
}

func TestBadRootIsRejected(t *testing.T) {
	audit := filepath.Join(t.TempDir(), "audit.jsonl")
	if _, err := newApp(config{RootDir: filepath.Join(t.TempDir(), "missing"), AuditLog: audit}); err == nil {
		t.Error("missing root should fail")
	}
	f := filepath.Join(t.TempDir(), "file")
	os.WriteFile(f, nil, 0o644)
	if _, err := newApp(config{RootDir: f, AuditLog: audit}); err == nil {
		t.Error("file as root should fail")
	}
}

func getRange(t *testing.T, h http.Handler, path, rng string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Range", rng)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func TestRangedDownloadsAreCollapsedInTheAuditLog(t *testing.T) {
	count := func(window time.Duration) int {
		a, cfg := newTestApp(t, func(c *config) { c.AuditRangeWindow = window })
		os.WriteFile(filepath.Join(cfg.RootDir, "movie.bin"), []byte("0123456789"), 0o644)
		for _, rng := range []string{"bytes=0-", "bytes=3-", "bytes=6-"} {
			if code := getRange(t, a.Handler, "/files/movie.bin", rng); code != 206 {
				t.Fatalf("range %s = %d", rng, code)
			}
		}
		closeApp(t, a)
		return len(auditEvents(t, a.AuditPath))
	}
	if n := count(time.Minute); n != 2 {
		t.Errorf("with a window: %d records, want 2 (first access + summary)", n)
	}
	if n := count(0); n != 3 {
		t.Errorf("without a window: %d records, want 3", n)
	}
}

func TestHostAllowlist(t *testing.T) {
	has := func(list []string, h string) bool {
		for _, x := range list {
			if x == h {
				return true
			}
		}
		return false
	}

	l := hostAllowlist("localhost", "files.example, ,Box.lan")
	for _, h := range []string{"localhost", "127.0.0.1", "::1", "files.example", "Box.lan"} {
		if !has(l, h) {
			t.Errorf("%q missing from %v", h, l)
		}
	}
	if len(l) != 5 {
		t.Errorf("duplicates or extras in %v", l)
	}

	if l := hostAllowlist("192.168.1.20", ""); !has(l, "192.168.1.20") {
		t.Errorf("listen address missing: %v", l)
	}

	name, _ := os.Hostname()
	for _, wildcard := range []string{"0.0.0.0", "::", ""} {
		l := hostAllowlist(wildcard, "")
		if name != "" && !has(l, name) {
			t.Errorf("%q: host name %q missing from %v", wildcard, name, l)
		}
		if has(l, "0.0.0.0") || has(l, "::") {
			t.Errorf("%q: wildcard address listed as a host: %v", wildcard, l)
		}
	}
}

func TestCheckExposure(t *testing.T) {
	for _, host := range []string{"localhost", "LocalHost", "127.0.0.1", "127.0.0.2", "::1", "[::1]"} {
		if err := checkExposure(host, false); err != nil {
			t.Errorf("%q refused: %v", host, err)
		}
	}
	for _, host := range []string{"0.0.0.0", "::", "", "192.168.1.5", "myhost.lan", "localhost.example"} {
		if err := checkExposure(host, false); err == nil || !strings.Contains(err.Error(), "-insecure-no-auth") {
			t.Errorf("%q allowed without -insecure-no-auth: %v", host, err)
		}
		if err := checkExposure(host, true); err != nil {
			t.Errorf("%q refused despite -insecure-no-auth: %v", host, err)
		}
	}
}

func TestCloseWaitsForOperationsStillRunning(t *testing.T) {
	a, cfg := newTestApp(t)
	big := filepath.Join(cfg.RootDir, "big")
	for d := 0; d < 30; d++ {
		dir := filepath.Join(big, fmt.Sprint(d))
		os.MkdirAll(dir, 0o755)
		for f := 0; f < 1000; f++ {
			os.WriteFile(filepath.Join(dir, fmt.Sprint(f)), nil, 0o644)
		}
	}
	srv := httptest.NewServer(a.Handler)
	defer srv.Close()

	result := make(chan int, 1)
	go func() {
		resp, err := http.Post(srv.URL+"/api/fs/delete", "application/json", strings.NewReader(`{"path":"big"}`))
		if err != nil {
			result <- 0
			return
		}
		resp.Body.Close()
		result <- resp.StatusCode
	}()
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(time.Millisecond) {
		if _, err := os.Stat(filepath.Join(big, "0", "0")); errors.Is(err, os.ErrNotExist) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("delete did not start")
		}
	}

	// As after a forced shutdown: the HTTP server no longer waits for the handler.
	closeApp(t, a)
	if _, err := os.Stat(big); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("Close returned while the delete was still running")
	}
	var deleted bool
	for _, ev := range auditEvents(t, cfg.AuditLog) {
		deleted = deleted || (ev.Type == events.FileDeleted && ev.Resolved == "big" && ev.Outcome == events.OutcomeOK)
	}
	if !deleted {
		t.Error("the delete is missing from the audit log")
	}
	if code := <-result; code != 200 {
		t.Errorf("delete answered %d", code)
	}
}

func TestUploadsKeepTheFreeSpaceReserve(t *testing.T) {
	a, cfg := newTestApp(t, func(c *config) { c.MinFreeBytes = 1 << 62 })
	if a.space == nil {
		closeApp(t, a)
		t.Skipf("free space cannot be measured here: %v", a.spaceErr)
	}
	for _, chunked := range []bool{false, true} {
		rec := httptest.NewRecorder()
		a.Handler.ServeHTTP(rec, uploadRequest(t, "a.bin", 10, chunked))
		if rec.Code != http.StatusInsufficientStorage {
			t.Errorf("chunked=%v: %d %s", chunked, rec.Code, rec.Body)
		}
	}
	closeApp(t, a)
	if _, err := os.Stat(filepath.Join(cfg.RootDir, "a.bin")); err == nil {
		t.Error("an upload below the reserve was stored")
	}
	evs := auditEvents(t, cfg.AuditLog)
	if len(evs) != 2 {
		t.Fatalf("audit records: %+v", evs)
	}
	for _, ev := range evs {
		if ev.Type != events.FileUploaded || ev.Outcome != events.OutcomeNoSpace {
			t.Errorf("audit record %+v, want file.uploaded / no_space", ev)
		}
	}
}
