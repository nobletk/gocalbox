package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/nobletk/gocalbox/internal/events"
)

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func do(t *testing.T, h http.Handler, method, path, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func TestEveryChangeRepliesOnlyOnceItsRecordIsOnDisk(t *testing.T) {
	a, _ := newTestApp(t)
	defer closeApp(t, a)
	for i := range 20 {
		name := "f" + string(rune('a'+i)) + ".txt"
		rec := httptest.NewRecorder()
		a.Handler.ServeHTTP(rec, uploadRequest(t, name, 10, false))
		if rec.Code != http.StatusCreated {
			t.Fatalf("upload %s = %d %s", name, rec.Code, rec.Body)
		}
		evs := auditEvents(t, a.AuditPath)
		if last := evs[len(evs)-1]; last.Type != events.FileUploaded || last.Resolved != name {
			t.Fatalf("after the reply to %s the log ends with %+v", name, last)
		}
	}
}

func TestAWriterThatStoppedPausesChangesButNotReads(t *testing.T) {
	var lost lockedBuffer
	t.Cleanup(events.SetLostOutput(&lost))
	a, cfg := newTestApp(t)
	defer closeApp(t, a)
	os.WriteFile(filepath.Join(cfg.RootDir, "public", "a.txt"), []byte("A"), 0o644)
	if code, _ := do(t, a.Handler, "POST", "/api/fs/mkdir", `{"targetPath":"public","name":"before"}`); code != http.StatusCreated {
		t.Fatalf("mkdir before = %d", code)
	}
	if code, body := do(t, a.Handler, "GET", "/api/status", ""); !strings.Contains(body, `"changesPaused":false`) {
		t.Errorf("status = %d %s", code, body)
	}

	a.audit.Close()

	code, body := do(t, a.Handler, "POST", "/api/fs/mkdir", `{"targetPath":"public","name":"during"}`)
	var reply struct {
		Error  struct{ Code string }
		Result struct{ Path string }
	}
	json.Unmarshal([]byte(body), &reply)
	if code != http.StatusInternalServerError || reply.Error.Code != "not_recorded" || reply.Result.Path != "public/during" {
		t.Errorf("mkdir as the log stops = %d %s", code, body)
	}
	if _, err := os.Stat(filepath.Join(cfg.RootDir, "public", "during")); err != nil {
		t.Error("the folder whose record failed wasn't made")
	}
	if !strings.Contains(lost.String(), `"audit":"not_recorded"`) || !strings.Contains(lost.String(), `"path":"public/during"`) {
		t.Errorf("console = %s", lost.String())
	}

	code, body = do(t, a.Handler, "POST", "/api/fs/mkdir", `{"targetPath":"public","name":"after"}`)
	if code != http.StatusServiceUnavailable || !strings.Contains(body, "changes_paused") {
		t.Errorf("next change = %d %s", code, body)
	}
	if _, err := os.Stat(filepath.Join(cfg.RootDir, "public", "after")); err == nil {
		t.Error("a change was made while changes are paused")
	}
	if code, body := do(t, a.Handler, "GET", "/api/files?path=public", ""); code != 200 || !strings.Contains(body, "a.txt") {
		t.Errorf("listing while paused = %d %s", code, body)
	}
	if code, body := do(t, a.Handler, "GET", "/files/public/a.txt", ""); code != 200 || body != "A" {
		t.Errorf("download while paused = %d %q", code, body)
	}
	if _, body := do(t, a.Handler, "GET", "/api/status", ""); !strings.Contains(body, `"changesPaused":true`) {
		t.Errorf("status while paused = %s", body)
	}
	if code, body := do(t, a.Handler, "POST", "/api/auth/sessions/revoke-others", ""); code != http.StatusOK {
		t.Errorf("revoke-others while paused = %d %s", code, body)
	}
	req := httptest.NewRequest("POST", "/api/auth/password", strings.NewReader(`{"current":"`+testPassword+`","new":"another password of some length"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	a.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("password change while paused = %d %s", rec.Code, rec.Body)
	}
	logout := httptest.NewRequest("POST", "/api/auth/logout", nil)
	for _, c := range rec.Result().Cookies() {
		logout.AddCookie(c)
	}
	rec = httptest.NewRecorder()
	a.Handler.ServeHTTP(rec, logout)
	if rec.Code != http.StatusNoContent {
		t.Errorf("logout while paused = %d %s", rec.Code, rec.Body)
	}
}

func TestFailOpenKeepsChangesGoing(t *testing.T) {
	t.Cleanup(events.SetLostOutput(&lockedBuffer{}))
	a, _ := newTestApp(t, func(c *config) { c.AuditFailOpen = true })
	defer closeApp(t, a)
	a.audit.Close()
	for _, name := range []string{"one", "two"} {
		code, body := do(t, a.Handler, "POST", "/api/fs/mkdir", `{"targetPath":"public","name":"`+name+`"}`)
		if code != http.StatusInternalServerError || !strings.Contains(body, "not_recorded") {
			t.Errorf("mkdir %s = %d %s", name, code, body)
		}
	}
}

func TestWithoutWaitingChangesReplyAtOnce(t *testing.T) {
	t.Cleanup(events.SetLostOutput(&lockedBuffer{}))
	a, _ := newTestApp(t, func(c *config) { c.AuditNoWait = true })
	defer closeApp(t, a)
	a.audit.Close()
	if code, body := do(t, a.Handler, "POST", "/api/fs/mkdir", `{"targetPath":"public","name":"x"}`); code != http.StatusCreated {
		t.Errorf("mkdir without waiting = %d %s", code, body)
	}
}
