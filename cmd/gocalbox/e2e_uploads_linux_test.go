package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/transfer"
)

// mountAt mounts a tmpfs of size at dir, or binds src there when it is set.
func mountAt(t *testing.T, dir, src, size string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("mounting a file system needs root")
	}
	var err error
	if src == "" {
		err = syscall.Mount("tmpfs", dir, "tmpfs", 0, "size="+size)
	} else {
		err = syscall.Mount(src, dir, "", syscall.MS_BIND, "")
	}
	if err != nil {
		t.Skipf("cannot mount: %v", err)
	}
	t.Cleanup(func() { syscall.Unmount(dir, syscall.MNT_DETACH) })
}

// A folder on another mount can't take a resumable upload, which would have
// to cross file systems at its end: create answers 409 cross_device, and
// the browser falls back to the single-request upload, which still works.
func TestE2EAFolderOnAnotherMountAnswersCrossDevice(t *testing.T) {
	s := startServer(t)
	other := filepath.Join(s.root, "public", "other")
	bound := filepath.Join(s.root, "public", "bound")
	for _, d := range []string{other, bound, filepath.Join(s.root, "public", "elsewhere")} {
		os.Mkdir(d, 0o755)
	}
	mountAt(t, other, "", "4m")
	mountAt(t, bound, filepath.Join(s.root, "public", "elsewhere"), "")
	admin := s.uploader(sessionCookie(s.statePath).Value)
	for _, dir := range []string{"public/other", "public/bound"} {
		f := source{dir: dir, name: "a.bin", data: []byte("data"), modified: time.Now()}
		_, err := admin.create(f)
		if codeOf(err) != "cross_device" || err.(*apiError).Status != 409 {
			t.Errorf("create into %s: %v", dir, err)
		}
		if code, err := s.upload(dir, "a.bin", f.data); err != nil || code != 201 {
			t.Errorf("the single-request upload into %s: %d %v", dir, code, err)
		}
		if b, err := os.ReadFile(filepath.Join(s.root, filepath.FromSlash(dir), "a.bin")); err != nil || string(b) != "data" {
			t.Errorf("%s/a.bin: %q %v", dir, b, err)
		}
	}
	if res, err := admin.upload(source{dir: "public", name: "here.bin", data: []byte("here"), modified: time.Now()}); err != nil || res.Path != "public/here.bin" {
		t.Errorf("an upload into the served file system: %+v %v", res, err)
	}
	if err := s.stop(syscall.SIGTERM); err != nil {
		t.Fatalf("exit: %v", err)
	}
	refused := 0
	for _, ev := range auditEvents(t, s.auditPath) {
		if ev.Type == events.UploadRejected && ev.Outcome == events.OutcomeInvalid && strings.Contains(ev.Detail, "different file systems") {
			refused++
		}
	}
	if refused != 2 {
		t.Errorf("%d refusals recorded for another mount, want 2", refused)
	}
}

// -upload-window-mb reaches the engine: on a disk of 200 MiB, an upload of
// 150 MiB holds all of it by default, and only 40 MiB with a window of 40.
// A second upload of 140 MiB then fits, as it wouldn't with a window of 80.
func TestE2EUploadWindowReachesTheEngine(t *testing.T) {
	for _, tc := range []struct {
		args []string
		code string
	}{
		{nil, "insufficient_storage"},
		{[]string{"-upload-window-mb=40"}, ""},
	} {
		s := newLiveServer(t)
		mountAt(t, s.root, "", "200m")
		tokens := addUsers(t, s, "alice:contributor")
		s.start(tc.args...)
		alice := s.uploader(tokens["alice"])
		var c transfer.Created
		if err := alice.call("/api/upload/create", transfer.CreateRequest{Dir: "users/alice", Name: "a.bin", Size: 150 << 20}, &c); err != nil {
			t.Fatalf("%v: the first upload: %v", tc.args, err)
		}
		err := alice.call("/api/upload/create", transfer.CreateRequest{Dir: "users/alice", Name: "b.bin", Size: 140 << 20}, &c)
		if codeOf(err) != tc.code || tc.code == "" && err != nil {
			t.Errorf("%v: the second upload: %v, want %q", tc.args, err, tc.code)
		}
		if err := s.stop(syscall.SIGTERM); err != nil {
			t.Fatalf("exit: %v", err)
		}
	}
}

// A read-only served folder turns resumable uploads off while downloads
// work, with or without a .gocalbox an earlier start made.
func TestAReadOnlyRootTurnsResumableUploadsOff(t *testing.T) {
	for _, earlier := range []bool{false, true} {
		cfg := testConfig(t)
		seedAdmin(t, cfg.StateFile, cfg.RootDir)
		if err := os.WriteFile(filepath.Join(cfg.RootDir, "public", "f.txt"), []byte("file"), 0o644); err != nil {
			t.Fatal(err)
		}
		if earlier {
			a, err := openTestApp(t, cfg)
			if err != nil {
				t.Fatal(err)
			}
			closeApp(t, a)
		}
		mountAt(t, cfg.RootDir, cfg.RootDir, "")
		if err := syscall.Mount("", cfg.RootDir, "", syscall.MS_BIND|syscall.MS_REMOUNT|syscall.MS_RDONLY, ""); err != nil {
			t.Skipf("cannot make the folder read-only: %v", err)
		}
		a, err := openTestApp(t, cfg)
		if err != nil {
			t.Fatalf("earlier start %v: %v", earlier, err)
		}
		code, body := call(t, a.Handler, "POST", "/api/upload/create", transfer.CreateRequest{Dir: "public", Name: "a.txt", Size: 1})
		if code != http.StatusServiceUnavailable || !strings.Contains(body, `"uploads_unavailable"`) {
			t.Errorf("earlier start %v: create %d %s", earlier, code, body)
		}
		if code, content := get(t, a.Handler, "/files/public/f.txt"); code != 200 || content != "file" {
			t.Errorf("earlier start %v: download %d %q", earlier, code, content)
		}
		closeApp(t, a)
	}
}

// A folder the server may not write to answers 403 permission_denied on
// both upload paths.
func TestAnImmutableFolderRefusesBothUploadPaths(t *testing.T) {
	a, cfg := newTestApp(t)
	defer closeApp(t, a)
	d := filepath.Join(cfg.RootDir, "public", "frozen")
	if err := os.Mkdir(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("chattr", "+i", d).CombinedOutput(); err != nil {
		t.Skipf("chattr: %v %s", err, out)
	}
	t.Cleanup(func() { exec.Command("chattr", "-i", d).Run() })
	code, body := call(t, a.Handler, "POST", "/api/upload/create", transfer.CreateRequest{Dir: "public/frozen", Name: "a.txt", Size: 1})
	if code != http.StatusForbidden || !strings.Contains(body, `"permission_denied"`) {
		t.Errorf("create: %d %s", code, body)
	}
	req := uploadRequest(t, "b.txt", 10, false)
	req.URL.RawQuery = "path=public/frozen"
	w := httptest.NewRecorder()
	a.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), `"permission_denied"`) {
		t.Errorf("the single-request upload: %d %s", w.Code, w.Body)
	}
}
