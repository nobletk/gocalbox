package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/nobletk/gocalbox/internal/events"
)

func mountSmall(t *testing.T, dir string, size string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("mounting a test file system needs root")
	}
	if err := syscall.Mount("tmpfs", dir, "tmpfs", 0, "size="+size); err != nil {
		t.Skipf("cannot mount a test file system: %v", err)
	}
	t.Cleanup(func() { syscall.Unmount(dir, syscall.MNT_DETACH) })
}

func TestFullVolumeAnswers507(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	os.Mkdir(root, 0o755)
	mountSmall(t, root, "2m")
	a, err := newApp(seeded(t, config{RootDir: root, AuditLog: filepath.Join(t.TempDir(), "a.jsonl")}))
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name    string
		chunked bool
	}{
		{"declared.bin", false}, // refused by the ledger before anything is written
		{"chunked.bin", true},   // refused when the disk fills while writing
	} {
		rec := httptest.NewRecorder()
		a.Handler.ServeHTTP(rec, uploadRequest(t, tc.name, 5<<20, tc.chunked))
		if rec.Code != http.StatusInsufficientStorage || !strings.Contains(rec.Body.String(), `"insufficient_storage"`) {
			t.Errorf("%s: %d %s", tc.name, rec.Code, rec.Body)
		}
		if _, err := os.Stat(filepath.Join(root, tc.name)); err == nil {
			t.Errorf("%s: partial file left behind", tc.name)
		}
	}
	closeApp(t, a)

	evs := auditEvents(t, a.AuditPath)
	if len(evs) != 2 {
		t.Fatalf("audit records: %+v", evs)
	}
	for _, ev := range evs {
		if ev.Type != events.FileUploaded || ev.Outcome != events.OutcomeNoSpace {
			t.Errorf("audit record %+v, want file.uploaded / no_space", ev)
		}
	}
}

func TestMoveIntoAnotherMountAnswers409(t *testing.T) {
	root := t.TempDir()
	ext := filepath.Join(root, "ext")
	os.Mkdir(ext, 0o755)
	mountSmall(t, ext, "1m")
	os.WriteFile(filepath.Join(root, "a.txt"), []byte("x"), 0o644)
	a, err := newApp(seeded(t, config{RootDir: root, AuditLog: filepath.Join(t.TempDir(), "a.jsonl")}))
	if err != nil {
		t.Fatal(err)
	}
	defer closeApp(t, a)

	req := httptest.NewRequest(http.MethodPost, "/api/fs/move", strings.NewReader(`{"oldPath":"a.txt","newPath":"ext/a.txt"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	a.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), `"cross_device"`) {
		t.Errorf("move into another mount: %d %s", rec.Code, rec.Body)
	}
	if _, err := os.Stat(filepath.Join(root, "a.txt")); err != nil {
		t.Error("the source was lost")
	}
}

func TestUploadIntoAnotherMountIgnoresTheServedDisk(t *testing.T) {
	root := t.TempDir()
	ext := filepath.Join(root, "ext")
	os.Mkdir(ext, 0o755)
	mountSmall(t, ext, "2m")
	a, err := newApp(seeded(t, config{RootDir: root, AuditLog: filepath.Join(t.TempDir(), "a.jsonl"), MinFreeBytes: 1 << 62}))
	if err != nil {
		t.Fatal(err)
	}
	defer closeApp(t, a)
	if a.space == nil {
		t.Skip("free space cannot be measured here")
	}

	upload := func(dir, name string, size int) int {
		req := uploadRequest(t, name, size, false)
		req.URL.RawQuery = "path=" + dir
		rec := httptest.NewRecorder()
		a.Handler.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := upload("ext", "small.bin", 10); code != http.StatusCreated {
		t.Errorf("small upload into the mounted folder: %d, want 201 although the served disk is below its reserve", code)
	}
	if code := upload("", "small.bin", 10); code != http.StatusInsufficientStorage {
		t.Errorf("small upload into the served folder: %d, want 507", code)
	}
	if code := upload("ext", "big.bin", 5<<20); code != http.StatusInsufficientStorage {
		t.Errorf("upload larger than the mounted folder's disk: %d, want 507", code)
	}
	if _, err := os.Stat(filepath.Join(ext, "big.bin")); err == nil {
		t.Error("partial file left behind")
	}
}

func TestReadOnlyMountAnswers403(t *testing.T) {
	root := t.TempDir()
	ro := filepath.Join(root, "ro")
	os.Mkdir(ro, 0o755)
	mountSmall(t, ro, "1m")
	os.WriteFile(filepath.Join(ro, "a.txt"), []byte("x"), 0o644)
	if err := syscall.Mount("tmpfs", ro, "tmpfs", syscall.MS_REMOUNT|syscall.MS_RDONLY, "size=1m"); err != nil {
		t.Skipf("cannot make the test file system read-only: %v", err)
	}
	a, err := newApp(seeded(t, config{RootDir: root, AuditLog: filepath.Join(t.TempDir(), "a.jsonl")}))
	if err != nil {
		t.Fatal(err)
	}

	req := uploadRequest(t, "b.txt", 10, false)
	req.URL.RawQuery = "path=ro"
	rec := httptest.NewRecorder()
	a.Handler.ServeHTTP(rec, req)
	codes := []int{rec.Code}
	for _, c := range []struct{ path, body string }{
		{"/api/fs/mkdir", `{"name":"d","targetPath":"ro"}`},
		{"/api/fs/move", `{"oldPath":"ro/a.txt","newPath":"ro/c.txt"}`},
		{"/api/fs/delete", `{"path":"ro/a.txt"}`},
	} {
		codes = append(codes, post(t, a.Handler, c.path, c.body))
	}
	for i, code := range codes {
		if code != http.StatusForbidden {
			t.Errorf("operation %d on a read-only folder: %d, want 403", i, code)
		}
	}
	closeApp(t, a)

	evs := auditEvents(t, a.AuditPath)
	if len(evs) != 4 {
		t.Fatalf("audit records: %+v", evs)
	}
	for _, ev := range evs {
		if ev.Outcome != events.OutcomeDenied {
			t.Errorf("audit record %+v, want outcome denied", ev)
		}
	}
}
