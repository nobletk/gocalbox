//go:build unix

package httpapi

import (
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestSpecialFilesAreNeitherListedNorOpened(t *testing.T) {
	e := newEnv(t, 0)
	e.write("a.txt", "x")
	pipe := filepath.Join(e.root, "pipe")
	if err := syscall.Mkfifo(pipe, 0o644); err != nil {
		t.Skipf("no FIFOs: %v", err)
	}
	t.Cleanup(func() {
		for range 3 {
			if f, err := os.OpenFile(pipe, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
				f.Close()
			}
		}
	})
	client := &http.Client{Timeout: 5 * time.Second}

	resp, err := client.Get(e.srv.URL + "/files/pipe")
	if err != nil {
		t.Fatalf("download of a FIFO hung: %v", err)
	}
	resp.Body.Close()
	want(t, resp.StatusCode, 404, "download FIFO")

	resp, err = client.Get(e.srv.URL + "/api/files?path=pipe")
	if err != nil {
		t.Fatalf("listing a FIFO hung: %v", err)
	}
	resp.Body.Close()
	want(t, resp.StatusCode, 400, "list FIFO")

	_, files, _ := e.list("")
	if len(files) != 1 || files[0].Name != "a.txt" {
		t.Errorf("listing = %+v, want only a.txt", files)
	}
}
