package main

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A single-request upload into a folder on another mount is written there
// from the start, as before, since a staged file can't be placed across
// file systems.
func TestE2EASingleRequestUploadIntoAnotherMountIsWrittenInPlace(t *testing.T) {
	s := startServer(t)
	other := filepath.Join(s.root, "public", "other")
	os.Mkdir(other, 0o755)
	mountAt(t, other, "", "4m")
	pr, pw := io.Pipe()
	t.Cleanup(func() { pw.Close() })
	mw := multipart.NewWriter(pw)
	answered := make(chan int, 1)
	go func() {
		req, _ := http.NewRequest(http.MethodPost, s.url+"/api/upload?path=public/other", pr)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		resp, err := s.client.Do(req)
		if err != nil {
			answered <- 0
			return
		}
		resp.Body.Close()
		answered <- resp.StatusCode
	}()
	fw, _ := mw.CreateFormFile("myFile", "slow.bin")
	fw.Write(bytes.Repeat([]byte("x"), 256<<10))
	deadline := time.Now().Add(10 * time.Second)
	for {
		if info, err := os.Stat(filepath.Join(other, "slow.bin")); err == nil && info.Size() > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the upload isn't written in its folder\n%s", s.out)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if left := stagedFiles(t, s.root); len(left) != 0 {
		t.Errorf("staged: %v", left)
	}
	mw.Close()
	pw.Close()
	if code := within(t, "the answer", answered); code != http.StatusCreated {
		t.Fatalf("the upload = %d", code)
	}
	if err := s.stop(syscall.SIGTERM); err != nil {
		t.Fatalf("exit: %v", err)
	}
}
