package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/sandbox"
)

// stagedFiles lists the single-request uploads staged under root.
func stagedFiles(t *testing.T, root string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(root, filepath.FromSlash(sandbox.TmpDir)))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "s-") {
			names = append(names, e.Name())
		}
	}
	return names
}

// slowUpload starts a single-request upload of name into the root whose
// body the test writes, and waits until the server has staged its first
// bytes.
func slowUpload(t *testing.T, s *liveServer, name string) (*multipart.Writer, io.Writer, *io.PipeWriter, <-chan int) {
	t.Helper()
	pr, pw := io.Pipe()
	t.Cleanup(func() { pw.CloseWithError(fmt.Errorf("the test ended")) })
	mw := multipart.NewWriter(pw)
	answered := make(chan int, 1)
	go func() {
		req, _ := http.NewRequest(http.MethodPost, s.url+"/api/upload", pr)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		resp, err := s.client.Do(req)
		if err != nil {
			answered <- 0
			return
		}
		resp.Body.Close()
		answered <- resp.StatusCode
	}()
	fw, _ := mw.CreateFormFile("myFile", name)
	fw.Write(bytes.Repeat([]byte("x"), 256<<10))
	deadline := time.Now().Add(10 * time.Second)
	for len(stagedFiles(t, s.root)) == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("nothing was staged\n%s", s.out)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return mw, fw, pw, answered
}

// A single-request upload shows in its folder only once it has arrived
// whole: the listing and the folder itself have nothing of it before.
func TestE2EASingleRequestUploadIsListedOnlyOnceWhole(t *testing.T) {
	s := startServer(t)
	mw, fw, pw, answered := slowUpload(t, s, "slow.bin")
	if code, body := s.get("/api/files?path="); code != 200 || strings.Contains(body, "slow.bin") {
		t.Errorf("listing during the upload: %d %s", code, body)
	}
	if _, err := os.Stat(filepath.Join(s.root, "slow.bin")); err == nil {
		t.Error("the file is in its folder before the upload ends")
	}
	fw.Write(bytes.Repeat([]byte("y"), 256<<10))
	mw.Close()
	pw.Close()
	if code := within(t, "the answer", answered); code != http.StatusCreated {
		t.Fatalf("the upload = %d\n%s", code, s.out)
	}
	if info, err := os.Stat(filepath.Join(s.root, "slow.bin")); err != nil || info.Size() != 512<<10 {
		t.Errorf("the placed file: %v, %v", info, err)
	}
	if code, body := s.get("/api/files?path="); code != 200 || !strings.Contains(body, `"slow.bin"`) {
		t.Errorf("listing after the upload: %d %s", code, body)
	}
	if left := stagedFiles(t, s.root); len(left) != 0 {
		t.Errorf("staged after the upload: %v", left)
	}
	if err := s.stop(syscall.SIGTERM); err != nil {
		t.Fatalf("exit: %v", err)
	}
	if evs := auditEvents(t, s.auditPath); len(evs) != 1 || evs[0].Type != events.FileUploaded || evs[0].Outcome != events.OutcomeOK || evs[0].Resolved != "slow.bin" || evs[0].Size != 512<<10 {
		t.Errorf("audit: %+v", evs)
	}
}

// A server killed during a single-request upload leaves no part of the file
// in its folder, and the next start removes what was staged.
func TestE2EAKilledSingleRequestUploadLeavesNothing(t *testing.T) {
	s := startServer(t)
	slowUpload(t, s, "cut.bin")
	if err := s.stop(syscall.SIGKILL); err == nil {
		t.Fatal("the killed server exited cleanly")
	}
	if _, err := os.Stat(filepath.Join(s.root, "cut.bin")); err == nil {
		t.Error("the killed upload is in its folder")
	}
	if len(stagedFiles(t, s.root)) != 1 {
		t.Fatalf("staged after the kill: %v", stagedFiles(t, s.root))
	}
	s.restart()
	if left := stagedFiles(t, s.root); len(left) != 0 {
		t.Errorf("staged after the restart: %v", left)
	}
	if code, body := s.get("/api/files?path="); code != 200 || strings.Contains(body, "cut.bin") {
		t.Errorf("listing after the restart: %d %s", code, body)
	}
}

// A single-request upload whose body stalls is answered 400 upload_aborted,
// over HTTP/1.1 and HTTP/2, and logged as aborted, not as the server's error.
func TestE2EAStalledSingleRequestUploadAnswersUploadAborted(t *testing.T) {
	s := startServer(t, "-body-timeout=1s")
	for _, h2 := range []bool{false, true} {
		cfg := s.tlsConfig.Clone()
		cfg.NextProtos = []string{map[bool]string{false: "http/1.1", true: "h2"}[h2]}
		var resp *http.Response
		var body []byte
		if !h2 {
			conn, err := tls.Dial("tcp", s.addr, cfg)
			if err != nil {
				t.Fatal(err)
			}
			head := "--B\r\nContent-Disposition: form-data; name=\"myFile\"; filename=\"stalled.bin\"\r\n\r\n"
			fmt.Fprintf(conn, "POST /api/upload HTTP/1.1\r\nHost: 127.0.0.1\r\n%sContent-Type: multipart/form-data; boundary=B\r\nContent-Length: %d\r\n\r\n%sxxxx", s.cookieLine(), 1<<20, head)
			conn.SetReadDeadline(time.Now().Add(10 * time.Second))
			if resp, err = http.ReadResponse(bufio.NewReader(conn), nil); err != nil {
				t.Fatalf("HTTP/1.1: no answer: %v", err)
			}
			body, _ = io.ReadAll(resp.Body)
			conn.Close()
		} else {
			_, c := trustClient(s.tlsConfig.RootCAs, true)
			pr, pw := io.Pipe()
			t.Cleanup(func() { pw.Close() })
			go io.WriteString(pw, "--B\r\nContent-Disposition: form-data; name=\"myFile\"; filename=\"stalled.bin\"\r\n\r\nxxxx")
			req, _ := http.NewRequest(http.MethodPost, s.url+"/api/upload", pr)
			req.Header.Set("Content-Type", "multipart/form-data; boundary=B")
			req.ContentLength = 1 << 20
			req.AddCookie(sessionCookie(s.statePath))
			var err error
			if resp, err = c.Do(req); err != nil {
				t.Fatalf("HTTP/2: no answer: %v", err)
			}
			body, _ = io.ReadAll(resp.Body)
			resp.Body.Close()
		}
		if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), `"upload_aborted"`) || resp.ProtoMajor != map[bool]int{false: 1, true: 2}[h2] {
			t.Errorf("HTTP/2 %v: a stalled upload over %s = %d %s", h2, resp.Proto, resp.StatusCode, body)
		}
	}
	if out := s.out.String(); !strings.Contains(out, "Upload aborted: ") || strings.Contains(out, "Internal error") {
		t.Errorf("console:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(s.root, "stalled.bin")); err == nil {
		t.Error("the stalled upload left its file")
	}
	if left := stagedFiles(t, s.root); len(left) != 0 {
		t.Errorf("staged: %v", left)
	}
	if err := s.stop(syscall.SIGTERM); err != nil {
		t.Fatalf("exit: %v", err)
	}
	for _, ev := range auditEvents(t, s.auditPath) {
		if ev.Type != events.FileUploaded || ev.Outcome != events.OutcomeError || !strings.Contains(ev.Detail, "broke off") {
			t.Errorf("audit: %+v", ev)
		}
	}
}
