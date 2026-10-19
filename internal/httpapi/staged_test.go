package httpapi

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nobletk/gocalbox/internal/fsops"
	"github.com/nobletk/gocalbox/internal/sandbox"
)

type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func captureLog(t *testing.T) *logBuffer {
	var b logBuffer
	log.SetOutput(&b)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return &b
}

func (e *env) staged() []string {
	e.t.Helper()
	entries, err := os.ReadDir(filepath.Join(e.root, filepath.FromSlash(sandbox.TmpDir)))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		e.t.Fatal(err)
	}
	var names []string
	for _, d := range entries {
		names = append(names, d.Name())
	}
	return names
}

// stalledUpload sends a single-request upload over HTTP/1.1 that stops
// partway, and returns the answer, or nil once the connection closes
// without one. close ends the body by closing the connection instead.
func stalledUpload(t *testing.T, e *env, closeEarly bool) *http.Response {
	t.Helper()
	addr := strings.TrimPrefix(e.srv.URL, "http://")
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	part := "--B\r\nContent-Disposition: form-data; name=\"myFile\"; filename=\"slow.bin\"\r\n\r\n"
	fmt.Fprintf(conn, "POST /api/upload HTTP/1.1\r\nHost: %s\r\nContent-Type: multipart/form-data; boundary=B\r\nContent-Length: %d\r\n\r\n%s%s", addr, 1<<20, part, strings.Repeat("x", 100<<10))
	if closeEarly {
		conn.(*net.TCPConn).CloseWrite()
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return nil
	}
	resp.Body = io.NopCloser(bytes.NewReader(must(io.ReadAll(resp.Body))))
	return resp
}

func must[T any](v T, _ error) T { return v }

// waitEvents waits until n events were published.
func (e *env) waitEvents(n int) {
	e.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for len(e.rec.all()) < n {
		if time.Now().After(deadline) {
			e.t.Fatalf("%d events published, want %d", len(e.rec.all()), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestAStalledUploadAnswersUploadAborted(t *testing.T) {
	out := captureLog(t)
	e := newEnvOpts(t, Options{BodyTimeout: 300 * time.Millisecond})
	resp := stalledUpload(t, e, false)
	if resp == nil {
		t.Fatal("no answer")
	}
	body := must(io.ReadAll(resp.Body))
	if resp.StatusCode != http.StatusBadRequest || errorCode(string(body)) != "upload_aborted" {
		t.Errorf("a stalled upload = %d %s", resp.StatusCode, body)
	}
	e.waitEvents(1)
	if ev := e.lastEvent(); ev.Outcome != "error" || !strings.Contains(ev.Detail, "broke off") || !strings.Contains(ev.Detail, "timeout") || strings.Contains(ev.Detail, "write file") {
		t.Errorf("event = %+v", ev)
	}
	if log := out.String(); !strings.Contains(log, "Upload aborted: ") || strings.Contains(log, "Internal error") {
		t.Errorf("log: %q", log)
	}
	if e.exists(filepath.Join(e.root, "slow.bin")) || len(e.staged()) != 0 {
		t.Errorf("the stalled upload left its file, or %v staged", e.staged())
	}
}

func TestADisconnectedUploadIsLoggedAsAborted(t *testing.T) {
	out := captureLog(t)
	e := newEnvOpts(t, Options{})
	stalledUpload(t, e, true)
	e.waitEvents(1)
	if ev := e.lastEvent(); ev.Outcome != "error" || !strings.Contains(ev.Detail, "broke off") {
		t.Errorf("event = %+v", ev)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(out.String(), "Upload aborted: ") && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if log := out.String(); !strings.Contains(log, "Upload aborted: ") || strings.Contains(log, "Internal error") {
		t.Errorf("log: %q", log)
	}
	if len(e.staged()) != 0 {
		t.Errorf("staged: %v", e.staged())
	}
}

func TestAStalledUploadAnswersUploadAbortedOverHTTP2(t *testing.T) {
	e := newTLSEnv(t, Options{BodyTimeout: 300 * time.Millisecond}, time.Second)
	pr, pw := io.Pipe()
	defer pw.Close()
	go io.WriteString(pw, "--B\r\nContent-Disposition: form-data; name=\"myFile\"; filename=\"slow.bin\"\r\n\r\nxxxx")
	req, _ := http.NewRequest(http.MethodPost, "https://"+e.addr+"/api/upload", pr)
	req.Header.Set("Content-Type", "multipart/form-data; boundary=B")
	req.ContentLength = 1 << 20
	resp, err := e.client(true).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body := must(io.ReadAll(resp.Body))
	resp.Body.Close()
	if resp.ProtoMajor != 2 || resp.StatusCode != http.StatusBadRequest || errorCode(string(body)) != "upload_aborted" {
		t.Errorf("a stalled upload over %s = %d %s", resp.Proto, resp.StatusCode, body)
	}
}

func TestATooLargeUploadStillAnswers413(t *testing.T) {
	e := newEnv(t, 1000)
	code, body := e.upload("", "big.bin", strings.Repeat("x", 2000))
	if code != http.StatusRequestEntityTooLarge || errorCode(body) != "too_large" {
		t.Errorf("an upload over the limit = %d %s", code, body)
	}
	if ev := e.lastEvent(); strings.Contains(ev.Detail, "broke off") {
		t.Errorf("event = %+v", ev)
	}
	if len(e.staged()) != 0 {
		t.Errorf("staged: %v", e.staged())
	}
}

func TestBodyErrorsAreTheClients(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code int
		want string
	}{
		{fmt.Errorf("%w: unexpected EOF", fsops.ErrBodyAborted), http.StatusBadRequest, "upload_aborted"},
		{fmt.Errorf("write file: %w", errors.New("input/output error")), http.StatusInternalServerError, "internal"},
	} {
		w := httptest.NewRecorder()
		writeError(w, httptest.NewRequest(http.MethodPost, "/api/upload", nil), tc.err)
		if w.Code != tc.code || errorCode(w.Body.String()) != tc.want {
			t.Errorf("%v: %d %s", tc.err, w.Code, w.Body)
		}
	}
}

type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

func TestUploadBodyMarksOnlyTheBodysOwnFailures(t *testing.T) {
	reset := errors.New("connection reset")
	if _, err := (uploadBody{errReader{reset}}).Read(make([]byte, 1)); !errors.Is(err, fsops.ErrBodyAborted) || !errors.Is(err, reset) {
		t.Errorf("a body that broke off: %v", err)
	}
	if _, err := (uploadBody{errReader{io.EOF}}).Read(make([]byte, 1)); err != io.EOF {
		t.Errorf("the end of the body: %v", err)
	}
	var tooBig *http.MaxBytesError
	_, err := (uploadBody{errReader{&http.MaxBytesError{Limit: 5}}}).Read(make([]byte, 1))
	if !errors.As(err, &tooBig) || errors.Is(err, fsops.ErrBodyAborted) {
		t.Errorf("a body over the limit: %v", err)
	}
	if n, err := (uploadBody{strings.NewReader("abc")}).Read(make([]byte, 8)); n != 3 || err != nil {
		t.Errorf("a read: %d, %v", n, err)
	}
}

// The file of a single-request upload appears in its folder only once its
// body has arrived whole.
func TestAnUploadIsListedOnlyOnceWhole(t *testing.T) {
	e := newEnvOpts(t, Options{})
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	answered := make(chan int, 1)
	go func() {
		req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/api/upload", pr)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			answered <- 0
			return
		}
		resp.Body.Close()
		answered <- resp.StatusCode
	}()
	fw, _ := mw.CreateFormFile("myFile", "slow.bin")
	fw.Write(bytes.Repeat([]byte("x"), 64<<10))
	deadline := time.Now().Add(10 * time.Second)
	for len(e.staged()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("nothing was staged")
		}
		time.Sleep(2 * time.Millisecond)
	}
	if _, files, body := e.list(""); len(files) != 0 {
		t.Errorf("listing during the upload: %s", body)
	}
	mw.Close()
	pw.Close()
	if code := <-answered; code != http.StatusCreated {
		t.Fatalf("the upload = %d", code)
	}
	if _, files, body := e.list(""); len(files) != 1 || files[0].Name != "slow.bin" || files[0].Size != 64<<10 {
		t.Errorf("listing after the upload: %s", body)
	}
	if len(e.staged()) != 0 {
		t.Errorf("staged: %v", e.staged())
	}
}
