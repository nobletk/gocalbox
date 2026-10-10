package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/nobletk/gocalbox/internal/audit"
	"github.com/nobletk/gocalbox/internal/events"
)

// End-to-end tests run the real binary as a separate process, covering flag
// parsing, signals, graceful shutdown and the final audit flush. Skipped with
// -short.

var (
	buildOnce sync.Once
	binPath   string
	buildErr  error
)

func binary(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("end-to-end tests are skipped with -short")
	}
	if runtime.GOOS == "windows" {
		t.Skip("end-to-end tests send POSIX signals")
	}
	buildOnce.Do(func() {
		goTool, err := exec.LookPath("go")
		if err != nil {
			buildErr = err
			return
		}
		dir, err := os.MkdirTemp("", "gocalbox-e2e-")
		if err != nil {
			buildErr = err
			return
		}
		binPath = filepath.Join(dir, "gocalbox")
		// Prefer a race-enabled build so a data race in a real run fails.
		for _, args := range [][]string{{"build", "-race", "-o", binPath, "."}, {"build", "-o", binPath, "."}} {
			out, err := exec.Command(goTool, args...).CombinedOutput()
			if err == nil {
				buildErr = nil
				return
			}
			buildErr = fmt.Errorf("go %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	})
	if buildErr != nil {
		t.Skipf("cannot build the binary: %v", buildErr)
	}
	return binPath
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type liveServer struct {
	t         *testing.T
	cmd       *exec.Cmd
	out       *syncBuffer
	url       string
	root      string
	auditPath string
	done      chan error
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// startServer runs the binary on a free port with a fresh root and audit log
// and waits until it answers.
func startServer(t *testing.T, extraArgs ...string) *liveServer {
	t.Helper()
	bin := binary(t)

	base := t.TempDir()
	s := &liveServer{
		t:         t,
		out:       &syncBuffer{},
		root:      filepath.Join(base, "root"),
		auditPath: filepath.Join(base, "audit", "audit.jsonl"),
		done:      make(chan error, 1),
	}
	if err := os.Mkdir(s.root, 0o755); err != nil {
		t.Fatal(err)
	}
	port := freePort(t)
	s.url = fmt.Sprintf("http://127.0.0.1:%d", port)

	args := append([]string{
		"-host=127.0.0.1", fmt.Sprintf("-port=%d", port),
		"-root=" + s.root, "-audit-log=" + s.auditPath,
	}, extraArgs...)
	s.cmd = exec.Command(bin, args...)
	s.cmd.Stdout, s.cmd.Stderr = s.out, s.out
	if err := s.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { s.done <- s.cmd.Wait() }()

	t.Cleanup(func() {
		if s.cmd.ProcessState == nil {
			s.cmd.Process.Kill()
			select {
			case <-s.done:
			case <-time.After(5 * time.Second):
			}
		}
	})

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-s.done:
			t.Fatalf("server exited during startup: %v\n%s", err, s.out)
		default:
		}
		if resp, err := http.Get(s.url + "/"); err == nil {
			resp.Body.Close()
			return s
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("server did not start listening\n%s", s.out)
	return nil
}

func (s *liveServer) stop(sig syscall.Signal) error {
	s.t.Helper()
	if err := s.cmd.Process.Signal(sig); err != nil {
		s.t.Fatalf("signal: %v", err)
	}
	return s.wait()
}

func (s *liveServer) wait() error {
	s.t.Helper()
	select {
	case err := <-s.done:
		s.done <- err // for the cleanup
		return err
	case <-time.After(20 * time.Second):
		s.cmd.Process.Kill()
		s.t.Fatalf("server did not exit in time\n%s", s.out)
		return nil
	}
}

func (s *liveServer) get(path string) (int, string) {
	s.t.Helper()
	resp, err := http.Get(s.url + path)
	if err != nil {
		s.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (s *liveServer) postJSON(path, body string) int {
	s.t.Helper()
	resp, err := http.Post(s.url+path, "application/json", strings.NewReader(body))
	if err != nil {
		s.t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func (s *liveServer) upload(dir, name string, content []byte) (int, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("myFile", name)
	fw.Write(content)
	mw.Close()
	resp, err := http.Post(s.url+"/api/upload?path="+dir, mw.FormDataContentType(), &buf)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

func runToCompletion(t *testing.T, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(binary(t), args...)
	var out syncBuffer
	cmd.Stdout, cmd.Stderr = &out, &out
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return out.String(), exitCode(err)
	case <-time.After(20 * time.Second):
		cmd.Process.Kill()
		t.Fatalf("process did not exit\n%s", out.String())
		return "", -1
	}
}

func TestE2EGracefulShutdownFlushesTheAuditLog(t *testing.T) {
	for name, sig := range map[string]syscall.Signal{"SIGTERM": syscall.SIGTERM, "SIGINT": syscall.SIGINT} {
		t.Run(name, func(t *testing.T) {
			s := startServer(t)

			if code, _ := s.upload("", "hello.txt", []byte("hello")); code != 201 {
				t.Fatalf("upload = %d", code)
			}
			if code := s.postJSON("/api/fs/mkdir", `{"name":"docs","targetPath":""}`); code != 201 {
				t.Fatalf("mkdir = %d", code)
			}
			if code := s.postJSON("/api/fs/rename", `{"oldPath":"dog4.jpg","newPath":"dog3.jpg"}`); code != 404 {
				t.Fatalf("rename missing = %d", code)
			}
			if code := s.postJSON("/api/fs/delete", `{"path":""}`); code != 400 {
				t.Fatalf("delete root = %d", code)
			}
			if code, _ := s.get("/api/files?path=../"); code != 403 {
				t.Fatalf("traversal = %d", code)
			}

			if err := s.stop(sig); err != nil {
				t.Fatalf("exit after %s: %v\n%s", name, err, s.out)
			}
			if !strings.Contains(s.out.String(), "Shutting down") {
				t.Errorf("no shutdown message in output:\n%s", s.out)
			}

			rep, err := audit.Verify(s.auditPath)
			if err != nil || rep.Records != 5 {
				t.Fatalf("audit after shutdown: %+v, %v\n%s", rep, err, s.out)
			}
			evs := auditEvents(t, s.auditPath)
			want := []struct {
				typ events.Type
				out events.Outcome
			}{
				{events.FileUploaded, events.OutcomeOK},
				{events.FolderCreated, events.OutcomeOK},
				{events.FileMoved, events.OutcomeNotFound},
				{events.FileDeleted, events.OutcomeDenied},
				{events.FileListed, events.OutcomeDenied},
			}
			for i, w := range want {
				if evs[i].Type != w.typ || evs[i].Outcome != w.out {
					t.Errorf("event %d = {%s %s}, want {%s %s}", i, evs[i].Type, evs[i].Outcome, w.typ, w.out)
				}
				if evs[i].RequestID == "" || !strings.HasPrefix(evs[i].Actor.RemoteAddr, "127.0.0.1:") {
					t.Errorf("event %d lacks request id / remote address: %+v", i, evs[i])
				}
			}

			if _, err := http.Get(s.url + "/"); err == nil {
				t.Error("server still answers after shutdown")
			}
			if out, code := runToCompletion(t, "-verify-audit="+s.auditPath); code != 0 || !strings.Contains(out, "OK: 5 records") {
				t.Errorf("-verify-audit: exit %d\n%s", code, out)
			}
		})
	}
}

func TestE2EInFlightUploadSurvivesShutdown(t *testing.T) {
	s := startServer(t)

	const chunks, chunkSize = 20, 32 << 10
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	started := make(chan struct{})
	go func() {
		fw, _ := mw.CreateFormFile("myFile", "slow.bin")
		chunk := bytes.Repeat([]byte("x"), chunkSize)
		for i := 0; i < chunks; i++ {
			fw.Write(chunk)
			if i == 2 {
				close(started)
			}
			time.Sleep(40 * time.Millisecond)
		}
		mw.Close()
		pw.Close()
	}()

	req, _ := http.NewRequest(http.MethodPost, s.url+"/api/upload", pr)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	type result struct {
		code int
		err  error
	}
	resCh := make(chan result, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			resCh <- result{err: err}
			return
		}
		resp.Body.Close()
		resCh <- result{code: resp.StatusCode}
	}()

	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("upload never started")
	}
	exitCh := make(chan error, 1)
	go func() { exitCh <- s.stop(syscall.SIGTERM) }()

	res := <-resCh
	if res.err != nil || res.code != 201 {
		t.Fatalf("in-flight upload was cut by shutdown: code %d, err %v\n%s", res.code, res.err, s.out)
	}
	if err := <-exitCh; err != nil {
		t.Fatalf("exit: %v\n%s", err, s.out)
	}

	info, err := os.Stat(filepath.Join(s.root, "slow.bin"))
	if err != nil || info.Size() != chunks*chunkSize {
		t.Fatalf("uploaded file: %v, %v", info, err)
	}
	evs := auditEvents(t, s.auditPath)
	if len(evs) != 1 || evs[0].Type != events.FileUploaded || evs[0].Outcome != events.OutcomeOK || evs[0].Size != chunks*chunkSize {
		t.Errorf("audit = %+v", evs)
	}
}

func TestE2EClientDisconnectMidUploadLeavesNoFile(t *testing.T) {
	s := startServer(t)

	conn, err := net.Dial("tcp", strings.TrimPrefix(s.url, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	head := "--BOUND\r\nContent-Disposition: form-data; name=\"myFile\"; filename=\"cut.bin\"\r\n" +
		"Content-Type: application/octet-stream\r\n\r\n"
	// Promise a megabyte, deliver 100 KiB, then hang up.
	fmt.Fprintf(conn, "POST /api/upload HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: multipart/form-data; boundary=BOUND\r\nContent-Length: %d\r\n\r\n", 1<<20)
	io.WriteString(conn, head)
	conn.Write(bytes.Repeat([]byte("y"), 100<<10))
	time.Sleep(200 * time.Millisecond)
	conn.Close()

	// The audit log is synced per batch, so it can be polled while running.
	var ev events.Event
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(s.auditPath); err == nil && bytes.Contains(data, []byte("file.uploaded")) {
			ev = auditEvents(t, s.auditPath)[0]
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if ev.Type != events.FileUploaded {
		t.Fatalf("the aborted upload was never audited\n%s", s.out)
	}
	if ev.Outcome != events.OutcomeError || ev.Path != "cut.bin" {
		t.Errorf("event = %+v, want outcome=error for cut.bin", ev)
	}
	if _, err := os.Stat(filepath.Join(s.root, "cut.bin")); err == nil {
		t.Error("truncated file left on disk")
	}

	if code, _ := s.upload("", "after.txt", []byte("ok")); code != 201 {
		t.Errorf("upload after the aborted one = %d", code)
	}
	if err := s.stop(syscall.SIGTERM); err != nil {
		t.Errorf("exit: %v", err)
	}
}

func TestE2EConcurrentUploadsOfTheSameName(t *testing.T) {
	s := startServer(t)

	const n = 20
	var wg sync.WaitGroup
	codes := make([]int, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes[i], errs[i] = s.upload("", "same.txt", []byte(fmt.Sprintf("content-%02d", i)))
		}(i)
	}
	wg.Wait()
	for i := range codes {
		if errs[i] != nil || codes[i] != 201 {
			t.Fatalf("upload %d: %d, %v", i, codes[i], errs[i])
		}
	}

	entries, _ := os.ReadDir(s.root)
	if len(entries) != n {
		t.Fatalf("%d files for %d uploads", len(entries), n)
	}
	seen := map[string]bool{}
	for _, e := range entries {
		b, _ := os.ReadFile(filepath.Join(s.root, e.Name()))
		if !strings.HasPrefix(string(b), "content-") || seen[string(b)] {
			t.Errorf("%s holds %q (missing or duplicated payload)", e.Name(), b)
		}
		seen[string(b)] = true
	}

	if err := s.stop(syscall.SIGTERM); err != nil {
		t.Fatalf("exit: %v", err)
	}
	if rep, err := audit.Verify(s.auditPath); err != nil || rep.Records != n {
		t.Errorf("audit: %+v, %v (want %d records)", rep, err, n)
	}
}

func TestE2EUploadLimitRejectsAndCleansUp(t *testing.T) {
	s := startServer(t, "-max-upload-mb=1")

	if code, err := s.upload("", "big.bin", bytes.Repeat([]byte("z"), 3<<20)); err == nil && code != 413 {
		t.Errorf("3 MiB upload with a 1 MiB limit = %d, want 413", code)
	}
	if code, err := s.upload("", "ok.bin", bytes.Repeat([]byte("z"), 100<<10)); err != nil || code != 201 {
		t.Errorf("small upload = %d, %v", code, err)
	}
	if _, err := os.Stat(filepath.Join(s.root, "big.bin")); err == nil {
		t.Error("partial big.bin left on disk")
	}
	if err := s.stop(syscall.SIGTERM); err != nil {
		t.Errorf("exit: %v", err)
	}
}

func TestE2ERangeDownloadsOverARealConnection(t *testing.T) {
	s := startServer(t)
	data := bytes.Repeat([]byte("0123456789"), 100_000) // 1 MB
	os.WriteFile(filepath.Join(s.root, "movie.bin"), data, 0o644)

	req, _ := http.NewRequest(http.MethodGet, s.url+"/files/movie.bin", nil)
	req.Header.Set("Range", "bytes=500000-500009")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 206 || string(got) != "0123456789" || resp.Header.Get("Content-Range") != "bytes 500000-500009/1000000" {
		t.Errorf("range response: %d %q %q", resp.StatusCode, got, resp.Header.Get("Content-Range"))
	}

	req, _ = http.NewRequest(http.MethodGet, s.url+"/files/movie.bin", nil)
	req.Header.Set("Range", "bytes=400000-")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	rest, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 206 || !bytes.Equal(append(append([]byte{}, data[:400000]...), rest...), data) {
		t.Errorf("resumed download does not reassemble the file (status %d, %d bytes)", resp.StatusCode, len(rest))
	}
	s.stop(syscall.SIGTERM)
}

func TestE2EVerifyAuditFlag(t *testing.T) {
	s := startServer(t)
	s.postJSON("/api/fs/delete", `{"path":"a"}`)
	s.postJSON("/api/fs/delete", `{"path":"b"}`)
	if err := s.stop(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}

	out, code := runToCompletion(t, "-verify-audit="+s.auditPath)
	if code != 0 || !strings.Contains(out, "OK: 2 records") || !strings.Contains(out, "head hash:") {
		t.Errorf("valid log: exit %d\n%s", code, out)
	}

	data, _ := os.ReadFile(s.auditPath)
	os.WriteFile(s.auditPath, bytes.Replace(data, []byte(`"path":"a"`), []byte(`"path":"c"`), 1), 0o600)
	out, code = runToCompletion(t, "-verify-audit="+s.auditPath)
	if code == 0 || !strings.Contains(out, "record 1") {
		t.Errorf("tampered log: exit %d\n%s", code, out)
	}

	out, code = runToCompletion(t, "-verify-audit="+filepath.Join(t.TempDir(), "missing.jsonl"))
	if code == 0 {
		t.Errorf("missing file verified OK\n%s", out)
	}
}

func TestE2EStartupFailures(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	os.Mkdir(root, 0o755)
	good := filepath.Join(base, "audit.jsonl")

	t.Run("audit log inside the served folder", func(t *testing.T) {
		out, code := runToCompletion(t, "-port=0", "-root="+root, "-audit-log="+filepath.Join(root, "audit.jsonl"))
		if code == 0 || !strings.Contains(out, "inside the served directory") {
			t.Errorf("exit %d\n%s", code, out)
		}
	})

	t.Run("network address without authentication", func(t *testing.T) {
		out, code := runToCompletion(t, "-host=0.0.0.0", "-port=0", "-root="+root, "-audit-log="+good)
		if code == 0 || !strings.Contains(out, "-insecure-no-auth") {
			t.Errorf("exit %d\n%s", code, out)
		}
		if _, err := os.Stat(good); err == nil {
			t.Error("the refused start created the audit log")
		}
	})

	t.Run("root does not exist", func(t *testing.T) {
		out, code := runToCompletion(t, "-root="+filepath.Join(base, "missing"), "-audit-log="+good)
		if code == 0 || !strings.Contains(out, "invalid root directory") {
			t.Errorf("exit %d\n%s", code, out)
		}
	})

	t.Run("tampered audit log", func(t *testing.T) {
		s := startServer(t)
		s.postJSON("/api/fs/delete", `{"path":"x"}`)
		s.postJSON("/api/fs/delete", `{"path":"y"}`)
		s.stop(syscall.SIGTERM)
		data, _ := os.ReadFile(s.auditPath)
		os.WriteFile(s.auditPath, bytes.Replace(data, []byte(`"path":"x"`), []byte(`"path":"q"`), 1), 0o600)
		tampered, _ := os.ReadFile(s.auditPath)

		out, code := runToCompletion(t, "-port=0", "-root="+s.root, "-audit-log="+s.auditPath)
		if code == 0 || !strings.Contains(out, "failed verification") {
			t.Errorf("exit %d\n%s", code, out)
		}
		if after, _ := os.ReadFile(s.auditPath); !bytes.Equal(after, tampered) {
			t.Error("a refused start modified the audit log")
		}
	})

	t.Run("port already in use", func(t *testing.T) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		port := l.Addr().(*net.TCPAddr).Port

		audit := filepath.Join(base, "busy-audit.jsonl")
		out, code := runToCompletion(t, "-host=127.0.0.1", fmt.Sprintf("-port=%d", port), "-root="+root, "-audit-log="+audit)
		if code == 0 || !strings.Contains(out, "address already in use") {
			t.Errorf("exit %d\n%s", code, out)
		}
		if _, err := os.Stat(audit); err == nil {
			if _, err := verifyOnly(audit); err != nil {
				t.Errorf("audit log left in a bad state: %v", err)
			}
		}
	})
}

func verifyOnly(path string) (int, error) {
	rep, err := audit.Verify(path)
	return rep.Records, err
}

func TestE2EListensOnLoopbackByDefault(t *testing.T) {
	bin := binary(t)
	base := t.TempDir()
	root := filepath.Join(base, "root")
	os.Mkdir(root, 0o755)
	port := freePort(t)

	cmd := exec.Command(bin, fmt.Sprintf("-port=%d", port), "-root="+root, "-audit-log="+filepath.Join(base, "a.jsonl"))
	var out syncBuffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(out.String(), "Starting server") {
		time.Sleep(25 * time.Millisecond)
	}
	if !strings.Contains(out.String(), fmt.Sprintf("http://localhost:%d", port)) {
		t.Fatalf("default address is not localhost:\n%s", out.String())
	}
	time.Sleep(200 * time.Millisecond)

	if resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", port)); err != nil {
		t.Errorf("not reachable on loopback: %v", err)
	} else {
		resp.Body.Close()
	}
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		ip, _, err := net.ParseCIDR(a.String())
		if err != nil || ip.IsLoopback() || ip.To4() == nil {
			continue
		}
		c, err := net.DialTimeout("tcp", net.JoinHostPort(ip.String(), fmt.Sprint(port)), time.Second)
		if err == nil {
			c.Close()
			t.Errorf("server is reachable on %s although it should listen on loopback only", ip)
		}
		break
	}
}

func TestE2EBrowserProtections(t *testing.T) {
	s := startServer(t)
	os.WriteFile(filepath.Join(s.root, "victim.txt"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(s.root, "page.html"), []byte("<script>alert(1)</script>"), 0o644)

	send := func(method, path, body string, h map[string]string) *http.Response {
		req, _ := http.NewRequest(method, s.url+path, strings.NewReader(body))
		for k, v := range h {
			if k == "Host" {
				req.Host = v
			} else {
				req.Header.Set(k, v)
			}
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}

	if r := send("POST", "/api/fs/delete", `{"path":"victim.txt"}`, map[string]string{"Content-Type": "text/plain"}); r.StatusCode != 415 {
		t.Errorf("text/plain delete = %d, want 415", r.StatusCode)
	}
	if r := send("POST", "/api/fs/delete", `{"path":"victim.txt"}`, map[string]string{"Content-Type": "application/json", "Origin": "http://evil.example"}); r.StatusCode != 403 {
		t.Errorf("cross-origin delete = %d, want 403", r.StatusCode)
	}
	if r := send("GET", "/files/victim.txt", "", map[string]string{"Host": "rebind.evil.example:1234"}); r.StatusCode != http.StatusMisdirectedRequest {
		t.Errorf("unknown Host = %d, want 421", r.StatusCode)
	}
	if r := send("GET", "/files/page.html", "", nil); !strings.HasPrefix(r.Header.Get("Content-Disposition"), "attachment") ||
		!strings.HasPrefix(r.Header.Get("Content-Security-Policy"), "sandbox") {
		t.Errorf("HTML served without protections: %v", r.Header)
	}
	if _, err := os.Stat(filepath.Join(s.root, "victim.txt")); err != nil {
		t.Error("victim.txt was deleted")
	}
	if err := s.stop(syscall.SIGTERM); err != nil {
		t.Errorf("exit: %v", err)
	}
}

func TestE2ESecondSignalExitsAtOnce(t *testing.T) {
	s := startServer(t)
	addr := strings.TrimPrefix(s.url, "http://")

	// An upload in progress keeps the graceful shutdown waiting.
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "POST /api/upload HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: multipart/form-data; boundary=B\r\nContent-Length: %d\r\n\r\n"+
		"--B\r\nContent-Disposition: form-data; name=\"myFile\"; filename=\"held.bin\"\r\n\r\n", 1<<20)
	conn.Write(make([]byte, 100<<10))
	time.Sleep(200 * time.Millisecond)

	if err := s.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(5 * time.Second); !strings.Contains(s.out.String(), "Shutting down"); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("no shutdown message:\n%s", s.out)
		}
	}
	start := time.Now()
	if err := s.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	err = s.wait()
	if waited := time.Since(start); waited > 3*time.Second {
		t.Errorf("second signal took %v to end the process", waited)
	}
	if err == nil {
		t.Error("process exited normally; want it ended by the second signal")
	}
}
