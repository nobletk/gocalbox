package httpapi

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/nobletk/gocalbox/internal/fsops"
	"github.com/nobletk/gocalbox/internal/sandbox"
)

func TestFetchMetadataIsolatesFilesAndAPI(t *testing.T) {
	e := newEnv(t, 0)
	e.write("photo.jpg", "jpg")

	crossSiteImage := map[string]string{"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Dest": "image"}
	for _, tc := range []struct {
		name, path string
		headers    map[string]string
		status     int
	}{
		{"cross-site <img>", "/files/photo.jpg", crossSiteImage, 403},
		{"cross-site <img> of a missing file", "/files/nope.jpg", crossSiteImage, 403},
		{"other port on localhost", "/files/photo.jpg", map[string]string{"Sec-Fetch-Site": "same-site", "Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Dest": "video"}, 403},
		{"cross-site iframe", "/files/photo.jpg", map[string]string{"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "iframe"}, 403},
		{"cross-site fetch of the API", "/api/files", map[string]string{"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty"}, 403},
		{"link followed from another site", "/files/photo.jpg", map[string]string{"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"}, 200},
		{"the UI's own <img>", "/files/photo.jpg", map[string]string{"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Dest": "image"}, 200},
		{"typed into the address bar", "/files/photo.jpg", map[string]string{"Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"}, 200},
		{"non-browser client", "/files/photo.jpg", nil, 200},
		{"UI opened from another site", "/", map[string]string{"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"}, 200},
	} {
		resp := e.request(http.MethodGet, tc.path, nil, tc.headers)
		want(t, resp.StatusCode, tc.status, tc.name)
		if tc.status == 403 {
			if er := readErr(t, resp); er.Error.Code != "cross_origin" {
				t.Errorf("%s: code %q", tc.name, er.Error.Code)
			}
		}
	}
}

func TestSecurityHeaders(t *testing.T) {
	e := newEnvOpts(t, Options{AllowedHosts: []string{"127.0.0.1"}})
	e.write("a.txt", "x")

	for _, p := range []string{"/files/a.txt", "/files/missing", "/api/files", "/api/nope"} {
		h := e.request(http.MethodGet, p, nil, nil).Header
		if h.Get("Cross-Origin-Resource-Policy") != "same-origin" {
			t.Errorf("%s: CORP = %q", p, h.Get("Cross-Origin-Resource-Policy"))
		}
		if h.Get("Referrer-Policy") != "no-referrer" || h.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: Referrer-Policy %q, nosniff %q", p, h.Get("Referrer-Policy"), h.Get("X-Content-Type-Options"))
		}
		if h.Get("X-Frame-Options") != "SAMEORIGIN" {
			t.Errorf("%s: X-Frame-Options = %q, want SAMEORIGIN (the UI frames files)", p, h.Get("X-Frame-Options"))
		}
	}
	if csp := e.request(http.MethodGet, "/files/a.txt", nil, nil).Header.Get("Content-Security-Policy"); !strings.Contains(csp, "frame-ancestors 'self'") {
		t.Errorf("file CSP = %q", csp)
	}

	h := e.request(http.MethodGet, "/", nil, nil).Header
	if csp := h.Get("Content-Security-Policy"); !strings.Contains(csp, "frame-ancestors 'none'") || !strings.Contains(csp, "object-src 'none'") {
		t.Errorf("UI CSP = %q", csp)
	}
	if h.Get("X-Frame-Options") != "DENY" || h.Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("UI framing / referrer headers: %v", h)
	}
	if h.Get("Cross-Origin-Resource-Policy") != "" {
		t.Error("UI got CORP")
	}

	resp := e.request(http.MethodGet, "/", nil, map[string]string{"Host": "attacker.example"})
	want(t, resp.StatusCode, http.StatusMisdirectedRequest, "unknown host")
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("early rejections lack the common headers")
	}
}

func TestJSONBodiesAreStrict(t *testing.T) {
	e := newEnv(t, 0)
	e.write("keep.txt", "x")

	for name, body := range map[string]string{
		"wrong case":         `{"PATH":"keep.txt"}`,
		"unknown field":      `{"path":"keep.txt","recursive":true}`,
		"duplicate field":    `{"path":"nope.txt","path":"keep.txt"}`,
		"trailing garbage":   `{"path":"keep.txt"} x`,
		"second object":      `{"path":"keep.txt"}{"path":"keep.txt"}`,
		"array":              `[{"path":"keep.txt"}]`,
		"null":               `null`,
		"wrong value type":   `{"path":5}`,
		"empty":              ``,
		"unterminated":       `{"path":"keep.txt"`,
		"nested key smuggle": `{"path":"x","":{"path":"keep.txt"}}`,
	} {
		resp := e.request(http.MethodPost, "/api/fs/delete", strings.NewReader(body), map[string]string{"Content-Type": "application/json"})
		want(t, resp.StatusCode, 400, name)
		if er := readErr(t, resp); er.Error.Code != "invalid_body" {
			t.Errorf("%s: code %q", name, er.Error.Code)
		}
	}
	if !e.exists(filepath.Join(e.root, "keep.txt")) {
		t.Fatal("a rejected body deleted the file")
	}

	code, _ := e.do(http.MethodPost, "/api/fs/delete", strings.NewReader(" {\"path\" : \"keep.txt\"}\n "), "application/json; charset=utf-8")
	want(t, code, 200, "well-formed body with white space")
	code, _ = e.do(http.MethodPost, "/api/fs/mkdir", strings.NewReader(`{"name":"d"}`), "application/json")
	want(t, code, 201, "optional field left out")
}

func TestETagMakesResumesSafe(t *testing.T) {
	e := newEnv(t, 0)
	p := filepath.Join(e.root, "doc.bin")
	mtime := time.Unix(1_800_000_000, 100_000_000)
	writeAt := func(content string, at time.Time) {
		os.WriteFile(p, []byte(content), 0o644)
		os.Chtimes(p, at, at)
	}
	get := func(h map[string]string) (*http.Response, string) {
		resp := e.request(http.MethodGet, "/files/doc.bin", nil, h)
		b, _ := io.ReadAll(resp.Body)
		return resp, string(b)
	}

	writeAt(strings.Repeat("A", 100), mtime)
	resp, _ := get(nil)
	etag, lastMod := resp.Header.Get("ETag"), resp.Header.Get("Last-Modified")
	if !strings.HasPrefix(etag, `"`) || strings.HasPrefix(etag, "W/") || len(etag) < 10 {
		t.Fatalf("ETag = %q, want a strong tag", etag)
	}
	if resp.Header.Get("Cache-Control") != "private, no-cache" {
		t.Errorf("Cache-Control = %q", resp.Header.Get("Cache-Control"))
	}
	if again, _ := get(nil); again.Header.Get("ETag") != etag {
		t.Error("ETag not stable for an unchanged file")
	}

	resp, body := get(map[string]string{"Range": "bytes=50-", "If-Range": etag})
	if resp.StatusCode != 206 || body != strings.Repeat("A", 50) {
		t.Errorf("resume of the same version: %d %q", resp.StatusCode, body)
	}

	// Replaced half a second later: same second, same size.
	writeAt(strings.Repeat("B", 100), mtime.Add(500*time.Millisecond))
	resp, body = get(map[string]string{"Range": "bytes=50-", "If-Range": etag})
	if resp.StatusCode != 200 || body != strings.Repeat("B", 100) {
		t.Errorf("resume against a stale ETag: %d %q, want the whole new file", resp.StatusCode, body)
	}
	if resp.Header.Get("ETag") == etag {
		t.Error("ETag unchanged after the content changed")
	}
	resp, body = get(map[string]string{"Range": "bytes=50-", "If-Range": lastMod})
	if resp.StatusCode != 200 || len(body) != 100 {
		t.Errorf("resume validated by a date: %d (%d bytes), want the whole file", resp.StatusCode, len(body))
	}
	if ev := e.lastEvent(); ev.Range != "" || ev.Size != 100 {
		t.Errorf("event for an ignored range: %+v", ev)
	}

	resp, _ = get(map[string]string{"If-None-Match": resp.Header.Get("ETag")})
	want(t, resp.StatusCode, 304, "revalidation")
}

func TestContentTypesDoNotDependOnTheHost(t *testing.T) {
	for name, wantType := range map[string]fileType{
		"clip.ts":      {"video/mp2t", true},
		"clip.webm":    {"video/webm", true},
		"song.weba":    {"audio/webm", true},
		"IMG_0001.JPG": {"image/jpeg", true},
		"readme.md":    plainText,
		"data.json":    plainText,
		"subs.vtt":     {"text/vtt; charset=utf-8", false},
		"page.html":    {"text/html; charset=utf-8", false},
		"logo.svg":     {"image/svg+xml", false},
		"logo.svgz":    unknown,
		"archive.zip":  {"application/zip", false},
		"Makefile":     unknown,
		".bashrc":      unknown,
	} {
		if got := typeOf(name); got != wantType {
			t.Errorf("typeOf(%q) = %+v, want %+v", name, got, wantType)
		}
	}
}

func TestBadNamesAndLongPathsAreClientErrors(t *testing.T) {
	e := newEnv(t, 0)
	e.write("a.txt", "x")
	long := strings.Repeat("n", 300)

	for _, tc := range []struct {
		name string
		do   func() (int, string)
		code string
	}{
		{"mkdir with a newline", func() (int, string) { return e.postJSON("/api/fs/mkdir", CreateFolderRequest{Name: "a\nb"}) }, "invalid_name"},
		{"mkdir with a terminal escape", func() (int, string) { return e.postJSON("/api/fs/mkdir", CreateFolderRequest{Name: "\x1b[31mred"}) }, "invalid_name"},
		{"mkdir blank", func() (int, string) { return e.postJSON("/api/fs/mkdir", CreateFolderRequest{Name: "  "}) }, "invalid_name"},
		{"move to a newline name", func() (int, string) {
			return e.postJSON("/api/fs/move", MoveRequest{OldPath: "a.txt", NewPath: "b\nc.txt"})
		}, "invalid_name"},
		{"move to a backslash name", func() (int, string) {
			return e.postJSON("/api/fs/move", MoveRequest{OldPath: "a.txt", NewPath: `b\c.txt`})
		}, "invalid_name"},
		{"upload a 300-byte name", func() (int, string) { return e.upload("", long+".txt", "x") }, "invalid_name"},
		{"download a 300-byte name", func() (int, string) { return e.do(http.MethodGet, "/files/"+long, nil, "") }, "invalid_path"},
		{"list a 300-byte name", func() (int, string) { return e.do(http.MethodGet, "/api/files?path="+long, nil, "") }, "invalid_path"},
	} {
		code, body := tc.do()
		want(t, code, 400, tc.name)
		if er := decode[ErrorResponse](t, body); er.Error.Code != tc.code {
			t.Errorf("%s: code %q, want %q", tc.name, er.Error.Code, tc.code)
		}
	}
	if !e.exists(filepath.Join(e.root, "a.txt")) {
		t.Error("a rejected move moved the file")
	}
}

// slowService delays Delete after the request body has been read, and
// reports whether the request's context was cancelled meanwhile.
type slowService struct {
	FileService
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *slowService) free() { s.once.Do(func() { close(s.release) }) }

func (s *slowService) Delete(ctx context.Context, p string) (string, error) {
	if s.started != nil {
		close(s.started)
	}
	<-s.release
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("context cancelled while working: %w", err)
	}
	return s.FileService.Delete(ctx, p)
}

func newSlowEnv(t *testing.T, opts Options) (*httptest.Server, *slowService, string) {
	t.Helper()
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "a.txt"), []byte("x"), 0o644)
	sb, err := sandbox.New(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sb.Close() })
	svc := &slowService{FileService: fsops.New(sb, nil), started: make(chan struct{}), release: make(chan struct{})}
	srv := httptest.NewServer(newTestHandler(svc, fstest.MapFS{}, opts))
	t.Cleanup(srv.Close)
	t.Cleanup(svc.free) // runs before srv.Close, which waits for the handler
	return srv, svc, root
}

func postDelete(url string) (int, error) { return postDeleteBody(url, `{"path":"a.txt"}`) }

func postDeleteBody(url, body string) (int, error) {
	resp, err := http.Post(url+"/api/fs/delete", "application/json", strings.NewReader(body))
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}

func TestStalledUploadIsAborted(t *testing.T) {
	e := newEnvOpts(t, Options{BodyTimeout: 300 * time.Millisecond})
	addr := strings.TrimPrefix(e.srv.URL, "http://")

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	part := "--B\r\nContent-Disposition: form-data; name=\"myFile\"; filename=\"slow.bin\"\r\n\r\n"
	fmt.Fprintf(conn, "POST /api/upload HTTP/1.1\r\nHost: %s\r\nContent-Type: multipart/form-data; boundary=B\r\nContent-Length: %d\r\n\r\n%sxxxx", addr, 1<<20, part)

	start := time.Now()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	io.Copy(io.Discard, bufio.NewReader(conn))
	if waited := time.Since(start); waited > 3*time.Second {
		t.Fatalf("stalled upload held the connection for %v", waited)
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(e.rec.all()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if ev := e.lastEvent(); ev.Outcome != "error" || !strings.Contains(ev.Detail, "timeout") {
		t.Errorf("event = %+v, want an upload error from the read timeout", ev)
	}
	if e.exists(filepath.Join(e.root, "slow.bin")) {
		t.Error("partial upload left behind")
	}
}

func TestSlowButSteadyUploadIsNotAborted(t *testing.T) {
	e := newEnvOpts(t, Options{BodyTimeout: 300 * time.Millisecond})
	const chunks, chunk = 8, 96 << 10
	pr, pw := io.Pipe()
	go func() {
		io.WriteString(pw, "--B\r\nContent-Disposition: form-data; name=\"myFile\"; filename=\"steady.bin\"\r\n\r\n")
		for i := 0; i < chunks; i++ {
			pw.Write(make([]byte, chunk))
			time.Sleep(150 * time.Millisecond)
		}
		io.WriteString(pw, "\r\n--B--\r\n")
		pw.Close()
	}()
	code, body := e.do(http.MethodPost, "/api/upload", pr, "multipart/form-data; boundary=B")
	want(t, code, 201, "upload that takes 1.2 s but keeps arriving")
	if r := decode[PathResponse](t, body); r.Size != chunks*chunk {
		t.Errorf("stored %d bytes", r.Size)
	}
}

func TestBodyDeadlineDoesNotOutliveTheBody(t *testing.T) {
	small := `{"path":"a.txt"}`
	// Exactly bodyProgress bytes: the read that reaches the progress mark is
	// the one that also reports the end of the body.
	exact := `{"path":"a.txt"` + strings.Repeat(" ", bodyProgress-len(`{"path":"a.txt"}`)) + `}`
	for name, body := range map[string]string{"small body": small, "64 KiB body": exact} {
		srv, svc, root := newSlowEnv(t, Options{BodyTimeout: 100 * time.Millisecond})
		go func() {
			<-svc.started
			time.Sleep(400 * time.Millisecond)
			svc.free()
		}()
		code, err := postDeleteBody(srv.URL, body)
		if err != nil || code != 200 {
			t.Errorf("%s: operation outlasting the body timeout: %d, %v", name, code, err)
			continue
		}
		if _, err := os.Stat(filepath.Join(root, "a.txt")); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s: file not deleted", name)
		}
	}
}

func TestTrackerDrainWaitsForRunningOperations(t *testing.T) {
	tr := NewTracker()
	srv, svc, root := newSlowEnv(t, Options{Tracker: tr})

	result := make(chan int, 1)
	go func() {
		code, _ := postDelete(srv.URL)
		result <- code
	}()
	<-svc.started

	drained := make(chan error, 1)
	go func() {
		_, err := tr.Drain(context.Background())
		drained <- err
	}()
	time.Sleep(100 * time.Millisecond)
	select {
	case <-drained:
		t.Fatal("Drain returned while an operation was running")
	default:
	}

	resp, err := http.Get(srv.URL + "/api/files")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	want(t, resp.StatusCode, 503, "new operation while draining")

	svc.free()
	if err := <-drained; err != nil {
		t.Errorf("Drain = %v", err)
	}
	want(t, <-result, 200, "operation that was allowed to finish")
	if _, err := os.Stat(filepath.Join(root, "a.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Error("the drained operation did not complete")
	}
}

func TestTrackerDrainReportsWhatIsLeftAtTheDeadline(t *testing.T) {
	tr := NewTracker()
	srv, svc, _ := newSlowEnv(t, Options{Tracker: tr})
	defer svc.free()
	go postDelete(srv.URL)
	<-svc.started

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	left, err := tr.Drain(ctx)
	if !errors.Is(err, context.DeadlineExceeded) || len(left) != 1 || !strings.HasPrefix(left[0], "POST /api/fs/delete (") {
		t.Errorf("Drain = %q, %v", left, err)
	}
}

// deadlineRecorder is a ResponseWriter whose read deadlines can be observed
// through http.ResponseController.
type deadlineRecorder struct {
	http.ResponseWriter
	set []time.Time
}

func (d *deadlineRecorder) SetReadDeadline(t time.Time) error {
	d.set = append(d.set, t)
	return nil
}

type chunks struct {
	sizes []int
}

func (c *chunks) Read(p []byte) (int, error) {
	if len(c.sizes) == 0 {
		return 0, io.EOF
	}
	n := c.sizes[0]
	c.sizes = c.sizes[1:]
	if len(c.sizes) == 0 {
		return n, io.EOF
	}
	return n, nil
}

func TestStallLimitExtendsOnProgressButNeverAfterTheEnd(t *testing.T) {
	rec := &deadlineRecorder{ResponseWriter: httptest.NewRecorder()}
	body := &stallLimitedBody{
		ReadCloser: io.NopCloser(&chunks{sizes: []int{40 << 10, 40 << 10, 10 << 10, 70 << 10}}),
		rc:         http.NewResponseController(rec),
		timeout:    time.Second,
	}
	buf := make([]byte, 128<<10)
	for {
		if _, err := body.Read(buf); err != nil {
			break
		}
	}
	// Extended once, when 80 KiB had arrived; the last 70 KiB came with EOF.
	if len(rec.set) != 1 {
		t.Errorf("deadline set %d times, want 1 (after 64 KiB, not at the end)", len(rec.set))
	}
}

func TestStalledBodyIsAbortedOnEveryRoute(t *testing.T) {
	e := newEnvOpts(t, Options{BodyTimeout: 300 * time.Millisecond, AllowedHosts: []string{"127.0.0.1"}})
	addr := strings.TrimPrefix(e.srv.URL, "http://")

	for _, tc := range []struct{ name, path, ctype, host string }{
		{"web UI", "/", "text/plain", "127.0.0.1"},
		{"unknown API endpoint", "/api/nope", "application/json", "127.0.0.1"},
		{"refused content type", "/api/fs/delete", "text/plain", "127.0.0.1"},
		{"unknown host", "/api/fs/delete", "application/json", "attacker.example"},
	} {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(conn, "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\nxx", tc.path, tc.host, tc.ctype, 100<<10)
		start := time.Now()
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		io.Copy(io.Discard, conn)
		conn.Close()
		if waited := time.Since(start); waited > 3*time.Second {
			t.Errorf("%s: a stalled body held the connection for %v", tc.name, waited)
		}
	}
}
