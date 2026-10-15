package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/fstest"

	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/fsops"
	"github.com/nobletk/gocalbox/internal/sandbox"
)

type recorder struct {
	mu  sync.Mutex
	evs []events.Event
}

func (r *recorder) Publish(ev events.Event) {
	r.mu.Lock()
	r.evs = append(r.evs, ev)
	r.mu.Unlock()
}

func (r *recorder) all() []events.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]events.Event(nil), r.evs...)
}

type env struct {
	t       *testing.T
	root    string
	outside string
	srv     *httptest.Server
	rec     *recorder
}

func newEnv(t *testing.T, maxUpload int64) *env {
	t.Helper()
	return newEnvOpts(t, Options{MaxUploadBytes: maxUpload})
}

func newEnvOpts(t *testing.T, opts Options, fileOpts ...fsops.Option) *env {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "root")
	outside := filepath.Join(base, "outside")
	for _, d := range []string{root, outside} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("top secret"), 0o644)

	sb, err := sandbox.New(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sb.Close() })
	web := fstest.MapFS{"index.html": {Data: []byte("<html></html>")}}
	rec := &recorder{}
	srv := httptest.NewServer(newTestHandler(adminFiles(sb, rec, fileOpts...), web, opts))
	t.Cleanup(srv.Close)
	return &env{t: t, root: sb.Root(), outside: outside, srv: srv, rec: rec}
}

func (e *env) write(rel, content string) {
	e.t.Helper()
	p := filepath.Join(e.root, rel)
	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) symlink(target, rel string) {
	e.t.Helper()
	if err := os.Symlink(target, filepath.Join(e.root, rel)); err != nil {
		e.t.Skipf("symlinks not supported: %v", err)
	}
}

func (e *env) exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

func (e *env) do(method, path string, body io.Reader, contentType string) (int, string) {
	e.t.Helper()
	req, err := http.NewRequest(method, e.srv.URL+path, body)
	if err != nil {
		e.t.Fatal(err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (e *env) postJSON(path string, v any) (int, string) {
	e.t.Helper()
	b, _ := json.Marshal(v)
	return e.do(http.MethodPost, path, bytes.NewReader(b), "application/json")
}

func (e *env) upload(dir, filename, content string) (int, string) {
	e.t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("myFile", filename)
	io.WriteString(fw, content)
	mw.Close()
	p := "/api/upload"
	if dir != "" {
		p += "?path=" + url.QueryEscape(dir)
	}
	return e.do(http.MethodPost, p, &buf, mw.FormDataContentType())
}

func (e *env) list(dir string) (int, []ClientFileInfo, string) {
	e.t.Helper()
	code, body := e.do(http.MethodGet, "/api/files?path="+url.QueryEscape(dir), nil, "")
	var files []ClientFileInfo
	if code == http.StatusOK {
		if err := json.Unmarshal([]byte(body), &files); err != nil {
			e.t.Fatalf("bad JSON %q: %v", body, err)
		}
	}
	return code, files, body
}

func decode[T any](t *testing.T, body string) T {
	t.Helper()
	var v T
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		t.Fatalf("bad JSON %q: %v", body, err)
	}
	return v
}

func want(t *testing.T, got, expected int, what string) {
	t.Helper()
	if got != expected {
		t.Errorf("%s: status = %d, want %d", what, got, expected)
	}
}

func TestListEmptyFolderIsJSONArray(t *testing.T) {
	e := newEnv(t, 0)
	code, body := e.do(http.MethodGet, "/api/files?path=", nil, "")
	want(t, code, 200, "list root")
	if strings.TrimSpace(body) != "[]" {
		t.Errorf("empty folder body = %q, want []", body)
	}
}

func TestListErrors(t *testing.T) {
	e := newEnv(t, 0)
	e.write("a.txt", "x")
	code, _, _ := e.list("missing")
	want(t, code, 404, "missing dir")
	code, _, _ = e.list("a.txt")
	want(t, code, 400, "file as dir")
	code, _ = e.do(http.MethodPost, "/api/files", nil, "")
	want(t, code, 405, "POST list")
}

func TestListAndSubfolder(t *testing.T) {
	e := newEnv(t, 0)
	e.write("sub/inner.txt", "12345")
	code, files, _ := e.list("")
	want(t, code, 200, "root")
	if len(files) != 1 || files[0].Name != "sub" || !files[0].IsDir {
		t.Errorf("root listing = %+v", files)
	}
	code, files, _ = e.list("sub")
	want(t, code, 200, "sub")
	if len(files) != 1 || files[0].Name != "inner.txt" || files[0].Size != 5 {
		t.Errorf("sub listing = %+v", files)
	}
}

func TestTraversalIsForbidden(t *testing.T) {
	e := newEnv(t, 0)
	e.write("keep.txt", "x")

	for _, p := range []string{"..", "../outside", "a/../../outside", "../../etc"} {
		code, _, _ := e.list(p)
		want(t, code, 403, "list "+p)
	}
	code, _ := e.postJSON("/api/fs/delete", DeleteRequest{Path: "../outside/secret.txt"})
	want(t, code, 403, "delete traversal")
	code, _ = e.postJSON("/api/fs/rename", MoveRequest{OldPath: "keep.txt", NewPath: "../escaped.txt"})
	want(t, code, 403, "move out")
	code, _ = e.postJSON("/api/fs/rename", MoveRequest{OldPath: "../outside/secret.txt", NewPath: "stolen.txt"})
	want(t, code, 403, "move in")
	code, _ = e.postJSON("/api/fs/mkdir", CreateFolderRequest{Name: "x", TargetPath: "../outside"})
	want(t, code, 403, "mkdir traversal")
	code, _ = e.upload("../outside", "evil.txt", "x")
	want(t, code, 403, "upload traversal")

	if !e.exists(filepath.Join(e.outside, "secret.txt")) {
		t.Error("secret.txt outside the sandbox was touched")
	}
	if e.exists(filepath.Join(e.outside, "evil.txt")) || e.exists(filepath.Join(e.outside, "x")) {
		t.Error("something was created outside the sandbox")
	}
}

func TestSymlinksCannotEscape(t *testing.T) {
	e := newEnv(t, 0)
	e.symlink(e.outside, "dirlink")
	e.symlink(filepath.Join(e.outside, "secret.txt"), "filelink")
	e.write("real.txt", "ok")

	code, _ := e.do(http.MethodGet, "/files/filelink", nil, "")
	want(t, code, 403, "GET file symlink")
	code, _ = e.do(http.MethodGet, "/files/dirlink/secret.txt", nil, "")
	want(t, code, 403, "GET through dir symlink")
	code, _, _ = e.list("dirlink")
	want(t, code, 403, "list through dir symlink")

	code, files, _ := e.list("")
	want(t, code, 200, "list root")
	if len(files) != 1 || files[0].Name != "real.txt" {
		t.Errorf("listing exposes escaping symlinks: %+v", files)
	}

	code, _ = e.upload("dirlink", "evil.txt", "x")
	want(t, code, 403, "upload through symlink")
	code, _ = e.postJSON("/api/fs/mkdir", CreateFolderRequest{Name: "x", TargetPath: "dirlink"})
	want(t, code, 403, "mkdir through symlink")
	code, _ = e.postJSON("/api/fs/rename", MoveRequest{OldPath: "real.txt", NewPath: "dirlink/real.txt"})
	want(t, code, 403, "move through symlink")
	code, _ = e.postJSON("/api/fs/delete", DeleteRequest{Path: "dirlink/secret.txt"})
	want(t, code, 403, "delete through symlink")

	if e.exists(filepath.Join(e.outside, "evil.txt")) || e.exists(filepath.Join(e.outside, "x")) || e.exists(filepath.Join(e.outside, "real.txt")) {
		t.Error("something was written outside the sandbox through a symlink")
	}
	if !e.exists(filepath.Join(e.outside, "secret.txt")) {
		t.Error("outside secret was deleted through a symlink")
	}
}

func TestDeletingSymlinkRemovesOnlyTheLink(t *testing.T) {
	e := newEnv(t, 0)
	e.symlink(e.outside, "dirlink")
	e.symlink(filepath.Join(e.outside, "secret.txt"), "filelink")

	for _, name := range []string{"dirlink", "filelink"} {
		code, _ := e.postJSON("/api/fs/delete", DeleteRequest{Path: name})
		want(t, code, 200, "delete "+name)
		if e.exists(filepath.Join(e.root, name)) {
			t.Errorf("%s still exists", name)
		}
	}
	if !e.exists(filepath.Join(e.outside, "secret.txt")) {
		t.Error("deleting a symlink removed the target outside the sandbox")
	}
}

func TestSymlinkInsideSandboxIsListedAsTarget(t *testing.T) {
	e := newEnv(t, 0)
	e.write("docs/a.txt", "hello")
	e.symlink(filepath.Join(e.root, "docs"), "docs-link")

	code, files, _ := e.list("")
	want(t, code, 200, "list")
	var found bool
	for _, f := range files {
		if f.Name == "docs-link" {
			found = true
			if !f.IsDir {
				t.Error("link to directory should be listed as directory")
			}
		}
	}
	if !found {
		t.Errorf("inside symlink missing from listing: %+v", files)
	}
}

func TestRootCannotBeDeletedOrMoved(t *testing.T) {
	e := newEnv(t, 0)
	e.write("a.txt", "x")
	e.write("sub/b.txt", "y")

	for _, p := range []string{"", ".", "/", "sub/..", "./"} {
		code, _ := e.postJSON("/api/fs/delete", DeleteRequest{Path: p})
		want(t, code, 400, "delete root as "+p)
	}
	code, _ := e.postJSON("/api/fs/rename", MoveRequest{OldPath: "", NewPath: "renamed"})
	want(t, code, 400, "rename root")
	code, _ = e.postJSON("/api/fs/rename", MoveRequest{OldPath: "a.txt", NewPath: ""})
	want(t, code, 400, "move onto root")

	if !e.exists(filepath.Join(e.root, "a.txt")) || !e.exists(filepath.Join(e.root, "sub", "b.txt")) {
		t.Error("root contents were damaged")
	}
}

func TestMoveRename(t *testing.T) {
	e := newEnv(t, 0)
	e.write("a.txt", "A")
	e.write("b.txt", "B")
	e.write("dir/inner.txt", "I")
	os.Mkdir(filepath.Join(e.root, "target"), 0o755)

	code, _ := e.postJSON("/api/fs/rename", MoveRequest{OldPath: "a.txt", NewPath: "b.txt"})
	want(t, code, 409, "rename onto existing")
	if got, _ := os.ReadFile(filepath.Join(e.root, "b.txt")); string(got) != "B" {
		t.Errorf("b.txt was overwritten: %q", got)
	}
	code, _ = e.postJSON("/api/fs/rename", MoveRequest{OldPath: "a.txt", NewPath: "a.txt"})
	want(t, code, 409, "rename onto itself")

	code, _ = e.postJSON("/api/fs/move", MoveRequest{OldPath: "dir", NewPath: "dir/sub"})
	want(t, code, 400, "folder into itself")

	code, _ = e.postJSON("/api/fs/move", MoveRequest{OldPath: "nope", NewPath: "x"})
	want(t, code, 404, "missing source")
	code, _ = e.postJSON("/api/fs/move", MoveRequest{OldPath: "a.txt", NewPath: "missing/a.txt"})
	want(t, code, 400, "missing target folder")
	code, _ = e.postJSON("/api/fs/move", MoveRequest{OldPath: "a.txt", NewPath: "b.txt/a.txt"})
	want(t, code, 400, "target parent is a file")

	code, body := e.postJSON("/api/fs/rename", MoveRequest{OldPath: "a.txt", NewPath: "renamed.txt"})
	want(t, code, 200, "rename")
	if p := decode[PathResponse](t, body); p.Path != "renamed.txt" {
		t.Errorf("rename response = %q", body)
	}
	code, _ = e.postJSON("/api/fs/move", MoveRequest{OldPath: "renamed.txt", NewPath: "target/renamed.txt"})
	want(t, code, 200, "move")
	code, _ = e.postJSON("/api/fs/move", MoveRequest{OldPath: "dir", NewPath: "target/dir"})
	want(t, code, 200, "move folder")
	if !e.exists(filepath.Join(e.root, "target", "dir", "inner.txt")) || !e.exists(filepath.Join(e.root, "target", "renamed.txt")) {
		t.Error("moved files not found at destination")
	}

	code, _ = e.do(http.MethodGet, "/api/fs/move", nil, "")
	want(t, code, 405, "GET move")
	code, _ = e.do(http.MethodPost, "/api/fs/move", strings.NewReader("{not json"), "application/json")
	want(t, code, 400, "bad JSON")
}

func TestDelete(t *testing.T) {
	e := newEnv(t, 0)
	e.write("dir/inner.txt", "I")
	e.write("f.txt", "F")

	code, _ := e.postJSON("/api/fs/delete", DeleteRequest{Path: "missing"})
	want(t, code, 404, "delete missing")
	code, body := e.postJSON("/api/fs/delete", DeleteRequest{Path: "./dir/"})
	want(t, code, 200, "delete dir")
	if p := decode[PathResponse](t, body); p.Path != "dir" {
		t.Errorf("delete response = %q", body)
	}
	code, _ = e.postJSON("/api/fs/delete", DeleteRequest{Path: "f.txt"})
	want(t, code, 200, "delete file")
	code, _ = e.do(http.MethodGet, "/api/fs/delete", nil, "")
	want(t, code, 405, "GET delete")

	code, files, _ := e.list("")
	want(t, code, 200, "list")
	if len(files) != 0 {
		t.Errorf("root not empty: %+v", files)
	}
}

func TestMkdir(t *testing.T) {
	e := newEnv(t, 0)
	e.write("existing.txt", "x")

	for _, name := range []string{"", ".", "..", "a/b", "a\\b", "x\x00y"} {
		code, _ := e.postJSON("/api/fs/mkdir", CreateFolderRequest{Name: name, TargetPath: ""})
		want(t, code, 400, "mkdir name "+name)
	}

	code, body := e.postJSON("/api/fs/mkdir", CreateFolderRequest{Name: "docs"})
	want(t, code, 201, "mkdir")
	if p := decode[PathResponse](t, body); p.Path != "docs" {
		t.Errorf("mkdir response = %q", body)
	}
	code, _ = e.postJSON("/api/fs/mkdir", CreateFolderRequest{Name: "docs"})
	want(t, code, 409, "mkdir twice")
	code, body = e.postJSON("/api/fs/mkdir", CreateFolderRequest{Name: "child", TargetPath: "/docs/"})
	want(t, code, 201, "nested mkdir")
	if p := decode[PathResponse](t, body); p.Path != "docs/child" {
		t.Errorf("nested mkdir response = %q", body)
	}
	code, _ = e.postJSON("/api/fs/mkdir", CreateFolderRequest{Name: "child", TargetPath: "nope"})
	want(t, code, 400, "mkdir in missing parent")
	code, _ = e.postJSON("/api/fs/mkdir", CreateFolderRequest{Name: "child", TargetPath: "existing.txt"})
	want(t, code, 400, "mkdir inside a file")
	code, _ = e.postJSON("/api/fs/mkdir", CreateFolderRequest{Name: "existing.txt"})
	want(t, code, 409, "mkdir over file")

	if !dirExists(filepath.Join(e.root, "docs", "child")) {
		t.Error("nested folder missing")
	}
}

func TestUploadAutoRenames(t *testing.T) {
	e := newEnv(t, 0)

	for i, wantName := range []string{"x.txt", "x (1).txt", "x (2).txt"} {
		code, body := e.upload("", "x.txt", "content"+string(rune('A'+i)))
		want(t, code, 201, "upload "+wantName)
		if p := decode[PathResponse](t, body); p.Name != wantName || p.Path != wantName || p.Size != 8 {
			t.Errorf("upload response = %q, want name %q", body, wantName)
		}
		got, err := os.ReadFile(filepath.Join(e.root, wantName))
		if err != nil || string(got) != "content"+string(rune('A'+i)) {
			t.Errorf("%s = %q, %v", wantName, got, err)
		}
	}

	e.upload("", ".env", "1")
	e.upload("", ".env", "2")
	if !e.exists(filepath.Join(e.root, ".env (1)")) {
		t.Error("dotfile duplicate not named '.env (1)'")
	}
}

func TestUploadIntoSubfolderAndErrors(t *testing.T) {
	e := newEnv(t, 0)
	os.Mkdir(filepath.Join(e.root, "docs"), 0o755)

	code, body := e.upload("docs", "a.txt", "hi")
	want(t, code, 201, "upload to subfolder")
	if p := decode[PathResponse](t, body); p.Path != "docs/a.txt" || p.Name != "a.txt" {
		t.Errorf("upload response = %q", body)
	}
	if !e.exists(filepath.Join(e.root, "docs", "a.txt")) {
		t.Error("file not in subfolder")
	}
	code, _ = e.upload("missing", "a.txt", "hi")
	want(t, code, 400, "upload to missing folder")
	code, _ = e.do(http.MethodGet, "/api/upload", nil, "")
	want(t, code, 405, "GET upload")
	code, _ = e.do(http.MethodPost, "/api/upload", strings.NewReader("plain"), "text/plain")
	want(t, code, 415, "non-multipart upload")

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	mw.WriteField("other", "value")
	mw.Close()
	code, _ = e.do(http.MethodPost, "/api/upload", &buf, mw.FormDataContentType())
	want(t, code, 400, "missing file part")
}

func TestUploadFileNamesCannotEscape(t *testing.T) {
	e := newEnv(t, 0)
	os.Mkdir(filepath.Join(e.root, "docs"), 0o755)

	// The standard library reduces these to base names.
	for _, name := range []string{"../evil.txt", "../../evil.txt", "/abs/evil.txt", "a/b/evil.txt"} {
		e.upload("docs", name, "x")
	}
	if e.exists(filepath.Join(e.root, "evil.txt")) || e.exists(filepath.Join(filepath.Dir(e.root), "evil.txt")) {
		t.Error("upload escaped its target folder")
	}
	if !e.exists(filepath.Join(e.root, "docs", "evil.txt")) {
		t.Error("expected sanitized file inside docs/")
	}
}

func TestUploadTooLargeLeavesNoFile(t *testing.T) {
	e := newEnv(t, 1024)
	code, _ := e.upload("", "big.bin", strings.Repeat("x", 64*1024))
	want(t, code, 413, "oversized upload")
	if e.exists(filepath.Join(e.root, "big.bin")) {
		t.Error("truncated file left on disk after rejected upload")
	}

	code, _ = e.upload("", "small.txt", "tiny")
	want(t, code, 201, "small upload under limit")
}

func TestServeFileRangeAndDirectories(t *testing.T) {
	e := newEnv(t, 0)
	e.write("docs/movie.bin", "0123456789")

	code, body := e.do(http.MethodGet, "/files/docs/movie.bin", nil, "")
	want(t, code, 200, "GET file")
	if body != "0123456789" {
		t.Errorf("body = %q", body)
	}

	req, _ := http.NewRequest(http.MethodGet, e.srv.URL+"/files/docs/movie.bin", nil)
	req.Header.Set("Range", "bytes=2-5")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	want(t, resp.StatusCode, 206, "range request")
	if string(b) != "2345" {
		t.Errorf("range body = %q", b)
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("missing nosniff header")
	}

	for _, p := range []string{"/files/", "/files/docs", "/files/docs/", "/files/nope.txt"} {
		code, _ := e.do(http.MethodGet, p, nil, "")
		want(t, code, 404, "GET "+p)
	}
	code, _ = e.do(http.MethodPost, "/files/docs/movie.bin", nil, "")
	want(t, code, 405, "POST file")
}

func TestEncodedTraversalOnFileRoute(t *testing.T) {
	e := newEnv(t, 0)
	e.write("a.txt", "x")
	for _, p := range []string{"/files/..%2foutside/secret.txt", "/files/%2e%2e/outside/secret.txt", "/files/..%2f..%2fetc/passwd"} {
		code, body := e.do(http.MethodGet, p, nil, "")
		if code == 200 || strings.Contains(body, "top secret") {
			t.Errorf("GET %s leaked data (status %d)", p, code)
		}
	}
}

func TestWebUIIsServed(t *testing.T) {
	e := newEnv(t, 0)
	code, body := e.do(http.MethodGet, "/", nil, "")
	want(t, code, 200, "GET /")
	if !strings.Contains(body, "<html>") {
		t.Errorf("unexpected index body %q", body)
	}
}

func dirExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.IsDir()
}

func (e *env) lastEvent() events.Event {
	e.t.Helper()
	evs := e.rec.all()
	if len(evs) == 0 {
		e.t.Fatal("no event was published")
	}
	return evs[len(evs)-1]
}

func TestFailedRenameIsAuditedWithRequestIDAndActor(t *testing.T) {
	e := newEnv(t, 0)

	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/api/fs/rename",
		strings.NewReader(`{"oldPath":"dog4.jpg","newPath":"dog3.jpg"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	want(t, resp.StatusCode, 404, "rename of missing file")

	ev := e.lastEvent()
	if ev.Type != events.FileMoved || ev.Outcome != events.OutcomeNotFound || ev.Path != "dog4.jpg" || ev.Target != "dog3.jpg" {
		t.Errorf("event = %+v", ev)
	}
	if ev.Actor.ID != tester.User.ID || ev.Actor.Name != "tester" || ev.Actor.Role != "admin" || ev.Actor.Session != tester.Session.ID ||
		!strings.HasPrefix(ev.Actor.RemoteAddr, "127.0.0.1:") {
		t.Errorf("actor = %+v", ev.Actor)
	}

	id := resp.Header.Get("X-Request-ID")
	if id == "" || id != ev.RequestID {
		t.Errorf("X-Request-ID %q does not match event request id %q", id, ev.RequestID)
	}
}

func TestRequestIDsAreUnique(t *testing.T) {
	e := newEnv(t, 0)
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		resp, err := http.Get(e.srv.URL + "/api/files?path=")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		id := resp.Header.Get("X-Request-ID")
		if id == "" || seen[id] {
			t.Fatalf("missing or repeated request id %q", id)
		}
		seen[id] = true
	}
}

func TestOperationsPublishEventsWithOutcomes(t *testing.T) {
	e := newEnv(t, 0)
	e.write("keep.txt", "0123456789")
	e.symlink(e.outside, "escape")

	type step struct {
		name    string
		do      func() int
		code    int
		typ     events.Type
		outcome events.Outcome
		path    string
	}
	steps := []step{
		{"upload", func() int { c, _ := e.upload("", "up.txt", "abc"); return c }, 201, events.FileUploaded, events.OutcomeOK, "up.txt"},
		{"mkdir", func() int { c, _ := e.postJSON("/api/fs/mkdir", CreateFolderRequest{Name: "docs"}); return c }, 201, events.FolderCreated, events.OutcomeOK, "docs"},
		{"mkdir again", func() int { c, _ := e.postJSON("/api/fs/mkdir", CreateFolderRequest{Name: "docs"}); return c }, 409, events.FolderCreated, events.OutcomeExists, "docs"},
		{"download", func() int { c, _ := e.do(http.MethodGet, "/files/keep.txt", nil, ""); return c }, 200, events.FileDownloaded, events.OutcomeOK, "keep.txt"},
		{"download via symlink", func() int { c, _ := e.do(http.MethodGet, "/files/escape/secret.txt", nil, ""); return c }, 403, events.FileDownloaded, events.OutcomeDenied, "escape/secret.txt"},
		{"traversal", func() int { c, _, _ := e.list("../outside"); return c }, 403, events.FileListed, events.OutcomeDenied, "../outside"},
		{"delete root", func() int { c, _ := e.postJSON("/api/fs/delete", DeleteRequest{Path: ""}); return c }, 400, events.FileDeleted, events.OutcomeDenied, ""},
		{"delete", func() int { c, _ := e.postJSON("/api/fs/delete", DeleteRequest{Path: "up.txt"}); return c }, 200, events.FileDeleted, events.OutcomeOK, "up.txt"},
	}

	for _, st := range steps {
		before := len(e.rec.all())
		if got := st.do(); got != st.code {
			t.Errorf("%s: status %d, want %d", st.name, got, st.code)
		}
		if n := len(e.rec.all()) - before; n != 1 {
			t.Errorf("%s: %d events published, want exactly 1", st.name, n)
			continue
		}
		ev := e.lastEvent()
		if ev.Type != st.typ || ev.Outcome != st.outcome || ev.Path != st.path {
			t.Errorf("%s: event = {%s %s %q}, want {%s %s %q}", st.name, ev.Type, ev.Outcome, ev.Path, st.typ, st.outcome, st.path)
		}
	}
}

func TestUploadEventRecordsSize(t *testing.T) {
	e := newEnv(t, 0)
	e.upload("", "five.txt", "12345")
	if ev := e.lastEvent(); ev.Size != 5 || ev.Path != "five.txt" {
		t.Errorf("event = %+v", ev)
	}
}

// Collapsing ranged reads is the audit filter's job; the API reports each.
func TestEveryRangeRequestPublishesAnEvent(t *testing.T) {
	e := newEnv(t, 0)
	e.write("movie.bin", "0123456789")
	for _, rng := range []string{"bytes=0-3", "bytes=4-9"} {
		req, _ := http.NewRequest(http.MethodGet, e.srv.URL+"/files/movie.bin", nil)
		req.Header.Set("Range", rng)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	n := 0
	for _, ev := range e.rec.all() {
		if ev.Type == events.FileDownloaded && ev.Outcome == events.OutcomeOK {
			n++
		}
	}
	if n != 2 {
		t.Errorf("%d download events for 2 ranged requests", n)
	}
}

func TestStaticAssetsAreNotFileOperations(t *testing.T) {
	e := newEnv(t, 0)
	e.do(http.MethodGet, "/", nil, "")
	if n := len(e.rec.all()); n != 0 {
		t.Errorf("serving the web UI published %d events", n)
	}
}
