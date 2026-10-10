package httpapi

import (
	"bytes"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nobletk/gocalbox/internal/events"
)

func (e *env) request(method, path string, body io.Reader, headers map[string]string) *http.Response {
	e.t.Helper()
	req, err := http.NewRequest(method, e.srv.URL+path, body)
	if err != nil {
		e.t.Fatal(err)
	}
	for k, v := range headers {
		if k == "Host" {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func readErr(t *testing.T, resp *http.Response) ErrorResponse {
	t.Helper()
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("error Content-Type = %q, want application/json", ct)
	}
	b, _ := io.ReadAll(resp.Body)
	er := decode[ErrorResponse](t, string(b))
	if er.Error.Code == "" || er.Error.Message == "" {
		t.Errorf("error body lacks code or message: %s", b)
	}
	if er.RequestID == "" || er.RequestID != resp.Header.Get("X-Request-ID") {
		t.Errorf("error body request id %q, header %q", er.RequestID, resp.Header.Get("X-Request-ID"))
	}
	return er
}

func TestCrossSiteRequestsCannotModifyFiles(t *testing.T) {
	e := newEnv(t, 0)
	e.write("victim.txt", "x")
	body := `{"path":"victim.txt"}`

	for name, h := range map[string]map[string]string{
		"fetch metadata cross-site": {"Content-Type": "application/json", "Sec-Fetch-Site": "cross-site"},
		"fetch metadata same-site":  {"Content-Type": "application/json", "Sec-Fetch-Site": "same-site"},
		"foreign Origin":            {"Content-Type": "application/json", "Origin": "https://evil.example"},
	} {
		resp := e.request(http.MethodPost, "/api/fs/delete", strings.NewReader(body), h)
		want(t, resp.StatusCode, 403, name)
		if er := readErr(t, resp); er.Error.Code != "cross_origin" {
			t.Errorf("%s: code %q", name, er.Error.Code)
		}
	}

	// A form-encoded or text/plain body needs no CORS preflight, so it must
	// be refused even when no browser headers identify the request.
	resp := e.request(http.MethodPost, "/api/fs/delete", strings.NewReader(body), map[string]string{"Content-Type": "text/plain"})
	want(t, resp.StatusCode, 415, "text/plain JSON body")
	readErr(t, resp)

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("myFile", "dropped.txt")
	fw.Write([]byte("x"))
	mw.Close()
	resp = e.request(http.MethodPost, "/api/upload", &buf, map[string]string{"Content-Type": mw.FormDataContentType(), "Sec-Fetch-Site": "cross-site"})
	want(t, resp.StatusCode, 403, "cross-site upload")

	if !e.exists(filepath.Join(e.root, "victim.txt")) || e.exists(filepath.Join(e.root, "dropped.txt")) {
		t.Fatal("a cross-site request changed the folder")
	}

	// The UI itself, and the same origin, keep working.
	resp = e.request(http.MethodPost, "/api/fs/delete", strings.NewReader(body),
		map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "Origin": e.srv.URL})
	want(t, resp.StatusCode, 200, "same-origin delete")
}

func TestUnknownHostsAreRejected(t *testing.T) {
	e := newEnvOpts(t, Options{AllowedHosts: []string{"localhost", "127.0.0.1", "::1", "MyBox.lan"}})
	e.write("a.txt", "secret")

	for _, host := range []string{"attacker.example", "attacker.example:80", "127.0.0.2", "localhost.attacker.example"} {
		resp := e.request(http.MethodGet, "/files/a.txt", nil, map[string]string{"Host": host})
		want(t, resp.StatusCode, http.StatusMisdirectedRequest, "Host "+host)
		if er := readErr(t, resp); er.Error.Code != "host_not_allowed" {
			t.Errorf("Host %s: code %q", host, er.Error.Code)
		}
	}
	for _, host := range []string{"localhost:8080", "127.0.0.1", "[::1]:8080", "mybox.lan", "MYBOX.LAN.:9000"} {
		resp := e.request(http.MethodGet, "/files/a.txt", nil, map[string]string{"Host": host})
		want(t, resp.StatusCode, 200, "Host "+host)
	}
}

func TestFilesAreServedWithSafeHeaders(t *testing.T) {
	e := newEnv(t, 0)
	for name, content := range map[string]string{
		"evil.html": "<script>fetch('/api/fs/delete')</script>", "evil.svg": "<svg onload=alert(1)>",
		"photo.png": "png", "clip.mp4": "mp4", "notes.txt": "hi", "doc.pdf": "%PDF", "blob": "?", "naïve résumé.txt": "x",
	} {
		e.write(name, content)
	}

	const (
		opaque     = "sandbox;"                   // no origin, no scripts
		sameOrigin = "sandbox allow-same-origin;" // keeps its origin for media refetches, no scripts
		none       = ""
	)
	for _, tc := range []struct {
		path, ctypePrefix, disposition string
		csp                            string
	}{
		{"evil.html", "text/html", "attachment", opaque},
		{"evil.svg", "image/svg+xml", "attachment", opaque},
		{"photo.png", "image/png", "inline", sameOrigin},
		{"clip.mp4", "video/mp4", "inline", sameOrigin},
		{"notes.txt", "text/plain", "inline", sameOrigin},
		{"notes.txt?download=1", "text/plain", "attachment", opaque},
		{"doc.pdf", "application/pdf", "inline", none},
		{"blob", "application/octet-stream", "attachment", opaque},
	} {
		resp := e.request(http.MethodGet, "/files/"+tc.path, nil, nil)
		want(t, resp.StatusCode, 200, tc.path)
		h := resp.Header
		if !strings.HasPrefix(h.Get("Content-Type"), tc.ctypePrefix) {
			t.Errorf("%s: Content-Type %q", tc.path, h.Get("Content-Type"))
		}
		if !strings.HasPrefix(h.Get("Content-Disposition"), tc.disposition) {
			t.Errorf("%s: Content-Disposition %q", tc.path, h.Get("Content-Disposition"))
		}
		csp := h.Get("Content-Security-Policy")
		if !strings.HasPrefix(csp, tc.csp) || (tc.csp == none) != (csp == "") || strings.Contains(csp, "allow-scripts") {
			t.Errorf("%s: CSP %q, want prefix %q", tc.path, csp, tc.csp)
		}
		if h.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: missing nosniff", tc.path)
		}
	}

	resp := e.request(http.MethodGet, "/files/na%C3%AFve%20r%C3%A9sum%C3%A9.txt", nil, nil)
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, "filename*=utf-8''na%C3%AFve%20r%C3%A9sum%C3%A9.txt") {
		t.Errorf("non-ASCII filename not encoded: %q", cd)
	}
}

func TestErrorsAreJSONEverywhere(t *testing.T) {
	e := newEnv(t, 0)
	e.write("a.txt", "0123456789")

	for _, tc := range []struct {
		name, method, path, body, ctype string
		status                          int
		code                            string
	}{
		{"traversal", "GET", "/api/files?path=../x", "", "", 403, "path_outside_root"},
		{"missing", "GET", "/files/nope", "", "", 404, "not_found"},
		{"method", "DELETE", "/api/fs/delete", "", "", 405, "method_not_allowed"},
		{"media type", "POST", "/api/fs/mkdir", `{"name":"x"}`, "text/plain", 415, "unsupported_media_type"},
		{"bad json", "POST", "/api/fs/mkdir", `{`, "application/json", 400, "invalid_body"},
		{"exists", "POST", "/api/fs/mkdir", `{"name":"a.txt"}`, "application/json", 409, "already_exists"},
		{"root", "POST", "/api/fs/delete", `{"path":"/"}`, "application/json", 400, "root_not_allowed"},
		{"unknown endpoint", "GET", "/api/nope", "", "", 404, "not_found"},
		{"unclean API path", "GET", "/api//files", "", "", 400, "invalid_path"},
		{"unclean file path", "GET", "/files/x/../a.txt", "", "", 400, "invalid_path"},
		{"path through a file", "GET", "/files/a.txt/x", "", "", 404, "not_found"},
	} {
		h := map[string]string{}
		if tc.ctype != "" {
			h["Content-Type"] = tc.ctype
		}
		resp := e.request(tc.method, tc.path, strings.NewReader(tc.body), h)
		want(t, resp.StatusCode, tc.status, tc.name)
		if er := readErr(t, resp); er.Error.Code != tc.code {
			t.Errorf("%s: code %q, want %q", tc.name, er.Error.Code, tc.code)
		}
	}

	resp := e.request("GET", "/files/a.txt", nil, map[string]string{"Range": "bytes=50-60"})
	want(t, resp.StatusCode, 416, "unsatisfiable range")
	if er := readErr(t, resp); er.Error.Code != "range_not_satisfiable" {
		t.Errorf("416 code %q", er.Error.Code)
	}
	if resp.Header.Get("Content-Disposition") != "" {
		t.Error("file headers leaked into an error response")
	}
}

func TestDownloadEventsReportBytesSent(t *testing.T) {
	e := newEnv(t, 0)
	e.write("movie.bin", "0123456789")

	etag := e.request("HEAD", "/files/movie.bin", nil, nil).Header.Get("ETag")

	for _, tc := range []struct {
		name, method string
		headers      map[string]string
		typ          events.Type
		outcome      events.Outcome
		size         int64
	}{
		{"full", "GET", nil, events.FileDownloaded, events.OutcomeOK, 10},
		{"range", "GET", map[string]string{"Range": "bytes=2-5"}, events.FileDownloaded, events.OutcomeOK, 4},
		{"HEAD", "HEAD", nil, events.FileChecked, events.OutcomeOK, 0},
		{"304", "GET", map[string]string{"If-None-Match": etag}, events.FileChecked, events.OutcomeOK, 0},
		{"416", "GET", map[string]string{"Range": "bytes=50-"}, events.FileDownloaded, events.OutcomeInvalid, 0},
		{"412", "GET", map[string]string{"If-Match": `"stale"`}, events.FileDownloaded, events.OutcomeInvalid, 0},
	} {
		resp := e.request(tc.method, "/files/movie.bin", nil, tc.headers)
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		ev := e.lastEvent()
		if ev.Type != tc.typ || ev.Outcome != tc.outcome || ev.Size != tc.size || ev.Range != tc.headers["Range"] || ev.Resolved != "movie.bin" {
			t.Errorf("%s: event = %+v", tc.name, ev)
		}
	}
}

func TestReadyGateSuspendsFileOperations(t *testing.T) {
	var auditErr error
	e := newEnvOpts(t, Options{Ready: func() error { return auditErr }})
	e.write("a.txt", "x")

	if code, _, _ := e.list(""); code != 200 {
		t.Fatalf("healthy list = %d", code)
	}
	auditErr = errors.New("disk full")
	for _, p := range []string{"/api/files", "/files/a.txt"} {
		resp := e.request("GET", p, nil, nil)
		want(t, resp.StatusCode, 503, p)
		if er := readErr(t, resp); er.Error.Code != "unavailable" {
			t.Errorf("%s: code %q", p, er.Error.Code)
		}
	}
	code, _ := e.postJSON("/api/fs/delete", DeleteRequest{Path: "a.txt"})
	want(t, code, 503, "delete while unhealthy")
	if _, err := os.Stat(filepath.Join(e.root, "a.txt")); err != nil {
		t.Error("file deleted while operations were suspended")
	}
	if code, _ := e.do("GET", "/", nil, ""); code != 200 {
		t.Errorf("UI not served while suspended: %d", code)
	}
}

func TestNormalizeHost(t *testing.T) {
	for in, want := range map[string]string{
		"LocalHost:8080": "localhost", "[::1]:80": "::1", "[::1]": "::1", "::1": "::1",
		"box.lan.": "box.lan", "10.0.0.5": "10.0.0.5",
	} {
		if got := normalizeHost(in); got != want {
			t.Errorf("normalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}
