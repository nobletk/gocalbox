package httpapi

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/fsops"
	"github.com/nobletk/gocalbox/internal/sandbox"
	"github.com/nobletk/gocalbox/internal/state"
)

// readZip returns each entry's content; folders end in "/" and map to "".
func readZip(t *testing.T, body []byte) map[string]string {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatalf("not a zip: %v", err)
	}
	got := map[string]string{}
	for _, f := range zr.File {
		if f.Method != zip.Store {
			t.Errorf("%s: method %d, want stored", f.Name, f.Method)
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("%s: %v", f.Name, err)
		}
		got[f.Name] = string(b)
	}
	return got
}

func getZip(t *testing.T, c *http.Client, base, dir string) (*http.Response, []byte) {
	t.Helper()
	resp, err := c.Get(base + "/api/fs/zip?path=" + url.QueryEscape(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the archive: %v", err)
	}
	return resp, b
}

func keys(m map[string]string) []string {
	k := make([]string, 0, len(m))
	for n := range m {
		k = append(k, n)
	}
	sort.Strings(k)
	return k
}

func TestZipHoldsTheFolderWithItsSubfolders(t *testing.T) {
	e := newEnv(t, 0)
	e.write("a/x.txt", "ex")
	e.write("a/sub/y.txt", "why")
	e.write("a/sub/deeper/z.txt", "zed")
	os.Mkdir(filepath.Join(e.root, "a", "empty"), 0o755)
	e.write("other.txt", "not in it")

	resp, body := getZip(t, http.DefaultClient, e.srv.URL, "a")
	want(t, resp.StatusCode, 200, "zip")
	if ct := resp.Header.Get("Content-Type"); ct != "application/zip" {
		t.Errorf("Content-Type = %q", ct)
	}
	_, params, err := mime.ParseMediaType(resp.Header.Get("Content-Disposition"))
	if err != nil || params["filename"] != "a.zip" {
		t.Errorf("Content-Disposition = %q", resp.Header.Get("Content-Disposition"))
	}
	if !strings.HasPrefix(resp.Header.Get("Content-Security-Policy"), "sandbox") {
		t.Errorf("CSP = %q", resp.Header.Get("Content-Security-Policy"))
	}
	got := readZip(t, body)
	wantEntries := map[string]string{
		"a/": "", "a/x.txt": "ex", "a/empty/": "", "a/sub/": "", "a/sub/y.txt": "why",
		"a/sub/deeper/": "", "a/sub/deeper/z.txt": "zed",
	}
	if !slices.Equal(keys(got), keys(wantEntries)) {
		t.Fatalf("entries = %v, want %v", keys(got), keys(wantEntries))
	}
	for n, c := range wantEntries {
		if got[n] != c {
			t.Errorf("%s = %q, want %q", n, got[n], c)
		}
	}
}

func TestZipRecordsEachFileAsADownload(t *testing.T) {
	e := newEnv(t, 0)
	e.write("a/x.txt", "ex")
	e.write("a/sub/y.txt", "why!")
	if resp, _ := getZip(t, http.DefaultClient, e.srv.URL, "a"); resp.StatusCode != 200 {
		t.Fatal(resp.Status)
	}
	sizes := map[string]int64{}
	for _, ev := range e.rec.all() {
		if ev.Type == events.FileDownloaded && ev.Outcome == events.OutcomeOK {
			sizes[ev.Path] = ev.Size
		}
	}
	if sizes["a/x.txt"] != 2 || sizes["a/sub/y.txt"] != 4 || len(sizes) != 2 {
		t.Errorf("downloads recorded = %v", sizes)
	}
}

func TestZipOfTheRootIsNamedAfterTheServer(t *testing.T) {
	e := newEnv(t, 0)
	e.write("x.txt", "ex")
	resp, body := getZip(t, http.DefaultClient, e.srv.URL, "")
	_, params, _ := mime.ParseMediaType(resp.Header.Get("Content-Disposition"))
	if params["filename"] != "gocalbox.zip" {
		t.Errorf("filename = %q", params["filename"])
	}
	if got := readZip(t, body); got["gocalbox/x.txt"] != "ex" {
		t.Errorf("entries = %v", keys(got))
	}
}

func TestZipNamesAFolderOutsideASCII(t *testing.T) {
	e := newEnv(t, 0)
	e.write("Fényképek/kép.txt", "k")
	resp, body := getZip(t, http.DefaultClient, e.srv.URL, "Fényképek")
	_, params, err := mime.ParseMediaType(resp.Header.Get("Content-Disposition"))
	if err != nil || params["filename"] != "Fényképek.zip" {
		t.Errorf("Content-Disposition = %q", resp.Header.Get("Content-Disposition"))
	}
	if got := readZip(t, body); got["Fényképek/kép.txt"] != "k" {
		t.Errorf("entries = %v", keys(got))
	}
}

func TestZipLeavesOutLinkedFoldersAndTheReservedFolder(t *testing.T) {
	e := newEnv(t, 0)
	e.write("a/x.txt", "ex")
	e.write("a/.gocalbox/state", "hidden")
	e.write("elsewhere/w.txt", "w")
	e.symlink(".", "a/loop")
	e.symlink("../elsewhere", "a/away")
	e.symlink("x.txt", "a/alias.txt")
	e.symlink(e.outside, "a/escape")

	_, body := getZip(t, http.DefaultClient, e.srv.URL, "a")
	got := readZip(t, body)
	if want := []string{"a/", "a/alias.txt", "a/x.txt"}; !slices.Equal(keys(got), want) {
		t.Errorf("entries = %v, want %v", keys(got), want)
	}
	if got["a/alias.txt"] != "ex" {
		t.Errorf("the linked file = %q", got["a/alias.txt"])
	}
}

func TestZipRefusals(t *testing.T) {
	e := newEnv(t, 0)
	e.write("x.txt", "ex")
	for _, tc := range []struct {
		method, path string
		status       int
		code         string
	}{
		{"GET", "/api/fs/zip?path=missing", 404, "not_found"},
		{"GET", "/api/fs/zip?path=x.txt", 400, "not_a_directory"},
		{"GET", "/api/fs/zip?path=../outside", 403, ""},
		{"POST", "/api/fs/zip?path=", 405, ""},
	} {
		code, body := e.do(tc.method, tc.path, nil, "")
		want(t, code, tc.status, tc.method+" "+tc.path)
		if tc.code != "" && !strings.Contains(body, `"`+tc.code+`"`) {
			t.Errorf("%s: body %s, want code %s", tc.path, body, tc.code)
		}
	}
}

func TestZipShowsEachUserOnlyWhatTheyMayRead(t *testing.T) {
	e := newAuthEnv(t)
	e.addUserAs("root", state.RoleAdmin)
	e.addUserAs("alice", state.RoleContributor)
	e.addUserAs("bob", state.RoleContributor)
	if warnings := e.acc.EnsureLayout(context.Background()); len(warnings) > 0 {
		t.Fatal(warnings)
	}
	alice, bob := e.browser(), e.browser()
	e.login(alice, "alice")
	e.login(bob, "bob")
	e.upload(alice, "users/alice", "mine.txt", "private")
	e.upload(alice, "public", "shared.txt", "for all")

	_, body := getZip(t, bob, e.srv.URL, "")
	got := readZip(t, body)
	if got["gocalbox/public/shared.txt"] != "for all" {
		t.Errorf("bob's archive lacks the shared file: %v", keys(got))
	}
	for n := range got {
		if strings.Contains(n, "alice") {
			t.Errorf("bob's archive holds %s", n)
		}
	}
	resp, _ := getZip(t, bob, e.srv.URL, "users/alice")
	want(t, resp.StatusCode, 404, "bob zips alice's home")

	_, body = getZip(t, alice, e.srv.URL, "users/alice")
	if got := readZip(t, body); got["alice/mine.txt"] != "private" {
		t.Errorf("alice's archive = %v", keys(got))
	}
}

// shrinkingFiles truncates a file once it has been opened, as if another
// program cut it while the archive was being written.
type shrinkingFiles struct {
	*fsops.Service
	root, victim string
	skip         string
	// fail answers these paths' Open or List with an error that isn't a
	// vanished entry.
	fail map[string]error
}

func (s shrinkingFiles) List(ctx context.Context, p string) ([]fsops.Entry, error) {
	if err := s.fail[p]; err != nil {
		return nil, err
	}
	return s.Service.List(ctx, p)
}

func (s shrinkingFiles) Open(ctx context.Context, p string) (*fsops.File, error) {
	if p == s.skip {
		return nil, fsops.ErrNotFound
	}
	if err := s.fail[p]; err != nil {
		return nil, err
	}
	f, err := s.Service.Open(ctx, p)
	if err == nil && p == s.victim {
		os.Truncate(filepath.Join(s.root, filepath.FromSlash(p)), 1)
	}
	return f, err
}

func zipEnv(t *testing.T, victim, skip string, fail ...map[string]error) (*httptest.Server, string) {
	t.Helper()
	root := t.TempDir()
	sb, err := sandbox.New(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sb.Close() })
	files := shrinkingFiles{Service: adminFiles(sb, &recorder{}), root: sb.Root(), victim: victim, skip: skip}
	if len(fail) > 0 {
		files.fail = fail[0]
	}
	srv := httptest.NewServer(newTestHandler(files, fstest.MapFS{}, Options{}))
	t.Cleanup(srv.Close)
	return srv, sb.Root()
}

func TestZipLeavesOutAFileThatCantBeOpenedAnyMore(t *testing.T) {
	srv, root := zipEnv(t, "", "a/gone.txt")
	os.MkdirAll(filepath.Join(root, "a"), 0o755)
	os.WriteFile(filepath.Join(root, "a", "gone.txt"), []byte("g"), 0o644)
	os.WriteFile(filepath.Join(root, "a", "kept.txt"), []byte("k"), 0o644)

	_, body := getZip(t, http.DefaultClient, srv.URL, "a")
	if got := readZip(t, body); !slices.Equal(keys(got), []string{"a/", "a/kept.txt"}) {
		t.Errorf("entries = %v", keys(got))
	}
}

func TestZipCutsTheConnectionWhenAFileShrinks(t *testing.T) {
	srv, root := zipEnv(t, "a/big.bin", "")
	os.MkdirAll(filepath.Join(root, "a"), 0o755)
	os.WriteFile(filepath.Join(root, "a", "big.bin"), bytes.Repeat([]byte("b"), 1<<20), 0o644)

	resp, err := http.Get(srv.URL + "/api/fs/zip?path=a")
	if err != nil {
		return
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err == nil {
		if _, zerr := zip.NewReader(bytes.NewReader(b), int64(len(b))); zerr == nil {
			t.Fatal("a whole archive arrived for a file that shrank")
		}
		t.Fatal("the body ended without an error")
	}
}

func TestZipCutsTheConnectionWhenAnEntryCantBeRead(t *testing.T) {
	for _, failing := range []string{"a/locked.txt", "a/sub"} {
		srv, root := zipEnv(t, "", "", map[string]error{failing: fs.ErrPermission})
		os.MkdirAll(filepath.Join(root, "a", "sub"), 0o755)
		os.WriteFile(filepath.Join(root, "a", "locked.txt"), []byte("l"), 0o644)
		os.WriteFile(filepath.Join(root, "a", "sub", "s.txt"), []byte("s"), 0o644)
		os.WriteFile(filepath.Join(root, "a", "ok.txt"), []byte("k"), 0o644)

		resp, err := http.Get(srv.URL + "/api/fs/zip?path=a")
		if err != nil {
			continue
		}
		b, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err == nil {
			if _, zerr := zip.NewReader(bytes.NewReader(b), int64(len(b))); zerr == nil {
				t.Errorf("%s couldn't be read, but a whole archive arrived", failing)
			}
		}
	}
}

func TestZipEntryNamesHaveNoBackslash(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a backslash separates folders on Windows")
	}
	e := newEnv(t, 0)
	e.write(`a/..\..\evil.bat`, "x")
	e.write(`a/b\c/d.txt`, "d")
	_, body := getZip(t, http.DefaultClient, e.srv.URL, "a")
	got := readZip(t, body)
	if want := []string{"a/", "a/.._.._evil.bat", "a/b_c/", "a/b_c/d.txt"}; !slices.Equal(keys(got), want) {
		t.Errorf("entries = %q, want %q", keys(got), want)
	}
}
