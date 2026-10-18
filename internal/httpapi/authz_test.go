package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"testing/fstest"

	"github.com/nobletk/gocalbox/internal/authz"
	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/fsops"
	"github.com/nobletk/gocalbox/internal/sandbox"
	"github.com/nobletk/gocalbox/internal/state"
	"github.com/nobletk/gocalbox/internal/transfer"
	"github.com/nobletk/gocalbox/internal/transfer/registry"
)

func (e *authEnv) addUserAs(name string, role state.Role) {
	e.t.Helper()
	if _, err := e.acc.CreateUser(events.WithActor(context.Background(), events.Actor{ID: events.ConsoleID}), name, role, passphrase); err != nil {
		e.t.Fatal(err)
	}
}

func (e *authEnv) upload(c *http.Client, dir, name, content string) (*http.Response, string) {
	e.t.Helper()
	body, ctype := multipartBody(name, content)
	req, err := http.NewRequest(http.MethodPost, e.srv.URL+"/api/upload?path="+dir, body)
	if err != nil {
		e.t.Fatal(err)
	}
	req.Header.Set("Content-Type", ctype)
	resp, err := c.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func TestFileRoutesAnswerTheDecisions(t *testing.T) {
	e := newAuthEnv(t)
	e.addUserAs("root", state.RoleAdmin)
	e.addUserAs("alice", state.RoleContributor)
	e.addUserAs("bob", state.RoleContributor)
	e.addUserAs("vera", state.RoleViewer)
	if warnings := e.acc.EnsureLayout(context.Background()); len(warnings) > 0 {
		t.Fatal(warnings)
	}
	users := map[string]*http.Client{}
	for _, name := range []string{"root", "alice", "bob", "vera"} {
		users[name] = e.browser()
		e.login(users[name], name)
	}
	if resp, body := e.upload(users["alice"], "public", "a.txt", "alice's text"); resp.StatusCode != http.StatusCreated {
		t.Fatalf("alice uploads: %d %s", resp.StatusCode, body)
	}
	e.upload(users["alice"], "users/alice", "mine.txt", "private")
	e.upload(users["root"], "users/alice", "from-root.txt", "x")

	for _, tc := range []struct {
		user, method, path string
		body               any
		status             int
		code               string
	}{
		{"bob", "POST", "/api/fs/delete", DeleteRequest{Path: "public/a.txt"}, 403, "forbidden"},
		{"bob", "POST", "/api/fs/rename", MoveRequest{OldPath: "public/a.txt", NewPath: "public/b.txt"}, 403, "forbidden"},
		{"bob", "GET", "/api/files?path=users/alice", nil, 404, "not_found"},
		{"bob", "GET", "/files/users/alice/mine.txt", nil, 404, "not_found"},
		{"bob", "POST", "/api/fs/mkdir", CreateFolderRequest{TargetPath: "users/alice", Name: "x"}, 400, "parent_not_found"},
		{"bob", "POST", "/api/fs/move", MoveRequest{OldPath: "users/alice/mine.txt", NewPath: "public/mine.txt"}, 404, "not_found"},
		{"bob", "POST", "/api/fs/mkdir", CreateFolderRequest{TargetPath: "users", Name: "x"}, 403, "forbidden"},
		{"vera", "POST", "/api/fs/mkdir", CreateFolderRequest{TargetPath: "public", Name: "x"}, 403, "forbidden"},
		{"vera", "POST", "/api/fs/delete", DeleteRequest{Path: "public/a.txt"}, 403, "forbidden"},
		{"root", "POST", "/api/fs/delete", DeleteRequest{Path: "public"}, 409, "bound_folder"},
		{"alice", "POST", "/api/fs/move", MoveRequest{OldPath: "users/alice", NewPath: "public/alice"}, 409, "bound_folder"},
		{"alice", "GET", "/files/public/.gocalbox/x", nil, 403, "reserved_path"},
		{"alice", "POST", "/api/fs/mkdir", CreateFolderRequest{TargetPath: "public", Name: ".gocalbox"}, 403, "reserved_path"},
		{"alice", "POST", "/api/fs/rename", MoveRequest{OldPath: "users/alice/from-root.txt", NewPath: "users/alice/r.txt"}, 403, "forbidden"},
		{"alice", "POST", "/api/fs/delete", DeleteRequest{Path: "users/alice/from-root.txt"}, 200, ""},
		{"alice", "POST", "/api/fs/rename", MoveRequest{OldPath: "public/a.txt", NewPath: "public/b.txt"}, 200, ""},
		{"vera", "GET", "/files/public/b.txt", nil, 200, ""},
	} {
		resp, body := e.call(users[tc.user], tc.method, tc.path, tc.body)
		if resp.StatusCode != tc.status || errorCode(body) != tc.code {
			t.Errorf("%s %s %s: %d %s, want %d %s", tc.user, tc.method, tc.path, resp.StatusCode, body, tc.status, tc.code)
		}
	}
	if resp, body := e.upload(users["vera"], "public", "v.txt", "v"); resp.StatusCode != 403 || errorCode(body) != "forbidden" {
		t.Errorf("the viewer uploads: %d %s", resp.StatusCode, body)
	}
	if resp, body := e.upload(users["bob"], "users/alice", "b.txt", "b"); resp.StatusCode != 400 || errorCode(body) != "parent_not_found" {
		t.Errorf("bob uploads into alice's home: %d %s", resp.StatusCode, body)
	}

	listing := func(user, dir string) map[string]string {
		resp, body := e.call(users[user], "GET", "/api/files?path="+dir, nil)
		if resp.StatusCode != 200 {
			t.Fatalf("%s lists %s: %d %s", user, dir, resp.StatusCode, body)
		}
		var entries []map[string]any
		if err := json.Unmarshal([]byte(body), &entries); err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, en := range entries {
			b, _ := json.Marshal([]any{en["uploader"], en["actions"]})
			out[en["name"].(string)] = string(b)
		}
		return out
	}
	for _, tc := range []struct {
		user, dir string
		want      map[string]string
	}{
		{"alice", "public", map[string]string{"b.txt": `["alice",["rename","move","delete"]]`}},
		{"bob", "public", map[string]string{"b.txt": `["alice",[]]`}},
		{"alice", "users", map[string]string{"alice": `[null,[]]`}},
		{"alice", "", map[string]string{"public": `[null,[]]`, "users": `[null,[]]`}},
		{"vera", "", map[string]string{"public": `[null,[]]`}},
	} {
		if got := listing(tc.user, tc.dir); !maps.Equal(got, tc.want) {
			t.Errorf("%s lists %q: %v, want %v", tc.user, tc.dir, got, tc.want)
		}
	}
}

// refusingPolicy knows the actor, or not, and lets them do nothing.
type refusingPolicy struct{ known bool }

func (p refusingPolicy) Subject(ctx context.Context) (fsops.Subject, bool) {
	return fsops.Subject{ID: events.ActorFrom(ctx).ID, Role: authz.Contributor, Bindings: authz.NewBindings(nil)}, p.known
}

func (refusingPolicy) UserName(string) (string, bool) { return "", false }

type denyCase struct {
	method, target string
	body           any // JSON, a multipart upload when a string, or a part's body
	// own marks a call on the account's own uploads, which their owner may
	// read, list and abort whatever their rights.
	own bool
}

// rawPart is the body of an upload's part.
type rawPart string

// denyAllCases has requests for every route that touches files. A route
// without any fails the deny-all test, so a new route can't miss it. In the
// upload calls, {open}, {ready}, {abort} and {theirs} name uploads the test
// prepares under a policy that allows them: the first three the user's own,
// none with any part, every part and none, and the last another user's,
// every part received; {sum} is the composite of a received upload.
var denyAllCases = map[string][]denyCase{
	"/files/": {
		{method: "GET", target: "/files/dir/secret.txt"},
		{method: "HEAD", target: "/files/dir/secret.txt"},
		{method: "GET", target: "/files/dir/secret.txt?download"},
		{method: "GET", target: "/files/dir"},
		{method: "GET", target: "/files/missing.txt"},
	},
	"/api/files": {
		{method: "GET", target: "/api/files"},
		{method: "GET", target: "/api/files?path=dir"},
		{method: "GET", target: "/api/files?path=dir/sub"},
		{method: "GET", target: "/api/files?path=dir/secret.txt"},
		{method: "GET", target: "/api/files?path=missing"},
	},
	"/api/upload": {
		{method: "POST", target: "/api/upload?path=dir", body: "upload"},
		{method: "POST", target: "/api/upload", body: "upload"},
		{method: "POST", target: "/api/upload?path=missing", body: "upload"},
	},
	"/api/fs/delete": {
		{method: "POST", target: "/api/fs/delete", body: DeleteRequest{Path: "dir/secret.txt"}},
		{method: "POST", target: "/api/fs/delete", body: DeleteRequest{Path: "dir"}},
		{method: "POST", target: "/api/fs/delete", body: DeleteRequest{Path: "missing"}},
	},
	"/api/fs/rename": {
		{method: "POST", target: "/api/fs/rename", body: MoveRequest{OldPath: "dir/secret.txt", NewPath: "dir/renamed.txt"}},
		{method: "POST", target: "/api/fs/rename", body: MoveRequest{OldPath: "dir", NewPath: "dir2"}},
	},
	"/api/fs/move": {
		{method: "POST", target: "/api/fs/move", body: MoveRequest{OldPath: "dir/secret.txt", NewPath: "secret.txt"}},
		{method: "POST", target: "/api/fs/move", body: MoveRequest{OldPath: "dir/sub", NewPath: "sub"}},
		{method: "POST", target: "/api/fs/move", body: MoveRequest{OldPath: "missing", NewPath: "dir/x"}},
	},
	"/api/fs/mkdir": {
		{method: "POST", target: "/api/fs/mkdir", body: CreateFolderRequest{TargetPath: "dir", Name: "new"}},
		{method: "POST", target: "/api/fs/mkdir", body: CreateFolderRequest{TargetPath: "", Name: "new"}},
		{method: "POST", target: "/api/fs/mkdir", body: CreateFolderRequest{TargetPath: "dir", Name: "sub"}},
	},
	"/api/upload/create": {
		{method: "POST", target: "/api/upload/create", body: transfer.CreateRequest{Dir: "dir", Name: "new.txt", Size: 5}},
		{method: "POST", target: "/api/upload/create", body: transfer.CreateRequest{Dir: "dir", Name: "open.txt", Size: 5, ClientKey: "open-key"}},
		{method: "POST", target: "/api/upload/create", body: transfer.CreateRequest{Dir: "dir/sub", Name: "secret.txt", Size: 5}},
		{method: "POST", target: "/api/upload/create", body: transfer.CreateRequest{Dir: "missing", Name: "new.txt", Size: 5}},
	},
	"/api/upload/part": {
		{method: "POST", target: "/api/upload/part?id={open}&n=1", body: rawPart("hello")},
		{method: "POST", target: "/api/upload/part?id={theirs}&n=1", body: rawPart("hello")},
	},
	"/api/upload/status": {
		{method: "POST", target: "/api/upload/status", body: UploadStatusRequest{UploadID: "{theirs}", Hashes: []int{1}}},
		{method: "POST", target: "/api/upload/status", body: UploadStatusRequest{UploadID: "{open}", Hashes: []int{1}}, own: true},
	},
	"/api/upload/complete": {
		{method: "POST", target: "/api/upload/complete", body: UploadCompleteRequest{UploadID: "{ready}", CompositeSHA256: "{sum}"}},
		{method: "POST", target: "/api/upload/complete", body: UploadCompleteRequest{UploadID: "{theirs}", CompositeSHA256: "{sum}"}},
	},
	"/api/upload/abort": {
		{method: "POST", target: "/api/upload/abort", body: UploadAbortRequest{UploadID: "{theirs}"}},
		{method: "POST", target: "/api/upload/abort", body: UploadAbortRequest{UploadID: "{abort}"}, own: true},
	},
	"/api/upload/list": {
		{method: "GET", target: "/api/upload/list", own: true},
		{method: "GET", target: "/api/upload/list?all=1", own: true},
	},
}

func allRoutes() []route {
	a := &api{accounts: &fakeAccounts{}}
	return a.routes(fstest.MapFS{}, Options{CACert: []byte("cert")})
}

// concrete turns a route's pattern into a path it serves.
func concrete(pattern string) string {
	if strings.HasSuffix(pattern, "/") && pattern != "/" {
		return pattern + "x"
	}
	return pattern
}

func TestRoutesDeclareWhetherTheyArePublic(t *testing.T) {
	for _, rt := range allRoutes() {
		if got := isPublic(concrete(rt.pattern)); got != (rt.access == accessPublic) {
			t.Errorf("%s: declared access %d, but isPublic = %v", rt.pattern, rt.access, got)
		}
		if _, ok := denyAllCases[rt.pattern]; ok != (rt.access == accessFiles || rt.access == accessUploads) {
			t.Errorf("%s: declared access %d, but it has deny-all requests: %v", rt.pattern, rt.access, ok)
		}
	}
}

func TestEveryNonPublicRouteInTheTableNeedsASession(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "secret.txt"), []byte("top secret"), 0o644)
	sb, err := sandbox.New(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sb.Close() })
	srv := httptest.NewServer(New(adminFiles(sb, nil), fstest.MapFS{"index.html": {Data: []byte("<html></html>")}},
		Options{Accounts: &fakeAccounts{}, CACert: []byte("cert")}))
	t.Cleanup(srv.Close)
	for _, rt := range allRoutes() {
		if rt.access == accessPublic {
			continue
		}
		for _, method := range []string{"GET", "HEAD", "POST", "PUT", "DELETE"} {
			req, _ := http.NewRequest(method, srv.URL+concrete(rt.pattern)+"?path=secret.txt", strings.NewReader(`{"path":"secret.txt"}`))
			req.Header.Set("Content-Type", "application/json")
			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized || strings.Contains(string(body), "top secret") {
				t.Errorf("%s %s without a session: %d %s", method, rt.pattern, resp.StatusCode, body)
			}
		}
	}
	if _, err := os.Stat(filepath.Join(root, "secret.txt")); err != nil {
		t.Error(err)
	}
}

// allowingPolicy lets every user upload into dir until refuse is set, and
// then answers as refusingPolicy.
type allowingPolicy struct {
	refuse atomic.Bool
	known  bool
}

func (p *allowingPolicy) Subject(ctx context.Context) (fsops.Subject, bool) {
	if p.refuse.Load() {
		return refusingPolicy{known: p.known}.Subject(ctx)
	}
	return fsops.Subject{ID: events.ActorFrom(ctx).ID, Role: authz.Contributor, Bindings: authz.NewBindings([]authz.Binding{
		{Subject: authz.Everyone, Folder: "dir", Grant: authz.GrantContributor},
	})}, true
}

func (p *allowingPolicy) UserName(string) (string, bool) { return "", !p.refuse.Load() }

func TestDenyAll(t *testing.T) {
	for _, known := range []bool{true, false} {
		root := t.TempDir()
		for rel, content := range map[string]string{"dir/secret.txt": "top secret", "dir/sub/deeper.txt": "top secret too", "other.txt": "top secret three"} {
			os.MkdirAll(filepath.Join(root, filepath.Dir(rel)), 0o755)
			os.WriteFile(filepath.Join(root, rel), []byte(content), 0o644)
		}
		sb, err := sandbox.New(root)
		if err != nil {
			t.Fatal(err)
		}
		st, err := sandbox.CheckStaging(sb.OSRoot())
		if err != nil {
			t.Fatal(err)
		}
		if !st.Usable() {
			t.Fatal(st.Problem)
		}
		db, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
		if err != nil {
			t.Fatal(err)
		}
		files := fsops.New(sb, nil, fsops.WithStaging(st))
		policy := &allowingPolicy{known: known}
		files.SetPolicy(policy)
		eng, err := transfer.New(transfer.Config{Root: sb.OSRoot(), Staging: st, Files: files, Registry: registry.New(db),
			Events: &recorder{}, JanitorEvery: -1})
		if err != nil {
			t.Fatal(err)
		}
		ids := prepareUploads(t, eng)
		before, staged := tree(t, root), stagedData(t, root)
		policy.refuse.Store(true)
		srv := httptest.NewServer(newTestHandler(files, fstest.MapFS{"index.html": {Data: []byte("<html></html>")}}, Options{Uploads: eng}))

		for _, rt := range allRoutes() {
			if rt.access != accessFiles && rt.access != accessUploads {
				continue
			}
			cases := denyAllCases[rt.pattern]
			if len(cases) == 0 {
				t.Errorf("no deny-all requests for %s", rt.pattern)
			}
			for _, c := range cases {
				var body io.Reader
				ctype, target := "", ids.Replace(c.target)
				var sum string
				switch b := c.body.(type) {
				case nil:
				case string:
					body, ctype = multipartBody("x.txt", "uploaded")
				case rawPart:
					h := sha256.Sum256([]byte(b))
					body, ctype, sum = strings.NewReader(string(b)), "application/octet-stream", hex.EncodeToString(h[:])
				default:
					j, _ := json.Marshal(b)
					body, ctype = strings.NewReader(ids.Replace(string(j))), "application/json"
				}
				req, _ := http.NewRequest(c.method, srv.URL+target, body)
				if ctype != "" {
					req.Header.Set("Content-Type", ctype)
				}
				if sum != "" {
					req.Header.Set(PartChecksumHeader, sum)
				}
				resp, err := srv.Client().Do(req)
				if err != nil {
					t.Fatal(err)
				}
				got, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				leaked := strings.Contains(string(got), "top secret") || strings.Contains(string(got), "secret.txt") ||
					strings.Contains(string(got), ids.Replace("{theirs}")) || strings.Contains(string(got), "theirs.txt")
				refused := resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 404 ||
					resp.StatusCode == 400 && errorCode(string(got)) == "parent_not_found"
				if c.own && known {
					refused = resp.StatusCode == 200
				}
				if !refused || leaked {
					t.Errorf("known %v: %s %s: %d %s", known, c.method, target, resp.StatusCode, got)
				}
			}
		}
		srv.Close()
		eng.Close(context.Background())
		db.Close()
		st.Close()
		sb.Close()
		if after := tree(t, root); !maps.Equal(before, after) {
			t.Errorf("known %v: the tree changed from %v to %v", known, before, after)
		}
		after := stagedData(t, root)
		if aborted := ids.Replace("{abort}"); known && after[aborted] == "-" {
			// The owner aborted their own upload, which removes its data.
			delete(staged, aborted)
			delete(after, aborted)
		}
		if !maps.Equal(staged, after) {
			t.Errorf("known %v: the staged uploads changed from %v to %v", known, staged, after)
		}
	}
}

// prepareUploads makes the uploads the deny-all cases name, and returns
// what replaces their names.
func prepareUploads(t *testing.T, eng *transfer.Engine) *strings.Replacer {
	t.Helper()
	data := []byte("hello")
	h := sha256.Sum256(data)
	sum := hex.EncodeToString(h[:])
	as := func(id string) context.Context {
		return events.WithActor(context.Background(), events.Actor{ID: id})
	}
	up := func(user, name, key string, send bool) string {
		c, err := eng.Create(as(user), transfer.CreateRequest{Dir: "dir", Name: name, Size: int64(len(data)), ClientKey: key})
		if err != nil {
			t.Fatal(err)
		}
		if send {
			if _, err := eng.Part(as(user), transfer.PartRequest{ID: c.UploadID, N: 1, SHA256: sum, Length: 5, Body: bytes.NewReader(data)}); err != nil {
				t.Fatal(err)
			}
		}
		return c.UploadID
	}
	return strings.NewReplacer(
		"{open}", up(tester.User.ID, "open.txt", "open-key", false),
		"{ready}", up(tester.User.ID, "ready.txt", "", true),
		"{abort}", up(tester.User.ID, "abort.txt", "", false),
		"{theirs}", up("u-someone-else", "theirs.txt", "", true),
		"{sum}", transfer.Composite([][sha256.Size]byte{h}),
	)
}

// stagedData maps each staged upload to its data, or "-" where it has none.
func stagedData(t *testing.T, root string) map[string]string {
	t.Helper()
	dir := filepath.Join(root, sandbox.ReservedName, "uploads")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, en := range entries {
		b, err := os.ReadFile(filepath.Join(dir, en.Name(), "data"))
		if err != nil {
			out[en.Name()] = "-"
			continue
		}
		out[en.Name()] = string(b)
	}
	return out
}

// tree maps every path below root to its content, or "/" for a folder,
// leaving out the server's own folder.
func tree(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		if rel == sandbox.ReservedName {
			return fs.SkipDir
		}
		if d.IsDir() {
			out[rel] = "/"
			return nil
		}
		b, err := os.ReadFile(p)
		out[rel] = string(b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestAnUploadWhoseFileWasMovedAnswers409(t *testing.T) {
	w := httptest.NewRecorder()
	writeError(w, httptest.NewRequest(http.MethodPost, "/api/upload", nil), fsops.ErrUploadMoved)
	if w.Code != http.StatusConflict || errorCode(w.Body.String()) != "upload_moved" {
		t.Errorf("%d %s", w.Code, w.Body)
	}
}
