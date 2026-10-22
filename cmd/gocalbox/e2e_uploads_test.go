package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	be "encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/nobletk/gocalbox/internal/audit"
	"github.com/nobletk/gocalbox/internal/auth"
	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/httpapi"
	"github.com/nobletk/gocalbox/internal/transfer"
)

// uploader is a browser of one user that uploads as the protocol's client
// does: a key from the file's identity, a resume checked against the
// server's hashes, the lowest missing parts first, and retries where the
// server says to come back.
type uploader struct {
	t     *testing.T
	s     *liveServer
	c     *http.Client
	token string
}

func (s *liveServer) uploader(token string) *uploader {
	_, c := trustClient(s.tlsConfig.RootCAs, true)
	return &uploader{t: s.t, s: s, c: c, token: token}
}

// apiError is a refusal of the server, with the fields a client acts on.
type apiError struct {
	Status int
	Body   struct {
		Error   httpapi.ErrorBody `json:"error"`
		Missing []transfer.Range  `json:"missing"`
		State   transfer.State    `json:"state"`
		Result  *transfer.Result  `json:"result"`
	}
	RetryAfter string
}

func (e *apiError) Error() string { return fmt.Sprintf("%d %s", e.Status, e.Body.Error.Code) }

func codeOf(err error) string {
	var ae *apiError
	if errors.As(err, &ae) {
		return ae.Body.Error.Code
	}
	return ""
}

// send makes one call and decodes its answer into out, or returns the
// refusal; a network error is returned as it is.
func (u *uploader) send(method, path, ctype string, body io.Reader, length int64, header map[string]string, out any) error {
	req, err := http.NewRequest(method, u.s.url+path, body)
	if err != nil {
		return err
	}
	req.ContentLength = length
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: u.token})
	resp, err := u.c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		ae := &apiError{Status: resp.StatusCode, RetryAfter: resp.Header.Get("Retry-After")}
		if err := json.Unmarshal(b, &ae.Body); err != nil {
			return fmt.Errorf("%d %s", resp.StatusCode, b)
		}
		return ae
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

func (u *uploader) call(path string, in, out any) error {
	b, _ := json.Marshal(in)
	return u.send("POST", path, "application/json", bytes.NewReader(b), int64(len(b)), nil, out)
}

type source struct {
	dir, name string
	data      []byte
	modified  time.Time
}

func (f source) key() string {
	h := sha256.Sum256(fmt.Appendf(nil, "%s\n%s\n%d\n%d", f.dir, f.name, len(f.data), f.modified.UnixMilli()))
	return hex.EncodeToString(h[:])
}

func (f source) part(c transfer.Created, n int) []byte {
	off := int64(n-1) * c.PartSize
	return f.data[off:min(off+c.PartSize, int64(len(f.data)))]
}

func digest(b []byte) [sha256.Size]byte { return sha256.Sum256(b) }

func (u *uploader) create(f source) (transfer.Created, error) {
	var c transfer.Created
	err := u.call("/api/upload/create", transfer.CreateRequest{Dir: f.dir, Name: f.name, Size: int64(len(f.data)), ClientKey: f.key()}, &c)
	return c, err
}

func (u *uploader) part(id string, n int, data []byte) error {
	sum := digest(data)
	return u.send("POST", "/api/upload/part?id="+id+"&n="+strconv.Itoa(n), "application/octet-stream",
		bytes.NewReader(data), int64(len(data)), map[string]string{httpapi.PartChecksumHeader: hex.EncodeToString(sum[:])}, nil)
}

// retrying repeats call while the server asks to come back later, as long
// as a few seconds.
func retrying(call func() error) error {
	deadline := time.Now().Add(20 * time.Second)
	for wait := 10 * time.Millisecond; ; wait = min(2*wait, time.Second) {
		err := call()
		var ae *apiError
		again := err != nil && !errors.As(err, &ae) // the network
		if ae != nil {
			switch ae.Body.Error.Code {
			case "busy", "unavailable", "too_many_requests", "part_in_progress", "parts_in_flight", "upload_completing", "part_aborted":
				again = true
				if s, err := strconv.Atoi(ae.RetryAfter); err == nil {
					wait = time.Duration(s) * time.Second
				}
			}
		}
		if !again || time.Now().After(deadline) {
			return err
		}
		time.Sleep(wait)
	}
}

// upload sends f as the browser does, resuming its own session if the
// server still has one, and returns what complete answered.
func (u *uploader) upload(f source) (transfer.Result, error) {
	c, err := u.create(f)
	if err != nil {
		return transfer.Result{}, err
	}
	if c.Resumed && len(c.Received) > 0 {
		probe := []int{c.Received[0][0], c.Received[len(c.Received)-1][1]}
		var st transfer.Status
		if err := u.call("/api/upload/status", httpapi.UploadStatusRequest{UploadID: c.UploadID, Hashes: probe}, &st); err != nil {
			return transfer.Result{}, err
		}
		for _, n := range probe {
			sum := digest(f.part(c, n))
			if h := st.Hashes[strconv.Itoa(n)]; h == nil || *h != hex.EncodeToString(sum[:]) {
				u.call("/api/upload/abort", httpapi.UploadAbortRequest{UploadID: c.UploadID}, nil)
				return u.upload(f)
			}
		}
	}
	received := func(n int) bool {
		for _, r := range c.Received {
			if n >= r[0] && n <= r[1] {
				return true
			}
		}
		return false
	}
	var todo []int
	for n := 1; n <= c.PartCount; n++ {
		if !received(n) {
			todo = append(todo, n)
		}
	}
	var mu sync.Mutex
	var firstErr error
	next := make(chan int)
	var wg sync.WaitGroup
	for range min(c.MaxParallel, max(len(todo), 1)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := range next {
				if err := retrying(func() error { return u.part(c.UploadID, n, f.part(c, n)) }); err != nil {
					mu.Lock()
					firstErr = cmpErr(firstErr, fmt.Errorf("part %d: %w", n, err))
					mu.Unlock()
				}
			}
		}()
	}
	for _, n := range todo {
		next <- n
	}
	close(next)
	wg.Wait()
	if firstErr != nil {
		return transfer.Result{}, firstErr
	}
	hashes := make([][sha256.Size]byte, c.PartCount)
	for n := 1; n <= c.PartCount; n++ {
		hashes[n-1] = digest(f.part(c, n))
	}
	var res transfer.Result
	err = retrying(func() error {
		return u.call("/api/upload/complete", httpapi.UploadCompleteRequest{UploadID: c.UploadID, CompositeSHA256: transfer.Composite(hashes)}, &res)
	})
	return res, err
}

func cmpErr(a, b error) error {
	if a != nil {
		return a
	}
	return b
}

func randomData(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// addUsers gives a server that hasn't started an admin, and the accounts
// users names as "name:role", and returns a session token of each of them.
func addUsers(t *testing.T, s *liveServer, users ...string) map[string]string {
	t.Helper()
	seedAdmin(t, s.statePath, s.root)
	tokens := map[string]string{}
	for _, u := range users {
		name, role, _ := strings.Cut(u, ":")
		cmd := exec.Command(binary(t), "users", "add", "-username", name, "-role", role, "-state", s.statePath, "-audit-log", s.auditPath)
		cmd.Env = isolatedEnv(t)
		cmd.Stdin = strings.NewReader(testPassword + "\n")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("users add %s: %v\n%s", name, err, out)
		}
		tokens[name] = mintSession(t, s.statePath, name)
	}
	return tokens
}

func (s *liveServer) restart(extraArgs ...string) {
	s.t.Helper()
	s.done = make(chan error, 1)
	s.client = nil
	s.start(extraArgs...)
}

// A server killed while a part is on its way loses only that part: after a
// restart the browser finds its session by the file's key, checks the parts
// the server kept, sends the rest, and the stored file is the source.
func TestE2EAnUploadResumesAfterTheServerIsKilled(t *testing.T) {
	s := newLiveServer(t)
	tokens := addUsers(t, s, "alice:contributor")
	s.start()
	alice := s.uploader(tokens["alice"])
	f := source{dir: "users/alice", name: "film.bin", data: randomData(t, 2*(8<<20)+12345), modified: time.Now()}

	c, err := alice.create(f)
	if err != nil || c.PartCount != 3 {
		t.Fatalf("create: %+v %v", c, err)
	}
	if err := alice.part(c.UploadID, 1, f.part(c, 1)); err != nil {
		t.Fatal(err)
	}

	// Part 2 stops halfway, and the server is killed while it waits.
	pr, pw := io.Pipe()
	t.Cleanup(func() { pw.CloseWithError(errors.New("the test ended")) })
	sent := make(chan error, 1)
	go func() {
		p2 := f.part(c, 2)
		sum := digest(p2)
		sent <- alice.send("POST", "/api/upload/part?id="+c.UploadID+"&n=2", "application/octet-stream", pr, int64(len(p2)),
			map[string]string{httpapi.PartChecksumHeader: hex.EncodeToString(sum[:])}, nil)
	}()
	go pw.Write(f.part(c, 2)[:4<<20])
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		var st transfer.Status
		if err := alice.call("/api/upload/status", httpapi.UploadStatusRequest{UploadID: c.UploadID}, &st); err == nil && slices.Equal(st.InFlight, []int{2}) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("part 2 never arrived")
		}
	}
	if err := s.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	s.wait()
	pw.CloseWithError(errors.New("the server is gone"))
	if err := within(t, "part 2", sent); err == nil {
		t.Fatal("part 2 was answered by a killed server")
	}
	staged := filepath.Join(s.root, ".gocalbox", "uploads", c.UploadID)
	if log, err := os.ReadFile(filepath.Join(staged, "parts.log")); err != nil || strings.Count(string(log), `"op":"part"`) != 1 {
		t.Fatalf("parts.log after the kill: %v\n%s", err, log)
	}

	s.restart()
	alice = s.uploader(tokens["alice"])
	again, err := alice.create(f)
	if err != nil || !again.Resumed || again.UploadID != c.UploadID || !slices.Equal(again.Received, []transfer.Range{{1, 1}}) {
		t.Fatalf("create after the restart: %+v %v\n%s", again, err, s.out)
	}
	res, err := alice.upload(f)
	if err != nil {
		t.Fatalf("resume: %v\n%s", err, s.out)
	}
	if res.Path != "users/alice/film.bin" || res.Size != int64(len(f.data)) {
		t.Errorf("result %+v", res)
	}
	stored, err := os.ReadFile(filepath.Join(s.root, "users", "alice", "film.bin"))
	if err != nil || !bytes.Equal(stored, f.data) {
		t.Fatalf("the stored file differs from the source (%d of %d bytes): %v", len(stored), len(f.data), err)
	}
	if _, err := os.Stat(filepath.Join(staged, "data")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the staged data is still there: %v", err)
	}
	if err := s.stop(syscall.SIGTERM); err != nil {
		t.Fatalf("exit: %v\n%s", err, s.out)
	}

	if out, code := runToCompletion(t, "-verify-audit="+s.auditPath); code != 0 {
		t.Fatalf("-verify-audit: %d\n%s", code, out)
	}
	var types []events.Type
	for _, ev := range auditEvents(t, s.auditPath) {
		if ev.Upload == nil {
			continue
		}
		types = append(types, ev.Type)
		if ev.Type == events.UploadCompleted && (ev.Upload.SHA256 != res.CompositeSHA256 || ev.Actor.Name != "alice" || ev.Resolved != res.Path) {
			t.Errorf("upload.completed %+v %+v", ev, ev.Upload)
		}
	}
	if want := []events.Type{events.UploadCreated, events.UploadCreated, events.UploadCreated, events.FileUploaded, events.UploadCompleted}; !slices.Equal(types, want) {
		t.Errorf("upload records %v, want %v", types, want)
	}
}

// Two users finishing an upload of one name into one folder both land, the
// second under a numbered name, each recorded as the uploader of their own.
func TestE2ETwoUsersUploadTheSameName(t *testing.T) {
	s := newLiveServer(t)
	tokens := addUsers(t, s, "alice:contributor", "bob:contributor")
	s.start()
	files := map[string]source{
		"alice": {dir: "public", name: "same.bin", data: randomData(t, 8<<20+100), modified: time.Now()},
		"bob":   {dir: "public", name: "same.bin", data: randomData(t, 3000), modified: time.Now()},
	}
	results := map[string]transfer.Result{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for user, f := range files {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := s.uploader(tokens[user]).upload(f)
			if err != nil {
				t.Errorf("%s: %v", user, err)
			}
			mu.Lock()
			results[user] = res
			mu.Unlock()
		}()
	}
	wg.Wait()
	paths := []string{results["alice"].Path, results["bob"].Path}
	slices.Sort(paths)
	if !slices.Equal(paths, []string{"public/same (1).bin", "public/same.bin"}) {
		t.Fatalf("paths %v", paths)
	}
	for user, f := range files {
		stored, err := os.ReadFile(filepath.Join(s.root, filepath.FromSlash(results[user].Path)))
		if err != nil || !bytes.Equal(stored, f.data) {
			t.Errorf("%s's file at %s differs: %v", user, results[user].Path, err)
		}
	}
	var listing []httpapi.ClientFileInfo
	req, _ := http.NewRequest("GET", s.url+"/api/files?path=public", nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: tokens["bob"]})
	resp, err := s.uploader(tokens["bob"]).c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	json.NewDecoder(resp.Body).Decode(&listing)
	resp.Body.Close()
	for _, en := range listing {
		owner := map[string]string{results["alice"].Name: "alice", results["bob"].Name: "bob"}[en.Name]
		if en.Uploader == nil || *en.Uploader != owner {
			t.Errorf("%s: uploader %v, want %s", en.Name, en.Uploader, owner)
		}
		if want := owner == "bob"; slices.Contains(en.Actions, "delete") != want {
			t.Errorf("%s: bob may %v", en.Name, en.Actions)
		}
	}
	if err := s.stop(syscall.SIGTERM); err != nil {
		t.Fatalf("exit: %v", err)
	}
	uploaded := map[string]string{}
	for _, ev := range auditEvents(t, s.auditPath) {
		if ev.Type == events.FileUploaded {
			uploaded[ev.Actor.Name] = ev.Resolved
		}
	}
	if uploaded["alice"] != results["alice"].Path || uploaded["bob"] != results["bob"].Path {
		t.Errorf("file.uploaded records %v", uploaded)
	}
}

// Every upload call needs a session, and an account whose rights are taken
// away reaches nothing through them but its own sessions' state.
func TestE2EUploadCallsRefuseWithoutRights(t *testing.T) {
	s := newLiveServer(t)
	tokens := addUsers(t, s, "alice:contributor", "bob:contributor")
	s.start()
	alice, bob := s.uploader(tokens["alice"]), s.uploader(tokens["bob"])
	open := source{dir: "public", name: "open.bin", data: []byte("open"), modified: time.Now()}
	ready := source{dir: "public", name: "ready.bin", data: []byte("ready"), modified: time.Now()}
	openC, err := alice.create(open)
	if err != nil {
		t.Fatal(err)
	}
	readyC, err := alice.create(ready)
	if err != nil {
		t.Fatal(err)
	}
	if err := alice.part(readyC.UploadID, 1, ready.data); err != nil {
		t.Fatal(err)
	}
	theirs := source{dir: "public", name: "theirs.bin", data: []byte("theirs"), modified: time.Now()}
	theirsC, err := bob.create(theirs)
	if err != nil {
		t.Fatal(err)
	}
	bob.part(theirsC.UploadID, 1, theirs.data)

	sum := digest([]byte("x"))
	calls := []struct {
		name, method, path, ctype, body string
		own                             bool
	}{
		{"create", "POST", "/api/upload/create", "application/json", `{"dir":"public","name":"new.bin","size":1}`, false},
		{"create at home", "POST", "/api/upload/create", "application/json", `{"dir":"users/alice","name":"new.bin","size":1}`, false},
		{"resume", "POST", "/api/upload/create", "application/json", fmt.Sprintf(`{"dir":"public","name":"open.bin","size":4,"clientKey":%q}`, open.key()), false},
		{"part", "POST", "/api/upload/part?id=" + openC.UploadID + "&n=1", "application/octet-stream", "x", false},
		{"bob's part", "POST", "/api/upload/part?id=" + theirsC.UploadID + "&n=1", "application/octet-stream", "x", false},
		{"complete", "POST", "/api/upload/complete", "application/json",
			fmt.Sprintf(`{"uploadId":%q,"compositeSha256":%q}`, readyC.UploadID, transfer.Composite([][32]byte{digest(ready.data)})), false},
		{"bob's status", "POST", "/api/upload/status", "application/json", fmt.Sprintf(`{"uploadId":%q}`, theirsC.UploadID), false},
		{"bob's abort", "POST", "/api/upload/abort", "application/json", fmt.Sprintf(`{"uploadId":%q}`, theirsC.UploadID), false},
		{"status", "POST", "/api/upload/status", "application/json", fmt.Sprintf(`{"uploadId":%q}`, openC.UploadID), true},
		{"list", "GET", "/api/upload/list?all=1", "", "", true},
		{"abort", "POST", "/api/upload/abort", "application/json", fmt.Sprintf(`{"uploadId":%q}`, openC.UploadID), true},
	}
	send := func(token string, c struct {
		name, method, path, ctype, body string
		own                             bool
	}) (int, string) {
		req, _ := http.NewRequest(c.method, s.url+c.path, strings.NewReader(c.body))
		if c.ctype != "" {
			req.Header.Set("Content-Type", c.ctype)
		}
		req.Header.Set(httpapi.PartChecksumHeader, hex.EncodeToString(sum[:]))
		if token != "" {
			req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: token})
		}
		_, client := trustClient(s.tlsConfig.RootCAs, true)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	for _, c := range calls {
		if code, body := send("", c); code != 401 || !strings.Contains(body, `"unauthenticated"`) {
			t.Errorf("%s without a session: %d %s", c.name, code, body)
		}
	}

	// The admin takes away alice's rights: no public folder, and her home
	// read-only.
	admin := s.browser()
	if code, body := s.call(admin, "POST", "/api/auth/login", fmt.Sprintf(`{"username":"admin","password":%q}`, testPassword)); code != 200 {
		t.Fatalf("login: %d %s", code, body)
	}
	_, body := s.call(admin, "GET", "/api/admin/bindings/list", "")
	var bindings []auth.BindingInfo
	json.Unmarshal([]byte(body), &bindings)
	for _, b := range bindings {
		if b.Folder == "public" {
			if code, body := s.call(admin, "POST", "/api/admin/bindings/delete", fmt.Sprintf(`{"id":%q}`, b.ID)); code != 200 && code != 204 {
				t.Fatalf("delete the public binding: %d %s", code, body)
			}
		}
	}
	_, body = s.call(admin, "GET", "/api/admin/users/list", "")
	var users []auth.UserInfo
	json.Unmarshal([]byte(body), &users)
	for _, u := range users {
		if u.Username == "alice" {
			if code, body := s.call(admin, "POST", "/api/admin/users/update", fmt.Sprintf(`{"id":%q,"role":"viewer"}`, u.ID)); code != 200 {
				t.Fatalf("demote alice: %d %s", code, body)
			}
		}
	}

	before := tree(t, s.root)
	for _, c := range calls {
		code, body := send(tokens["alice"], c)
		refused := code == 401 || code == 403 || code == 404 || code == 400 && strings.Contains(body, `"parent_not_found"`)
		if c.own {
			refused = code == 200
		}
		if !refused || strings.Contains(body, theirsC.UploadID) || strings.Contains(body, "theirs.bin") {
			t.Errorf("%s without rights: %d %s", c.name, code, body)
		}
	}
	if after := tree(t, s.root); !maps.Equal(before, after) {
		t.Errorf("the served folder changed from %v to %v", before, after)
	}
	if err := s.stop(syscall.SIGTERM); err != nil {
		t.Fatalf("exit: %v", err)
	}
	if rep, err := audit.Verify(s.auditPath); err != nil || rep.Records == 0 {
		t.Errorf("audit log: %+v %v", rep, err)
	}
}

// tree maps the files of the served folder, the server's own folder left
// out, to their content.
func tree(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		if rel == ".gocalbox" {
			return filepath.SkipDir
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

// A graceful shutdown lets a part on its way finish, and the next start
// still has it.
func TestE2EAShutdownLetsAPartOnItsWayFinish(t *testing.T) {
	s := newLiveServer(t)
	tokens := addUsers(t, s, "alice:contributor")
	s.start()
	alice := s.uploader(tokens["alice"])
	f := source{dir: "users/alice", name: "a.bin", data: randomData(t, 3<<20), modified: time.Now()}
	c, err := alice.create(f)
	if err != nil {
		t.Fatal(err)
	}
	pr, pw := io.Pipe()
	t.Cleanup(func() { pw.CloseWithError(errors.New("the test ended")) })
	sent := make(chan error, 1)
	go func() {
		sum := digest(f.data)
		sent <- alice.send("POST", "/api/upload/part?id="+c.UploadID+"&n=1", "application/octet-stream", pr, int64(len(f.data)),
			map[string]string{httpapi.PartChecksumHeader: hex.EncodeToString(sum[:])}, nil)
	}()
	go pw.Write(f.data[:1<<20])
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		var st transfer.Status
		if err := alice.call("/api/upload/status", httpapi.UploadStatusRequest{UploadID: c.UploadID}, &st); err == nil && slices.Equal(st.InFlight, []int{1}) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the part never arrived")
		}
	}
	exited := make(chan error, 1)
	go func() { exited <- s.stop(syscall.SIGTERM) }()
	for deadline := time.Now().Add(10 * time.Second); !strings.Contains(s.out.String(), "Shutting down"); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("no shutdown:\n%s", s.out)
		}
	}
	go func() { pw.Write(f.data[1<<20:]); pw.Close() }()
	if err := within(t, "the part on its way at shutdown", sent); err != nil {
		t.Errorf("the part on its way at shutdown: %v", err)
	}
	if err := within(t, "the shutdown", exited); err != nil {
		t.Fatalf("exit: %v\n%s", err, s.out)
	}
	if strings.Contains(s.out.String(), "SHUTDOWN:") {
		t.Errorf("the shutdown didn't finish in time:\n%s", s.out)
	}

	s.restart()
	alice = s.uploader(tokens["alice"])
	again, err := alice.create(f)
	if err != nil || !again.Resumed || !slices.Equal(again.Received, []transfer.Range{{1, 1}}) {
		t.Fatalf("after the restart: %+v %v", again, err)
	}
	if _, err := alice.upload(f); err != nil {
		t.Fatal(err)
	}
	if stored, err := os.ReadFile(filepath.Join(s.root, "users", "alice", "a.bin")); err != nil || !bytes.Equal(stored, f.data) {
		t.Errorf("the stored file differs: %v", err)
	}
	s.stop(syscall.SIGTERM)
}

func TestE2EUploadFlagsAreChecked(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	os.Mkdir(root, 0o755)
	for _, flag := range []string{"-upload-window-mb=0", "-upload-idle-ttl=0", "-upload-first-part-ttl=0", "-upload-max-age=-1s",
		"-upload-tombstone-ttl=0", "-upload-max-sessions=0", "-upload-max-sessions-total=0", "-upload-max-inflight=-1",
		"-max-upload-mb=-1", "-max-upload-mb=67108865"} {
		out, code := runToCompletion(t, flag, "-port=0", "-root="+root, "-audit-log="+filepath.Join(base, "a.jsonl"))
		name, _, _ := strings.Cut(flag, "=")
		if code == 0 || !strings.Contains(out, name+" must be") {
			t.Errorf("%s: exit %d\n%s", flag, code, out)
		}
		if _, err := os.Stat(filepath.Join(root, ".gocalbox")); err == nil {
			t.Errorf("%s: the refused start made the server's folder", flag)
		}
	}
}

// The upload flags reach the engine: each one shows in an answer.
func TestE2EUploadFlagsReachTheEngine(t *testing.T) {
	s := newLiveServer(t)
	tokens := addUsers(t, s, "alice:contributor")
	s.start("-upload-max-sessions=2", "-upload-max-sessions-total=1", "-upload-first-part-ttl=1h",
		"-upload-idle-ttl=2h", "-upload-max-age=150m", "-upload-tombstone-ttl=7h")
	alice := s.uploader(tokens["alice"])
	near := func(what string, got time.Time, want time.Duration) {
		t.Helper()
		if d := time.Until(got) - want; d < -5*time.Minute || d > 5*time.Minute {
			t.Errorf("%s: expires in %v, want about %v", what, time.Until(got).Round(time.Minute), want)
		}
	}
	status := func(id string) transfer.Status {
		t.Helper()
		var st transfer.Status
		if err := alice.call("/api/upload/status", httpapi.UploadStatusRequest{UploadID: id}, &st); err != nil {
			t.Fatal(err)
		}
		return st
	}
	f := source{dir: "users/alice", name: "a.bin", data: []byte("hello"), modified: time.Now()}
	c, err := alice.create(f)
	if err != nil {
		t.Fatal(err)
	}
	near("-upload-first-part-ttl", c.ExpiresAt, time.Hour)
	if _, err := alice.create(source{dir: "users/alice", name: "b.bin", data: []byte("x"), modified: time.Now()}); codeOf(err) != "busy" {
		t.Errorf("-upload-max-sessions-total=1 with -upload-max-sessions=2: %v", err)
	}
	if err := alice.part(c.UploadID, 1, f.data); err != nil {
		t.Fatal(err)
	}
	near("-upload-idle-ttl", status(c.UploadID).ExpiresAt, 2*time.Hour)
	if err := alice.call("/api/upload/abort", httpapi.UploadAbortRequest{UploadID: c.UploadID}, nil); err != nil {
		t.Fatal(err)
	}
	near("-upload-tombstone-ttl", status(c.UploadID).ExpiresAt, 7*time.Hour)
	if err := s.stop(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}

	// -upload-first-part-ttl above -upload-max-age tells the age from the
	// idle time at create.
	s.restart("-upload-first-part-ttl=3h", "-upload-idle-ttl=4h", "-upload-max-age=150m", "-upload-max-sessions=2", "-upload-max-inflight=1")
	alice = s.uploader(tokens["alice"])
	g := source{dir: "users/alice", name: "c.bin", data: randomData(t, 1000), modified: time.Now()}
	c, err = alice.create(g)
	if err != nil {
		t.Fatal(err)
	}
	near("-upload-max-age below -upload-first-part-ttl", c.ExpiresAt, 150*time.Minute)
	d, err := alice.create(source{dir: "users/alice", name: "d.bin", data: []byte("x"), modified: time.Now()})
	if err != nil {
		t.Errorf("a second upload with -upload-max-sessions=2: %v", err)
	}
	if _, err := alice.create(source{dir: "users/alice", name: "e.bin", data: []byte("x"), modified: time.Now()}); codeOf(err) != "too_many_uploads" {
		t.Errorf("a third upload with -upload-max-sessions=2: %v", err)
	}
	if err := alice.part(c.UploadID, 1, g.data); err != nil {
		t.Fatal(err)
	}
	near("-upload-max-age below -upload-idle-ttl", status(c.UploadID).ExpiresAt, 150*time.Minute)

	// With one part in flight on the server, a second one is refused.
	bob := addUsersLater(t, s, "bob")
	h := source{dir: "users/bob", name: "e.bin", data: randomData(t, 1000), modified: time.Now()}
	hc, err := bob.create(h)
	if err != nil {
		t.Fatal(err)
	}
	pr, pw := io.Pipe()
	t.Cleanup(func() { pw.CloseWithError(errors.New("the test ended")) })
	sent := make(chan error, 1)
	go func() {
		sum := digest(h.data)
		sent <- bob.send("POST", "/api/upload/part?id="+hc.UploadID+"&n=1", "application/octet-stream", pr, int64(len(h.data)),
			map[string]string{httpapi.PartChecksumHeader: hex.EncodeToString(sum[:])}, nil)
	}()
	go pw.Write(h.data[:1])
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		var st transfer.Status
		if err := bob.call("/api/upload/status", httpapi.UploadStatusRequest{UploadID: hc.UploadID}, &st); err == nil && slices.Equal(st.InFlight, []int{1}) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("bob's part never arrived")
		}
	}
	if err := alice.call("/api/upload/abort", httpapi.UploadAbortRequest{UploadID: c.UploadID}, nil); err != nil {
		t.Fatal(err)
	}
	k := source{dir: "users/alice", name: "f.bin", data: g.data, modified: g.modified}
	kc, err := alice.create(k)
	if err != nil {
		t.Fatal(err)
	}
	// The one slot is taken: alice's part waits for it, and the queue, as
	// long as the slots, is then full.
	waiting := make(chan error, 1)
	go func() { waiting <- alice.part(kc.UploadID, 1, k.data) }()
	time.Sleep(500 * time.Millisecond)
	if err := alice.part(d.UploadID, 1, []byte("x")); codeOf(err) != "busy" {
		t.Errorf("-upload-max-inflight=1 with a part on its way and one waiting: %v", err)
	}
	go func() { pw.Write(h.data[1:]); pw.Close() }()
	if err := within(t, "bob's part", sent); err != nil {
		t.Errorf("bob's part: %v", err)
	}
	if err := within(t, "alice's waiting part", waiting); err != nil {
		t.Errorf("alice's part, once bob's ended: %v", err)
	}
	s.stop(syscall.SIGTERM)
}

// A part waiting for a slot when the server is told to stop is answered at
// once, while the part in flight finishes.
func TestE2EShutdownAnswersAWaitingPart(t *testing.T) {
	s := startServer(t, "-upload-max-inflight=1")
	bob := addUsersLater(t, s, "bob")
	alice := addUsersLater(t, s, "alice")
	h := source{dir: "users/bob", name: "h.bin", data: randomData(t, 1000), modified: time.Now()}
	hc, err := bob.create(h)
	if err != nil {
		t.Fatal(err)
	}
	pr, pw := io.Pipe()
	t.Cleanup(func() { pw.CloseWithError(errors.New("the test ended")) })
	held := make(chan error, 1)
	go func() {
		sum := digest(h.data)
		held <- bob.send("POST", "/api/upload/part?id="+hc.UploadID+"&n=1", "application/octet-stream", pr, int64(len(h.data)),
			map[string]string{httpapi.PartChecksumHeader: hex.EncodeToString(sum[:])}, nil)
	}()
	go pw.Write(h.data[:1])
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		var st transfer.Status
		if err := bob.call("/api/upload/status", httpapi.UploadStatusRequest{UploadID: hc.UploadID}, &st); err == nil && slices.Equal(st.InFlight, []int{1}) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("bob's part never arrived")
		}
	}
	a := source{dir: "users/alice", name: "a.bin", data: randomData(t, 1000), modified: time.Now()}
	ac, err := alice.create(a)
	if err != nil {
		t.Fatal(err)
	}
	waiting := make(chan error, 1)
	go func() { waiting <- alice.part(ac.UploadID, 1, a.data) }()
	time.Sleep(500 * time.Millisecond)

	exited := make(chan error, 1)
	start := time.Now()
	go func() { exited <- s.stop(syscall.SIGTERM) }()
	if err := within(t, "alice's waiting part", waiting); codeOf(err) != "unavailable" {
		t.Errorf("a part waiting at shutdown: %v\n%s", err, s.out)
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Errorf("the waiting part was answered %v after the signal", took)
	}
	go func() { pw.Write(h.data[1:]); pw.Close() }()
	if err := within(t, "bob's part", held); err != nil {
		t.Errorf("the part in flight at shutdown: %v\n%s", err, s.out)
	}
	if err := within(t, "the server's exit", exited); err != nil {
		t.Errorf("exit: %v\n%s", err, s.out)
	}
}

// addUsersLater adds a contributor to a running server through the admin
// API, and returns their uploader.
func addUsersLater(t *testing.T, s *liveServer, name string) *uploader {
	t.Helper()
	admin := s.browser()
	if code, body := s.call(admin, "POST", "/api/auth/login", fmt.Sprintf(`{"username":"admin","password":%q}`, testPassword)); code != 200 {
		t.Fatalf("login: %d %s", code, body)
	}
	code, body := s.call(admin, "POST", "/api/admin/invites/create", fmt.Sprintf(`{"role":"contributor","username":%q}`, name))
	if code != 201 {
		t.Fatalf("invite: %d %s", code, body)
	}
	c := s.browser()
	if code, body := s.call(c, "POST", "/api/invite/accept", fmt.Sprintf(`{"token":%q,"username":%q,"password":%q}`, tokenOf(t, body), name, testPassword)); code != 201 {
		t.Fatalf("accept: %d %s", code, body)
	}
	return s.uploader(sessionToken(t, s, c))
}

// logIn logs name in with their password, and returns their uploader.
func logIn(t *testing.T, s *liveServer, name string) *uploader {
	t.Helper()
	c := s.browser()
	if code, body := s.call(c, "POST", "/api/auth/login", fmt.Sprintf(`{"username":%q,"password":%q}`, name, testPassword)); code != 200 {
		t.Fatalf("login of %s: %d %s", name, code, body)
	}
	return s.uploader(sessionToken(t, s, c))
}

func sessionToken(t *testing.T, s *liveServer, c *http.Client) string {
	t.Helper()
	u, _ := url.Parse(s.url)
	for _, ck := range c.Jar.Cookies(u) {
		if ck.Name == auth.SessionCookie {
			return ck.Value
		}
	}
	t.Fatal("no session cookie")
	return ""
}

// An upload outlives the login that started it: once the login has
// expired, the user logs in again and resumes where it stopped.
func TestE2EAnUploadResumesAfterTheLoginExpired(t *testing.T) {
	s := newLiveServer(t)
	addUsers(t, s, "alice:contributor")
	s.start("-session-idle=3s")
	alice := logIn(t, s, "alice")
	f := source{dir: "users/alice", name: "a.bin", data: randomData(t, 8<<20+100), modified: time.Now()}
	c, err := alice.create(f)
	if err != nil || c.PartCount != 2 {
		t.Fatalf("create: %+v %v", c, err)
	}
	if err := alice.part(c.UploadID, 1, f.part(c, 1)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(4 * time.Second)
	if err := alice.part(c.UploadID, 2, f.part(c, 2)); codeOf(err) != "unauthenticated" {
		t.Fatalf("a part after the login expired: %v", err)
	}
	alice = logIn(t, s, "alice")
	again, err := alice.create(f)
	if err != nil || !again.Resumed || again.UploadID != c.UploadID || !slices.Equal(again.Received, []transfer.Range{{1, 1}}) {
		t.Fatalf("create after logging in again: %+v %v", again, err)
	}
	res, err := alice.upload(f)
	if err != nil || res.Path != "users/alice/a.bin" {
		t.Fatalf("resume: %+v %v", res, err)
	}
	if stored, err := os.ReadFile(filepath.Join(s.root, "users", "alice", "a.bin")); err != nil || !bytes.Equal(stored, f.data) {
		t.Errorf("the stored file differs from the source (%d of %d bytes): %v", len(stored), len(f.data), err)
	}
	if err := s.stop(syscall.SIGTERM); err != nil {
		t.Fatalf("exit: %v", err)
	}
}

// A file of 5 GiB, past every 32-bit offset, is stored byte for byte. It
// writes 5 GiB to the disk of TMPDIR, so it runs only when asked for.
func TestE2EAFiveGiBUpload(t *testing.T) {
	if os.Getenv("GOCALBOX_E2E_LARGE") == "" {
		t.Skip("set GOCALBOX_E2E_LARGE=1 to upload 5 GiB")
	}
	s := newLiveServer(t)
	tokens := addUsers(t, s, "alice:contributor")
	s.start()
	alice := s.uploader(tokens["alice"])
	const size = 5<<30 + 12345
	var c transfer.Created
	if err := alice.call("/api/upload/create", transfer.CreateRequest{Dir: "users/alice", Name: "big.bin", Size: size}, &c); err != nil {
		t.Fatal(err)
	}
	// Each part is mostly zeros, as a sparse file reads, marked with its
	// number at both ends.
	part := func(n int) []byte {
		b := make([]byte, min(c.PartSize, size-int64(n-1)*c.PartSize))
		be.BigEndian.PutUint64(b, uint64(n))
		be.BigEndian.PutUint64(b[len(b)-8:], uint64(n))
		return b
	}
	hashes := make([][sha256.Size]byte, c.PartCount)
	next := make(chan int)
	errs := make(chan error, c.MaxParallel)
	for range c.MaxParallel {
		go func() {
			var err error
			for n := range next {
				b := part(n)
				hashes[n-1] = digest(b)
				if err == nil {
					err = retrying(func() error { return alice.part(c.UploadID, n, b) })
				}
			}
			errs <- err
		}()
	}
	for n := 1; n <= c.PartCount; n++ {
		next <- n
	}
	close(next)
	for range c.MaxParallel {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	var res transfer.Result
	if err := alice.call("/api/upload/complete", httpapi.UploadCompleteRequest{UploadID: c.UploadID, CompositeSHA256: transfer.Composite(hashes)}, &res); err != nil {
		t.Fatal(err)
	}
	if res.Size != size || res.CompositeSHA256 != transfer.Composite(hashes) {
		t.Errorf("result %+v", res)
	}
	stored, err := os.Open(filepath.Join(s.root, "users", "alice", "big.bin"))
	if err != nil {
		t.Fatal(err)
	}
	defer stored.Close()
	got := make([][sha256.Size]byte, c.PartCount)
	buf := make([]byte, c.PartSize)
	for n := 1; n <= c.PartCount; n++ {
		k, err := io.ReadFull(stored, buf)
		if err != nil && !(n == c.PartCount && errors.Is(err, io.ErrUnexpectedEOF)) {
			t.Fatalf("part %d of the stored file: %v", n, err)
		}
		got[n-1] = digest(buf[:k])
	}
	if transfer.Composite(got) != res.CompositeSHA256 {
		t.Error("the stored file isn't the one sent")
	}
	if err := s.stop(syscall.SIGTERM); err != nil {
		t.Fatalf("exit: %v", err)
	}
}

// -h shows each upload flag with its default.
func TestE2EUploadFlagDefaults(t *testing.T) {
	out, _ := runToCompletion(t, "-h")
	for flag, def := range map[string]string{
		"upload-window-mb": "1024", "upload-idle-ttl": "24h0m0s", "upload-first-part-ttl": "1h0m0s",
		"upload-max-age": "168h0m0s", "upload-tombstone-ttl": "24h0m0s", "upload-max-sessions": "16",
		"upload-max-sessions-total": "256", "upload-max-inflight": "32",
	} {
		i := strings.Index(out, "  -"+flag+" ")
		if i < 0 {
			t.Errorf("-%s is missing from the usage", flag)
			continue
		}
		usage, _, _ := strings.Cut(out[i+3:], "\n  -")
		if !strings.Contains(usage, "(default "+def+")") {
			t.Errorf("-%s: %q, want the default %s", flag, usage, def)
		}
	}
	i := strings.Index(out, "  -max-upload-mb ")
	if usage, _, _ := strings.Cut(out[max(i, 0)+3:], "\n  -"); i < 0 || !strings.Contains(usage, "from 0 to 67108864") {
		t.Errorf("-max-upload-mb's usage doesn't give its range: %q", usage)
	}
}

// within returns what ch gives, and fails the test if it gives nothing
// for 30 seconds.
func within[T any](t *testing.T, what string, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(30 * time.Second):
		t.Fatalf("%s: nothing after 30 seconds", what)
		panic("unreachable")
	}
}

// A part whose body stalls past -body-timeout is answered part_aborted over
// HTTP/2 and HTTP/1.1, and can be sent again.
func TestE2EAStalledPartIsAnsweredPartAborted(t *testing.T) {
	s := newLiveServer(t)
	tokens := addUsers(t, s, "alice:contributor")
	s.start("-body-timeout=1s")
	for _, h2 := range []bool{true, false} {
		alice := s.uploader(tokens["alice"])
		_, alice.c = trustClient(s.tlsConfig.RootCAs, h2)
		if proto := protoOf(t, s, alice); proto != map[bool]int{true: 2, false: 1}[h2] {
			t.Fatalf("HTTP/2 %v: the client speaks HTTP/%d", h2, proto)
		}
		f := source{dir: "users/alice", name: fmt.Sprintf("h2-%v.bin", h2), data: randomData(t, 1<<20), modified: time.Now()}
		c, err := alice.create(f)
		if err != nil {
			t.Fatal(err)
		}
		pr, pw := io.Pipe()
		t.Cleanup(func() { pw.CloseWithError(errors.New("the test ended")) })
		go pw.Write(f.data[:100])
		sum := digest(f.data)
		err = alice.send("POST", "/api/upload/part?id="+c.UploadID+"&n=1", "application/octet-stream", pr, int64(len(f.data)),
			map[string]string{httpapi.PartChecksumHeader: hex.EncodeToString(sum[:])}, nil)
		if codeOf(err) != "part_aborted" {
			t.Errorf("HTTP/2 %v: a stalled part: %v", h2, err)
		}
		if err := alice.part(c.UploadID, 1, f.data); err != nil {
			t.Errorf("HTTP/2 %v: the part sent again: %v", h2, err)
		}
	}
	if err := s.stop(syscall.SIGTERM); err != nil {
		t.Fatalf("exit: %v", err)
	}
}

// protoOf is the major version of HTTP that u's client speaks with s.
func protoOf(t *testing.T, s *liveServer, u *uploader) int {
	t.Helper()
	req, _ := http.NewRequest("GET", s.url+"/api/upload/list", nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: u.token})
	resp, err := u.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.ProtoMajor
}

// Over HTTP/2, a part refused before its body is read ends only its own
// stream: the next request goes on the same connection.
func TestE2EARefusedPartLeavesAnHTTP2ConnectionInUse(t *testing.T) {
	s := newLiveServer(t)
	tokens := addUsers(t, s, "alice:contributor")
	s.start()
	alice := s.uploader(tokens["alice"])
	if proto := protoOf(t, s, alice); proto != 2 {
		t.Fatalf("the client speaks HTTP/%d", proto)
	}
	big := make([]byte, 8<<20)
	sum := digest(big)
	var reused bool
	req, _ := http.NewRequest("POST", s.url+"/api/upload/part?id="+strings.Repeat("0", 32)+"&n=1", bytes.NewReader(big))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set(httpapi.PartChecksumHeader, hex.EncodeToString(sum[:]))
	req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: alice.token})
	resp, err := alice.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("a part of an unknown upload: %d", resp.StatusCode)
	}
	next, _ := http.NewRequest("GET", s.url+"/api/upload/list", nil)
	next = next.WithContext(httptrace.WithClientTrace(next.Context(), &httptrace.ClientTrace{
		GotConn: func(i httptrace.GotConnInfo) { reused = i.Reused },
	}))
	next.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: alice.token})
	resp, err = alice.c.Do(next)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !reused {
		t.Errorf("the next request: %d, on the same connection %v", resp.StatusCode, reused)
	}
	if err := s.stop(syscall.SIGTERM); err != nil {
		t.Fatalf("exit: %v", err)
	}
}

// -max-upload-mb bounds a resumable upload to the byte.
func TestE2EMaxUploadMBBoundsResumableUploads(t *testing.T) {
	s := newLiveServer(t)
	tokens := addUsers(t, s, "alice:contributor")
	s.start("-max-upload-mb=1")
	alice := s.uploader(tokens["alice"])
	var c transfer.Created
	if err := alice.call("/api/upload/create", transfer.CreateRequest{Dir: "users/alice", Name: "a.bin", Size: 1 << 20}, &c); err != nil {
		t.Errorf("1 MiB: %v", err)
	}
	err := alice.call("/api/upload/create", transfer.CreateRequest{Dir: "users/alice", Name: "b.bin", Size: 1<<20 + 1}, &c)
	if codeOf(err) != "too_large" {
		t.Errorf("1 MiB and a byte: %v", err)
	}
	if err := s.stop(syscall.SIGTERM); err != nil {
		t.Fatalf("exit: %v", err)
	}
}

func TestE2EHelpSaysPartsMayWaitForASlot(t *testing.T) {
	out, _ := runToCompletion(t, "-h")
	if !strings.Contains(out, "as many more may wait up to 10s for a slot") {
		t.Errorf("-h doesn't say that parts may wait for a slot:\n%s", out)
	}
}
