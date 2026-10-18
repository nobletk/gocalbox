package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/nobletk/gocalbox/internal/auth"
	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/fsops"
	"github.com/nobletk/gocalbox/internal/sandbox"
	"github.com/nobletk/gocalbox/internal/state"
	"github.com/nobletk/gocalbox/internal/transfer"
	"github.com/nobletk/gocalbox/internal/transfer/registry"
)

var _ UploadService = (*transfer.Engine)(nil)

func (r *recorder) TryPublish(ev events.Event) bool {
	r.Publish(ev)
	return true
}

// testAuditor applies policies C and D with answers the test sets.
type testAuditor struct {
	mu     sync.Mutex
	paused error
	recErr error
	pub    *recorder
}

func (a *testAuditor) set(paused, recErr error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.paused, a.recErr = paused, recErr
}

func (a *testAuditor) Allow() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.paused != nil {
		return fmt.Errorf("%w: %v", events.ErrChangesPaused, a.paused)
	}
	return nil
}

func (a *testAuditor) Record(_ context.Context, evs ...events.Event) error {
	for _, ev := range evs {
		a.pub.Publish(ev)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.recErr
}

func (a *testAuditor) RecordProtective(ctx context.Context, evs ...events.Event) error {
	return a.Record(ctx, evs...)
}

// uploadEnv serves real accounts, fsops and the upload engine over HTTPS,
// with root an admin and alice and bob contributors, each logged in.
type uploadEnv struct {
	*authEnv
	eng     *transfer.Engine
	files   *fsops.Service
	staging *sandbox.Staging
	auditor *testAuditor
	users   map[string]*http.Client
	ids     map[string]string
}

func newUploadEnv(t *testing.T, mods ...func(*transfer.Config)) *uploadEnv {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "root")
	os.Mkdir(root, 0o755)
	sb, err := sandbox.New(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sb.Close() })
	st, err := sandbox.CheckStaging(sb.OSRoot())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	db, err := state.Open(filepath.Join(base, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	rec := &recorder{}
	auditor := &testAuditor{pub: rec}
	files := fsops.New(sb, rec, fsops.WithRecords(db), fsops.WithStaging(st), fsops.WithAudit(auditor))
	acc := auth.New(auth.Config{
		DB: db, Hasher: auth.NewHasher(auth.Params{Memory: 64, Time: 1, Threads: 1}, 2, time.Second),
		Policy: auth.Policy{MinLength: 15}, Folders: files, Events: rec,
		FailureDelay: func(int) time.Duration { return 0 },
	})
	if err := acc.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { acc.Close() })
	files.SetPolicy(acc)
	cfg := transfer.Config{Root: sb.OSRoot(), Staging: st, Files: files, Registry: registry.New(db), Events: rec,
		Audit: auditor, JanitorEvery: -1}
	for _, m := range mods {
		m(&cfg)
	}
	eng, err := transfer.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { eng.Close(context.Background()) })
	srv := httptest.NewTLSServer(New(files, fstest.MapFS{"index.html": {Data: []byte("<html></html>")}},
		Options{Accounts: acc, Uploads: eng}))
	t.Cleanup(srv.Close)

	e := &uploadEnv{
		authEnv: &authEnv{t: t, srv: srv, acc: acc, rec: rec, root: sb.Root()},
		eng:     eng, files: files, staging: st, auditor: auditor,
		users: map[string]*http.Client{}, ids: map[string]string{},
	}
	for _, u := range []struct {
		name string
		role state.Role
	}{{"root", state.RoleAdmin}, {"alice", state.RoleContributor}, {"bob", state.RoleContributor}} {
		created, err := acc.CreateUser(events.WithActor(context.Background(), events.Actor{ID: events.ConsoleID}), u.name, u.role, passphrase)
		if err != nil {
			t.Fatal(err)
		}
		e.ids[u.name] = created.ID
	}
	if warnings := acc.EnsureLayout(context.Background()); len(warnings) > 0 {
		t.Fatal(warnings)
	}
	for _, name := range []string{"root", "alice", "bob"} {
		e.users[name] = e.browser()
		e.login(e.users[name], name)
	}
	return e
}

// payload is a file of size bytes, cut into parts as the server says.
type payload struct {
	data     []byte
	partSize int64
}

func newPayload(size int, seed byte) payload {
	b := make([]byte, size)
	for i := range b {
		b[i] = byte(i%251) ^ seed
	}
	return payload{data: b, partSize: transfer.PartSize(int64(size))}
}

func (p payload) parts() int { return transfer.PartCount(int64(len(p.data)), p.partSize) }

func (p payload) part(n int) []byte {
	off := int64(n-1) * p.partSize
	return p.data[off:min(off+p.partSize, int64(len(p.data)))]
}

func (p payload) sum(n int) string {
	h := sha256.Sum256(p.part(n))
	return hex.EncodeToString(h[:])
}

func (p payload) composite() string {
	var hs [][sha256.Size]byte
	for n := 1; n <= p.parts(); n++ {
		hs = append(hs, sha256.Sum256(p.part(n)))
	}
	return transfer.Composite(hs)
}

// as sends a call of user, with body as JSON unless it is nil.
func (e *uploadEnv) as(user, method, path string, body any) (*http.Response, string) {
	e.t.Helper()
	return e.call(e.users[user], method, path, body)
}

func (e *uploadEnv) create(user, dir, name string, p payload, key string) transfer.Created {
	e.t.Helper()
	resp, body := e.as(user, "POST", "/api/upload/create", transfer.CreateRequest{Dir: dir, Name: name, Size: int64(len(p.data)), ClientKey: key})
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		e.t.Fatalf("%s creates %s/%s: %d %s", user, dir, name, resp.StatusCode, body)
	}
	var c transfer.Created
	if err := json.Unmarshal([]byte(body), &c); err != nil {
		e.t.Fatal(err)
	}
	return c
}

// sendPart sends part n of p; sum and length replace the right ones when
// set, and ctype the content type.
func (e *uploadEnv) sendPart(user, id string, n int, body io.Reader, sum string, length int64, ctype string) (*http.Response, string) {
	e.t.Helper()
	req, err := http.NewRequest("POST", e.srv.URL+"/api/upload/part?id="+id+"&n="+strconv.Itoa(n), body)
	if err != nil {
		e.t.Fatal(err)
	}
	req.ContentLength = length
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	if sum != "" {
		req.Header.Set(PartChecksumHeader, sum)
	}
	resp, err := e.users[user].Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func (e *uploadEnv) part(user, id string, p payload, n int) (*http.Response, string) {
	e.t.Helper()
	b := p.part(n)
	return e.sendPart(user, id, n, bytes.NewReader(b), p.sum(n), int64(len(b)), "application/octet-stream")
}

func (e *uploadEnv) sendAll(user, id string, p payload) {
	e.t.Helper()
	for n := 1; n <= p.parts(); n++ {
		if resp, body := e.part(user, id, p, n); resp.StatusCode != http.StatusOK {
			e.t.Fatalf("part %d: %d %s", n, resp.StatusCode, body)
		}
	}
}

func (e *uploadEnv) complete(user, id, composite string) (*http.Response, string) {
	e.t.Helper()
	return e.as(user, "POST", "/api/upload/complete", UploadCompleteRequest{UploadID: id, CompositeSHA256: composite})
}

func decodeAs[T any](t *testing.T, body string) T {
	t.Helper()
	var v T
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		t.Fatalf("%s: %v", body, err)
	}
	return v
}

func TestAnUploadOverHTTPFromCreateToComplete(t *testing.T) {
	e := newUploadEnv(t)
	p := newPayload(8<<20+100, 1)
	c := e.create("alice", "public", "big.bin", p, "key-1")
	if c.PartCount != 2 || c.PartSize != 8<<20 || c.Resumed || len(c.Received) != 0 || c.MaxParallel != 4 {
		t.Fatalf("created %+v", c)
	}

	resp, body := e.part("alice", c.UploadID, p, 2)
	got := decodeAs[transfer.PartResult](t, body)
	if resp.StatusCode != 200 || got != (transfer.PartResult{Part: 2, Size: 100, SHA256: p.sum(2), Received: 1, PartCount: 2}) {
		t.Fatalf("part 2: %d %s", resp.StatusCode, body)
	}
	if resp, body := e.part("alice", c.UploadID, p, 2); resp.StatusCode != 200 || !decodeAs[transfer.PartResult](t, body).Duplicate {
		t.Errorf("part 2 again: %d %s", resp.StatusCode, body)
	}

	// A reload finds the session by its key, with what it received.
	resp, body = e.as("alice", "POST", "/api/upload/create", transfer.CreateRequest{Dir: "public", Name: "big.bin", Size: int64(len(p.data)), ClientKey: "key-1"})
	again := decodeAs[transfer.Created](t, body)
	if resp.StatusCode != http.StatusOK || !again.Resumed || again.UploadID != c.UploadID || !slices.Equal(again.Received, []transfer.Range{{2, 2}}) {
		t.Fatalf("resumed: %d %s", resp.StatusCode, body)
	}
	resp, body = e.as("alice", "POST", "/api/upload/status", UploadStatusRequest{UploadID: c.UploadID, Hashes: []int{1, 2}})
	st := decodeAs[map[string]any](t, body)
	if resp.StatusCode != 200 || st["state"] != "receiving" || st["hashes"].(map[string]any)["2"] != p.sum(2) ||
		st["hashes"].(map[string]any)["1"] != nil || st["owner"] != nil {
		t.Errorf("status: %d %s", resp.StatusCode, body)
	}

	e.sendAll("alice", c.UploadID, p)
	resp, body = e.complete("alice", c.UploadID, p.composite())
	want := transfer.Result{Path: "public/big.bin", Name: "big.bin", Size: int64(len(p.data)), CompositeSHA256: p.composite()}
	if resp.StatusCode != http.StatusCreated || decodeAs[transfer.Result](t, body) != want {
		t.Fatalf("complete: %d %s", resp.StatusCode, body)
	}
	if b, err := os.ReadFile(filepath.Join(e.root, "public", "big.bin")); err != nil || !bytes.Equal(b, p.data) {
		t.Fatalf("the stored file differs: %v", err)
	}
	// A client that lost the answer asks again.
	if resp, body := e.complete("alice", c.UploadID, p.composite()); resp.StatusCode != http.StatusCreated || decodeAs[transfer.Result](t, body) != want {
		t.Errorf("complete again: %d %s", resp.StatusCode, body)
	}
	resp, body = e.as("alice", "GET", "/api/upload/list", nil)
	list := decodeAs[UploadListResponse](t, body)
	if resp.StatusCode != 200 || len(list.Uploads) != 1 || list.Uploads[0].State != transfer.Completed || *list.Uploads[0].Result != want {
		t.Errorf("list: %d %s", resp.StatusCode, body)
	}
	resp, body = e.as("alice", "GET", "/api/files?path=public", nil)
	if resp.StatusCode != 200 || !strings.Contains(body, `"uploader":"alice"`) {
		t.Errorf("the listing doesn't name alice as the uploader: %s", body)
	}
}

func TestAnEmptyFileTakesNoParts(t *testing.T) {
	e := newUploadEnv(t)
	c := e.create("alice", "users/alice", "empty.txt", payload{partSize: 8 << 20}, "")
	if c.PartCount != 0 {
		t.Fatalf("created %+v", c)
	}
	if resp, body := e.complete("alice", c.UploadID, transfer.Composite(nil)); resp.StatusCode != http.StatusCreated {
		t.Fatalf("complete: %d %s", resp.StatusCode, body)
	}
	if info, err := os.Stat(filepath.Join(e.root, "users", "alice", "empty.txt")); err != nil || info.Size() != 0 {
		t.Errorf("%v %v", info, err)
	}
}

func errorBody(t *testing.T, body string) (code string, extra map[string]any) {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("%s: %v", body, err)
	}
	e, _ := m["error"].(map[string]any)
	code, _ = e["code"].(string)
	return code, m
}

func TestUploadRefusalsCarryTheirStatusAndCode(t *testing.T) {
	e := newUploadEnv(t, func(c *transfer.Config) { c.Limits.MaxSize = 20 << 20 })
	p := newPayload(8<<20+10, 2)
	c := e.create("alice", "public", "a.bin", p, "")
	e.part("alice", c.UploadID, p, 1)
	one := newPayload(10, 3)
	done := e.create("alice", "public", "done.bin", one, "")
	e.sendAll("alice", done.UploadID, one)
	if resp, body := e.complete("alice", done.UploadID, one.composite()); resp.StatusCode != 201 {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	other := sha256.Sum256([]byte("other"))
	otherSum := hex.EncodeToString(other[:])
	octet := "application/octet-stream"

	for _, tc := range []struct {
		name   string
		do     func() (*http.Response, string)
		status int
		code   string
	}{
		{"negative size", func() (*http.Response, string) {
			return e.as("alice", "POST", "/api/upload/create", transfer.CreateRequest{Dir: "public", Name: "x", Size: -1})
		}, 400, "invalid_body"},
		{"unknown field", func() (*http.Response, string) {
			return e.as("alice", "POST", "/api/upload/create", map[string]any{"dir": "public", "name": "x", "size": 1, "owner": "bob"})
		}, 400, "invalid_body"},
		{"a size above -max-upload-mb", func() (*http.Response, string) {
			return e.as("alice", "POST", "/api/upload/create", transfer.CreateRequest{Dir: "public", Name: "x", Size: 20<<20 + 1})
		}, 413, "too_large"},
		{"a size above 64 TiB", func() (*http.Response, string) {
			return e.as("alice", "POST", "/api/upload/create", transfer.CreateRequest{Dir: "public", Name: "x", Size: 1<<46 + 1})
		}, 413, "too_large"},
		{"a folder that doesn't exist", func() (*http.Response, string) {
			return e.as("alice", "POST", "/api/upload/create", transfer.CreateRequest{Dir: "nowhere", Name: "x", Size: 1})
		}, 400, "parent_not_found"},
		{"another user's home", func() (*http.Response, string) {
			return e.as("alice", "POST", "/api/upload/create", transfer.CreateRequest{Dir: "users/bob", Name: "x", Size: 1})
		}, 400, "parent_not_found"},
		{"a folder alice may only see", func() (*http.Response, string) {
			return e.as("alice", "POST", "/api/upload/create", transfer.CreateRequest{Dir: "users", Name: "x", Size: 1})
		}, 403, "forbidden"},
		{"the reserved name", func() (*http.Response, string) {
			return e.as("alice", "POST", "/api/upload/create", transfer.CreateRequest{Dir: "public", Name: ".gocalbox", Size: 1})
		}, 403, "reserved_path"},
		{"an invalid name", func() (*http.Response, string) {
			return e.as("alice", "POST", "/api/upload/create", transfer.CreateRequest{Dir: "public", Name: "a/b", Size: 1})
		}, 400, "invalid_name"},
		{"a path outside the root", func() (*http.Response, string) {
			return e.as("alice", "POST", "/api/upload/create", transfer.CreateRequest{Dir: "../x", Name: "a", Size: 1})
		}, 403, "path_outside_root"},
		{"create as GET", func() (*http.Response, string) { return e.as("alice", "GET", "/api/upload/create", nil) }, 405, "method_not_allowed"},
		{"create as text", func() (*http.Response, string) {
			return e.call(e.users["alice"], "POST", "/api/upload/create", nil, "Content-Type", "text/plain")
		}, 415, "unsupported_media_type"},

		{"a malformed ID", func() (*http.Response, string) {
			return e.sendPart("alice", "../../x", 1, strings.NewReader("x"), p.sum(1), 1, octet)
		}, 400, "invalid_part"},
		{"an ID in upper case", func() (*http.Response, string) {
			return e.sendPart("alice", strings.ToUpper(c.UploadID), 2, bytes.NewReader(p.part(2)), p.sum(2), 10, octet)
		}, 400, "invalid_part"},
		{"a number that isn't one", func() (*http.Response, string) {
			req, _ := http.NewRequest("POST", e.srv.URL+"/api/upload/part?id="+c.UploadID+"&n=one", strings.NewReader("x"))
			req.Header.Set("Content-Type", octet)
			req.Header.Set(PartChecksumHeader, p.sum(1))
			resp, err := e.users["alice"].Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			return resp, string(b)
		}, 400, "invalid_part"},
		{"a part out of range", func() (*http.Response, string) {
			return e.sendPart("alice", c.UploadID, 3, strings.NewReader("x"), p.sum(1), 1, octet)
		}, 400, "invalid_part"},
		{"no checksum", func() (*http.Response, string) {
			return e.sendPart("alice", c.UploadID, 2, bytes.NewReader(p.part(2)), "", 10, octet)
		}, 400, "missing_checksum"},
		{"an upper-case checksum", func() (*http.Response, string) {
			return e.sendPart("alice", c.UploadID, 2, bytes.NewReader(p.part(2)), strings.ToUpper(p.sum(2)), 10, octet)
		}, 400, "missing_checksum"},
		{"an unknown upload", func() (*http.Response, string) {
			return e.sendPart("alice", strings.Repeat("0", 32), 1, strings.NewReader("x"), p.sum(1), 1, octet)
		}, 404, "upload_not_found"},
		{"another length", func() (*http.Response, string) {
			return e.sendPart("alice", c.UploadID, 2, strings.NewReader("123456789"), p.sum(2), 9, octet)
		}, 400, "part_size_mismatch"},
		{"a body shorter than it says", func() (*http.Response, string) {
			return e.sendPart("alice", c.UploadID, 2, strings.NewReader("123456789"), p.sum(2), -1, octet)
		}, 400, "part_size_mismatch"},
		{"a wrong checksum", func() (*http.Response, string) {
			return e.sendPart("alice", c.UploadID, 2, bytes.NewReader(p.part(2)), otherSum, 10, octet)
		}, 400, "checksum_mismatch"},
		{"a part received before, said to be longer", func() (*http.Response, string) {
			b := append(slices.Clone(p.part(1)), 'x')
			return e.sendPart("alice", c.UploadID, 1, bytes.NewReader(b), p.sum(1), int64(len(b)), octet)
		}, 400, "part_size_mismatch"},
		{"another hash for a part received", func() (*http.Response, string) {
			return e.sendPart("alice", c.UploadID, 1, bytes.NewReader(p.part(1)), otherSum, int64(len(p.part(1))), octet)
		}, 409, "part_conflict"},
		{"a part as JSON", func() (*http.Response, string) {
			return e.sendPart("alice", c.UploadID, 2, bytes.NewReader(p.part(2)), p.sum(2), 10, "application/json")
		}, 415, "unsupported_media_type"},
		{"a part as GET", func() (*http.Response, string) {
			return e.as("alice", "GET", "/api/upload/part?id="+c.UploadID+"&n=2", nil)
		}, 405, "method_not_allowed"},

		{"status of a malformed ID", func() (*http.Response, string) {
			return e.as("alice", "POST", "/api/upload/status", UploadStatusRequest{UploadID: "x"})
		}, 400, "invalid_body"},
		{"status of an ID in upper case", func() (*http.Response, string) {
			return e.as("alice", "POST", "/api/upload/status", UploadStatusRequest{UploadID: strings.ToUpper(c.UploadID)})
		}, 400, "invalid_body"},
		{"status of 17 hashes", func() (*http.Response, string) {
			return e.as("alice", "POST", "/api/upload/status", UploadStatusRequest{UploadID: c.UploadID, Hashes: make([]int, 17)})
		}, 400, "invalid_body"},
		{"status of an unknown upload", func() (*http.Response, string) {
			return e.as("alice", "POST", "/api/upload/status", UploadStatusRequest{UploadID: strings.Repeat("a", 32)})
		}, 404, "upload_not_found"},
		{"a composite of the wrong form", func() (*http.Response, string) { return e.complete("alice", c.UploadID, "abc") }, 400, "invalid_body"},
		{"a completed upload, whatever the composite", func() (*http.Response, string) { return e.complete("alice", done.UploadID, otherSum) }, 201, ""},
		{"abort of a malformed ID", func() (*http.Response, string) {
			return e.as("alice", "POST", "/api/upload/abort", UploadAbortRequest{UploadID: "x"})
		}, 400, "invalid_body"},
		{"abort of a completed upload", func() (*http.Response, string) {
			return e.as("alice", "POST", "/api/upload/abort", UploadAbortRequest{UploadID: done.UploadID})
		}, 409, "upload_closed"},
		{"status as GET", func() (*http.Response, string) { return e.as("alice", "GET", "/api/upload/status", nil) }, 405, "method_not_allowed"},
		{"complete as GET", func() (*http.Response, string) { return e.as("alice", "GET", "/api/upload/complete", nil) }, 405, "method_not_allowed"},
		{"abort as GET", func() (*http.Response, string) { return e.as("alice", "GET", "/api/upload/abort", nil) }, 405, "method_not_allowed"},
		{"list as POST", func() (*http.Response, string) { return e.as("alice", "POST", "/api/upload/list", struct{}{}) }, 405, "method_not_allowed"},
		{"an unknown call", func() (*http.Response, string) { return e.as("alice", "POST", "/api/upload/rename", struct{}{}) }, 404, "not_found"},
	} {
		resp, body := tc.do()
		code, _ := errorBody(t, body)
		if resp.StatusCode != tc.status || code != tc.code {
			t.Errorf("%s: %d %s, want %d %s", tc.name, resp.StatusCode, body, tc.status, tc.code)
		}
		if resp.Header.Get("Retry-After") != "" {
			t.Errorf("%s: Retry-After %q", tc.name, resp.Header.Get("Retry-After"))
		}
	}

	// The parts still missing, and the state of an upload that ended, come
	// with the refusal.
	resp, body := e.complete("alice", c.UploadID, p.composite())
	code, extra := errorBody(t, body)
	if resp.StatusCode != 409 || code != "parts_missing" || fmt.Sprint(extra["missing"]) != "[[2 2]]" {
		t.Errorf("complete with a part missing: %d %s", resp.StatusCode, body)
	}
	if _, ok := extra["state"]; ok || extra["requestId"] == "" || extra["requestId"] == nil {
		t.Errorf("complete with a part missing: %s, want a request ID and no state", body)
	}
	e.part("alice", c.UploadID, p, 2)
	if resp, body := e.complete("alice", c.UploadID, otherSum); resp.StatusCode != 400 || !strings.Contains(body, `"checksum_mismatch"`) {
		t.Errorf("complete with a wrong composite: %d %s", resp.StatusCode, body)
	}
	if resp, body := e.as("alice", "POST", "/api/upload/abort", UploadAbortRequest{UploadID: c.UploadID}); resp.StatusCode != 200 ||
		body != `{"uploadId":"`+c.UploadID+`","state":"aborted"}`+"\n" {
		t.Errorf("abort: %d %s", resp.StatusCode, body)
	}
	for _, do := range []func() (*http.Response, string){
		func() (*http.Response, string) { return e.part("alice", c.UploadID, p, 1) },
		func() (*http.Response, string) { return e.complete("alice", c.UploadID, p.composite()) },
	} {
		resp, body := do()
		code, extra := errorBody(t, body)
		if resp.StatusCode != 409 || code != "upload_closed" || extra["state"] != "aborted" {
			t.Errorf("a call on an aborted upload: %d %s", resp.StatusCode, body)
		}
		if _, ok := extra["missing"]; ok || extra["requestId"] == "" || extra["requestId"] == nil {
			t.Errorf("a call on an aborted upload: %s, want a request ID and nothing missing", body)
		}
	}
	if resp, body := e.as("alice", "POST", "/api/upload/abort", UploadAbortRequest{UploadID: c.UploadID}); resp.StatusCode != 200 || !strings.Contains(body, `"aborted"`) {
		t.Errorf("abort again: %d %s", resp.StatusCode, body)
	}
}

func TestOnlyTheOwnerOrAnAdminReachesAnUpload(t *testing.T) {
	e := newUploadEnv(t)
	p := newPayload(100, 4)
	c := e.create("alice", "public", "a.bin", p, "")
	mine := e.create("bob", "public", "b.bin", p, "")

	for _, user := range []string{"bob", "root"} {
		if resp, body := e.part(user, c.UploadID, p, 1); resp.StatusCode != 404 || !strings.Contains(body, `"upload_not_found"`) {
			t.Errorf("%s sends alice's part: %d %s", user, resp.StatusCode, body)
		}
	}
	e.sendAll("alice", c.UploadID, p)
	for _, user := range []string{"bob", "root"} {
		if resp, body := e.complete(user, c.UploadID, p.composite()); resp.StatusCode != 404 || !strings.Contains(body, `"upload_not_found"`) {
			t.Errorf("%s completes alice's upload: %d %s", user, resp.StatusCode, body)
		}
	}
	for _, call := range []string{"status", "abort"} {
		if resp, body := e.as("bob", "POST", "/api/upload/"+call, UploadAbortRequest{UploadID: c.UploadID}); resp.StatusCode != 404 ||
			!strings.Contains(body, `"upload_not_found"`) || strings.Contains(body, "a.bin") {
			t.Errorf("bob's %s of alice's upload: %d %s", call, resp.StatusCode, body)
		}
	}
	resp, body := e.as("root", "POST", "/api/upload/status", UploadStatusRequest{UploadID: c.UploadID})
	st := decodeAs[transfer.Status](t, body)
	if resp.StatusCode != 200 || st.Owner == nil || *st.Owner != (transfer.Owner{ID: e.ids["alice"], Username: "alice"}) {
		t.Errorf("the admin's status: %d %s", resp.StatusCode, body)
	}

	ids := func(user, query string) []string {
		t.Helper()
		resp, body := e.as(user, "GET", "/api/upload/list"+query, nil)
		if resp.StatusCode != 200 {
			t.Fatalf("%s lists: %d %s", user, resp.StatusCode, body)
		}
		var out []string
		for _, s := range decodeAs[UploadListResponse](t, body).Uploads {
			out = append(out, s.UploadID)
		}
		slices.Sort(out)
		return out
	}
	both := []string{c.UploadID, mine.UploadID}
	slices.Sort(both)
	if got := ids("bob", "?all=1"); !slices.Equal(got, []string{mine.UploadID}) {
		t.Errorf("bob lists all: %v", got)
	}
	if got := ids("root", "?all=1"); !slices.Equal(got, both) {
		t.Errorf("the admin lists all: %v", got)
	}
	for _, q := range []string{"", "?all=0", "?all=true"} {
		if got := ids("root", q); len(got) != 0 {
			t.Errorf("the admin lists %q: %v", q, got)
		}
	}
	if got := ids("alice", "?all=true"); !slices.Equal(got, []string{c.UploadID}) {
		t.Errorf("alice lists: %v", got)
	}

	if resp, body := e.as("root", "POST", "/api/upload/abort", UploadAbortRequest{UploadID: c.UploadID}); resp.StatusCode != 200 {
		t.Errorf("the admin aborts alice's upload: %d %s", resp.StatusCode, body)
	}
	var aborted events.Event
	for _, ev := range e.rec.all() {
		if ev.Type == events.UploadAborted {
			aborted = ev
		}
	}
	if aborted.Actor.Name != "root" || aborted.Upload == nil || aborted.Upload.OwnerName != "alice" {
		t.Errorf("the abort's record: %+v", aborted)
	}
	denied := 0
	for _, ev := range e.rec.all() {
		if ev.Type == events.UploadRejected && ev.Outcome == events.OutcomeDenied {
			denied++
		}
	}
	if denied != 6 {
		t.Errorf("%d refusals of someone else's upload recorded as denied, want 6", denied)
	}
}

// An upload belongs to the user, not to the login: it is resumed after
// logging in again from another browser.
func TestAnUploadOutlivesTheLoginThatStartedIt(t *testing.T) {
	e := newUploadEnv(t)
	p := newPayload(100, 5)
	c := e.create("alice", "public", "a.bin", p, "file-key")
	if resp, _ := e.as("alice", "POST", "/api/auth/logout", nil); resp.StatusCode != 204 {
		t.Fatalf("logout: %d", resp.StatusCode)
	}
	if resp, body := e.part("alice", c.UploadID, p, 1); resp.StatusCode != 401 || !strings.Contains(body, `"unauthenticated"`) {
		t.Errorf("a part after logging out: %d %s", resp.StatusCode, body)
	}
	e.users["alice"] = e.browser()
	e.login(e.users["alice"], "alice")
	if again := e.create("alice", "public", "a.bin", p, "file-key"); !again.Resumed || again.UploadID != c.UploadID {
		t.Fatalf("after logging in again: %+v", again)
	}
	e.sendAll("alice", c.UploadID, p)
	if resp, body := e.complete("alice", c.UploadID, p.composite()); resp.StatusCode != 201 {
		t.Errorf("complete: %d %s", resp.StatusCode, body)
	}
}

func TestADemotedUserStopsAtTheirNextPart(t *testing.T) {
	e := newUploadEnv(t)
	p := newPayload(8<<20+1, 6)
	c := e.create("alice", "public", "a.bin", p, "")
	e.part("alice", c.UploadID, p, 1)
	if resp, body := e.as("root", "POST", "/api/admin/users/update", map[string]any{"id": e.ids["alice"], "role": "viewer"}); resp.StatusCode != 200 {
		t.Fatalf("demote: %d %s", resp.StatusCode, body)
	}
	if resp, body := e.part("alice", c.UploadID, p, 2); resp.StatusCode != 403 || !strings.Contains(body, `"forbidden"`) {
		t.Errorf("a part after demotion: %d %s", resp.StatusCode, body)
	}
	if resp, body := e.as("alice", "POST", "/api/upload/status", UploadStatusRequest{UploadID: c.UploadID}); resp.StatusCode != 200 {
		t.Errorf("the owner's status after demotion: %d %s", resp.StatusCode, body)
	}
	if resp, body := e.as("alice", "POST", "/api/upload/abort", UploadAbortRequest{UploadID: c.UploadID}); resp.StatusCode != 200 {
		t.Errorf("the owner's abort after demotion: %d %s", resp.StatusCode, body)
	}
}

func TestPoliciesCAndDAtTheHTTPBoundary(t *testing.T) {
	e := newUploadEnv(t)
	p := newPayload(100, 7)
	c := e.create("alice", "public", "a.bin", p, "k")
	e.sendAll("alice", c.UploadID, p)

	e.auditor.set(errors.New("disk failed"), nil)
	for _, do := range []func() (*http.Response, string){
		func() (*http.Response, string) {
			return e.as("alice", "POST", "/api/upload/create", transfer.CreateRequest{Dir: "public", Name: "b.bin", Size: 1})
		},
		func() (*http.Response, string) { return e.complete("alice", c.UploadID, p.composite()) },
	} {
		if resp, body := do(); resp.StatusCode != 503 || !strings.Contains(body, `"changes_paused"`) {
			t.Errorf("while changes are paused: %d %s", resp.StatusCode, body)
		}
	}
	// A resume creates nothing, and a status reads.
	if resp, body := e.as("alice", "POST", "/api/upload/create", transfer.CreateRequest{Dir: "public", Name: "a.bin", Size: 100, ClientKey: "k"}); resp.StatusCode != 200 {
		t.Errorf("a resume while changes are paused: %d %s", resp.StatusCode, body)
	}

	for _, tc := range []struct {
		err  error
		code string
	}{{events.ErrNotRecorded, "not_recorded"}, {events.ErrNotConfirmed, "not_confirmed"}} {
		e.auditor.set(nil, tc.err)
		q := newPayload(100, 8)
		u := e.create("alice", "public", "d.bin", q, "")
		e.sendAll("alice", u.UploadID, q)
		for range 2 {
			resp, body := e.complete("alice", u.UploadID, q.composite())
			code, extra := errorBody(t, body)
			result, _ := extra["result"].(map[string]any)
			if resp.StatusCode != 500 || code != tc.code || result["path"] == nil || result["compositeSha256"] != q.composite() {
				t.Errorf("%s: %d %s", tc.code, resp.StatusCode, body)
			}
		}
	}
}

func TestRefusalsToComeBackLaterSayWhen(t *testing.T) {
	e := newUploadEnv(t, func(c *transfer.Config) {
		c.Limits.MaxInflight, c.Limits.MaxInflightUser = 2, 1
		c.Limits.MaxSessions, c.Limits.MaxSessionsTotal = 2, 4
	})
	p := newPayload(1000, 9)
	a := e.create("alice", "public", "a.bin", p, "")
	b := e.create("alice", "public", "b.bin", p, "")
	if resp, body := e.as("alice", "POST", "/api/upload/create", transfer.CreateRequest{Dir: "public", Name: "c.bin", Size: 1}); resp.StatusCode != 429 ||
		!strings.Contains(body, `"too_many_uploads"`) || resp.Header.Get("Retry-After") != "" {
		t.Errorf("a third upload of alice: %d %v %s", resp.StatusCode, resp.Header, body)
	}
	bobs := e.create("bob", "public", "c.bin", p, "")
	roots := e.create("root", "public", "d.bin", p, "")
	if resp, body := e.as("bob", "POST", "/api/upload/create", transfer.CreateRequest{Dir: "public", Name: "e.bin", Size: 1}); resp.StatusCode != 503 ||
		!strings.Contains(body, `"busy"`) || resp.Header.Get("Retry-After") != "1" {
		t.Errorf("a fifth upload on the server: %d %v %s", resp.StatusCode, resp.Header, body)
	}

	// hold sends the first byte of a part and keeps the rest back.
	hold := func(user, id string) (release func()) {
		t.Helper()
		pr, pw := io.Pipe()
		t.Cleanup(func() { pw.CloseWithError(errors.New("the test ended")) })
		done := make(chan struct{})
		go func() {
			defer close(done)
			req, _ := http.NewRequest("POST", e.srv.URL+"/api/upload/part?id="+id+"&n=1", pr)
			req.ContentLength = int64(len(p.data))
			req.Header.Set("Content-Type", "application/octet-stream")
			req.Header.Set(PartChecksumHeader, p.sum(1))
			if resp, err := e.users[user].Do(req); err == nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}()
		go pw.Write(p.data[:1])
		for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(time.Millisecond) {
			resp, body := e.as(user, "POST", "/api/upload/status", UploadStatusRequest{UploadID: id})
			if resp.StatusCode == 200 && strings.Contains(body, `"inFlight":[1]`) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("the held part never started: %s", body)
			}
		}
		return func() {
			t.Helper()
			go func() { pw.Write(p.data[1:]); pw.Close() }()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("the held part never ended")
			}
		}
	}
	releaseAlice := hold("alice", a.UploadID)
	if resp, body := e.part("alice", a.UploadID, p, 1); resp.StatusCode != 409 || !strings.Contains(body, `"part_in_progress"`) {
		t.Errorf("the same part again at once: %d %s", resp.StatusCode, body)
	}
	if resp, body := e.complete("alice", a.UploadID, p.composite()); resp.StatusCode != 409 || !strings.Contains(body, `"parts_in_flight"`) {
		t.Errorf("complete with the part on its way: %d %s", resp.StatusCode, body)
	}
	if resp, body := e.part("alice", b.UploadID, p, 1); resp.StatusCode != 429 || !strings.Contains(body, `"too_many_requests"`) || resp.Header.Get("Retry-After") != "1" {
		t.Errorf("alice's second part at once: %d %v %s", resp.StatusCode, resp.Header, body)
	}
	releaseBob := hold("bob", bobs.UploadID)
	releaseAlice()
	releaseRoot := hold("root", roots.UploadID)
	if resp, body := e.part("alice", b.UploadID, p, 1); resp.StatusCode != 503 || !strings.Contains(body, `"busy"`) || resp.Header.Get("Retry-After") != "1" {
		t.Errorf("a part with the server full: %d %v %s", resp.StatusCode, resp.Header, body)
	}
	releaseBob()
	releaseRoot()
	if resp, body := e.part("alice", b.UploadID, p, 1); resp.StatusCode != 200 {
		t.Errorf("once the slots are free: %d %s", resp.StatusCode, body)
	}
	for _, ev := range e.rec.all() {
		if ev.Type == events.UploadRejected && (strings.Contains(ev.Detail, "busy") || strings.Contains(ev.Detail, "too many")) {
			t.Errorf("an admission refusal was recorded: %+v", ev)
		}
	}
}

func TestUploadsAnswerUnavailableWithoutTheEngine(t *testing.T) {
	check := func(name string, h http.Handler, code string) {
		t.Helper()
		srv := httptest.NewServer(h)
		defer srv.Close()
		for _, c := range []struct{ method, path, ctype string }{
			{"POST", "/api/upload/create", "application/json"},
			{"POST", "/api/upload/part?id=" + strings.Repeat("0", 32) + "&n=1", "application/octet-stream"},
			{"POST", "/api/upload/create", "text/plain"},
			{"POST", "/api/upload/part?id=" + strings.Repeat("0", 32) + "&n=1", "text/plain"},
			{"POST", "/api/upload/status", "application/json"},
			{"POST", "/api/upload/complete", "application/json"},
			{"POST", "/api/upload/abort", "application/json"},
			{"GET", "/api/upload/list", ""},
		} {
			req, _ := http.NewRequest(c.method, srv.URL+c.path, strings.NewReader(`{"bogus":`))
			if c.ctype != "" {
				req.Header.Set("Content-Type", c.ctype)
			}
			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != 503 || !strings.Contains(string(body), `"`+code+`"`) {
				t.Errorf("%s: %s %s as %s: %d %s", name, c.method, c.path, c.ctype, resp.StatusCode, body)
			}
		}
	}
	root := t.TempDir()
	sb, err := sandbox.New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer sb.Close()
	files := adminFiles(sb, nil)
	check("no engine", newTestHandler(files, fstest.MapFS{}, Options{}), "uploads_unavailable")

	off, err := transfer.New(transfer.Config{Root: sb.OSRoot(), Staging: &sandbox.Staging{Problem: errors.New("a symlink")},
		Files: files, Registry: registry.New(nil), Events: &recorder{}})
	if err != nil {
		t.Fatal(err)
	}
	check("an engine that is off", newTestHandler(files, fstest.MapFS{}, Options{Uploads: off}), "uploads_unavailable")

	e := newUploadEnv(t)
	e.eng.Close(context.Background())
	check("an engine shutting down", newTestHandler(files, fstest.MapFS{}, Options{Uploads: e.eng}), "unavailable")
}

func TestErrorsOfTheEngineKeepTheirStatusAndCode(t *testing.T) {
	for _, te := range []*transfer.Error{
		transfer.ErrUnavailable, transfer.ErrShuttingDown, transfer.ErrInvalidRequest, transfer.ErrInvalidPart,
		transfer.ErrMissingChecksum, transfer.ErrChecksumMismatch, transfer.ErrPartSizeMismatch, transfer.ErrUploadNotFound,
		transfer.ErrNoAccount, transfer.ErrPartInProgress, transfer.ErrPartConflict, transfer.ErrPartsMissing,
		transfer.ErrPartsInFlight, transfer.ErrCompleting, transfer.ErrClosed, transfer.ErrTooLarge,
		transfer.ErrTooLargeForVolume, transfer.ErrTooManyUploads, transfer.ErrTooManyRequests, transfer.ErrBusy,
		transfer.ErrPartAborted,
	} {
		w := httptest.NewRecorder()
		// As the engine wraps them, with the system's error behind.
		writeUploadError(w, httptest.NewRequest("POST", "/api/upload/part", nil), fmt.Errorf("%w: write uploads/0123/data: disk on fire", te))
		code, extra := errorBody(t, w.Body.String())
		msg, _ := extra["error"].(map[string]any)["message"].(string)
		if w.Code != te.Status || code != te.Code || strings.Contains(msg, "uploads/") || msg == "" || strings.ToUpper(msg[:1]) != msg[:1] {
			t.Errorf("%s: %d %s", te.Code, w.Code, w.Body)
		}
		if retry := w.Header().Get("Retry-After"); (retry == "1") != (te.Code == "busy" || te.Code == "too_many_requests") {
			t.Errorf("%s: Retry-After %q", te.Code, retry)
		}
		if te == transfer.ErrPartAborted && msg != "The part's body ended early or stalled" {
			t.Errorf("part_aborted: %q, which should tell a stall too", msg)
		}
	}
	for _, tc := range []struct {
		err          error
		status       int
		code         string
		extra, value string
	}{
		{&transfer.MissingError{Missing: []transfer.Range{{1, 3}, {7, 7}}}, 409, "parts_missing", "missing", "[[1 3] [7 7]]"},
		{&transfer.ClosedError{State: transfer.Failed, Reason: "cannot write uploads/x/data"}, 409, "upload_closed", "state", "failed"},
		{fmt.Errorf("%w: %v", fsops.ErrInsufficientStorage, "no space"), 507, "insufficient_storage", "", ""},
		{fsops.ErrCrossDevice, 409, "cross_device", "", ""},
		{fmt.Errorf("check the folder: %w", fsops.ErrReadOnly), 403, "permission_denied", "", ""},
	} {
		w := httptest.NewRecorder()
		writeUploadError(w, httptest.NewRequest("POST", "/api/upload/complete", nil), tc.err)
		code, extra := errorBody(t, w.Body.String())
		msg, _ := extra["error"].(map[string]any)["message"].(string)
		if w.Code != tc.status || code != tc.code || (tc.extra != "" && fmt.Sprint(extra[tc.extra]) != tc.value) ||
			msg == "" || strings.ToUpper(msg[:1]) != msg[:1] {
			t.Errorf("%v: %d %s", tc.err, w.Code, w.Body)
		}
		if strings.Contains(w.Body.String(), "uploads/x") {
			t.Errorf("%v: the reason is in the answer: %s", tc.err, w.Body)
		}
	}
}

// The wire names a client written from the protocol uses, without the
// structs of this package.
func TestUploadCallsUseTheProtocolsNames(t *testing.T) {
	e := newUploadEnv(t)
	p := newPayload(10, 1)
	c := e.create("alice", "public", "a.bin", p, "")
	e.sendAll("alice", c.UploadID, p)
	resp, body := e.as("alice", "POST", "/api/upload/status", json.RawMessage(`{"uploadId":"`+c.UploadID+`","hashes":[1]}`))
	if resp.StatusCode != 200 || !strings.Contains(body, `"hashes":{"1":"`+p.sum(1)+`"}`) {
		t.Errorf("status: %d %s", resp.StatusCode, body)
	}
	resp, body = e.as("alice", "GET", "/api/upload/list", nil)
	if resp.StatusCode != 200 || !strings.HasPrefix(body, `{"uploads":[{"uploadId":"`+c.UploadID+`"`) {
		t.Errorf("list: %d %s", resp.StatusCode, body)
	}
}

// A malformed part is recorded with the ID it named, and a number that
// isn't one as -1, which a part 0 sent as such doesn't look like.
func TestAMalformedPartIsRecordedWithItsID(t *testing.T) {
	e := newUploadEnv(t)
	p := newPayload(10, 1)
	c := e.create("alice", "public", "a.bin", p, "")
	for _, tc := range []struct {
		n    string
		part int
	}{{"abc", -1}, {"0", 0}, {"", -1}} {
		before := len(e.rec.all())
		req, _ := http.NewRequest("POST", e.srv.URL+"/api/upload/part?id="+c.UploadID+"&n="+tc.n, strings.NewReader("x"))
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set(PartChecksumHeader, p.sum(1))
		resp, err := e.users["alice"].Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		evs := e.rec.all()[before:]
		if resp.StatusCode != 400 || len(evs) != 1 || evs[0].Type != events.UploadRejected || evs[0].Upload.ID != c.UploadID || evs[0].Upload.Part != tc.part {
			t.Errorf("n=%q: %d, recorded %+v", tc.n, resp.StatusCode, evs)
		}
	}
}

func TestAResumeAnswers200EvenBeforeAnyPart(t *testing.T) {
	e := newUploadEnv(t)
	req := transfer.CreateRequest{Dir: "public", Name: "a.bin", Size: 100, ClientKey: "k"}
	first, _ := e.as("alice", "POST", "/api/upload/create", req)
	again, body := e.as("alice", "POST", "/api/upload/create", req)
	if first.StatusCode != http.StatusCreated || again.StatusCode != http.StatusOK || !decodeAs[transfer.Created](t, body).Resumed {
		t.Errorf("create %d, then the resume %d %s", first.StatusCode, again.StatusCode, body)
	}
}

// A create without a size is refused, rather than taken for an empty file.
func TestACreateWithoutASizeIsRefused(t *testing.T) {
	e := newUploadEnv(t)
	before := len(e.rec.all())
	resp, body := e.as("alice", "POST", "/api/upload/create", json.RawMessage(`{"dir":"public","name":"a.bin"}`))
	if code, _ := errorBody(t, body); resp.StatusCode != 400 || code != "invalid_body" {
		t.Errorf("%d %s", resp.StatusCode, body)
	}
	if resp, body := e.as("alice", "GET", "/api/upload/list", nil); resp.StatusCode != 200 || body != `{"uploads":[]}`+"\n" {
		t.Errorf("a session was opened: %d %s", resp.StatusCode, body)
	}
	if evs := e.rec.all()[before:]; len(evs) != 0 {
		t.Errorf("recorded %+v", evs)
	}
	resp, body = e.as("alice", "POST", "/api/upload/create", json.RawMessage(`{"dir":"public","name":"a.bin","size":0}`))
	if resp.StatusCode != 201 || decodeAs[transfer.Created](t, body).PartCount != 0 {
		t.Errorf("an empty file: %d %s", resp.StatusCode, body)
	}
}

// A part sent without Content-Length, as a chunked body, is taken when its
// bytes are right.
func TestAChunkedPartIsAccepted(t *testing.T) {
	e := newUploadEnv(t)
	p := newPayload(8<<20+10, 4)
	c := e.create("alice", "public", "a.bin", p, "")
	body := io.MultiReader(bytes.NewReader(p.part(2)))
	if resp, b := e.sendPart("alice", c.UploadID, 2, body, p.sum(2), -1, "application/octet-stream"); resp.StatusCode != 200 {
		t.Errorf("a chunked part: %d %s", resp.StatusCode, b)
	}
}

// Over HTTP/1.1, a duplicate part is read to its end, so the client's next
// part goes on the same connection.
func TestADuplicatePartKeepsTheConnection(t *testing.T) {
	e := newUploadEnv(t)
	p := newPayload(8<<20+10, 3)
	c := e.create("alice", "public", "a.bin", p, "")
	send := func(n int) (int, bool) {
		var reused bool
		b := p.part(n)
		req, _ := http.NewRequest("POST", e.srv.URL+"/api/upload/part?id="+c.UploadID+"&n="+strconv.Itoa(n), bytes.NewReader(b))
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
			GotConn: func(i httptrace.GotConnInfo) { reused = i.Reused },
		}))
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set(PartChecksumHeader, p.sum(n))
		resp, err := e.users["alice"].Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode, reused
	}
	send(1)
	if code, _ := send(1); code != 200 {
		t.Fatalf("the duplicate: %d", code)
	}
	if code, reused := send(2); code != 200 || !reused {
		t.Errorf("the part after a duplicate: %d, on the same connection %v", code, reused)
	}
}

// A part whose body stalls past the body timeout, with the client still
// there, is answered part_aborted, and can be sent again.
func TestAStalledPartIsAnsweredPartAborted(t *testing.T) {
	e := newUploadEnv(t)
	e.srv.Config.Handler = New(e.files, fstest.MapFS{"index.html": {Data: []byte("<html></html>")}},
		Options{Accounts: e.acc, Uploads: e.eng, BodyTimeout: 300 * time.Millisecond})
	p := newPayload(1000, 9)
	c := e.create("alice", "public", "a.bin", p, "")
	pr, pw := io.Pipe()
	t.Cleanup(func() { pw.CloseWithError(errors.New("the test ended")) })
	go pw.Write(p.data[:10])
	resp, body := e.sendPart("alice", c.UploadID, 1, pr, p.sum(1), int64(len(p.data)), "application/octet-stream")
	if code, _ := errorBody(t, body); resp.StatusCode != 400 || code != "part_aborted" {
		t.Errorf("a stalled part: %d %s", resp.StatusCode, body)
	}
	if resp, body := e.part("alice", c.UploadID, p, 1); resp.StatusCode != 200 {
		t.Errorf("the part sent again: %d %s", resp.StatusCode, body)
	}
}

// Part requests as a client may send them, well formed or not: never a 5xx
// but busy, and never a change in the served tree.
func FuzzPartRequest(f *testing.F) {
	f.Add("{id}", "1", "{sum}", "application/octet-stream", int64(-1), []byte("hello"))
	f.Add("{id}", "01", "{sum}", "application/octet-stream", int64(5), []byte("hello"))
	f.Add("../../x", "-1", "", "text/plain", int64(3), []byte("abc"))
	f.Add("{id}", "99999999999999999999", "{sum}", "application/octet-stream; charset=x", int64(0), []byte{})
	f.Add("{id}", "2", "{sum}", "application/octet-stream", int64(6), []byte("hello!"))
	f.Add("{ID}", "1", "{SUM}", "application/octet-stream", int64(5), []byte("hello"))
	f.Fuzz(func(t *testing.T, id, n, sum, ctype string, length int64, body []byte) {
		e := newUploadEnv(t)
		p := newPayload(5, 1)
		c := e.create("alice", "public", "a.bin", p, "")
		r := strings.NewReplacer("{id}", c.UploadID, "{ID}", strings.ToUpper(c.UploadID), "{sum}", p.sum(1), "{SUM}", strings.ToUpper(p.sum(1)))
		id, sum = r.Replace(id), r.Replace(sum)
		before := tree(t, e.root)
		req, err := http.NewRequest("POST", e.srv.URL+"/api/upload/part?id="+url.QueryEscape(id)+"&n="+url.QueryEscape(n), bytes.NewReader(body))
		if err != nil {
			return
		}
		if length >= 0 && length <= int64(len(body)) {
			req.ContentLength = length
			req.Body = io.NopCloser(bytes.NewReader(body[:length]))
		} else {
			req.ContentLength = -1
		}
		req.Header.Set("Content-Type", ctype)
		req.Header.Set(PartChecksumHeader, sum)
		resp, err := e.users["alice"].Do(req)
		if err != nil {
			return
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode >= 500 && !strings.Contains(string(b), `"busy"`) {
			t.Errorf("%q %q %q %q %d: %d %s", id, n, sum, ctype, length, resp.StatusCode, b)
		}
		if after := tree(t, e.root); !maps.Equal(before, after) {
			t.Errorf("the served tree changed")
		}
	})
}
