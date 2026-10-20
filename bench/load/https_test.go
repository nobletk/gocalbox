package load

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nobletk/gocalbox/internal/transfer"
)

type fakeSession struct {
	user, state, path string
}

// fakeHTTPS answers the upload protocol over HTTPS for users with the
// password "pw", cutting files into parts of partSize bytes.
type fakeHTTPS struct {
	srv *httptest.Server
	ca  []byte

	mu       sync.Mutex
	partSize int64
	conns    int
	closed   int
	protos   map[string]int
	parts    map[string]int
	sessions map[string]*fakeSession
	answer   map[string]func(w http.ResponseWriter, r *http.Request, body map[string]any) bool
	deleted  []string
	aborted  []string
}

func newFakeHTTPS(t *testing.T, h2 bool) *fakeHTTPS {
	f := &fakeHTTPS{partSize: 4, protos: map[string]int{}, parts: map[string]int{}, sessions: map[string]*fakeSession{},
		answer: map[string]func(http.ResponseWriter, *http.Request, map[string]any) bool{}}
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	f.srv.EnableHTTP2 = h2
	f.srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	f.srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch s {
		case http.StateNew:
			f.conns++
		case http.StateClosed:
			f.closed++
		}
	}
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	f.ca = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw})
	return f
}

// on answers the calls to path with fn first; fn returns false to leave
// the call to the usual answer.
func (f *fakeHTTPS) on(path string, fn func(w http.ResponseWriter, r *http.Request, body map[string]any) bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answer[path] = fn
}

func refuse(w http.ResponseWriter, status int, code string, extra string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"error":{"code":%q,"message":"refused"}%s}`, code, extra)
}

// hangUp closes the connection of a request without an answer.
func hangUp(w http.ResponseWriter) {
	if c, _, err := http.NewResponseController(w).Hijack(); err == nil {
		c.Close()
	}
}

func (f *fakeHTTPS) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.protos[r.Proto]++
	fn := f.answer[r.URL.Path]
	f.mu.Unlock()
	var body map[string]any
	if r.URL.Path != "/api/upload/part" {
		json.NewDecoder(r.Body).Decode(&body)
	}
	if fn != nil && fn(w, r, body) {
		return
	}
	if r.URL.Path == "/api/auth/login" {
		if body["password"] != "pw" {
			refuse(w, 401, "invalid_credentials", "")
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "s", Value: body["username"].(string), Path: "/"})
		w.Write([]byte(`{}`))
		return
	}
	c, err := r.Cookie("s")
	if err != nil {
		refuse(w, 401, "unauthenticated", "")
		return
	}
	user := c.Value
	if r.URL.Path == "/api/upload/part" {
		b, _ := io.ReadAll(r.Body)
		if r.Header.Get("Content-Type") != "application/octet-stream" || len(r.Header.Get("Upload-Part-SHA256")) != 64 || int64(len(b)) != r.ContentLength {
			refuse(w, 400, "invalid_part", "")
			return
		}
		f.mu.Lock()
		f.parts[r.URL.Query().Get("id")]++
		f.mu.Unlock()
		json.NewEncoder(w).Encode(transfer.PartResult{})
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.URL.Path {
	case "/api/upload/create":
		size := int64(body["size"].(float64))
		id := fmt.Sprintf("%s-%s", user, body["name"])
		if body["dir"] != "users/"+user {
			refuse(w, 403, "forbidden", "")
			return
		}
		f.sessions[id] = &fakeSession{user: user, state: "receiving"}
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(transfer.Created{UploadID: id, PartSize: f.partSize, PartCount: transfer.PartCount(size, f.partSize), MaxParallel: 4})
	case "/api/upload/complete":
		id := body["uploadId"].(string)
		f.complete(id, "users/"+user+"/"+id)
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(transfer.Result{Path: "users/" + user + "/" + id})
	case "/api/upload/list":
		var list []transfer.Status
		for id, s := range f.sessions {
			if s.user != user {
				continue
			}
			st := transfer.Status{UploadID: id, State: transfer.State(s.state)}
			if s.path != "" {
				st.Result = &transfer.Result{Path: s.path}
			}
			list = append(list, st)
		}
		json.NewEncoder(w).Encode(map[string]any{"uploads": list})
	case "/api/fs/delete":
		f.deleted = append(f.deleted, user+" "+body["path"].(string))
		w.Write([]byte(`{}`))
	case "/api/upload/abort":
		id := body["uploadId"].(string)
		if s := f.sessions[id]; s == nil || s.state != "receiving" {
			refuse(w, 409, "upload_closed", "")
			return
		}
		f.sessions[id].state = "aborted"
		f.aborted = append(f.aborted, user+" "+id)
		w.Write([]byte(`{}`))
	default:
		refuse(w, 404, "not_found", "")
	}
}

// complete marks a session completed with its file at path. The caller
// holds f.mu.
func (f *fakeHTTPS) complete(id, path string) {
	if s := f.sessions[id]; s != nil {
		s.state, s.path = "completed", path
	}
}

func (f *fakeHTTPS) remote(http1 bool) Remote {
	return Remote{URL: f.srv.URL, CA: f.ca, HTTP1: http1}
}

func (f *fakeHTTPS) logIn(t *testing.T, http1 bool, names ...string) []User {
	t.Helper()
	users, err := LogIn(context.Background(), f.remote(http1), names, "pw")
	if err != nil {
		t.Fatal(err)
	}
	return users
}

func TestEveryUserLogsInOverAConnectionOfItsOwn(t *testing.T) {
	for _, h2 := range []bool{true, false} {
		f := newFakeHTTPS(t, h2)
		users := f.logIn(t, !h2, "ann", "Bob")
		if len(users) != 2 || users[0].Dir != "users/ann" || users[1].Dir != "users/bob" {
			t.Fatalf("users %+v", users)
		}
		a, b := users[0].API.(*remote), users[1].API.(*remote)
		if a.client.Transport == b.client.Transport || a.client.Jar == b.client.Jar {
			t.Error("two users share a transport or a cookie jar")
		}
		res := Run(context.Background(), Config{Users: users, Files: 2, Size: 10, Parallel: 2})
		if res.CodeColumn() != "201" || res.Files != 4 || len(res.Parts) != 12 {
			t.Errorf("result %+v, codes %s", res, res.CodeColumn())
		}
		want := "HTTP/2.0"
		if !h2 {
			want = "HTTP/1.1"
		}
		f.mu.Lock()
		if f.protos[want] == 0 || len(f.protos) != 1 {
			t.Errorf("protocols %v, want %s only", f.protos, want)
		}
		if h2 && f.conns != 2 {
			t.Errorf("two users over HTTP/2 made %d connections, want one each", f.conns)
		}
		for _, id := range []string{"ann-load-000-0000.bin", "ann-load-000-0001.bin", "bob-load-001-0000.bin", "bob-load-001-0001.bin"} {
			if f.parts[id] != 3 {
				t.Errorf("upload %s: %d parts", id, f.parts[id])
			}
		}
		f.mu.Unlock()
	}
}

// Over HTTP/1.1 a connection goes back to the transport for the next part,
// as a browser keeps its connections: the client closes none during a run.
func TestHTTP1KeepsAConnectionForEachPartInFlight(t *testing.T) {
	f := newFakeHTTPS(t, false)
	f.partSize = 8 << 20
	users := f.logIn(t, true, "ann")
	res := Run(context.Background(), Config{Users: users, Files: 4, Size: 32 << 20, Parallel: 4})
	f.mu.Lock()
	closed, opened := f.closed, f.conns
	f.mu.Unlock()
	if res.CodeColumn() != "201" || len(res.Parts) != 16 {
		t.Fatalf("codes %s, %d parts", res.CodeColumn(), len(res.Parts))
	}
	if closed != 0 {
		t.Errorf("the client closed %d of the %d connections it opened during the run", closed, opened)
	}
}

func TestTheTransportGivesUpOnASilentServer(t *testing.T) {
	f := newFakeHTTPS(t, true)
	tr := f.logIn(t, false, "ann")[0].API.(*remote).client.Transport.(*http.Transport)
	if tr.TLSHandshakeTimeout != 10*time.Second || tr.ResponseHeaderTimeout != 5*time.Minute || tr.MaxIdleConnsPerHost != 64 ||
		tr.HTTP2 == nil || tr.HTTP2.SendPingTimeout != 30*time.Second || tr.HTTP2.PingTimeout != 15*time.Second {
		t.Errorf("transport: handshake %v, answer %v, idle %d, HTTP/2 %+v", tr.TLSHandshakeTimeout, tr.ResponseHeaderTimeout, tr.MaxIdleConnsPerHost, tr.HTTP2)
	}
}

func TestLogInRefusals(t *testing.T) {
	f := newFakeHTTPS(t, true)
	if _, err := LogIn(context.Background(), f.remote(false), []string{"ann"}, "wrong"); err == nil || !strings.Contains(err.Error(), "log in as ann") || status(err) != "401" {
		t.Errorf("a wrong password: %v", err)
	}
	host := strings.TrimPrefix(f.srv.URL, "https://")
	for _, u := range []string{"http://" + host, f.srv.URL + "/sub", "https://", "://x", f.srv.URL + "?x=1", f.srv.URL + "?", f.srv.URL + "#frag", "https://me:secret@" + host} {
		if _, err := LogIn(context.Background(), Remote{URL: u, CA: f.ca}, []string{"ann"}, "pw"); err == nil || !strings.Contains(err.Error(), "https://host:port") {
			t.Errorf("URL %q: %v", u, err)
		}
	}
	if _, err := LogIn(context.Background(), Remote{URL: f.srv.URL + "/", CA: f.ca}, []string{"ann"}, "pw"); err != nil {
		t.Errorf("a URL ending in a slash: %v", err)
	}
	for _, name := range []string{"a", "an n", "system"} {
		if _, err := LogIn(context.Background(), f.remote(false), []string{"ann", name}, "pw"); err == nil || !strings.Contains(err.Error(), fmt.Sprintf("user %q", name)) {
			t.Errorf("user %q: %v", name, err)
		}
	}
	if _, err := LogIn(context.Background(), Remote{URL: f.srv.URL, CA: []byte("not a certificate")}, []string{"ann"}, "pw"); err == nil || !strings.Contains(err.Error(), "no certificate") {
		t.Errorf("a CA file without a certificate: %v", err)
	}
	if _, err := LogIn(context.Background(), Remote{URL: f.srv.URL}, []string{"ann"}, "pw"); !errors.Is(err, ErrNoAnswer) {
		t.Errorf("a server the system doesn't trust: %v", err)
	}
	h1 := newFakeHTTPS(t, false)
	if _, err := LogIn(context.Background(), h1.remote(false), []string{"ann"}, "pw"); !errors.Is(err, ErrNoAnswer) {
		t.Errorf("HTTP/2 asked of a server without it: %v", err)
	}
}

func TestRefusalsOverHTTPSAreTheServers(t *testing.T) {
	f := newFakeHTTPS(t, true)
	busy := 2
	f.on("/api/upload/part", func(w http.ResponseWriter, r *http.Request, _ map[string]any) bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		if busy > 0 {
			busy--
			io.Copy(io.Discard, r.Body)
			w.Header().Set("Retry-After", "1")
			refuse(w, 503, "busy", "")
			return true
		}
		return false
	})
	tooMany := 1
	f.on("/api/upload/create", func(w http.ResponseWriter, r *http.Request, _ map[string]any) bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		if tooMany > 0 {
			tooMany--
			refuse(w, 429, "too_many_requests", "")
			return true
		}
		return false
	})
	busyComplete := 1
	f.on("/api/upload/complete", func(w http.ResponseWriter, r *http.Request, body map[string]any) bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch id := body["uploadId"].(string); {
		case strings.HasSuffix(id, "0001.bin"):
			f.complete(id, "users/ann/kept.bin")
			refuse(w, 500, "not_recorded", `,"result":{"path":"users/ann/kept.bin"}`)
			return true
		case busyComplete > 0:
			busyComplete--
			refuse(w, 503, "busy", "")
			return true
		}
		return false
	})
	users := f.logIn(t, false, "ann")
	res := Run(context.Background(), Config{Users: users, Files: 2, Size: 10, Parallel: 1})
	if res.CodeColumn() != "201x1 500x1" || res.Retried["503"] != 3 || res.Retried["429"] != 1 || len(res.Retried) != 2 {
		t.Errorf("codes %s, retried %v", res.CodeColumn(), res.Retried)
	}
	if err := Clean(context.Background(), users); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if strings.Join(f.deleted, ",") != "ann users/ann/ann-load-000-0000.bin,ann users/ann/kept.bin" || len(f.aborted) != 0 {
		t.Errorf("cleaned: deleted %v, aborted %v", f.deleted, f.aborted)
	}
}

func TestCleanAbortsWhatDidntFinish(t *testing.T) {
	f := newFakeHTTPS(t, true)
	f.on("/api/upload/part", func(w http.ResponseWriter, r *http.Request, _ map[string]any) bool {
		if r.URL.Query().Get("id") == "ann-load-000-0001.bin" {
			io.Copy(io.Discard, r.Body)
			refuse(w, 409, "part_conflict", "")
			return true
		}
		return false
	})
	f.on("/api/upload/complete", func(w http.ResponseWriter, r *http.Request, body map[string]any) bool {
		if body["uploadId"] == "ann-load-000-0002.bin" {
			refuse(w, 409, "parts_missing", `,"missing":[{"from":1,"to":1}]`)
			return true
		}
		return false
	})
	asked := 0
	f.on("/api/upload/abort", func(w http.ResponseWriter, r *http.Request, body map[string]any) bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		if asked++; asked == 1 {
			f.sessions[body["uploadId"].(string)].state = "expired"
			refuse(w, 409, "upload_closed", `,"state":"expired"`)
			return true
		}
		return false
	})
	users := f.logIn(t, false, "ann")
	res := Run(context.Background(), Config{Users: users, Files: 3, Size: 10, Parallel: 1})
	if res.CodeColumn() != "201x1 409x2" {
		t.Errorf("codes %s", res.CodeColumn())
	}
	if err := Clean(context.Background(), users); err != nil {
		t.Errorf("an upload that ended already: %v", err)
	}
	f.mu.Lock()
	if len(f.deleted) != 1 || asked != 2 || len(f.aborted) != 1 {
		t.Errorf("deleted %v, aborted %v, %d aborts asked", f.deleted, f.aborted, asked)
	}
	f.mu.Unlock()

	if err := Clean(context.Background(), users); err != nil {
		t.Errorf("a second clean: %v", err)
	}
	f.mu.Lock()
	if len(f.deleted) != 1 || asked != 2 {
		t.Errorf("a second clean deleted or aborted again: %v, %d aborts asked", f.deleted, asked)
	}
	f.mu.Unlock()

	f.on("/api/fs/delete", func(w http.ResponseWriter, r *http.Request, _ map[string]any) bool {
		refuse(w, 403, "forbidden", "")
		return true
	})
	f.on("/api/upload/abort", func(w http.ResponseWriter, r *http.Request, _ map[string]any) bool {
		refuse(w, 404, "upload_not_found", "")
		return true
	})
	Run(context.Background(), Config{Users: users, Files: 2, Size: 10, Parallel: 1})
	err := Clean(context.Background(), users)
	if err == nil || !strings.Contains(err.Error(), "delete users/ann/ann-load-000-0000.bin: 403 forbidden") || !strings.Contains(err.Error(), "abort upload ann-load-000-0001.bin: 404 upload_not_found") {
		t.Errorf("refused deletes and aborts: %v", err)
	}

	f.on("/api/upload/list", func(w http.ResponseWriter, r *http.Request, _ map[string]any) bool {
		refuse(w, 503, "uploads_unavailable", "")
		return true
	})
	f.on("/api/fs/delete", nil)
	Run(context.Background(), Config{Users: users, Files: 1, Size: 10, Parallel: 1})
	err = Clean(context.Background(), users)
	f.mu.Lock()
	defer f.mu.Unlock()
	if err == nil || !strings.Contains(err.Error(), "list the uploads: 503 uploads_unavailable") || f.deleted[len(f.deleted)-1] != "ann users/ann/ann-load-000-0000.bin" {
		t.Errorf("a list refused: %v, deleted %v", err, f.deleted)
	}
}

// A completion that placed the file, or a create that opened an upload,
// whose answer was lost is cleaned up from the user's list of uploads.
func TestCleanFindsWhatLostItsAnswer(t *testing.T) {
	f := newFakeHTTPS(t, false)
	f.on("/api/upload/complete", func(w http.ResponseWriter, r *http.Request, body map[string]any) bool {
		f.mu.Lock()
		id := body["uploadId"].(string)
		f.complete(id, "users/ann/"+id)
		f.mu.Unlock()
		hangUp(w)
		return true
	})
	f.on("/api/upload/create", func(w http.ResponseWriter, r *http.Request, body map[string]any) bool {
		if body["name"] == "load-000-0001.bin" {
			f.mu.Lock()
			f.sessions["ann-lost"] = &fakeSession{user: "ann", state: "receiving"}
			f.mu.Unlock()
			hangUp(w)
			return true
		}
		return false
	})
	users := f.logIn(t, true, "ann")
	f.mu.Lock()
	f.sessions["ann-before"] = &fakeSession{user: "ann", state: "completed", path: "users/ann/before.bin"}
	f.sessions["bob-open"] = &fakeSession{user: "bob", state: "receiving"}
	f.mu.Unlock()
	res := Run(context.Background(), Config{Users: users, Files: 2, Size: 10, Parallel: 1})
	if res.CodeColumn() != "000x2" {
		t.Errorf("codes %s", res.CodeColumn())
	}
	// The second clean finds the same completed upload in the list, but no
	// longer as one of this run's.
	for range 2 {
		if err := Clean(context.Background(), users); err != nil {
			t.Fatal(err)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if strings.Join(f.deleted, ",") != "ann users/ann/ann-load-000-0000.bin" || strings.Join(f.aborted, ",") != "ann ann-lost" {
		t.Errorf("deleted %v, aborted %v", f.deleted, f.aborted)
	}
}

func TestTheClientsCallsSayWhatTheServerAnswered(t *testing.T) {
	f := newFakeHTTPS(t, true)
	api := f.logIn(t, false, "ann")[0].API
	ctx := context.Background()

	if _, err := api.Part(ctx, transfer.PartRequest{ID: "x", N: 1, SHA256: strings.Repeat("0", 64), Length: 3, Body: io.LimitReader(strings.NewReader("abcdef"), 3)}); err != nil {
		t.Errorf("a part from a reader of no known length: %v", err)
	}

	f.on("/api/upload/complete", func(w http.ResponseWriter, r *http.Request, _ map[string]any) bool {
		refuse(w, 500, "not_confirmed", `,"result":{"path":"users/ann/a.bin","size":3}`)
		return true
	})
	res, err := api.Complete(ctx, "ann-a.bin", strings.Repeat("0", 64))
	var rf *Refused
	if !errors.As(err, &rf) || rf.Status != 500 || rf.Code != "not_confirmed" || res.Path != "users/ann/a.bin" || res.Size != 3 {
		t.Errorf("a completion placed without its records: %+v, %v", res, err)
	}

	f.on("/api/upload/create", func(w http.ResponseWriter, r *http.Request, _ map[string]any) bool {
		w.WriteHeader(201)
		w.Write([]byte(`{"uploadId":`))
		return true
	})
	if _, err := api.Create(ctx, transfer.CreateRequest{Dir: "users/ann", Name: "b.bin", Size: 1}); err == nil || !strings.Contains(err.Error(), "the server's answer to /api/upload/create") {
		t.Errorf("an answer that isn't JSON: %v", err)
	}

	f.on("/api/upload/create", func(w http.ResponseWriter, r *http.Request, _ map[string]any) bool {
		w.WriteHeader(http.StatusTemporaryRedirect)
		w.Write([]byte(`{"uploadId":"ann-c.bin","partCount":1}`))
		return true
	})
	if _, err := api.Create(ctx, transfer.CreateRequest{Dir: "users/ann", Name: "c.bin", Size: 1}); status(err) != "307" {
		t.Errorf("a redirect without a place to go: %v", err)
	}
}

func TestAConnectionCutShortIsNoAnswer(t *testing.T) {
	f := newFakeHTTPS(t, false)
	f.on("/api/upload/part", func(w http.ResponseWriter, r *http.Request, _ map[string]any) bool {
		if r.URL.Query().Get("id") == "ann-load-000-0000.bin" {
			hangUp(w)
			return true
		}
		io.Copy(io.Discard, r.Body)
		c, buf, err := http.NewResponseController(w).Hijack()
		if err == nil {
			buf.WriteString("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{\"part\"")
			buf.Flush()
			c.Close()
		}
		return true
	})
	users := f.logIn(t, true, "ann")
	res := Run(context.Background(), Config{Users: users, Files: 2, Size: 10, Parallel: 1})
	if res.CodeColumn() != "000x2" {
		t.Errorf("codes %s", res.CodeColumn())
	}
}

// fakeEmpty uploads empty files, answering the first completion busy.
type fakeEmpty struct{ calls atomic.Int32 }

func (a *fakeEmpty) Create(context.Context, transfer.CreateRequest) (transfer.Created, error) {
	return transfer.Created{UploadID: "u", PartSize: 4}, nil
}

func (a *fakeEmpty) Part(context.Context, transfer.PartRequest) (transfer.PartResult, error) {
	return transfer.PartResult{}, errors.New("an empty file has no parts")
}

func (a *fakeEmpty) Complete(context.Context, string, string) (transfer.Result, error) {
	if a.calls.Add(1) == 1 {
		return transfer.Result{}, transfer.ErrBusy
	}
	return transfer.Result{Path: "x"}, nil
}

func TestAnEmptyFileRefusedBusyIsTriedAgain(t *testing.T) {
	done := make(chan Result, 1)
	go func() {
		done <- Run(context.Background(), Config{Users: []User{{API: &fakeEmpty{}, Dir: "d"}}, Files: 2, Size: 0, Parallel: 1})
	}()
	select {
	case res := <-done:
		if res.CodeColumn() != "201" || res.Retried["503"] != 1 || len(res.Parts) != 0 {
			t.Errorf("codes %s, retried %v", res.CodeColumn(), res.Retried)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run didn't return")
	}
}

func TestARetryCutShortIsNotCounted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	st := &userState{res: Result{Retried: map[string]int{}}}
	_, _, err := retry(ctx, retrier{st: st}, func() (int, error) {
		calls++
		cancel()
		return 0, transfer.ErrBusy
	})
	if !errors.Is(err, transfer.ErrBusy) || calls != 1 || len(st.res.Retried) != 0 {
		t.Errorf("%v after %d calls, retried %v", err, calls, st.res.Retried)
	}
}

func TestARefusalMatchesTheEnginesErrorOfItsStatusAndCode(t *testing.T) {
	for _, c := range []struct {
		r    *Refused
		err  *transfer.Error
		want bool
	}{
		{&Refused{Status: 503, Code: "busy"}, transfer.ErrBusy, true},
		{&Refused{Status: 429, Code: "too_many_requests"}, transfer.ErrTooManyRequests, true},
		{&Refused{Status: 409, Code: "part_in_progress"}, transfer.ErrPartInProgress, true},
		{&Refused{Status: 503, Code: "unavailable"}, transfer.ErrBusy, false},
		{&Refused{Status: 429, Code: "too_many_uploads"}, transfer.ErrTooManyRequests, false},
		{&Refused{Status: 500, Code: "busy"}, transfer.ErrBusy, false},
	} {
		if got := errors.Is(c.r, c.err); got != c.want {
			t.Errorf("%v is %v: %v", c.r, c.err.Code, got)
		}
	}
	if errors.Is(&Refused{Status: 503, Code: "busy"}, errors.New("busy")) {
		t.Error("a refusal matched an error that isn't the engine's")
	}
	if got := (&Refused{Status: 507, Code: "insufficient_storage", Message: "No space"}).Error(); got != "507 insufficient_storage: No space" {
		t.Errorf("message %q", got)
	}
	if status(fmt.Errorf("%w: reset", ErrNoAnswer)) != "000" || status(&Refused{Status: 507}) != "507" {
		t.Error("the statuses of the HTTPS client's errors")
	}
}

// A request to a server that takes no connection is no answer and was never
// sent; one cut off after it was sent is no answer only.
func TestANoAnswerSaysWhetherItConnected(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := l.Addr().String()
	l.Close()
	a := &remote{url: "https://" + closed, client: &http.Client{Transport: &http.Transport{}}, open: map[string]bool{}}
	_, err = a.Part(context.Background(), transfer.PartRequest{ID: "u", N: 1, Length: 1, Body: strings.NewReader("x")})
	if !errors.Is(err, ErrNoAnswer) || !errors.Is(err, ErrNotConnected) {
		t.Errorf("a refused connection: %v", err)
	}

	f := newFakeHTTPS(t, false)
	f.on("/api/upload/part", func(w http.ResponseWriter, r *http.Request, _ map[string]any) bool {
		if r.URL.Query().Get("id") == "reset" {
			// A reset, which the client reads as a network error of its own.
			c, _, err := http.NewResponseController(w).Hijack()
			if err == nil {
				if tc, ok := c.(*tls.Conn); ok {
					if tcp, ok := tc.NetConn().(*net.TCPConn); ok {
						tcp.SetLinger(0)
						tcp.Close()
						return true
					}
				}
				c.Close()
			}
			return true
		}
		hangUp(w)
		return true
	})
	users := f.logIn(t, true, "ann")
	for _, id := range []string{"u", "reset"} {
		_, err = users[0].API.Part(context.Background(), transfer.PartRequest{ID: id, N: 1, Length: 1, Body: strings.NewReader("x")})
		if !errors.Is(err, ErrNoAnswer) || errors.Is(err, ErrNotConnected) {
			t.Errorf("a connection cut short (%s): %v", id, err)
		}
	}
}
