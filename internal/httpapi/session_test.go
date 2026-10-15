package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/nobletk/gocalbox/internal/auth"
	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/fsops"
	"github.com/nobletk/gocalbox/internal/sandbox"
	"github.com/nobletk/gocalbox/internal/state"
)

const passphrase = "a long enough passphrase"

type authEnv struct {
	t    *testing.T
	srv  *httptest.Server
	acc  *auth.Accounts
	rec  *recorder
	root string
}

// newAuthEnv serves real accounts over HTTPS, so clients keep the Secure
// cookies in a jar as a browser does. Each of mods may change the
// configuration first.
func newAuthEnv(t *testing.T, mods ...func(*auth.Config, *Options)) *authEnv {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "root")
	os.Mkdir(root, 0o755)
	sb, err := sandbox.New(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sb.Close() })
	db, err := state.Open(filepath.Join(base, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	rec := &recorder{}
	files := fsops.New(sb, rec, fsops.WithRecords(db))
	cfg := auth.Config{
		DB: db, Hasher: auth.NewHasher(auth.Params{Memory: 64, Time: 1, Threads: 1}, 2, time.Second),
		Policy: auth.Policy{MinLength: 15}, Folders: files, Events: rec,
		FailureDelay: func(int) time.Duration { return 0 },
	}
	var opts Options
	for _, mod := range mods {
		mod(&cfg, &opts)
	}
	acc := auth.New(cfg)
	if err := acc.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { acc.Close() })
	files.SetPolicy(acc)
	opts.Accounts = acc
	srv := httptest.NewTLSServer(New(files, fstest.MapFS{"index.html": {Data: []byte("<html></html>")}}, opts))
	t.Cleanup(srv.Close)
	return &authEnv{t: t, srv: srv, acc: acc, rec: rec, root: sb.Root()}
}

func (e *authEnv) addUser(name string) {
	e.t.Helper()
	if _, err := e.acc.CreateUser(events.WithActor(context.Background(), events.Actor{ID: events.ConsoleID}), name, state.RoleAdmin, passphrase); err != nil {
		e.t.Fatal(err)
	}
}

func (e *authEnv) browser() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Transport:     e.srv.Client().Transport,
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// call sends body as JSON unless it is nil; headers are name, value pairs.
func (e *authEnv) call(c *http.Client, method, path string, body any, headers ...string) (*http.Response, string) {
	e.t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, e.srv.URL+path, r)
	if err != nil {
		e.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := c.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func (e *authEnv) login(c *http.Client, name string) {
	e.t.Helper()
	if resp, body := e.call(c, "POST", "/api/auth/login", LoginRequest{Username: name, Password: passphrase}); resp.StatusCode != 200 {
		e.t.Fatalf("login %s = %d %s", name, resp.StatusCode, body)
	}
}

func (e *authEnv) token(c *http.Client) string {
	u, _ := url.Parse(e.srv.URL)
	for _, ck := range c.Jar.Cookies(u) {
		if ck.Name == auth.SessionCookie {
			return ck.Value
		}
	}
	return ""
}

func setCookieFor(resp *http.Response, name string) string {
	for _, v := range resp.Header.Values("Set-Cookie") {
		if strings.HasPrefix(v, name+"=") {
			return v
		}
	}
	return ""
}

func isCleared(resp *http.Response) bool {
	v := setCookieFor(resp, auth.SessionCookie)
	return strings.HasPrefix(v, auth.SessionCookie+"=;") && strings.Contains(v, "Max-Age=0")
}

func errorCode(body string) string {
	var er ErrorResponse
	json.Unmarshal([]byte(body), &er)
	return er.Error.Code
}

func TestLoginSessionAndLogout(t *testing.T) {
	e := newAuthEnv(t)
	e.addUser("alice")
	os.WriteFile(filepath.Join(e.root, "a.txt"), []byte("hello"), 0o644)
	c := e.browser()

	resp, body := e.call(c, "GET", "/api/files?path=", nil)
	if resp.StatusCode != 401 || errorCode(body) != "unauthenticated" || resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("listing without a session = %d %s %v", resp.StatusCode, body, resp.Header)
	}
	resp, body = e.call(c, "GET", "/files/a.txt?x=1", nil, "Sec-Fetch-Mode", "navigate", "Sec-Fetch-Dest", "document")
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/?next=%2Ffiles%2Fa.txt%3Fx%3D1" || body != "" {
		t.Errorf("navigation without a session = %d to %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp, body = e.call(c, "POST", "/api/auth/login", LoginRequest{Username: "alice", Password: "wrong password entirely"}); resp.StatusCode != 401 || errorCode(body) != "invalid_credentials" {
		t.Errorf("wrong password = %d %s", resp.StatusCode, body)
	}

	resp, body = e.call(c, "POST", "/api/auth/login", LoginRequest{Username: "Alice", Password: passphrase})
	var me auth.Me
	if resp.StatusCode != 200 || json.Unmarshal([]byte(body), &me) != nil || me.Username != "alice" || me.ReauthUntil == nil {
		t.Fatalf("login = %d %s", resp.StatusCode, body)
	}
	session, device := setCookieFor(resp, auth.SessionCookie), setCookieFor(resp, auth.DeviceCookie)
	for _, attr := range []string{"Path=/", "HttpOnly", "Secure", "SameSite=Lax"} {
		if !strings.Contains(session, "; "+attr) {
			t.Errorf("session cookie %q lacks %s", session, attr)
		}
	}
	_, maxAge, _ := strings.Cut(session, "Max-Age=")
	if n, _ := strconv.Atoi(strings.Split(maxAge, ";")[0]); n < 30*24*3600-60 || n > 30*24*3600 {
		t.Errorf("session cookie Max-Age %d", n)
	}
	if !strings.Contains(device, "; SameSite=Strict") || !strings.Contains(device, "; Max-Age=34560000") || !strings.Contains(device, "; HttpOnly") {
		t.Errorf("device cookie %q", device)
	}

	if resp, body = e.call(c, "GET", "/files/a.txt", nil); resp.StatusCode != 200 || body != "hello" || resp.Header.Get("Cache-Control") != "private, no-cache" {
		t.Errorf("file after login = %d %s %q", resp.StatusCode, body, resp.Header.Get("Cache-Control"))
	}
	ev := e.rec.all()[len(e.rec.all())-1]
	if ev.Type != events.FileDownloaded || ev.Actor.Name != "alice" || ev.Actor.Role != "admin" || len(ev.Actor.Session) != 16 {
		t.Errorf("download event %+v", ev)
	}
	if resp, body = e.call(c, "GET", "/api/auth/me", nil); resp.StatusCode != 200 || !strings.Contains(body, `"username":"alice"`) {
		t.Errorf("me = %d %s", resp.StatusCode, body)
	}
	var list []auth.SessionInfo
	resp, body = e.call(c, "GET", "/api/auth/sessions", nil)
	if json.Unmarshal([]byte(body), &list) != nil || len(list) != 1 || !list[0].Current || list[0].ID != ev.Actor.Session {
		t.Errorf("sessions = %s", body)
	}

	resp, body = e.call(c, "POST", "/api/auth/logout", nil)
	if resp.StatusCode != 204 || resp.Header.Get("Clear-Site-Data") != `"cache"` || !isCleared(resp) {
		t.Errorf("logout = %d %s %v", resp.StatusCode, body, resp.Header)
	}
	if resp, _ = e.call(c, "GET", "/api/auth/me", nil); resp.StatusCode != 401 {
		t.Errorf("me after logout = %d", resp.StatusCode)
	}
}

func TestOnlyAnEndedSessionsCookieIsCleared(t *testing.T) {
	e := newAuthEnv(t)
	e.addUser("alice")
	for _, p := range []string{"/api/files?path=", "/"} {
		resp, _ := e.call(e.srv.Client(), "GET", p, nil, "Cookie", auth.SessionCookie+"=forged")
		if v := resp.Header.Values("Set-Cookie"); len(v) != 0 {
			t.Errorf("%s with a token of no session: Set-Cookie %q", p, v)
		}
	}
	resp, _ := e.call(e.srv.Client(), "POST", "/api/auth/login", LoginRequest{Username: "alice", Password: passphrase}, "Cookie", auth.SessionCookie+"=forged")
	if v := resp.Header.Values("Set-Cookie"); resp.StatusCode != 200 || len(v) != 2 || isCleared(resp) {
		t.Errorf("login with a forged cookie = %d, Set-Cookie %q", resp.StatusCode, v)
	}

	c := e.browser()
	e.login(c, "alice")
	before := e.token(c)
	if resp, body := e.call(c, "POST", "/api/auth/confirm", ConfirmRequest{Password: passphrase}); resp.StatusCode != 204 {
		t.Fatalf("confirm = %d %s", resp.StatusCode, body)
	}
	for _, p := range []string{"/api/auth/me", "/"} {
		if resp, _ := e.call(e.srv.Client(), "GET", p, nil, "Cookie", auth.SessionCookie+"="+before); isCleared(resp) {
			t.Errorf("%s with the token the renewal replaced cleared the cookie", p)
		}
	}
	if resp, _ := e.call(c, "GET", "/api/auth/me", nil); resp.StatusCode != 200 {
		t.Errorf("the renewed session after a request with the old token = %d", resp.StatusCode)
	}

	ctx := events.WithActor(context.Background(), events.Actor{ID: events.ConsoleID})
	if _, _, err := e.acc.SetPassword(ctx, "alice", "another long passphrase"); err != nil {
		t.Fatal(err)
	}
	if resp, _ := e.call(c, "GET", "/api/files?path=", nil); resp.StatusCode != 401 || !isCleared(resp) {
		t.Errorf("a session ended by a new password = %d, Set-Cookie %q", resp.StatusCode, resp.Header.Values("Set-Cookie"))
	}
}

func TestSetupLogsTheAdminIn(t *testing.T) {
	e := newAuthEnv(t)
	code, err := e.acc.StartSetup()
	if err != nil {
		t.Fatal(err)
	}
	c := e.browser()
	if resp, body := e.call(c, "GET", "/api/files?path=", nil); resp.StatusCode != 503 || errorCode(body) != "setup_required" {
		t.Errorf("before setup = %d %s", resp.StatusCode, body)
	}
	resp, body := e.call(c, "POST", "/api/setup", SetupRequest{Code: code, Username: "alice", Password: passphrase})
	if resp.StatusCode != 201 || setCookieFor(resp, auth.DeviceCookie) == "" {
		t.Fatalf("setup = %d %s", resp.StatusCode, body)
	}
	if resp, body = e.call(c, "GET", "/api/files?path=", nil); resp.StatusCode != 200 || !strings.Contains(body, `"public"`) {
		t.Errorf("listing after setup = %d %s", resp.StatusCode, body)
	}
}

func TestPasswordChangeEndsOtherSessions(t *testing.T) {
	e := newAuthEnv(t)
	e.addUser("alice")
	c1, c2 := e.browser(), e.browser()
	e.login(c1, "alice")
	e.login(c2, "alice")
	before := e.token(c1)

	resp, body := e.call(c1, "POST", "/api/auth/password", PasswordRequest{Current: passphrase, New: "short"})
	if resp.StatusCode != 400 || errorCode(body) != "weak_password" {
		t.Errorf("weak password = %d %s", resp.StatusCode, body)
	}
	resp, body = e.call(c1, "POST", "/api/auth/password", PasswordRequest{Current: passphrase, New: "another long passphrase"})
	if resp.StatusCode != 200 || strings.TrimSpace(body) != `{"revokedLinks":[]}` || setCookieFor(resp, auth.DeviceCookie) == "" {
		t.Fatalf("password change = %d %s", resp.StatusCode, body)
	}
	if e.token(c1) == before {
		t.Error("the token was not renewed")
	}
	if resp, _ = e.call(c1, "GET", "/api/auth/me", nil); resp.StatusCode != 200 {
		t.Errorf("this session after the change = %d", resp.StatusCode)
	}
	if resp, _ = e.call(c2, "GET", "/api/auth/me", nil); resp.StatusCode != 401 {
		t.Errorf("another session after the change = %d", resp.StatusCode)
	}
}

func TestConfirmRenewsTheTokenAndWrongPasswordsEndTheSession(t *testing.T) {
	e := newAuthEnv(t)
	e.addUser("alice")
	c := e.browser()
	e.login(c, "alice")
	before := e.token(c)
	if resp, body := e.call(c, "POST", "/api/auth/confirm", ConfirmRequest{Password: passphrase}); resp.StatusCode != 204 || e.token(c) == before {
		t.Fatalf("confirm = %d %s", resp.StatusCode, body)
	}
	if resp, _ := e.call(e.srv.Client(), "GET", "/api/auth/me", nil, "Cookie", auth.SessionCookie+"="+before); resp.StatusCode != 401 {
		t.Errorf("the old token = %d", resp.StatusCode)
	}
	for i := 1; i <= 5; i++ {
		resp, body := e.call(c, "POST", "/api/auth/confirm", ConfirmRequest{Password: "wrong password entirely"})
		want := "invalid_credentials"
		if i == 5 {
			want = "unauthenticated"
			if !isCleared(resp) {
				t.Error("the ended session's cookie was not cleared")
			}
		}
		if resp.StatusCode != 401 || errorCode(body) != want {
			t.Fatalf("wrong password %d = %d %s", i, resp.StatusCode, body)
		}
	}
	if resp, _ := e.call(c, "GET", "/api/auth/me", nil); resp.StatusCode != 401 {
		t.Errorf("after five wrong passwords = %d", resp.StatusCode)
	}
}

func TestSessionRevocation(t *testing.T) {
	e := newAuthEnv(t)
	e.addUser("alice")
	c1, c2, c3 := e.browser(), e.browser(), e.browser()
	e.login(c1, "alice")
	e.login(c2, "alice")

	var list []auth.SessionInfo
	_, body := e.call(c1, "GET", "/api/auth/sessions", nil)
	json.Unmarshal([]byte(body), &list)
	var current, other string
	for _, s := range list {
		if s.Current {
			current = s.ID
		} else {
			other = s.ID
		}
	}
	if resp, body := e.call(c1, "POST", "/api/auth/sessions/revoke", SessionRequest{ID: "ffffffffffffffff"}); resp.StatusCode != 404 || errorCode(body) != "not_found" {
		t.Errorf("revoking an unknown session = %d %s", resp.StatusCode, body)
	}
	if resp, _ := e.call(c1, "POST", "/api/auth/sessions/revoke", SessionRequest{ID: other}); resp.StatusCode != 204 || isCleared(resp) {
		t.Errorf("revoking another session = %d", resp.StatusCode)
	}
	if resp, _ := e.call(c2, "GET", "/api/auth/me", nil); resp.StatusCode != 401 {
		t.Errorf("revoked session = %d", resp.StatusCode)
	}

	e.login(c3, "alice")
	if resp, body := e.call(c1, "POST", "/api/auth/sessions/revoke-others", nil); resp.StatusCode != 200 || strings.TrimSpace(body) != `{"revokedLinks":[]}` {
		t.Errorf("revoke-others = %d %s", resp.StatusCode, body)
	}
	if resp, _ := e.call(c3, "GET", "/api/auth/me", nil); resp.StatusCode != 401 {
		t.Errorf("after sign-out everywhere else = %d", resp.StatusCode)
	}
	if resp, _ := e.call(c1, "POST", "/api/auth/sessions/revoke", SessionRequest{ID: current}); resp.StatusCode != 204 || !isCleared(resp) {
		t.Errorf("revoking the current session = %d %v", resp.StatusCode, resp.Header.Values("Set-Cookie"))
	}
	if resp, _ := e.call(c1, "GET", "/api/auth/me", nil); resp.StatusCode != 401 {
		t.Errorf("after revoking the current session = %d", resp.StatusCode)
	}
}

func TestRepeatedFailedLoginsGet429(t *testing.T) {
	e := newAuthEnv(t)
	e.addUser("alice")
	c := e.browser()
	for range 5 {
		e.call(c, "POST", "/api/auth/login", LoginRequest{Username: "alice", Password: "wrong password entirely"})
	}
	resp, body := e.call(c, "POST", "/api/auth/login", LoginRequest{Username: "alice", Password: passphrase})
	if resp.StatusCode != 429 || errorCode(body) != "too_many_attempts" || resp.Header.Get("Retry-After") != "1" {
		t.Errorf("sixth attempt = %d %s Retry-After %q", resp.StatusCode, body, resp.Header.Get("Retry-After"))
	}
}

var protectedRoutes = []struct{ method, path string }{
	{"GET", "/api/files?path="}, {"GET", "/files/a.txt"}, {"HEAD", "/files/a.txt"}, {"POST", "/api/upload"},
	{"POST", "/api/fs/delete"}, {"POST", "/api/fs/rename"}, {"POST", "/api/fs/move"}, {"POST", "/api/fs/mkdir"},
	{"POST", "/api/auth/logout"}, {"GET", "/api/auth/me"}, {"POST", "/api/auth/confirm"}, {"POST", "/api/auth/password"},
	{"GET", "/api/auth/sessions"}, {"POST", "/api/auth/sessions/revoke"}, {"POST", "/api/auth/sessions/revoke-others"},
	{"GET", "/api/unknown"}, {"GET", "/api"}, {"GET", "/files"}, {"GET", "/files/"},
}

func TestEveryRouteButThePublicOnesNeedsASession(t *testing.T) {
	e := newAuthEnv(t)
	os.WriteFile(filepath.Join(e.root, "a.txt"), []byte("hello"), 0o644)
	for _, r := range protectedRoutes {
		resp, _ := e.call(e.srv.Client(), r.method, r.path, map[string]string{})
		if resp.StatusCode != 401 {
			t.Errorf("%s %s = %d", r.method, r.path, resp.StatusCode)
		}
	}
	for _, r := range []struct{ method, path string }{{"GET", "/"}, {"GET", "/api/status"}} {
		if resp, _ := e.call(e.srv.Client(), r.method, r.path, nil); resp.StatusCode != 200 {
			t.Errorf("%s %s = %d", r.method, r.path, resp.StatusCode)
		}
	}
}

func TestWithoutAccountsEveryRouteIsRefused(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "a.txt"), []byte("hello"), 0o644)
	sb, err := sandbox.New(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sb.Close() })
	srv := httptest.NewServer(New(fsops.New(sb, nil), fstest.MapFS{"index.html": {Data: []byte("<html></html>")}}, Options{}))
	t.Cleanup(srv.Close)
	for _, r := range protectedRoutes {
		req, _ := http.NewRequest(r.method, srv.URL+r.path, strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: testToken})
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Errorf("%s %s = %d", r.method, r.path, resp.StatusCode)
		}
	}
	for path, want := range map[string]int{"/": 200, "/api/setup": 404, "/api/auth/login": 404} {
		resp, err := http.Post(srv.URL+path, "application/json", strings.NewReader("{}"))
		if path == "/" {
			resp, err = http.Get(srv.URL + path)
		}
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("%s = %d, want %d", path, resp.StatusCode, want)
		}
	}
}

func TestAuthErrors(t *testing.T) {
	for _, tc := range []struct {
		path       string
		err        error
		status     int
		code       string
		retryAfter string
	}{
		{"/api/auth/login", auth.ErrInvalidCredentials, 401, "invalid_credentials", ""},
		{"/api/auth/login", auth.ErrAccountDisabled, 403, "account_disabled", ""},
		{"/api/auth/login", auth.ErrPasswordDisabled, 403, "password_disabled", ""},
		{"/api/auth/login", &auth.TooManyAttemptsError{RetryAfter: 1500 * time.Millisecond}, 429, "too_many_attempts", "2"},
		{"/api/auth/login", &auth.TooManyAttemptsError{}, 429, "too_many_attempts", ""},
		{"/api/auth/login", auth.ErrBusy, 503, "busy", ""},
		{"/api/auth/confirm", auth.ErrSessionEnded, 401, "unauthenticated", ""},
		{"/api/auth/confirm", auth.ErrTooManyWrongPasswords, 401, "unauthenticated", ""},
		{"/api/auth/password", auth.ErrTooManyWrongPasswords, 401, "unauthenticated", ""},
		{"/api/auth/password", &auth.TooManyAttemptsError{RetryAfter: time.Minute}, 429, "too_many_attempts", "60"},
		{"/api/auth/sessions/revoke", auth.ErrNoSuchSession, 404, "not_found", ""},
		{"/api/auth/logout", errors.New("disk on fire"), 500, "internal", ""},
	} {
		e := newEnvOpts(t, Options{Accounts: &fakeAccounts{err: tc.err}})
		var body any = map[string]string{}
		switch tc.path {
		case "/api/auth/login":
			body = LoginRequest{Username: "alice", Password: "pw"}
		case "/api/auth/confirm":
			body = ConfirmRequest{Password: "pw"}
		case "/api/auth/password":
			body = PasswordRequest{Current: "pw", New: "pw2"}
		case "/api/auth/sessions/revoke":
			body = SessionRequest{ID: "x"}
		}
		b, _ := json.Marshal(body)
		resp := e.request("POST", tc.path, bytes.NewReader(b), map[string]string{"Content-Type": "application/json"})
		er := readErr(t, resp)
		if resp.StatusCode != tc.status || er.Error.Code != tc.code || resp.Header.Get("Retry-After") != tc.retryAfter {
			t.Errorf("%s %v: %d %+v Retry-After %q", tc.path, tc.err, resp.StatusCode, er, resp.Header.Get("Retry-After"))
		}
		if cleared := isCleared(resp); cleared != (tc.err == auth.ErrTooManyWrongPasswords) {
			t.Errorf("%s %v: cookie cleared %v", tc.path, tc.err, cleared)
		}
	}
}

func TestLoginPassesTheClientOn(t *testing.T) {
	acc := &fakeAccounts{}
	e := newEnvOpts(t, Options{Accounts: acc})
	resp := e.request("POST", "/api/auth/login", strings.NewReader(`{"username":"alice","password":"pw"}`), map[string]string{
		"Content-Type": "application/json", "User-Agent": "TestBrowser/2.0",
		"Cookie": auth.DeviceCookie + "=u-1.2.mac; " + auth.SessionCookie + "=old-token",
	})
	if resp.StatusCode != 200 || len(acc.clients) != 1 {
		t.Fatalf("login = %d", resp.StatusCode)
	}
	if c := acc.clients[0]; c.Device != "u-1.2.mac" || c.Token != "old-token" || c.UserAgent != "TestBrowser/2.0" || !strings.HasPrefix(c.Addr, "127.0.0.1:") {
		t.Errorf("client = %+v", c)
	}
}

func TestAPIResponsesAreNotStored(t *testing.T) {
	e := newEnv(t, 0)
	e.write("a.txt", "x")
	for path, want := range map[string]string{
		"/api/status": "no-store", "/api/files?path=": "no-store", "/api/nothing": "no-store",
		"/files/a.txt": "private, no-cache", "/": "",
	} {
		if got := e.request("GET", path, nil, nil).Header.Get("Cache-Control"); got != want {
			t.Errorf("%s: Cache-Control %q, want %q", path, got, want)
		}
	}
}
