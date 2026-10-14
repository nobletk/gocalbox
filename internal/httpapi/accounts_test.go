package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/nobletk/gocalbox/internal/auth"
	"github.com/nobletk/gocalbox/internal/state"
)

type fakeAccounts struct {
	mu       sync.Mutex
	required bool
	err      error
	got      []auth.SetupRequest
}

func (f *fakeAccounts) SetupRequired() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.required
}

func (f *fakeAccounts) CompleteSetup(_ context.Context, req auth.SetupRequest) (auth.Me, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.got = append(f.got, req)
	if f.err != nil {
		return auth.Me{}, f.err
	}
	f.required = false
	return auth.Me{ID: "u-1", Username: req.Username, Role: state.RoleAdmin, Home: "users/" + req.Username, Bindings: []auth.MeBinding{}}, nil
}

func TestSetupModeHoldsBackFilesAndAPI(t *testing.T) {
	acc := &fakeAccounts{required: true}
	e := newEnvOpts(t, Options{Accounts: acc})
	e.write("secret.txt", "data")

	for _, tc := range []struct{ method, path string }{
		{"GET", "/api/files?path="},
		{"GET", "/files/secret.txt"},
		{"POST", "/api/fs/delete"},
		{"POST", "/api/upload"},
		{"GET", "/api/unknown"},
		{"GET", "/api"},
		{"GET", "/files"},
	} {
		code, body := e.do(tc.method, tc.path, strings.NewReader("{}"), "application/json")
		if code != http.StatusServiceUnavailable || !strings.Contains(body, `"setup_required"`) {
			t.Errorf("%s %s = %d %s", tc.method, tc.path, code, body)
		}
	}
	if code, _ := e.do("GET", "/", nil, ""); code != 200 {
		t.Errorf("UI shell = %d", code)
	}
	if code, body := e.do("GET", "/api/status", nil, ""); code != 200 || strings.TrimSpace(body) != `{"setupRequired":true}` {
		t.Errorf("status = %d %s", code, body)
	}

	code, body := e.postJSON("/api/setup", map[string]any{"code": "C", "username": "alice", "password": "pw", "useExisting": true})
	if code != http.StatusCreated {
		t.Fatalf("setup = %d %s", code, body)
	}
	var me auth.Me
	if err := json.Unmarshal([]byte(body), &me); err != nil || me.Username != "alice" || me.Role != state.RoleAdmin {
		t.Errorf("me = %+v, %v", me, err)
	}
	if len(acc.got) != 1 || acc.got[0] != (auth.SetupRequest{Code: "C", Username: "alice", Password: "pw", UseExisting: true}) {
		t.Errorf("request passed on = %+v", acc.got)
	}
	if code, body := e.do("GET", "/files/secret.txt", nil, ""); code != 200 || body != "data" {
		t.Errorf("after setup: %d %s", code, body)
	}
	if code, body := e.do("GET", "/api/status", nil, ""); code != 200 || strings.TrimSpace(body) != `{"setupRequired":false}` {
		t.Errorf("status after setup = %d %s", code, body)
	}
}

func TestSetupErrors(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
		code   string
	}{
		{auth.ErrSetupCodeInvalid, 403, "setup_code_invalid"},
		{auth.ErrSetupDone, 409, "setup_done"},
		{&auth.LayoutExistsError{Paths: []string{"users", "public"}}, 409, "layout_exists"},
		{auth.ErrHomeExists, 409, "home_exists"},
		{auth.ErrInvalidUsername, 400, "invalid_username"},
		{auth.ErrUsernameTaken, 409, "username_taken"},
		{&auth.WeakPasswordError{Reason: "too_short", Message: "the password needs at least 15 characters, not 3"}, 400, "weak_password"},
		{auth.ErrBusy, 503, "busy"},
		{errors.New("disk on fire"), 500, "internal"},
	} {
		e := newEnvOpts(t, Options{Accounts: &fakeAccounts{required: true, err: tc.err}})
		code, body := e.postJSON("/api/setup", map[string]any{"code": "C", "username": "alice", "password": "pw"})
		if code != tc.status || !strings.Contains(body, `"`+tc.code+`"`) {
			t.Errorf("%v: %d %s", tc.err, code, body)
		}
		if tc.code == "layout_exists" && !strings.Contains(body, "users, public") {
			t.Errorf("layout_exists does not name the folders: %s", body)
		}
		if tc.code == "weak_password" && !strings.Contains(body, "at least 15 characters") {
			t.Errorf("weak_password gives no reason: %s", body)
		}
	}
}

func TestSetupRequestValidation(t *testing.T) {
	acc := &fakeAccounts{required: true}
	e := newEnvOpts(t, Options{Accounts: acc})
	if code, _ := e.do("GET", "/api/setup", nil, ""); code != http.StatusMethodNotAllowed {
		t.Errorf("GET /api/setup = %d", code)
	}
	if code, _ := e.postJSON("/api/setup", map[string]any{"code": "C", "username": "a", "password": "p", "role": "admin"}); code != 400 {
		t.Errorf("unknown field = %d", code)
	}
	if code, _ := e.do("POST", "/api/setup", strings.NewReader(`code=C`), "application/x-www-form-urlencoded"); code != http.StatusUnsupportedMediaType {
		t.Errorf("form body = %d", code)
	}
	if len(acc.got) != 0 {
		t.Error("an invalid request reached CompleteSetup")
	}
}

func TestSetupIsRefusedCrossOrigin(t *testing.T) {
	acc := &fakeAccounts{required: true}
	e := newEnvOpts(t, Options{Accounts: acc})
	req, _ := http.NewRequest("POST", e.srv.URL+"/api/setup", strings.NewReader(`{"code":"C","username":"alice","password":"pw"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || len(acc.got) != 0 {
		t.Errorf("cross-site setup = %d, reached service: %v", resp.StatusCode, len(acc.got) != 0)
	}
}

func TestWithoutAccountsThereIsNoSetupRoute(t *testing.T) {
	e := newEnv(t, 0)
	if code, _ := e.postJSON("/api/setup", map[string]any{"code": "C"}); code != http.StatusNotFound {
		t.Errorf("POST /api/setup = %d", code)
	}
}
