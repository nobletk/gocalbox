package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nobletk/gocalbox/internal/auth"
	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/fsops"
)

type fakeAuditor struct {
	mu        sync.Mutex
	paused    bool
	fail      error
	budgets   int // records whose request had one limit for its waits
	unbudgets int
}

func (f *fakeAuditor) Allow() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.paused {
		return fmt.Errorf("%w: disk full", events.ErrChangesPaused)
	}
	return nil
}

func (f *fakeAuditor) Record(ctx context.Context, _ ...events.Event) error {
	events.Waited(ctx, time.Minute)
	shared := events.WaitLeft(ctx, time.Hour) == 59*time.Minute
	f.mu.Lock()
	defer f.mu.Unlock()
	if shared {
		f.budgets++
	} else {
		f.unbudgets++
	}
	return f.fail
}

func (f *fakeAuditor) RecordProtective(ctx context.Context, evs ...events.Event) error {
	return f.Record(ctx, evs...)
}

func TestPausedChangesAnswer503WhileReadsGoOn(t *testing.T) {
	a := &fakeAuditor{paused: true}
	e := newEnvOpts(t, Options{}, fsops.WithAudit(a))
	e.write("a.txt", "A")
	e.write("dir/b.txt", "B")

	for _, tc := range []struct {
		name string
		do   func() (int, string)
	}{
		{"upload", func() (int, string) { return e.upload("", "new.txt", "N") }},
		{"mkdir", func() (int, string) { return e.postJSON("/api/fs/mkdir", CreateFolderRequest{Name: "new"}) }},
		{"delete", func() (int, string) { return e.postJSON("/api/fs/delete", DeleteRequest{Path: "a.txt"}) }},
		{"rename", func() (int, string) {
			return e.postJSON("/api/fs/rename", MoveRequest{OldPath: "a.txt", NewPath: "c.txt"})
		}},
		{"move", func() (int, string) { return e.postJSON("/api/fs/move", MoveRequest{OldPath: "dir", NewPath: "moved"}) }},
	} {
		code, body := tc.do()
		er := decode[ErrorResponse](t, body)
		if code != http.StatusServiceUnavailable || er.Error.Code != "changes_paused" || er.Result != nil {
			t.Errorf("%s while paused = %d %s", tc.name, code, body)
		}
	}
	if e.exists(filepath.Join(e.root, "new.txt")) || e.exists(filepath.Join(e.root, "new")) || !e.exists(filepath.Join(e.root, "a.txt")) || e.exists(filepath.Join(e.root, "c.txt")) || e.exists(filepath.Join(e.root, "moved")) {
		t.Error("a change was made while changes are paused")
	}

	if code, files, _ := e.list(""); code != 200 || len(files) != 2 {
		t.Errorf("list while paused = %d %+v", code, files)
	}
	if code, body := e.do("GET", "/files/a.txt", nil, ""); code != 200 || body != "A" {
		t.Errorf("download while paused = %d %q", code, body)
	}
	if code, _ := e.do("GET", "/", nil, ""); code != 200 {
		t.Errorf("UI while paused = %d", code)
	}
}

func TestUnrecordedChangesAnswer500WithTheirResult(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code string
	}{
		{fmt.Errorf("%w: disk full", events.ErrNotRecorded), "not_recorded"},
		{fmt.Errorf("%w within 10s", events.ErrNotConfirmed), "not_confirmed"},
	} {
		t.Run(tc.code, func(t *testing.T) {
			a := &fakeAuditor{fail: tc.err}
			e := newEnvOpts(t, Options{}, fsops.WithAudit(a))
			e.write("a.txt", "A")

			check := func(what string, code int, body string, want PathResponse) {
				t.Helper()
				er := decode[ErrorResponse](t, body)
				res, _ := er.Result.(map[string]any)
				if code != http.StatusInternalServerError || er.Error.Code != tc.code || res == nil ||
					res["path"] != want.Path || (want.Name != "" && res["name"] != want.Name) || (want.Size != 0 && res["size"] != float64(want.Size)) {
					t.Errorf("%s = %d %s", what, code, body)
				}
				if !strings.Contains(er.Error.Message, "The change was made") {
					t.Errorf("%s: message %q", what, er.Error.Message)
				}
			}
			code, body := e.upload("", "a.txt", "NEW")
			check("upload", code, body, PathResponse{Path: "a (1).txt", Name: "a (1).txt", Size: 3})
			code, body = e.postJSON("/api/fs/mkdir", CreateFolderRequest{Name: "dir"})
			check("mkdir", code, body, PathResponse{Path: "dir"})
			code, body = e.postJSON("/api/fs/move", MoveRequest{OldPath: "a.txt", NewPath: "dir/a.txt"})
			check("move", code, body, PathResponse{Path: "dir/a.txt"})
			code, body = e.postJSON("/api/fs/delete", DeleteRequest{Path: "dir/a.txt"})
			check("delete", code, body, PathResponse{Path: "dir/a.txt"})
			if !e.exists(filepath.Join(e.root, "a (1).txt")) || !e.exists(filepath.Join(e.root, "dir")) || e.exists(filepath.Join(e.root, "dir/a.txt")) || e.exists(filepath.Join(e.root, "a.txt")) {
				t.Error("the changes weren't all made")
			}
			if a.budgets != 4 || a.unbudgets != 0 {
				t.Errorf("%d of 4 requests had a limit of their own for their waits", a.budgets)
			}
		})
	}
}

// unrecordedAccounts makes every change it is asked for, but its record
// fails.
type unrecordedAccounts struct {
	*fakeAccounts
	err error
}

func (u unrecordedAccounts) CompleteSetup(ctx context.Context, req auth.SetupRequest, c auth.Client) (auth.Grant, error) {
	g, _ := u.fakeAccounts.CompleteSetup(ctx, req, c)
	return g, u.err
}

func (u unrecordedAccounts) Login(ctx context.Context, name, pw string, c auth.Client) (auth.Grant, error) {
	g, _ := u.fakeAccounts.Login(ctx, name, pw, c)
	return g, u.err
}

func (u unrecordedAccounts) ChangePassword(ctx context.Context, id auth.Identity, cur, next string, c auth.Client) (auth.Grant, []auth.RevokedLink, error) {
	g, links, _ := u.fakeAccounts.ChangePassword(ctx, id, cur, next, c)
	return g, links, u.err
}

func (u unrecordedAccounts) RevokeSession(context.Context, auth.Identity, string) error { return u.err }

func (u unrecordedAccounts) RevokeOtherSessions(context.Context, auth.Identity) ([]auth.RevokedLink, error) {
	return []auth.RevokedLink{}, u.err
}

func TestUnrecordedAccountChangesKeepTheirCookiesAndResult(t *testing.T) {
	acc := unrecordedAccounts{&fakeAccounts{required: true}, fmt.Errorf("%w: disk full", events.ErrNotRecorded)}
	e := newEnvOpts(t, Options{Accounts: acc})

	for _, tc := range []struct {
		path    string
		body    any
		cookie  bool // the change sets the session cookie
		cleared bool // the change clears it
		result  string
	}{
		{"/api/setup", map[string]any{"code": "C", "username": "alice", "password": "pw"}, true, false, `"username":"alice"`},
		{"/api/auth/login", LoginRequest{Username: "alice", Password: "pw"}, true, false, `"username":"alice"`},
		{"/api/auth/password", PasswordRequest{Current: "a", New: "b"}, true, false, `"revokedLinks":[]`},
		{"/api/auth/sessions/revoke-others", nil, false, false, `"revokedLinks":[]`},
		{"/api/auth/sessions/revoke", SessionRequest{ID: tester.Session.ID}, false, true, ""},
	} {
		var resp *http.Response
		if tc.body == nil {
			resp = e.request("POST", tc.path, nil, nil)
		} else {
			resp = e.request("POST", tc.path, strings.NewReader(mustJSON(t, tc.body)), map[string]string{"Content-Type": "application/json"})
		}
		er := readErr(t, resp)
		resp.Body.Close()
		if resp.StatusCode != http.StatusInternalServerError || er.Error.Code != "not_recorded" {
			t.Errorf("%s = %d %+v", tc.path, resp.StatusCode, er)
		}
		if got := mustJSON(t, er.Result); tc.result != "" && !strings.Contains(got, tc.result) {
			t.Errorf("%s: result %s", tc.path, got)
		}
		cookies := strings.Join(resp.Header.Values("Set-Cookie"), "\n")
		if tc.cookie != strings.Contains(cookies, auth.SessionCookie+"=new-token") {
			t.Errorf("%s: cookies %q", tc.path, cookies)
		}
		if tc.cleared != strings.Contains(cookies, "Max-Age=0") {
			t.Errorf("%s: cookies %q", tc.path, cookies)
		}
	}
}

func TestStatusTellsOnlyALoggedInUserWhetherChangesArePaused(t *testing.T) {
	paused := true
	e := newEnvOpts(t, Options{ChangesPaused: func() bool { return paused }})
	if code, body := e.do("GET", "/api/status", nil, ""); code != 200 || strings.TrimSpace(body) != `{"setupRequired":false,"changesPaused":true}` {
		t.Errorf("status = %d %s", code, body)
	}
	resp := e.request("GET", "/api/status", nil, map[string]string{"Cookie": auth.SessionCookie + "=unknown"})
	if body := mustRead(t, resp); strings.TrimSpace(body) != `{"setupRequired":false}` {
		t.Errorf("status without a session = %s", body)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func mustRead(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
