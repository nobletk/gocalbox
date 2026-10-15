package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nobletk/gocalbox/internal/auth"
	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/state"
)

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// newAdminEnv serves accounts on a clock the test moves, with alice as an
// admin logged in, and target as what new links tell.
func newAdminEnv(t *testing.T, target func() LinkTarget, mods ...func(*auth.Config, *Options)) (*authEnv, *http.Client, *testClock) {
	t.Helper()
	clk := &testClock{t: time.Now().UTC().Round(0)}
	e := newAuthEnv(t, append([]func(*auth.Config, *Options){func(c *auth.Config, o *Options) {
		c.Now = clk.now
		o.LinkTarget = target
	}}, mods...)...)
	e.addUserAs("alice", state.RoleAdmin)
	alice := e.browser()
	e.login(alice, "alice")
	return e, alice, clk
}

// userID looks a user up through an admin's client.
func (e *authEnv) userID(admin *http.Client, name string) string {
	e.t.Helper()
	resp, body := e.call(admin, "GET", "/api/admin/users/list", nil)
	if resp.StatusCode == http.StatusOK {
		for _, u := range decode[[]auth.UserInfo](e.t, body) {
			if u.Username == name {
				return u.ID
			}
		}
	}
	e.t.Fatalf("no user %s: %d %s", name, resp.StatusCode, body)
	return ""
}

func adminRoutes() []route {
	var out []route
	for _, rt := range allRoutes() {
		if rt.access == accessAdmin {
			out = append(out, rt)
		}
	}
	return out
}

func readsOnly(pattern string) bool { return strings.HasSuffix(pattern, "/list") }

func TestAdminRoutesAnswerOnlyAdmins(t *testing.T) {
	e, alice, clk := newAdminEnv(t, nil)
	e.addUserAs("bob", state.RoleContributor)
	bob := e.browser()
	e.login(bob, "bob")
	if n := len(adminRoutes()); n != 12 {
		t.Errorf("%d admin routes", n)
	}
	request := func(pattern string) any {
		switch pattern {
		case "/api/admin/invites/create":
			return InviteCreateRequest{Role: "viewer"}
		case "/api/admin/bindings/create":
			return BindingCreateRequest{Subject: "*", Folder: "public", Role: "viewer"}
		}
		return IDRequest{ID: e.userID(alice, "bob")}
	}
	changes := 0
	for _, rt := range adminRoutes() {
		method, body := http.MethodGet, any(nil)
		if !readsOnly(rt.pattern) {
			method, body = http.MethodPost, request(rt.pattern)
			changes++
		}
		resp, got := e.call(bob, method, rt.pattern, body)
		if resp.StatusCode != http.StatusForbidden || errorCode(got) != "forbidden" {
			t.Errorf("a contributor's %s %s = %d %s", method, rt.pattern, resp.StatusCode, got)
		}
	}
	denied := 0
	for _, ev := range e.rec.all() {
		if ev.Outcome == events.OutcomeDenied && ev.Actor.Name == "bob" {
			denied++
		}
	}
	if changes != 8 || denied != changes {
		t.Errorf("%d of a contributor's %d admin changes were recorded as denied", denied, changes)
	}
	resp, body := e.call(alice, "GET", "/api/admin/users/list", nil)
	if resp.StatusCode != 200 || !strings.Contains(body, `"username":"bob"`) || strings.Contains(body, "argon2") || resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("users list = %d %s", resp.StatusCode, body)
	}

	clk.advance(15 * time.Minute)
	for _, rt := range adminRoutes() {
		if readsOnly(rt.pattern) {
			if resp, body := e.call(alice, "GET", rt.pattern, nil); resp.StatusCode != 200 {
				t.Errorf("%s outside the reauth window = %d %s", rt.pattern, resp.StatusCode, body)
			}
			continue
		}
		resp, body := e.call(alice, "POST", rt.pattern, request(rt.pattern))
		if resp.StatusCode != http.StatusForbidden || errorCode(body) != "reauth_required" {
			t.Errorf("%s outside the reauth window = %d %s", rt.pattern, resp.StatusCode, body)
		}
	}
	if resp, body := e.call(alice, "POST", "/api/auth/confirm", ConfirmRequest{Password: passphrase}); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("confirm = %d %s", resp.StatusCode, body)
	}
	if resp, body := e.call(alice, "POST", "/api/admin/invites/create", InviteCreateRequest{Role: "viewer"}); resp.StatusCode != http.StatusCreated {
		t.Errorf("invite after confirming = %d %s", resp.StatusCode, body)
	}
}

func TestAnInviteOverHTTP(t *testing.T) {
	target := LinkTarget{Address: "https://192.168.1.20:8443", CAFingerprint: "AB:CD:EF"}
	e, alice, _ := newAdminEnv(t, func() LinkTarget { return target })
	resp, body := e.call(alice, "POST", "/api/admin/invites/create", InviteCreateRequest{Role: "contributor", Note: "Bob's phone"})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create = %d %s", resp.StatusCode, body)
	}
	l := decode[NewLinkResponse](t, body)
	if l.Kind != "invite" || l.Role != "contributor" || len(l.Token) != 26 || l.Address == nil || *l.Address != target.Address ||
		l.CAFingerprint == nil || *l.CAFingerprint != target.CAFingerprint || l.Expires.IsZero() {
		t.Errorf("new link %s", body)
	}

	bob := e.browser()
	resp, body = e.call(bob, "POST", "/api/invite/inspect", TokenRequest{Token: l.Token})
	var info map[string]any
	json.Unmarshal([]byte(body), &info)
	if resp.StatusCode != 200 || info["role"] != "contributor" || info["username"] != "" || info["expires"] == nil {
		t.Errorf("inspect = %d %s", resp.StatusCode, body)
	}
	for _, tc := range []struct {
		req    InviteAcceptRequest
		status int
		code   string
	}{
		{InviteAcceptRequest{Token: "wrong", Username: "bob", Password: passphrase}, 403, "link_invalid"},
		{InviteAcceptRequest{Token: l.Token, Username: "b", Password: passphrase}, 400, "invalid_username"},
		{InviteAcceptRequest{Token: l.Token, Username: "bob", Password: "short"}, 400, "weak_password"},
		{InviteAcceptRequest{Token: l.Token, Username: "alice", Password: passphrase}, 409, "username_taken"},
	} {
		if resp, body := e.call(bob, "POST", "/api/invite/accept", tc.req); resp.StatusCode != tc.status || errorCode(body) != tc.code {
			t.Errorf("accept %+v = %d %s", tc.req, resp.StatusCode, body)
		}
	}
	os.MkdirAll(filepath.Join(e.root, "users", "dan", "old"), 0o755)
	if resp, body := e.call(bob, "POST", "/api/invite/accept", InviteAcceptRequest{Token: l.Token, Username: "dan", Password: passphrase}); resp.StatusCode != 409 || errorCode(body) != "home_exists" {
		t.Errorf("accept onto an existing folder = %d %s", resp.StatusCode, body)
	}

	resp, body = e.call(bob, "POST", "/api/invite/accept", InviteAcceptRequest{Token: l.Token, Username: "Bob", Password: passphrase})
	me := decode[auth.Me](t, body)
	if resp.StatusCode != http.StatusCreated || me.Username != "bob" || me.Role != state.RoleContributor || me.Home != "users/bob" {
		t.Fatalf("accept = %d %s", resp.StatusCode, body)
	}
	if resp, body := e.call(bob, "GET", "/api/auth/me", nil); resp.StatusCode != 200 || decode[auth.Me](t, body).Username != "bob" {
		t.Errorf("me after accepting = %d %s", resp.StatusCode, body)
	}
	if resp, body := e.call(e.browser(), "POST", "/api/invite/accept", InviteAcceptRequest{Token: l.Token, Username: "carol", Password: passphrase}); resp.StatusCode != 403 || errorCode(body) != "link_invalid" {
		t.Errorf("second accept = %d %s", resp.StatusCode, body)
	}
}

// The suggested address is null when the server knows none, and so is the
// fingerprint with a certificate from -tls-cert.
func TestALinksAddressIsNullWhenUnknown(t *testing.T) {
	for name, target := range map[string]func() LinkTarget{
		"no target":   nil,
		"none known":  func() LinkTarget { return LinkTarget{} },
		"no local CA": func() LinkTarget { return LinkTarget{Address: "https://files.example"} },
	} {
		t.Run(name, func(t *testing.T) {
			e, alice, _ := newAdminEnv(t, target)
			e.addUserAs("bob", state.RoleViewer)
			resp, body := e.call(alice, "POST", "/api/admin/users/reset-link", IDRequest{ID: e.userID(alice, "bob")})
			if resp.StatusCode != http.StatusCreated {
				t.Fatalf("reset link = %d %s", resp.StatusCode, body)
			}
			wantAddress := `"address":null`
			if target != nil && target().Address != "" {
				wantAddress = `"address":"https://files.example"`
			}
			if !strings.Contains(body, wantAddress) || !strings.Contains(body, `"caFingerprint":null`) {
				t.Errorf("reset link %s", body)
			}
		})
	}
}

func TestAResetOverHTTP(t *testing.T) {
	e, alice, _ := newAdminEnv(t, nil)
	e.addUserAs("bob", state.RoleContributor)
	bobID := e.userID(alice, "bob")
	old := e.browser()
	e.login(old, "bob")

	resp, body := e.call(alice, "POST", "/api/admin/users/reset-link", IDRequest{ID: bobID})
	l := decode[NewLinkResponse](t, body)
	if resp.StatusCode != http.StatusCreated || l.Kind != "reset" || l.Username != "bob" || l.Role != "" {
		t.Fatalf("reset link = %d %s", resp.StatusCode, body)
	}
	fresh := e.browser()
	if resp, body := e.call(fresh, "POST", "/api/reset/inspect", TokenRequest{Token: l.Token}); resp.StatusCode != 200 || !strings.Contains(body, `"username":"bob"`) {
		t.Errorf("inspect = %d %s", resp.StatusCode, body)
	}
	if resp, body := e.call(fresh, "POST", "/api/invite/inspect", TokenRequest{Token: l.Token}); resp.StatusCode != 403 || errorCode(body) != "link_invalid" {
		t.Errorf("a reset token at the invite endpoint = %d %s", resp.StatusCode, body)
	}
	if resp, body := e.call(fresh, "POST", "/api/reset/accept", ResetAcceptRequest{Token: l.Token, Password: "short"}); resp.StatusCode != 400 || errorCode(body) != "weak_password" {
		t.Errorf("a weak password = %d %s", resp.StatusCode, body)
	}
	resp, body = e.call(fresh, "POST", "/api/reset/accept", ResetAcceptRequest{Token: l.Token, Password: passphrase + " new"})
	if resp.StatusCode != 200 || !strings.Contains(body, `"username":"bob"`) || !strings.Contains(body, `"revokedLinks":[]`) {
		t.Fatalf("accept = %d %s", resp.StatusCode, body)
	}
	if resp, _ := e.call(fresh, "GET", "/api/auth/me", nil); resp.StatusCode != 200 {
		t.Errorf("the new session = %d", resp.StatusCode)
	}
	if resp, _ := e.call(old, "GET", "/api/auth/me", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("the session from before the reset = %d", resp.StatusCode)
	}

	resp, body = e.call(alice, "POST", "/api/admin/users/update", UserUpdateRequest{ID: bobID, Disabled: new(true)})
	if resp.StatusCode != 200 || !strings.Contains(body, `"disabled":true`) {
		t.Errorf("disable = %d %s", resp.StatusCode, body)
	}
	if resp, body := e.call(alice, "POST", "/api/admin/users/reset-link", IDRequest{ID: bobID}); resp.StatusCode != 409 || errorCode(body) != "user_disabled" {
		t.Errorf("a reset link for a disabled user = %d %s", resp.StatusCode, body)
	}
	if resp, _ := e.call(fresh, "GET", "/api/auth/me", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("a disabled user's session = %d", resp.StatusCode)
	}
}

func TestAdminErrorCodes(t *testing.T) {
	e, alice, _ := newAdminEnv(t, nil)
	e.addUserAs("bob", state.RoleContributor)
	aliceID, bobID := e.userID(alice, "alice"), e.userID(alice, "bob")
	os.Mkdir(filepath.Join(e.root, "shared"), 0o755)
	if resp, body := e.call(alice, "POST", "/api/admin/bindings/create", BindingCreateRequest{Subject: bobID, Folder: "shared", Role: "viewer"}); resp.StatusCode != 201 {
		t.Fatalf("bind = %d %s", resp.StatusCode, body)
	}
	e.acc.EnsureLayout(t.Context())
	var home string
	_, body := e.call(alice, "GET", "/api/admin/bindings/list", nil)
	for _, b := range decode[[]auth.BindingInfo](t, body) {
		if b.Kind == state.KindHome {
			home = b.ID
		}
	}

	for _, tc := range []struct {
		path   string
		body   any
		status int
		code   string
	}{
		{"/api/admin/users/update", UserUpdateRequest{ID: aliceID, Role: new("viewer")}, 409, "last_admin"},
		{"/api/admin/users/update", UserUpdateRequest{ID: aliceID, Disabled: new(true)}, 409, "last_admin"},
		{"/api/admin/users/delete", IDRequest{ID: aliceID}, 409, "last_admin"},
		{"/api/admin/users/update", UserUpdateRequest{ID: bobID, Role: new("owner")}, 400, "invalid_role"},
		{"/api/admin/users/update", UserUpdateRequest{ID: "u-0000000000000000", Disabled: new(true)}, 404, "not_found"},
		{"/api/admin/users/update", map[string]any{"id": bobID, "admin": true}, 400, "invalid_body"},
		{"/api/admin/users/delete", IDRequest{ID: "u-0000000000000000"}, 404, "not_found"},
		{"/api/admin/users/reset-link", IDRequest{ID: "u-0000000000000000"}, 404, "not_found"},
		{"/api/admin/invites/create", InviteCreateRequest{Role: "viewer", Note: "a\nb"}, 400, "invalid_note"},
		{"/api/admin/invites/create", InviteCreateRequest{Role: "root"}, 400, "invalid_role"},
		{"/api/admin/invites/create", InviteCreateRequest{Role: "viewer", Username: "Alice"}, 409, "username_taken"},
		{"/api/admin/invites/create", InviteCreateRequest{Role: "viewer", Username: "-x-"}, 400, "invalid_username"},
		{"/api/admin/links/revoke", IDRequest{ID: "missing"}, 404, "not_found"},
		{"/api/admin/bindings/create", BindingCreateRequest{Subject: bobID, Folder: "shared", Role: "contributor"}, 409, "already_exists"},
		{"/api/admin/bindings/create", BindingCreateRequest{Subject: bobID, Folder: "users", Role: "viewer"}, 409, "covers_homes"},
		{"/api/admin/bindings/create", BindingCreateRequest{Subject: "*", Folder: "", Role: "viewer"}, 409, "covers_homes"},
		{"/api/admin/bindings/create", BindingCreateRequest{Subject: bobID, Folder: "missing", Role: "viewer"}, 404, "not_found"},
		{"/api/admin/bindings/create", BindingCreateRequest{Subject: bobID, Folder: "../up", Role: "viewer"}, 403, "path_outside_root"},
		{"/api/admin/bindings/create", BindingCreateRequest{Subject: bobID, Folder: "shared", Role: "admin"}, 400, "invalid_role"},
		{"/api/admin/bindings/create", BindingCreateRequest{Subject: "u-0000000000000000", Folder: "shared", Role: "viewer"}, 404, "not_found"},
		{"/api/admin/bindings/delete", IDRequest{ID: home}, 409, "home_binding"},
		{"/api/admin/bindings/delete", IDRequest{ID: "missing"}, 404, "not_found"},
		{"/api/admin/sessions/revoke", IDRequest{ID: "missing"}, 404, "not_found"},
	} {
		resp, body := e.call(alice, "POST", tc.path, tc.body)
		if resp.StatusCode != tc.status || errorCode(body) != tc.code {
			t.Errorf("%s %+v = %d %s, want %d %s", tc.path, tc.body, resp.StatusCode, body, tc.status, tc.code)
		}
	}
	if home == "" {
		t.Error("no home binding to try")
	}
}

func TestDeletingAUserOverHTTP(t *testing.T) {
	e, alice, clk := newAdminEnv(t, nil)
	e.addUserAs("vic", state.RoleViewer)
	resp, body := e.call(alice, "POST", "/api/admin/invites/create", InviteCreateRequest{Role: "contributor", Username: "bob"})
	l := decode[NewLinkResponse](t, body)
	bob := e.browser()
	if resp, body = e.call(bob, "POST", "/api/invite/accept", InviteAcceptRequest{Token: l.Token, Password: passphrase}); resp.StatusCode != 201 {
		t.Fatalf("accept = %d %s", resp.StatusCode, body)
	}
	bobID := e.userID(alice, "bob")

	if resp, body := e.call(alice, "POST", "/api/admin/users/delete", IDRequest{ID: e.userID(alice, "vic")}); resp.StatusCode != 200 || strings.TrimSpace(body) != `{"archivedHome":null}` {
		t.Errorf("delete a viewer = %d %s", resp.StatusCode, body)
	}
	resp, body = e.call(alice, "POST", "/api/admin/users/delete", IDRequest{ID: bobID})
	want := fmt.Sprintf(`{"archivedHome":"users/.deleted/bob-%s-%s"}`, clk.now().Format("20060102"), bobID)
	if resp.StatusCode != 200 || strings.TrimSpace(body) != want {
		t.Errorf("delete a contributor = %d %s, want %s", resp.StatusCode, body, want)
	}
	if resp, _ := e.call(bob, "GET", "/api/auth/me", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("a deleted user's session = %d", resp.StatusCode)
	}
}

func TestAdminSessionsOverHTTP(t *testing.T) {
	e, alice, _ := newAdminEnv(t, nil)
	e.addUserAs("bob", state.RoleContributor)
	bob := e.browser()
	e.login(bob, "bob")
	bobID := e.userID(alice, "bob")

	_, body := e.call(alice, "GET", "/api/admin/sessions/list", nil)
	all := decode[[]auth.AdminSessionInfo](t, body)
	if len(all) != 2 {
		t.Fatalf("sessions %s", body)
	}
	_, body = e.call(alice, "GET", "/api/admin/sessions/list?user="+bobID, nil)
	only := decode[[]auth.AdminSessionInfo](t, body)
	if len(only) != 1 || only[0].Username != "bob" || only[0].Current {
		t.Fatalf("bob's sessions %s", body)
	}
	if resp, body := e.call(alice, "POST", "/api/admin/sessions/revoke", IDRequest{ID: only[0].ID}); resp.StatusCode != http.StatusNoContent {
		t.Errorf("end bob's session = %d %s", resp.StatusCode, body)
	}
	if resp, _ := e.call(bob, "GET", "/api/auth/me", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("the ended session = %d", resp.StatusCode)
	}

	var own string
	for _, s := range all {
		if s.Current {
			own = s.ID
		}
	}
	resp, _ := e.call(alice, "POST", "/api/admin/sessions/revoke", IDRequest{ID: own})
	cleared := false
	for _, c := range resp.Cookies() {
		if c.Name == auth.SessionCookie && c.MaxAge < 0 {
			cleared = true
		}
	}
	if resp.StatusCode != http.StatusNoContent || !cleared {
		t.Errorf("ending one's own session = %d, cookie cleared %t", resp.StatusCode, cleared)
	}
}

// A change made without its record answers 500 with the change's result, so
// the admin sees the token of a link that exists.
func TestAnUnrecordedAdminChangeAnswersWithItsResult(t *testing.T) {
	a := &fakeAuditor{}
	e, alice, _ := newAdminEnv(t, nil, func(c *auth.Config, _ *Options) { c.Audit = a })
	a.fail = fmt.Errorf("%w: disk full", events.ErrNotRecorded)
	resp, body := e.call(alice, "POST", "/api/admin/invites/create", InviteCreateRequest{Role: "viewer"})
	er := decode[ErrorResponse](t, body)
	res, _ := er.Result.(map[string]any)
	if resp.StatusCode != 500 || er.Error.Code != "not_recorded" || res == nil || res["token"] == nil || res["kind"] != "invite" {
		t.Fatalf("invite = %d %s", resp.StatusCode, body)
	}
	resp, body = e.call(e.browser(), "POST", "/api/invite/accept", InviteAcceptRequest{Token: res["token"].(string), Username: "bob", Password: passphrase})
	er = decode[ErrorResponse](t, body)
	res, _ = er.Result.(map[string]any)
	if resp.StatusCode != 500 || er.Error.Code != "not_recorded" || res == nil || res["username"] != "bob" || len(resp.Cookies()) == 0 {
		t.Errorf("accept = %d %s", resp.StatusCode, body)
	}
}
