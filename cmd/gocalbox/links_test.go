package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/nobletk/gocalbox/internal/auth"
	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/httpapi"
	"github.com/nobletk/gocalbox/internal/state"
)

// send serves a JSON request and returns the status and body.
func send(t *testing.T, h http.Handler, method, path, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func storedLinks(t *testing.T, statePath string) []state.Link {
	t.Helper()
	db, err := state.Open(statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var out []state.Link
	db.View(func(tx *state.Tx) error {
		return tx.Links(func(_ []byte, l state.Link) error { out = append(out, l); return nil })
	})
	return out
}

func captureLog(f func()) string {
	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)
	f()
	return logs.String()
}

func TestRecoverAdminPrintsALinkOnce(t *testing.T) {
	tlsDir := filepath.Join(t.TempDir(), "tls")
	a, _ := newTestApp(t, withLocalCA(tlsDir, "localhost", "127.0.0.1", "192.168.1.20"), func(c *config) { c.RecoverAdmin = "Admin" })
	defer closeApp(t, a)
	token := a.recovery.Token
	if token == "" || a.recovery.Username != "admin" {
		t.Fatalf("recovery link %+v", a.recovery)
	}
	out := captureLog(func() { a.logRecovery("0.0.0.0", "8443") })
	local := strings.Index(out, "On this machine, open https://localhost:8443/#reset="+token)
	ca := strings.Index(out, "first install the local CA: open https://192.168.1.20:8443/ca.crt")
	lan := strings.Index(out, "Then open https://192.168.1.20:8443/#reset="+token)
	if local < 0 || ca < 0 || lan < 0 || !(local < ca && ca < lan) || !strings.Contains(out, a.TLS.CA.Fingerprint()) {
		t.Errorf("console output:\n%s", out)
	}
	if !strings.Contains(out, "Reset link for the admin admin") || !strings.Contains(out, "/api/reset/accept") || strings.Count(out, token) != 3 {
		t.Errorf("console output:\n%s", out)
	}
	if again := captureLog(func() { a.logRecovery("0.0.0.0", "8443") }); again != "" {
		t.Errorf("printed twice:\n%s", again)
	}
	if tgt := a.linkTarget("0.0.0.0", "8443"); tgt != (httpapi.LinkTarget{Address: "https://192.168.1.20:8443", CAFingerprint: a.TLS.CA.Fingerprint()}) {
		t.Errorf("link target %+v", tgt)
	}
	if tgt := a.linkTarget("localhost", "8443"); tgt.Address != "" {
		t.Errorf("link target on loopback %+v", tgt)
	}
}

func TestRecoverAdminLinkWorksOnceAndDiesAtTheNextStart(t *testing.T) {
	a, cfg := newTestApp(t, func(c *config) { c.RecoverAdmin = "admin" })
	token := a.recovery.Token
	body := fmt.Sprintf(`{"token":%q,"password":%q}`, token, testPassword+" renewed")
	if code, resp := send(t, a.Handler, "POST", "/api/reset/inspect", fmt.Sprintf(`{"token":%q}`, token)); code != 200 || !strings.Contains(resp, `"username":"admin"`) {
		t.Errorf("inspect = %d %s", code, resp)
	}
	if code, resp := send(t, a.Handler, "POST", "/api/reset/accept", body); code != 200 {
		t.Fatalf("accept = %d %s", code, resp)
	}
	if code, resp := send(t, a.Handler, "POST", "/api/reset/accept", body); code != 403 || !strings.Contains(resp, "link_invalid") {
		t.Errorf("second accept = %d %s", code, resp)
	}
	closeApp(t, a)

	b, err := newApp(cfg)
	if err != nil {
		t.Fatal(err)
	}
	unused := b.recovery
	closeApp(t, b)
	cfg.RecoverAdmin = ""
	c, err := newApp(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if c.recovery.Token != "" {
		t.Error("a link without -recover-admin")
	}
	closeApp(t, c)
	if links := storedLinks(t, cfg.StateFile); len(links) != 0 {
		t.Errorf("links left after a start without -recover-admin: %+v", links)
	}

	var got []string
	for _, ev := range auditEvents(t, cfg.AuditLog) {
		switch ev.Type {
		case events.ResetCreated, events.ResetUsed, events.LinkRevoked:
			got = append(got, fmt.Sprintf("%s %s %s", ev.Type, ev.Actor.ID, ev.Path))
			if ev.Type == events.LinkRevoked && (!strings.Contains(ev.Detail, "id="+unused.ID) || !strings.Contains(ev.Detail, "reason=server_start")) {
				t.Errorf("link.revoked %+v", ev)
			}
		}
	}
	admin := readUsers(t, cfg.StateFile)[0].ID
	want := []string{
		"reset.created console admin", "reset.used " + admin + " admin",
		"reset.created console admin", "link.revoked system admin",
	}
	if !slices.Equal(got, want) {
		t.Errorf("audit events\n%q\nwant\n%q", got, want)
	}
}

func TestRecoverAdminRefusesToStart(t *testing.T) {
	cfg := seeded(t, testConfig(t))
	for _, u := range []struct{ name, role string }{{"carol", "contributor"}, {"dora", "admin"}} {
		if code, _, errOut := runCommand(t, testPassword+"\n", "users", "add", "-username", u.name, "-role", u.role, "-state", cfg.StateFile, "-audit-log", cfg.AuditLog); code != 0 {
			t.Fatalf("users add: %s", errOut)
		}
	}
	db, err := state.Open(cfg.StateFile)
	if err != nil {
		t.Fatal(err)
	}
	db.Update(func(tx *state.Tx) error {
		u, err := tx.UserByName("dora")
		if err != nil {
			return err
		}
		u.Disabled = true
		return tx.UpdateUser(u)
	})
	db.Close()

	for name, want := range map[string]string{
		"nobody":     "no such user",
		"carol":      "carol is not an admin",
		"dora":       "disabled",
		"not a name": "no such user",
	} {
		c := cfg
		c.RecoverAdmin = name
		a, err := newApp(c)
		if err == nil {
			closeApp(t, a)
			t.Errorf("-recover-admin %s started", name)
			continue
		}
		if !strings.Contains(err.Error(), "-recover-admin") || !strings.Contains(err.Error(), want) {
			t.Errorf("-recover-admin %s: %v", name, err)
		}
	}
	if links := storedLinks(t, cfg.StateFile); len(links) != 0 {
		t.Errorf("a refused start left links: %+v", links)
	}
}

func TestUsersPasswdListsTheRevokedLinks(t *testing.T) {
	a, cfg := newTestApp(t)
	code, body := send(t, a.Handler, "POST", "/api/admin/invites/create", `{"role":"contributor","username":"anna","note":"Anna's \"phone\""}`)
	if code != 201 {
		t.Fatalf("invite = %d %s", code, body)
	}
	var inv httpapi.NewLinkResponse
	json.Unmarshal([]byte(body), &inv)
	_, body = send(t, a.Handler, "GET", "/api/auth/me", "")
	var admin auth.Me
	json.Unmarshal([]byte(body), &admin)
	code, body = send(t, a.Handler, "POST", "/api/admin/users/reset-link", fmt.Sprintf(`{"id":%q}`, admin.ID))
	if code != 201 {
		t.Fatalf("reset link = %d %s", code, body)
	}
	var reset httpapi.NewLinkResponse
	json.Unmarshal([]byte(body), &reset)
	closeApp(t, a)

	code, out, errOut := runCommand(t, "another long passphrase\n", "users", "passwd", "admin", "-state", cfg.StateFile, "-audit-log", cfg.AuditLog)
	if code != 0 {
		t.Fatalf("users passwd = %d %q", code, errOut)
	}
	for _, want := range []string{
		"Revoked 2 unused link(s)",
		fmt.Sprintf(`  invite %s, role contributor, for anna, note "Anna's \"phone\""`, inv.ID),
		fmt.Sprintf("  reset %s, for admin", reset.ID),
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	var revoked []string
	for _, ev := range auditEvents(t, cfg.AuditLog) {
		if ev.Type == events.LinkRevoked {
			revoked = append(revoked, ev.Actor.ID+" "+ev.Detail)
		}
	}
	if len(revoked) != 2 || !strings.HasPrefix(revoked[0], "console id=") || !strings.Contains(revoked[1], "reason=password_changed") {
		t.Errorf("link.revoked records %q", revoked)
	}
	if code, out, _ := runCommand(t, "yet another long passphrase\n", "users", "passwd", "admin", "-state", cfg.StateFile, "-audit-log", cfg.AuditLog); code != 0 || strings.Contains(out, "Revoked") {
		t.Errorf("a second passwd = %d %q", code, out)
	}
}

func TestLinkTTLFlagsMustBePositive(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	os.Mkdir(root, 0o755)
	for _, f := range []string{"-invite-ttl=0", "-reset-ttl=-1h"} {
		out, code := runToCompletion(t, f, "-port=0", "-root="+root, "-audit-log="+filepath.Join(base, "audit.jsonl"))
		if code == 0 || !strings.Contains(out, "-invite-ttl and -reset-ttl must be longer than 0") {
			t.Errorf("%s: exit %d\n%s", f, code, out)
		}
	}
}

// browser is a client with its own cookies that trusts the server's CA.
func (s *liveServer) browser() *http.Client {
	_, c := trustClient(s.tlsConfig.RootCAs, true)
	c.Jar, _ = cookiejar.New(nil)
	return c
}

func (s *liveServer) call(c *http.Client, method, path, body string) (int, string) {
	s.t.Helper()
	req, _ := http.NewRequest(method, s.url+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		s.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func tokenOf(t *testing.T, body string) string {
	t.Helper()
	var l httpapi.NewLinkResponse
	if err := json.Unmarshal([]byte(body), &l); err != nil || l.Token == "" {
		t.Fatalf("no token in %s", body)
	}
	return l.Token
}

// An invite accepted on a second browser, a reset link used while the old
// password's session is still open elsewhere, and a deleted user's home
// moved to .deleted, through the real server.
func TestE2EInviteResetAndDelete(t *testing.T) {
	s := startServer(t)
	admin := s.client
	code, body := s.call(admin, "POST", "/api/admin/invites/create", `{"role":"contributor","note":"Bob's laptop"}`)
	if code != 201 || !strings.Contains(body, `"caFingerprint":"`) {
		t.Fatalf("invite = %d %s", code, body)
	}
	invite := tokenOf(t, body)

	bob := s.browser()
	if code, body := s.call(bob, "POST", "/api/invite/inspect", fmt.Sprintf(`{"token":%q}`, invite)); code != 200 || !strings.Contains(body, `"role":"contributor"`) {
		t.Errorf("inspect = %d %s", code, body)
	}
	code, body = s.call(bob, "POST", "/api/invite/accept", fmt.Sprintf(`{"token":%q,"username":"bob","password":%q}`, invite, testPassword))
	if code != 201 {
		t.Fatalf("accept = %d %s", code, body)
	}
	var me auth.Me
	json.Unmarshal([]byte(body), &me)
	if code, _ := s.call(bob, "GET", "/api/files?path=users/bob", ""); code != 200 {
		t.Errorf("bob lists his home = %d", code)
	}
	req, _ := http.NewRequest("POST", s.url+"/api/fs/mkdir", strings.NewReader(`{"targetPath":"users/bob","name":"photos"}`))
	req.Header.Set("Content-Type", "application/json")
	if resp, err := bob.Do(req); err != nil || resp.StatusCode != 201 {
		t.Fatalf("bob makes a folder: %v %v", resp, err)
	}

	code, body = s.call(admin, "POST", "/api/admin/users/reset-link", fmt.Sprintf(`{"id":%q}`, me.ID))
	if code != 201 {
		t.Fatalf("reset link = %d %s", code, body)
	}
	reset := tokenOf(t, body)
	phone := s.browser()
	code, body = s.call(phone, "POST", "/api/reset/accept", fmt.Sprintf(`{"token":%q,"password":%q}`, reset, testPassword+" new"))
	if code != 200 || !strings.Contains(body, `"revokedLinks":[]`) {
		t.Fatalf("reset = %d %s", code, body)
	}
	if code, _ := s.call(bob, "GET", "/api/auth/me", ""); code != 401 {
		t.Errorf("the session from before the reset = %d", code)
	}
	if code, _ := s.call(phone, "GET", "/api/auth/me", ""); code != 200 {
		t.Errorf("the session of the reset = %d", code)
	}

	code, body = s.call(admin, "POST", "/api/admin/users/delete", fmt.Sprintf(`{"id":%q}`, me.ID))
	m := regexp.MustCompile(`"archivedHome":"(users/\.deleted/bob-\d{8}-` + me.ID + `)"`).FindStringSubmatch(body)
	if code != 200 || m == nil {
		t.Fatalf("delete = %d %s", code, body)
	}
	if code, list := s.call(admin, "GET", "/api/files?path="+m[1], ""); code != 200 || !strings.Contains(list, `"photos"`) {
		t.Errorf("the archive = %d %s", code, list)
	}
	if code, _ := s.call(phone, "GET", "/api/auth/me", ""); code != 401 {
		t.Errorf("a deleted user's session = %d", code)
	}
	if err := s.stop(syscall.SIGTERM); err != nil {
		t.Fatalf("exit: %v\n%s", err, s.out)
	}
	if _, err := os.Stat(filepath.Join(s.root, filepath.FromSlash(m[1]), "photos")); err != nil {
		t.Error(err)
	}
	var types []events.Type
	for _, ev := range auditEvents(t, s.auditPath) {
		types = append(types, ev.Type)
	}
	for _, want := range []events.Type{events.InviteCreated, events.InviteUsed, events.ResetCreated, events.ResetUsed, events.FileMoved, events.UserDeleted} {
		if !slices.Contains(types, want) {
			t.Errorf("no %s in the audit log: %v", want, types)
		}
	}
	if _, err := verifyOnly(s.auditPath); err != nil {
		t.Error(err)
	}
}

func TestE2ERecoverAdmin(t *testing.T) {
	s := newLiveServer(t)
	seedAdmin(t, s.statePath, s.root)
	s.start("-recover-admin=admin")
	m := regexp.MustCompile(`On this machine, open https://localhost:\d+/#reset=([A-Z2-7]{26})`).FindStringSubmatch(s.out.String())
	if m == nil {
		t.Fatalf("no recovery link in the console output:\n%s", s.out)
	}
	c := s.browser()
	if code, body := s.call(c, "POST", "/api/reset/accept", fmt.Sprintf(`{"token":%q,"password":%q}`, m[1], testPassword+" new")); code != 200 {
		t.Fatalf("accept = %d %s", code, body)
	}
	if code, _ := s.call(c, "GET", "/api/admin/users/list", ""); code != 200 {
		t.Errorf("the recovered admin's session = %d", code)
	}
	if err := s.stop(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}

	out, code := runToCompletion(t, "-port=0", "-root="+s.root, "-audit-log="+s.auditPath, "-tls-dir="+s.tlsDir, "-state="+s.statePath, "-min-free-mb=0", "-recover-admin=nobody")
	if code == 0 || !strings.Contains(out, "-recover-admin: no such user") {
		t.Errorf("exit %d\n%s", code, out)
	}
	if strings.Contains(out, "#reset=") {
		t.Errorf("a refused start printed a link:\n%s", out)
	}
}
