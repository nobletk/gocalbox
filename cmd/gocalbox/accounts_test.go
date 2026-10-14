package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nobletk/gocalbox/internal/auth"
	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/state"
)

func runCommand(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := command(args, strings.NewReader(stdin), &out, &errOut)
	return code, out.String(), errOut.String()
}

func readUsers(t *testing.T, path string) []state.User {
	t.Helper()
	db, err := state.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var users []state.User
	db.View(func(tx *state.Tx) error { var err error; users, err = tx.Users(); return err })
	return users
}

func TestUsersCommands(t *testing.T) {
	base := t.TempDir()
	statePath := filepath.Join(base, "new", "state.db")
	auditPath := filepath.Join(base, "audit.jsonl")
	flags := []string{"-state", statePath, "-audit-log", auditPath}

	code, out, errOut := runCommand(t, testPassword+"\r\n", append([]string{"users", "add", "-username", "Bench", "-role", "contributor"}, flags...)...)
	if code != 0 || !strings.Contains(out, "Created bench (contributor, u-") || !strings.Contains(out, "/users/bench") {
		t.Fatalf("users add = %d %q %q", code, out, errOut)
	}
	if fi, err := os.Stat(filepath.Dir(statePath)); err != nil || fi.Mode().Perm() != 0o700 && runtime.GOOS != "windows" {
		t.Errorf("state folder: %v, %v", fi, err)
	}
	users := readUsers(t, statePath)
	if len(users) != 1 || users[0].Username != "bench" || users[0].CreatedBy != events.ConsoleID {
		t.Fatalf("users = %+v", users)
	}
	if ok, _, _ := auth.NewHasher(auth.DefaultParams, 1, time.Second).Verify(t.Context(), users[0].Hash, testPassword); !ok {
		t.Error("the stored hash does not match the password, or kept the line ending")
	}

	code, _, errOut = runCommand(t, testPassword, append([]string{"users", "add", "-username", "bench", "-role", "viewer"}, flags...)...)
	if code != 1 || !strings.Contains(errOut, "taken") {
		t.Errorf("duplicate = %d %q", code, errOut)
	}
	code, _, errOut = runCommand(t, "short", append([]string{"users", "add", "-username", "carol", "-role", "viewer"}, flags...)...)
	if code != 1 || !strings.Contains(errOut, "at least 15 characters") {
		t.Errorf("weak password = %d %q", code, errOut)
	}
	code, _, errOut = runCommand(t, "", append([]string{"users", "add", "-username", "carol", "-role", "viewer"}, flags...)...)
	if code != 1 || !strings.Contains(errOut, "no password") {
		t.Errorf("empty stdin = %d %q", code, errOut)
	}

	code, out, _ = runCommand(t, "", "users", "list", "-state", statePath)
	if code != 0 || !regexp.MustCompile(`(?m)^bench\s+contributor\s+enabled\s+\d{4}-\d{2}-\d{2}\s+u-[0-9a-f]{16}$`).MatchString(out) {
		t.Errorf("users list = %d\n%s", code, out)
	}

	code, out, errOut = runCommand(t, "another long passphrase\n", "users", "passwd", "bench", "-state", statePath, "-audit-log", auditPath)
	if code != 0 || !strings.Contains(out, "Changed the password of bench") {
		t.Fatalf("users passwd = %d %q %q", code, out, errOut)
	}
	if u := readUsers(t, statePath)[0]; u.Epoch != 1 {
		t.Errorf("epoch after passwd = %d", u.Epoch)
	}
	code, _, errOut = runCommand(t, "another long passphrase\n", append([]string{"users", "passwd", "nobody"}, flags...)...)
	if code != 1 || !strings.Contains(errOut, `no user named "nobody"`) {
		t.Errorf("passwd unknown = %d %q", code, errOut)
	}

	evs := auditEvents(t, auditPath)
	if len(evs) != 2 || evs[0].Type != events.UserCreated || evs[1].Type != events.AuthPasswordChanged {
		t.Fatalf("audit events %+v", evs)
	}
	for _, ev := range evs {
		if ev.Actor.ID != events.ConsoleID || ev.Path != "bench" || ev.Outcome != events.OutcomeOK || ev.Time.IsZero() {
			t.Errorf("event %+v", ev)
		}
	}

	code, out, _ = runCommand(t, "", "state", "dump", "-state", statePath)
	if code != 0 || !strings.Contains(out, `"username":"bench"`) || strings.Contains(out, "argon2id") {
		t.Errorf("state dump = %d\n%s", code, out)
	}
}

func TestUsersCommandsRefuseWhileTheServerRuns(t *testing.T) {
	a, cfg := newTestApp(t)
	defer closeApp(t, a)
	start := time.Now()
	code, _, errOut := runCommand(t, testPassword, "users", "add", "-username", "bob", "-role", "viewer", "-state", cfg.StateFile, "-audit-log", cfg.AuditLog)
	if code != 1 || !strings.Contains(errOut, "the server is running, or another users command; stop it or use the admin page") {
		t.Errorf("users add = %d %q", code, errOut)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("took %v", d)
	}
	if code, _, errOut := runCommand(t, "", "state", "dump", "-state", cfg.StateFile); code != 1 || !strings.Contains(errOut, "the server is running") {
		t.Errorf("state dump = %d %q", code, errOut)
	}
}

func TestCommandUsage(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "none.db")
	for _, tc := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"users"}, 2, "Usage:"},
		{[]string{"users", "rename"}, 2, `unknown command "users rename"`},
		{[]string{"users", "add", "-username", "x"}, 2, "needs -username and -role"},
		{[]string{"users", "add", "-bogus"}, 2, "flag provided but not defined"},
		{[]string{"users", "passwd", "-state", missing}, 2, "exactly one username"},
		{[]string{"users", "passwd", "a", "b", "-state", missing}, 2, "exactly one username"},
		{[]string{"users", "list", "-state", missing}, 1, "no state file"},
		{[]string{"state"}, 2, "Usage:"},
		{[]string{"state", "dump", "-state", missing}, 1, "no state file"},
		{[]string{"users", "list", "-h"}, 0, "-state"},
	} {
		code, _, errOut := runCommand(t, "", tc.args...)
		if code != tc.code || !strings.Contains(errOut, tc.want) {
			t.Errorf("%v = %d %q", tc.args, code, errOut)
		}
	}
	if _, err := os.Stat(missing); err == nil {
		t.Error("a read-only command created the state file")
	}
}

func TestStateFileInsideServedFolderIsRefused(t *testing.T) {
	cfg := testConfig(t)
	cfg.StateFile = filepath.Join(cfg.RootDir, "conf", "state.db")
	if _, err := newApp(cfg); err == nil || !strings.Contains(err.Error(), "-state") {
		t.Errorf("state inside the root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(cfg.RootDir, "conf")); err == nil {
		t.Error("the refused start created a folder in the served directory")
	}

	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(cfg.RootDir, link); err == nil {
		for _, p := range []string{filepath.Join(link, "state.db"), filepath.Join(link, "sub", "state.db")} {
			cfg.StateFile = p
			if _, err := newApp(cfg); err == nil {
				t.Errorf("state file %s reaching the root through a symlink was accepted", p)
			}
		}
		if _, err := os.Stat(filepath.Join(cfg.RootDir, "sub")); err == nil {
			t.Error("a start refused for a path through a symlink created a folder in the served directory")
		}
	}
	cfg.StateFile = ""
	if _, err := newApp(cfg); err == nil || !strings.Contains(err.Error(), "-state is empty") {
		t.Errorf("empty -state: %v", err)
	}
}

func TestFoldersThroughASymlinkIntoTheRootAreNotCreated(t *testing.T) {
	cfg := testConfig(t)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(cfg.RootDir, link); err != nil {
		t.Skipf("symlinks not supported: %v", err)
	}
	for name, mutate := range map[string]func(*config){
		"-audit-log": func(c *config) { c.AuditLog = filepath.Join(link, "a", "audit.jsonl") },
		"-tls-dir":   func(c *config) { c.TLSDir = filepath.Join(link, "b", "tls") },
	} {
		c := cfg
		mutate(&c)
		if _, err := newApp(c); err == nil || !strings.Contains(err.Error(), "inside the served directory") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if entries, _ := os.ReadDir(cfg.RootDir); len(entries) != 0 {
		t.Errorf("the served directory holds %v after refused starts", entries)
	}
}

func TestUsersCommandsRefuseTheAuditLogOfARunningServer(t *testing.T) {
	a, cfg := newTestApp(t)
	defer closeApp(t, a)
	other := filepath.Join(t.TempDir(), "other.db")
	code, _, errOut := runCommand(t, testPassword, "users", "add", "-username", "bob", "-role", "viewer", "-state", other, "-audit-log", cfg.AuditLog)
	if code != 1 || !strings.Contains(errOut, "the server is running") {
		t.Errorf("users add with the server's audit log = %d %q", code, errOut)
	}
	if _, err := os.Stat(other); err == nil {
		t.Error("the refused command created its state file")
	}

	otherLog := filepath.Join(t.TempDir(), "other.jsonl")
	code, _, errOut = runCommand(t, testPassword, "users", "add", "-username", "bob", "-role", "viewer", "-state", cfg.StateFile, "-audit-log", otherLog)
	if code != 1 || !strings.Contains(errOut, "the server is running") {
		t.Errorf("users add with the server's state file = %d %q", code, errOut)
	}
	if _, err := os.Stat(otherLog); err == nil {
		t.Error("the refused command created its audit log")
	}
}

func TestUsersCommandsCheckTheirArgumentsFirst(t *testing.T) {
	base := t.TempDir()
	statePath, auditPath := filepath.Join(base, "state.db"), filepath.Join(base, "audit.jsonl")
	flags := []string{"-state", statePath, "-audit-log", auditPath}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"users", "add", "-username", "Bad Name", "-role", "viewer"}, "invalid username"},
		{[]string{"users", "add", "-username", "console", "-role", "viewer"}, "taken or reserved"},
		{[]string{"users", "add", "-username", "bob", "-role", "superuser"}, `invalid role "superuser"`},
		{[]string{"users", "add", "-username", "bob", "-role", "viewer", "-min-password-length", "7"}, "between 8 and 1024"},
		{[]string{"users", "add", "-username", "bob", "-role", "viewer", "-min-password-length", "2000"}, "between 8 and 1024"},
		{[]string{"users", "passwd", "-min-password-length", "2000", "bob"}, "between 8 and 1024"},
		{[]string{"users", "passwd", "system"}, `no user named "system"`},
	} {
		code, _, errOut := runCommand(t, testPassword, append(tc.args, flags...)...)
		if code != 1 || !strings.Contains(errOut, tc.want) {
			t.Errorf("%v = %d %q, want %q", tc.args, code, errOut, tc.want)
		}
		if entries, _ := os.ReadDir(base); len(entries) != 0 {
			t.Fatalf("%v left %v behind", tc.args, entries)
		}
	}

	if code, _, errOut := runCommand(t, testPassword, append([]string{"users", "add", "-username", "bob", "-role", "viewer"}, flags...)...); code != 0 {
		t.Fatalf("users add: %s", errOut)
	}
	newLog := filepath.Join(base, "new", "audit.jsonl")
	code, _, errOut := runCommand(t, "", "users", "add", "-username", "Bob", "-role", "viewer", "-state", statePath, "-audit-log", newLog)
	if code != 1 || !strings.Contains(errOut, "taken or reserved") {
		t.Errorf("a taken name should be refused before the password is read: %d %q", code, errOut)
	}
	code, _, errOut = runCommand(t, "", "users", "passwd", "-state", statePath, "-audit-log", newLog, "nobody")
	if code != 1 || !strings.Contains(errOut, `no user named "nobody"`) {
		t.Errorf("passwd for an unknown user = %d %q", code, errOut)
	}
	if _, err := os.Stat(filepath.Dir(newLog)); err == nil {
		t.Error("a refused command created an audit log")
	}
}

func TestSetupCommand(t *testing.T) {
	certPath, keyPath := writeCertFiles(t, t.TempDir(), "files.example.com")
	certApp, _ := newTestApp(t, func(c *config) { c.TLSCert, c.TLSKey = certPath, keyPath })
	defer closeApp(t, certApp)
	lhCert, lhKey := writeCertFiles(t, t.TempDir(), "localhost", "files.example.com")
	lhApp, _ := newTestApp(t, func(c *config) { c.TLSCert, c.TLSKey = lhCert, lhKey })
	defer closeApp(t, lhApp)
	caApp, _ := newTestApp(t, withLocalCA(filepath.Join(t.TempDir(), "tls"), "localhost"))
	defer closeApp(t, caApp)
	noNameCert, noNameKey := writeCertFiles(t, t.TempDir(), "elsewhere.example.com")
	noNameApp, _ := newTestApp(t, func(c *config) { c.TLSCert, c.TLSKey = noNameCert, noNameKey })
	defer closeApp(t, noNameApp)
	v6Cert, v6Key := writeCertFilesFor(t, t.TempDir(), nil, []net.IP{net.ParseIP("fd00::5")})
	v6App, _ := newTestApp(t, func(c *config) { c.TLSCert, c.TLSKey = v6Cert, v6Key })
	defer closeApp(t, v6App)
	posixCA := &tlsSetup{CA: caApp.TLS.CA, CAPath: "/srv/it's $HOME/ca.crt"}
	windowsCA := &tlsSetup{CA: caApp.TLS.CA, CAPath: `C:\ProgramData\gocalbox\ca.crt`}
	allowed := []string{"localhost", "127.0.0.1", "files.example.com", "fd00::5"}

	for _, tc := range []struct {
		name, goos, local, other string
		t                        *tlsSetup
		want                     []string
		not                      string
	}{
		{"plain HTTP", "linux", "http://localhost:8443", "", nil,
			[]string{`  curl -H 'Content-Type: application/json' --data @- http://localhost:8443/api/setup`, "press Enter, then Ctrl-D."}, "--cacert"},
		{"local CA", "linux", "https://localhost:8443", "", posixCA,
			[]string{`  curl --cacert '/srv/it'\''s $HOME/ca.crt' -H 'Content-Type: application/json' --data @- https://localhost:8443/api/setup`}, "--connect-to"},
		{"local CA on Windows", "windows", "https://localhost:8443", "", windowsCA,
			[]string{`  curl.exe --ssl-no-revoke --cacert "C:\ProgramData\gocalbox\ca.crt" -H "Content-Type: application/json" --data "@-" https://localhost:8443/api/setup`, "press Enter, then Ctrl-Z and Enter."}, "Ctrl-D"},
		{"own certificate without localhost", "linux", "https://localhost:8443", "", certApp.TLS,
			[]string{`  curl --connect-to files.example.com:8443:localhost:8443 -H 'Content-Type: application/json' --data @- https://files.example.com:8443/api/setup`, "--cacert with the CA's file"}, "https://localhost"},
		{"own certificate with localhost", "linux", "https://localhost:8443", "", lhApp.TLS,
			[]string{`  curl -H 'Content-Type: application/json' --data @- https://localhost:8443/api/setup`}, "--connect-to"},
		{"own certificate, one LAN address", "linux", "", "https://files.example.com:8443", certApp.TLS,
			[]string{`  curl -H 'Content-Type: application/json' --data @- https://files.example.com:8443/api/setup`}, "--connect-to"},
		{"own certificate without a known name", "linux", "https://localhost:8443", "", noNameApp.TLS,
			[]string{`  curl -H 'Content-Type: application/json' --data @- https://localhost:8443/api/setup`, "add a name it has to -allowed-hosts"}, "--connect-to"},
		{"own certificate for an IPv6 address", "linux", "https://localhost:8443", "", v6App.TLS,
			[]string{`  curl --connect-to '[fd00::5]:8443:localhost:8443' -H 'Content-Type: application/json' --data @- 'https://[fd00::5]:8443/api/setup'`}, "https://localhost"},
	} {
		out := strings.Join(setupCommand(tc.goos, tc.local, tc.other, "8443", allowed, tc.t, "CODE", 15), "\n")
		for _, want := range append(tc.want, `{"code":"CODE","username":"admin","password":"<at least 15 characters>"}`) {
			if !strings.Contains(out, want) {
				t.Errorf("%s: lacks %q:\n%s", tc.name, want, out)
			}
		}
		if strings.Contains(out, tc.not) {
			t.Errorf("%s: has %q:\n%s", tc.name, tc.not, out)
		}
	}
	if lines := setupCommand("linux", "", "", "8443", allowed, caApp.TLS, "CODE", 15); lines != nil {
		t.Errorf("printed without an address: %q", lines)
	}
}

func TestSecondServerOnOneStateFileFails(t *testing.T) {
	a, cfg := newTestApp(t)
	defer closeApp(t, a)
	cfg.AuditLog = filepath.Join(t.TempDir(), "other.jsonl")
	if _, err := newApp(cfg); err == nil || !strings.Contains(err.Error(), "in use by another gocalbox process") {
		t.Errorf("second server: %v", err)
	}
}

func postSetup(t *testing.T, h http.Handler, body any) (int, string) {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/setup", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func TestSetupFromACleanStart(t *testing.T) {
	cfg := testConfig(t)
	a, err := newApp(cfg)
	if err != nil {
		t.Fatal(err)
	}
	code := a.setupCode
	if len(code) != 26 {
		t.Fatalf("setup code %q", code)
	}
	if c, body := get(t, a.Handler, "/api/files?path="); c != 503 || !strings.Contains(body, "setup_required") {
		t.Errorf("files before setup = %d %s", c, body)
	}
	if c, body := get(t, a.Handler, "/api/status"); c != 200 || !strings.Contains(body, `"setupRequired":true`) {
		t.Errorf("status = %d %s", c, body)
	}
	if c, body := postSetup(t, a.Handler, map[string]any{"code": "AAAAA", "username": "alice", "password": testPassword}); c != 403 || !strings.Contains(body, "setup_code_invalid") {
		t.Errorf("wrong code = %d %s", c, body)
	}
	c, body := postSetup(t, a.Handler, map[string]any{"code": auth.FormatCode(code), "username": "Alice", "password": testPassword})
	if c != 201 || !strings.Contains(body, `"username":"alice"`) || !strings.Contains(body, `"home":"users/alice"`) {
		t.Fatalf("setup = %d %s", c, body)
	}
	if c, _ := get(t, a.Handler, "/api/files?path=users"); c != 200 {
		t.Errorf("files after setup = %d", c)
	}
	closeApp(t, a)

	evs := auditEvents(t, a.AuditPath)
	var types []events.Type
	for _, ev := range evs {
		types = append(types, ev.Type)
	}
	if !slices.Equal(types, []events.Type{events.FolderCreated, events.FolderCreated, events.FolderCreated, events.AuthSetupCompleted}) {
		t.Errorf("audit events %v", types)
	}
	if last := evs[len(evs)-1]; last.Actor.Name != "alice" || !strings.HasPrefix(last.Actor.ID, "u-") {
		t.Errorf("setup recorded as %+v", last.Actor)
	}

	b, err := newApp(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer closeApp(t, b)
	if b.setupCode != "" || b.accounts.SetupRequired() {
		t.Error("setup mode after a restart with an admin")
	}
}

func TestStartupCreatesHomesOfUsersAddedFromTheConsole(t *testing.T) {
	cfg := testConfig(t)
	seedAdmin(t, cfg.StateFile, cfg.RootDir)
	if code, _, errOut := runCommand(t, testPassword, "users", "add", "-username", "carol", "-role", "contributor", "-state", cfg.StateFile, "-audit-log", cfg.AuditLog); code != 0 {
		t.Fatalf("users add: %s", errOut)
	}
	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)
	a, err := newApp(cfg)
	if err != nil {
		t.Fatal(err)
	}
	closeApp(t, a)
	if fi, err := os.Stat(filepath.Join(cfg.RootDir, "users", "carol")); err != nil || !fi.IsDir() {
		t.Fatalf("home not created: %v", err)
	}
	evs := auditEvents(t, a.AuditPath)
	if len(evs) != 2 || evs[1].Type != events.FolderCreated || evs[1].Detail != "home" || evs[1].Actor.ID != events.SystemID {
		t.Errorf("audit events %+v", evs)
	}
	if strings.Contains(logs.String(), "WARNING") {
		t.Errorf("warnings: %s", logs.String())
	}
}

func TestSetupConsoleOutput(t *testing.T) {
	capture := func(a *app, host string) string {
		var logs bytes.Buffer
		log.SetOutput(&logs)
		defer log.SetOutput(os.Stderr)
		a.logSetup(host, "8443")
		return logs.String()
	}

	a, _ := newTestApp(t)
	defer closeApp(t, a)
	if out := capture(a, "localhost"); out != "" {
		t.Errorf("printed without setup mode: %s", out)
	}

	tlsDir := filepath.Join(t.TempDir(), "tls")
	cfg := testConfig(t)
	cfg.TLSDir, cfg.AllowedHosts = tlsDir, []string{"localhost", "127.0.0.1", "192.168.1.20"}
	b, err := newApp(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer closeApp(t, b)
	code := b.setupCode
	out := capture(b, "0.0.0.0")
	local := strings.Index(out, "On this machine, open https://localhost:8443/#setup="+code)
	ca := strings.Index(out, "first install the local CA: open https://192.168.1.20:8443/ca.crt")
	lan := strings.Index(out, "Then open https://192.168.1.20:8443/#setup="+code)
	if local < 0 || ca < 0 || lan < 0 || !(local < ca && ca < lan) || !strings.Contains(out, b.TLS.CA.Fingerprint()) {
		t.Errorf("console output:\n%s", out)
	}
	if !strings.Contains(out, auth.FormatCode(code)) || !strings.Contains(out, "--cacert") {
		t.Errorf("console output:\n%s", out)
	}
	if again := capture(b, "0.0.0.0"); again != "" {
		t.Errorf("the code was printed twice:\n%s", again)
	}
	if strings.Contains(out, testPassword) || !strings.Contains(out, "@-") {
		t.Errorf("the curl line should read the JSON from standard input:\n%s", out)
	}

	c, err := newApp(func() config { c := testConfig(t); c.TLSDir = filepath.Join(t.TempDir(), "tls"); return c }())
	if err != nil {
		t.Fatal(err)
	}
	defer closeApp(t, c)
	if out := capture(c, "localhost"); !strings.Contains(out, "listens on loopback only") || strings.Contains(out, "From another device") {
		t.Errorf("loopback console output:\n%s", out)
	}
}

func TestSetupAddresses(t *testing.T) {
	certPath, keyPath := writeCertFiles(t, t.TempDir(), "files.example.com")
	certApp, _ := newTestApp(t, func(c *config) { c.TLSCert, c.TLSKey = certPath, keyPath })
	defer closeApp(t, certApp)
	caApp, _ := newTestApp(t, withLocalCA(filepath.Join(t.TempDir(), "tls"), "localhost"))
	defer closeApp(t, caApp)

	for _, tc := range []struct {
		name, host string
		allowed    []string
		t          *tlsSetup
		local, lan string
	}{
		{"loopback", "localhost", nil, caApp.TLS, "https://localhost:8443", ""},
		{"all interfaces", "0.0.0.0", []string{"127.0.0.1", "192.168.1.20"}, caApp.TLS, "https://localhost:8443", "https://192.168.1.20:8443"},
		{"all interfaces, IPv6", "[::]", []string{"fd00::5"}, caApp.TLS, "https://localhost:8443", ""},
		{"one LAN address", "192.168.1.20", nil, caApp.TLS, "", "https://192.168.1.20:8443"},
		{"plain HTTP", "127.0.0.1", nil, nil, "http://localhost:8443", ""},
		{"own certificate", "0.0.0.0", []string{"localhost", "127.0.0.1", "box.lan", "files.example.com"}, certApp.TLS, "https://localhost:8443", "https://files.example.com:8443"},
		{"own certificate, loopback only", "localhost", []string{"localhost", "127.0.0.1", "files.example.com"}, certApp.TLS, "https://localhost:8443", ""},
	} {
		l, o := setupAddresses(tc.host, "8443", tc.allowed, tc.t)
		if l != tc.local || o != tc.lan {
			t.Errorf("%s: %q, %q; want %q, %q", tc.name, l, o, tc.local, tc.lan)
		}
	}
}
