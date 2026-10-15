package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/nobletk/gocalbox/internal/auth"
	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/state"
)

// mintSession stores a session for username and returns its token.
func mintSession(t *testing.T, statePath, username string) string {
	t.Helper()
	db, err := state.Open(statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var b [32]byte
	rand.Read(b[:])
	token := base64.RawURLEncoding.EncodeToString(b[:])
	key := sha256.Sum256([]byte(token))
	now := time.Now().UTC()
	err = db.Update(func(tx *state.Tx) error {
		u, err := tx.UserByName(username)
		if err != nil {
			return err
		}
		return tx.PutSession(key[:], state.Session{ID: state.NewID(), User: u.ID, Created: now, LastSeen: now, AuthTime: now, Epoch: u.Epoch})
	})
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestE2ERolesAndUploaders(t *testing.T) {
	s := newLiveServer(t)
	for _, u := range []struct{ name, role string }{
		{"root", "admin"}, {"alice", "contributor"}, {"bob", "contributor"}, {"vera", "viewer"},
	} {
		cmd := exec.Command(binary(t), "users", "add", "-username", u.name, "-role", u.role, "-state", s.statePath, "-audit-log", s.auditPath)
		cmd.Env = isolatedEnv(t)
		cmd.Stdin = strings.NewReader(testPassword + "\n")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("users add %s: %v\n%s", u.name, err, out)
		}
	}
	tokens := map[string]string{}
	for _, name := range []string{"root", "alice", "bob", "vera"} {
		tokens[name] = mintSession(t, s.statePath, name)
	}
	s.start()
	_, client := trustClient(s.tlsConfig.RootCAs, true)

	send := func(user, method, path, ctype string, body io.Reader) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(method, s.url+path, body)
		if ctype != "" {
			req.Header.Set("Content-Type", ctype)
		}
		req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: tokens[user]})
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	call := func(user, method, path, body string) (int, string) {
		t.Helper()
		return send(user, method, path, "application/json", strings.NewReader(body))
	}
	upload := func(user, dir, name, content string) int {
		t.Helper()
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		fw, _ := mw.CreateFormFile("myFile", name)
		fw.Write([]byte(content))
		mw.Close()
		code, _ := send(user, "POST", "/api/upload?path="+dir, mw.FormDataContentType(), &buf)
		return code
	}
	uploaderOf := func(user, dir, name string) any {
		t.Helper()
		code, body := call(user, "GET", "/api/files?path="+dir, "")
		if code != 200 {
			t.Fatalf("%s lists %s: %d %s", user, dir, code, body)
		}
		var entries []map[string]any
		json.Unmarshal([]byte(body), &entries)
		for _, e := range entries {
			if e["name"] == name {
				return e["uploader"]
			}
		}
		return "<missing>"
	}

	if upload("alice", "users/alice", "home.txt", "mine") != 201 || upload("alice", "public", "shared.txt", "ours") != 201 {
		t.Fatalf("alice's uploads failed\n%s", s.out)
	}
	if upload("root", "users/alice", "from-root.txt", "x") != 201 {
		t.Fatal("the admin's upload failed")
	}
	for _, tc := range []struct {
		user, method, path, body string
		want                     int
	}{
		{"bob", "POST", "/api/fs/delete", `{"path":"public/shared.txt"}`, 403},
		{"bob", "POST", "/api/fs/rename", `{"oldPath":"public/shared.txt","newPath":"public/bobs.txt"}`, 403},
		{"bob", "GET", "/files/users/alice/home.txt", "", 404},
		{"bob", "GET", "/files/public/shared.txt", "", 200},
		{"alice", "POST", "/api/fs/delete", `{"path":"users/alice/from-root.txt"}`, 200},
		{"vera", "GET", "/files/public/shared.txt", "", 200},
		{"vera", "POST", "/api/fs/mkdir", `{"targetPath":"public","name":"v"}`, 403},
		{"vera", "POST", "/api/fs/delete", `{"path":"public/shared.txt"}`, 403},
		{"root", "POST", "/api/fs/move", `{"oldPath":"public/shared.txt","newPath":"public/moved.txt"}`, 200},
		{"root", "POST", "/api/fs/delete", `{"path":"users/alice"}`, 409},
	} {
		if code, body := call(tc.user, tc.method, tc.path, tc.body); code != tc.want {
			t.Errorf("%s %s %s: %d %s, want %d", tc.user, tc.method, tc.path, code, body, tc.want)
		}
	}
	if code := upload("vera", "public", "v.txt", "v"); code != 403 {
		t.Errorf("the viewer uploads: %d", code)
	}
	if got := uploaderOf("bob", "public", "moved.txt"); got != "alice" {
		t.Errorf("after the admin's move the uploader is %v", got)
	}
	if code, body := call("alice", "POST", "/api/fs/delete", `{"path":"public/moved.txt"}`); code != 200 {
		t.Errorf("alice deletes her moved file: %d %s", code, body)
	}

	if err := s.stop(syscall.SIGTERM); err != nil {
		t.Fatalf("exit: %v\n%s", err, s.out)
	}
	denied := map[string]int{}
	for _, ev := range auditEvents(t, s.auditPath) {
		if ev.Outcome == events.OutcomeDenied {
			denied[ev.Actor.Name]++
		}
	}
	if denied["bob"] != 3 || denied["vera"] != 3 {
		t.Errorf("denied operations in the audit log: %v", denied)
	}
}
