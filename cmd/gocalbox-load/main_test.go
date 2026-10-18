package main

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/iotest"

	"github.com/nobletk/gocalbox/bench/load"
	"github.com/nobletk/gocalbox/internal/transfer"
)

func TestTheScratchFolderMustBeThisCommands(t *testing.T) {
	dir := t.TempDir()
	keep := filepath.Join(dir, "repo", "go.mod")
	os.MkdirAll(filepath.Dir(keep), 0o755)
	os.WriteFile(keep, nil, 0o644)
	if err := emptyWork(filepath.Dir(keep)); err == nil {
		t.Error("a folder of other files was accepted")
	}
	if _, err := os.Stat(keep); err != nil {
		t.Errorf("a refused folder lost its files: %v", err)
	}

	work := filepath.Join(dir, "work")
	if err := emptyWork(work); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(work, "left"), nil, 0o644)
	if err := emptyWork(work); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(work, "left")); !os.IsNotExist(err) {
		t.Errorf("the scratch folder wasn't emptied: %v", err)
	}
}

func TestParseSize(t *testing.T) {
	for in, want := range map[string]int64{"10": 10, "64K": 64 << 10, "64M": 64 << 20, "2G": 2 << 30} {
		if got, err := parseSize(in); err != nil || got != want {
			t.Errorf("%s: %d, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "-1", "1T", "M"} {
		if _, err := parseSize(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestEachModeTakesOnlyItsFlags(t *testing.T) {
	for _, c := range []struct {
		set       []string
		remote    bool
		transport string
		want      string
	}{
		{nil, false, "https-h2", ""},
		{[]string{"work", "audit-wait", "audit-parts", "min-free-mb", "users", "csv"}, false, "https-h2", ""},
		{[]string{"url", "ca", "transport", "user-prefix", "users", "csv"}, true, "https-h1", ""},
		{[]string{"ca"}, false, "https-h2", "-ca: only for -url"},
		{[]string{"transport", "user-prefix"}, false, "https-h1", "-transport, -user-prefix: only for -url"},
		{[]string{"work"}, true, "https-h2", "-work: only for the in-process mode; set them on the server"},
		{[]string{"audit-wait", "audit-parts", "min-free-mb"}, true, "https-h2", "-audit-wait, -audit-parts, -min-free-mb: only for the in-process mode; set them on the server"},
		{[]string{"transport"}, true, "h2", `-transport must be https-h2 or https-h1, not "h2"`},
	} {
		set := map[string]bool{}
		for _, f := range c.set {
			set[f] = true
		}
		err := checkModes(set, c.remote, c.transport)
		if got := fmt.Sprint(err); c.want == "" && err != nil || c.want != "" && got != c.want {
			t.Errorf("%v, remote %v, %s: %v, want %q", c.set, c.remote, c.transport, err, c.want)
		}
	}
}

func TestThePasswordIsTheFirstLine(t *testing.T) {
	for in, want := range map[string]string{"secret\n": "secret", "secret\r\nmore\n": "secret", "no newline": "no newline", " spaced \n": " spaced "} {
		if got, err := readPassword(strings.NewReader(in)); err != nil || got != want {
			t.Errorf("%q: %q, %v", in, got, err)
		}
	}
	for _, in := range []string{"", "\n", "\r\n"} {
		if _, err := readPassword(strings.NewReader(in)); err == nil || !strings.Contains(err.Error(), "no password") {
			t.Errorf("%q: %v", in, err)
		}
	}
	if _, err := readPassword(iotest.ErrReader(errors.New("broken"))); err == nil || err.Error() != "broken" {
		t.Errorf("a failed read: %v", err)
	}
}

func TestUserNamesAndCounts(t *testing.T) {
	if got := strings.Join(userNames("load", 3), ","); got != "load00,load01,load02" {
		t.Errorf("names %s", got)
	}
	if got := len(userNames("u", 0)); got != 0 {
		t.Errorf("%d names for none", got)
	}
	for want, m := range map[string]map[string]int{
		"none":        nil,
		"429x1 503x2": {"503": 2, "429": 1},
		"409x3":       {"409": 3, "503": 0},
	} {
		if got := counts(m); got != want {
			t.Errorf("%v: %q, want %q", m, got, want)
		}
	}
}

// fakeServer answers the calls of the load client for any user whose
// password is "pw", and logs them.
type fakeServer struct {
	srv    *httptest.Server
	caFile string
	mu     sync.Mutex
	protos map[string]int
	calls  []string
	done   map[string]string // completed uploads and their paths

	refuseDeletes bool
	users         []string // who logged in
}

func newFakeServer(t *testing.T) *fakeServer {
	f := &fakeServer{protos: map[string]int{}, done: map[string]string{}}
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	f.srv.EnableHTTP2 = true
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	f.caFile = filepath.Join(t.TempDir(), "ca.crt")
	os.WriteFile(f.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw}), 0o644)
	return f
}

func (f *fakeServer) serve(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if r.Header.Get("Content-Type") == "application/json" {
		json.NewDecoder(r.Body).Decode(&body)
	} else {
		io.Copy(io.Discard, r.Body)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.protos[r.Proto]++
	f.calls = append(f.calls, r.URL.Path)
	switch r.URL.Path {
	case "/api/auth/login":
		if body["password"] != "pw" {
			w.WriteHeader(401)
			w.Write([]byte(`{"error":{"code":"invalid_credentials"}}`))
			return
		}
		f.users = append(f.users, body["username"].(string))
		http.SetCookie(w, &http.Cookie{Name: "s", Value: body["username"].(string), Path: "/"})
	case "/api/upload/create":
		id := fmt.Sprintf("%s/%s", body["dir"], body["name"])
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(transfer.Created{UploadID: id, PartSize: 4, PartCount: transfer.PartCount(int64(body["size"].(float64)), 4)})
		return
	case "/api/upload/complete":
		id := body["uploadId"].(string)
		f.done[id] = id
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(transfer.Result{Path: id})
		return
	case "/api/upload/list":
		w.Write([]byte(`{"uploads":[]}`))
		return
	case "/api/fs/delete":
		if f.refuseDeletes {
			w.WriteHeader(403)
			w.Write([]byte(`{"error":{"code":"forbidden"}}`))
			return
		}
	}
	w.Write([]byte(`{}`))
}

func readCSV(t *testing.T, path string) [][]string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rows [][]string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		rows = append(rows, strings.Split(line, ","))
	}
	if strings.Join(rows[0], ",") != load.Header {
		t.Fatalf("header %q", rows[0])
	}
	return rows[1:]
}

func TestTheCommandUploadsOverHTTPS(t *testing.T) {
	for _, c := range []struct {
		flags []string
		proto string
		col   string
		users string
	}{
		{nil, "HTTP/2.0", "https-h2", "load00 load01"},
		{[]string{"-transport", "https-h1", "-user-prefix", "Bench"}, "HTTP/1.1", "https-h1", "bench00 bench01"},
	} {
		f := newFakeServer(t)
		csv := filepath.Join(t.TempDir(), "out.csv")
		args := append([]string{"-url", f.srv.URL, "-ca", f.caFile, "-users", "2", "-files", "1", "-size", "10", "-reps", "2", "-csv", csv}, c.flags...)
		if err := run(args, strings.NewReader("pw\n")); err != nil {
			t.Fatal(err)
		}
		rows := readCSV(t, csv)
		if len(rows) != 2 {
			t.Fatalf("%d rows", len(rows))
		}
		for _, row := range rows {
			if row[2] != "engine_upload_2u" || row[3] != "10" || row[4] != "2" || row[5] != "8" || row[11] != "201" || row[12] != c.col {
				t.Errorf("%s: row %q", c.col, row)
			}
		}
		f.mu.Lock()
		if len(f.protos) != 1 || f.protos[c.proto] == 0 {
			t.Errorf("%s: protocols %v", c.col, f.protos)
		}
		if got := strings.Join(f.users, " "); got != c.users {
			t.Errorf("%s: logged in %s, want %s", c.col, got, c.users)
		}
		// Each repetition's files are deleted before the next one creates any.
		var order []string
		for _, call := range f.calls {
			if call == "/api/upload/create" || call == "/api/fs/delete" {
				order = append(order, strings.TrimPrefix(call, "/api/"))
			}
		}
		if got := strings.Join(order, " "); got != "upload/create upload/create fs/delete fs/delete upload/create upload/create fs/delete fs/delete" {
			t.Errorf("%s: calls %s", c.col, got)
		}
		f.mu.Unlock()
	}
}

func TestTheCommandRunsTheEngineInProcess(t *testing.T) {
	dir := t.TempDir()
	csv, work := filepath.Join(dir, "out.csv"), filepath.Join(dir, "work")
	if err := run([]string{"-work", work, "-csv", csv, "-size", "10", "-reps", "1", "-min-free-mb", "0", "-audit-parts", "-audit-wait=false"}, strings.NewReader("")); err != nil {
		t.Fatal(err)
	}
	rows := readCSV(t, csv)
	if len(rows) != 1 || rows[0][2] != "engine_upload_1u_audit_parts_no_wait" || rows[0][5] != "4" || rows[0][11] != "201" || rows[0][12] != "inprocess" {
		t.Errorf("rows %q", rows)
	}
	if entries, err := os.ReadDir(work); err != nil || len(entries) != 1 || entries[0].Name() != workMark {
		t.Errorf("the scratch folder after the run: %v, %v", entries, err)
	}
}

func TestTheCommandRefuses(t *testing.T) {
	f := newFakeServer(t)
	dir := t.TempDir()
	csv := filepath.Join(dir, "out.csv")
	remote := []string{"-url", f.srv.URL, "-ca", f.caFile, "-csv", csv, "-size", "10", "-reps", "1"}
	for _, c := range []struct {
		args  []string
		stdin string
		want  string
	}{
		{append(remote, "-work", dir), "pw\n", "-work: only for the in-process mode"},
		{remote, "", "no password"},
		{remote, "wrong\n", "log in as load00"},
		{[]string{"-url", f.srv.URL, "-ca", filepath.Join(dir, "missing.crt")}, "pw\n", "missing.crt"},
		{[]string{"-size", "1T"}, "", "invalid flags"},
		{[]string{"-users", "0"}, "", "invalid flags"},
		{[]string{"-ca", f.caFile}, "", "-ca: only for -url"},
	} {
		if err := run(c.args, strings.NewReader(c.stdin)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: %v, want %q", c.args, err, c.want)
		}
	}
	if _, err := os.Stat(csv); !os.IsNotExist(err) {
		t.Errorf("a refused run made its CSV: %v", err)
	}
	f.mu.Lock()
	f.refuseDeletes = true
	f.mu.Unlock()
	err := run(append(remote, "-reps", "2"), strings.NewReader("pw\n"))
	if err == nil || !strings.Contains(err.Error(), "removing what rep 1 uploaded") {
		t.Errorf("a refused delete: %v", err)
	}
	if rows := readCSV(t, csv); len(rows) != 1 || rows[0][11] != "201" {
		t.Errorf("the measured repetition's row: %q", rows)
	}
	if err := run([]string{"-no-such-flag"}, strings.NewReader("")); !errors.Is(err, errUsage) {
		t.Errorf("an unknown flag: %v", err)
	}
	if err := run([]string{"-h"}, strings.NewReader("")); !errors.Is(err, flag.ErrHelp) {
		t.Errorf("-h: %v", err)
	}
}
