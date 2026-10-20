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
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/iotest"

	"github.com/nobletk/gocalbox/bench/lib"
	"github.com/nobletk/gocalbox/bench/load"
	"github.com/nobletk/gocalbox/internal/transfer"
)

// benchDir makes a benchmark folder as bench/init.sh does.
func benchDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "bench")
	os.Mkdir(dir, 0o755)
	if err := os.WriteFile(filepath.Join(dir, lib.Mark), []byte("gocalbox-bench 0123456789abcdef0123456789abcdef\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// In process, the engine works in the benchmark folder's subfolder load,
// which is emptied before each repetition and deleted at the end; nothing
// else in the folder is touched, and a folder without the marker is refused.
func TestTheEngineWorksInTheBenchmarkFolder(t *testing.T) {
	dir := benchDir(t)
	keep := filepath.Join(dir, "server", "root", "keep.bin")
	os.MkdirAll(filepath.Dir(keep), 0o755)
	os.WriteFile(keep, []byte("mine"), 0o644)
	left := filepath.Join(dir, "load", "root", "left.bin")
	os.MkdirAll(filepath.Dir(left), 0o755)
	os.WriteFile(left, nil, 0o644)
	csv := filepath.Join(t.TempDir(), "out.csv")
	t.Setenv("BENCH_DIR", dir)
	if err := run([]string{"-csv", csv, "-size", "10", "-reps", "2", "-min-free-mb", "0"}, strings.NewReader(""), io.Discard); err != nil {
		t.Fatal(err)
	}
	if rows := readCSV(t, csv); len(rows) != 2 {
		t.Errorf("rows %q", rows)
	}
	if _, err := os.Stat(filepath.Join(dir, "load")); !os.IsNotExist(err) {
		t.Errorf("the engine's folder after the run: %v", err)
	}
	if b, err := os.ReadFile(keep); err != nil || string(b) != "mine" {
		t.Errorf("a file of the benchmark folder was touched: %q, %v", b, err)
	}

	unmarked := t.TempDir()
	os.WriteFile(filepath.Join(unmarked, "go.mod"), nil, 0o644)
	for _, c := range []struct {
		env  string
		args []string
		want string
	}{
		{"", nil, "no benchmark folder given"},
		{unmarked, nil, "is not a benchmark folder"},
		{dir, []string{"-bench-dir", unmarked}, "is not a benchmark folder"},
		{dir, []string{"-bench-dir", "relative"}, "must be an absolute path"},
		{dir, []string{"-work", dir}, "-work is replaced by -bench-dir"},
	} {
		t.Setenv("BENCH_DIR", c.env)
		err := run(append(c.args, "-csv", csv, "-size", "10", "-reps", "1"), strings.NewReader(""), io.Discard)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("BENCH_DIR=%q %q: %v, want %q", c.env, c.args, err, c.want)
		}
	}
	if _, err := os.Stat(filepath.Join(unmarked, "go.mod")); err != nil {
		t.Errorf("a refused folder lost its files: %v", err)
	}
}

// A file stopped halfway resumes in process, and the row says so.
func TestTheCommandResumesInProcess(t *testing.T) {
	csv := filepath.Join(t.TempDir(), "out.csv")
	if err := run([]string{"-bench-dir", benchDir(t), "-csv", csv, "-size", "20M", "-files", "2", "-reps", "1", "-min-free-mb", "0", "-resume-at", "0.5", "-retry-for", "1m"}, strings.NewReader(""), io.Discard); err != nil {
		t.Fatal(err)
	}
	rows := readCSV(t, csv)
	header := strings.Split(load.Header, ",")
	col := func(name string) string { return rows[0][slices.Index(header, name)] }
	if len(rows) != 1 || col("scenario") != "engine_upload_1u_resume50" || col("http_code") != "201" || col("resumed") != "2" || col("client_cpu_s") != "" {
		t.Errorf("rows %q", rows)
	}
}

// A CSV file with other columns isn't appended to.
func TestACSVWithOtherColumnsIsRefused(t *testing.T) {
	dir := t.TempDir()
	scripts := filepath.Join(dir, "scripts.csv")
	os.WriteFile(scripts, []byte(load.ScriptColumns+"\nc,0,s,1,1,1,1,1,1,1,,201,https-h2\n"), 0o644)
	_, err := openCSV(scripts)
	if err == nil || !strings.Contains(err.Error(), "other columns") {
		t.Errorf("a script's CSV: %v", err)
	}
	if b, _ := os.ReadFile(scripts); !strings.HasSuffix(string(b), "https-h2\n") {
		t.Errorf("a refused CSV was written to: %q", b)
	}
	ours := filepath.Join(dir, "ours.csv")
	for range 2 {
		f, err := openCSV(ours)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintln(f, "row")
		f.Close()
	}
	if b, _ := os.ReadFile(ours); string(b) != load.Header+"\nrow\nrow\n" {
		t.Errorf("our CSV: %q", b)
	}
	empty := filepath.Join(dir, "empty.csv")
	os.WriteFile(empty, nil, 0o644)
	if f, err := openCSV(empty); err != nil {
		t.Errorf("an empty file: %v", err)
	} else {
		f.Close()
	}
	if b, _ := os.ReadFile(empty); string(b) != load.Header+"\n" {
		t.Errorf("an empty file got %q", b)
	}
	unended := filepath.Join(dir, "unended.csv")
	os.WriteFile(unended, []byte(load.Header), 0o644)
	if f, err := openCSV(unended); err != nil {
		t.Errorf("a header without its line end: %v", err)
	} else {
		fmt.Fprintln(f, "row")
		f.Close()
	}
	if b, _ := os.ReadFile(unended); string(b) != load.Header+"\nrow\n" {
		t.Errorf("a header without its line end got %q", b)
	}
	if _, err := openCSV(filepath.Join(dir, "missing", "x.csv")); err == nil {
		t.Error("a CSV in a missing folder")
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
		{[]string{"bench-dir", "audit-wait", "audit-parts", "min-free-mb", "users", "csv", "resume-at", "retry-for"}, false, "https-h2", ""},
		{[]string{"url", "ca", "transport", "user-prefix", "users", "csv", "resume-at", "retry-for"}, true, "https-h1", ""},
		{[]string{"ca"}, false, "https-h2", "-ca: only for -url"},
		{[]string{"transport", "user-prefix"}, false, "https-h1", "-transport, -user-prefix: only for -url"},
		{[]string{"bench-dir"}, true, "https-h2", "-bench-dir: only for the in-process mode; set them on the server"},
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
		"":            nil,
		"429x1 503x2": {"503": 2, "429": 1},
		"409x3":       {"409": 3, "503": 0},
	} {
		if got := load.Counts(m); got != want {
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
	unavailable   int      // creates answered 503 unavailable, as by a server shutting down
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
		if f.unavailable > 0 {
			f.unavailable--
			w.WriteHeader(503)
			w.Write([]byte(`{"error":{"code":"unavailable"}}`))
			return
		}
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
		if err := run(args, strings.NewReader("pw\n"), io.Discard); err != nil {
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

// -retry-for waits out a server shutting down; without it, the file ends.
func TestTheCommandWaitsOutAServerShuttingDown(t *testing.T) {
	f := newFakeServer(t)
	header := strings.Split(load.Header, ",")
	for _, c := range []struct {
		args          []string
		code, retried string
	}{
		{nil, "503x1", ""},
		{[]string{"-retry-for", "30s"}, "201", "503x2"},
	} {
		f.mu.Lock()
		f.unavailable = 2
		f.mu.Unlock()
		csv := filepath.Join(t.TempDir(), "out.csv")
		args := append([]string{"-url", f.srv.URL, "-ca", f.caFile, "-csv", csv, "-size", "10", "-reps", "1"}, c.args...)
		if err := run(args, strings.NewReader("pw\n"), io.Discard); err != nil {
			t.Fatal(err)
		}
		row := readCSV(t, csv)[0]
		if code, retried := row[slices.Index(header, "http_code")], row[slices.Index(header, "retried")]; code != c.code || retried != c.retried {
			t.Errorf("%v: code %s, retried %q; want %s, %q", c.args, code, retried, c.code, c.retried)
		}
	}
}

func TestTheCommandRunsTheEngineInProcess(t *testing.T) {
	csv := filepath.Join(t.TempDir(), "out.csv")
	if err := run([]string{"-bench-dir", benchDir(t), "-csv", csv, "-size", "10", "-reps", "1", "-min-free-mb", "0", "-audit-parts", "-audit-wait=false"}, strings.NewReader(""), io.Discard); err != nil {
		t.Fatal(err)
	}
	rows := readCSV(t, csv)
	if len(rows) != 1 || rows[0][2] != "engine_upload_1u_audit_parts_no_wait" || rows[0][5] != "4" || rows[0][11] != "201" || rows[0][12] != "inprocess" {
		t.Errorf("rows %q", rows)
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
		{append(remote, "-bench-dir", dir), "pw\n", "-bench-dir: only for the in-process mode"},
		{append(remote, "-work", dir), "pw\n", "-work is replaced by -bench-dir"},
		{append(remote, "-resume-at", "1"), "pw\n", "-resume-at must be at least 0 and below 1"},
		{append(remote, "-resume-at", "-0.5"), "pw\n", "-resume-at must be"},
		{append(remote, "-resume-at", "NaN"), "pw\n", "-resume-at must be"},
		{append(remote, "-retry-for", "-1s"), "pw\n", "-retry-for not negative"},
		{remote, "", "no password"},
		{remote, "wrong\n", "log in as load00"},
		{[]string{"-url", f.srv.URL, "-ca", filepath.Join(dir, "missing.crt")}, "pw\n", "missing.crt"},
		{[]string{"-size", "1T"}, "", "invalid flags"},
		{[]string{"-users", "0"}, "", "invalid flags"},
		{[]string{"-ca", f.caFile}, "", "-ca: only for -url"},
	} {
		if err := run(c.args, strings.NewReader(c.stdin), io.Discard); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: %v, want %q", c.args, err, c.want)
		}
	}
	if _, err := os.Stat(csv); !os.IsNotExist(err) {
		t.Errorf("a refused run made its CSV: %v", err)
	}
	f.mu.Lock()
	f.refuseDeletes = true
	f.mu.Unlock()
	err := run(append(remote, "-reps", "2"), strings.NewReader("pw\n"), io.Discard)
	if err == nil || !strings.Contains(err.Error(), "removing what rep 1 uploaded") {
		t.Errorf("a refused delete: %v", err)
	}
	if rows := readCSV(t, csv); len(rows) != 1 || rows[0][11] != "201" {
		t.Errorf("the measured repetition's row: %q", rows)
	}
	if err := run([]string{"-no-such-flag"}, strings.NewReader(""), io.Discard); !errors.Is(err, errUsage) {
		t.Errorf("an unknown flag: %v", err)
	}
	if err := run([]string{"-h"}, strings.NewReader(""), io.Discard); !errors.Is(err, flag.ErrHelp) {
		t.Errorf("-h: %v", err)
	}
	var out strings.Builder
	if err := run([]string{"-header", "-users", "0"}, strings.NewReader(""), &out); err != nil || out.String() != load.Header+"\n" {
		t.Errorf("-header: %q, %v", out.String(), err)
	}
}
