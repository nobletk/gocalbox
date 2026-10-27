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
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"

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
		set         []string
		remote, tus bool
		transport   string
		want        string
	}{
		{nil, false, false, "https-h2", ""},
		{[]string{"bench-dir", "audit-wait", "audit-parts", "min-free-mb", "users", "files", "size", "parallel", "csv", "resume-at", "retry-for", "reps"}, false, false, "https-h2", ""},
		{[]string{"url", "ca", "transport", "user-prefix", "users", "files", "size", "parallel", "fault-at", "fault-cmd", "csv", "resume-at", "retry-for"}, true, false, "https-h1", ""},
		{[]string{"tus", "ca", "transport", "file", "chunk", "csv", "resume-at", "retry-for", "reps"}, false, true, "https-h1", ""},
		{[]string{"ca"}, false, false, "https-h2", "-ca: only for -url and -tus"},
		{[]string{"transport", "user-prefix"}, false, false, "https-h1", "-transport: only for -url and -tus; -user-prefix: only for -url"},
		{[]string{"bench-dir"}, true, false, "https-h2", "-bench-dir: only for the in-process mode; set them on the server"},
		{[]string{"audit-wait", "audit-parts", "min-free-mb"}, true, false, "https-h2", "-audit-wait, -audit-parts, -min-free-mb: only for the in-process mode; set them on the server"},
		{[]string{"file", "chunk"}, true, false, "https-h2", "-file, -chunk: only for -tus"},
		{[]string{"chunk"}, false, false, "https-h2", "-chunk: only for -tus"},
		{[]string{"bench-dir", "users", "size", "user-prefix", "fault-at"}, false, true, "https-h2",
			"-bench-dir: only for the in-process mode; -users, -size: only for the in-process mode and -url; -user-prefix, -fault-at: only for -url"},
		{nil, true, true, "https-h2", "-url and -tus: choose one server"},
		{[]string{"transport"}, true, false, "h2", `-transport must be https-h2 or https-h1, not "h2"`},
		{[]string{"transport"}, false, true, "h1", `-transport must be https-h2 or https-h1, not "h1"`},
	} {
		set := map[string]bool{}
		for _, f := range c.set {
			set[f] = true
		}
		err := checkModes(set, c.remote, c.tus, c.transport)
		if got := fmt.Sprint(err); c.want == "" && err != nil || c.want != "" && got != c.want {
			t.Errorf("%v, remote %v, tus %v, %s: %v, want %q", c.set, c.remote, c.tus, c.transport, err, c.want)
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

// -fault-cmd runs once in each repetition, and the row counts the time from
// it to the file's end; a fault that fails, or never comes, writes no row and
// stops the command, after cleaning up.
func TestTheCommandRunsItsFault(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil || runtime.GOOS == "windows" {
		t.Skip("the fault runs with bash, on Linux")
	}
	f := newFakeServer(t)
	dir := t.TempDir()
	header := strings.Split(load.Header, ",")
	csv, ran := filepath.Join(dir, "out.csv"), filepath.Join(dir, "ran")
	remote := []string{"-url", f.srv.URL, "-ca", f.caFile, "-csv", csv, "-size", "10", "-retry-for", "1m"}
	if err := run(append(remote, "-reps", "2", "-fault-at", "0.5", "-fault-cmd", "echo x >> "+ran), strings.NewReader("pw\n"), io.Discard); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(ran); string(b) != "x\nx\n" {
		t.Errorf("the fault ran %q", b)
	}
	rows := readCSV(t, csv)
	// What the fault prints goes to standard error, with the load client's log, and none to standard output.
	stdout, stderr := capture(t, func() {
		if err := run(append(remote, "-reps", "1", "-fault-at", "0.5", "-fault-cmd", "echo fault-said"), strings.NewReader("pw\n"), io.Discard); err != nil {
			t.Error(err)
		}
	})
	if strings.Contains(stdout, "fault-said") || !strings.Contains(stderr, "fault-said") {
		t.Errorf("standard output %q, standard error %q", stdout, stderr)
	}
	// The session quotes the command with bash's printf %q, which writes other than ASCII as $'\ooo'.
	accented := filepath.Join(dir, "ran-\u00e9")
	quoted := "$'" + strings.ReplaceAll(dir, "'", `\'`) + `/ran-\303\251'`
	if err := run(append(remote, "-reps", "1", "-fault-at", "0.5", "-fault-cmd", "echo y >> "+quoted), strings.NewReader("pw\n"), io.Discard); err != nil {
		t.Errorf("a command quoted by bash: %v", err)
	}
	if b, _ := os.ReadFile(accented); string(b) != "y\n" {
		t.Errorf("a command quoted by bash wrote %q", b)
	}
	os.Remove(csv)
	for _, row := range rows {
		if row[2] != "engine_upload_1u_fault50" || row[11] != "201" || row[slices.Index(header, "resumed")] != "1" {
			t.Errorf("row %q", row)
		}
	}
	if len(rows) != 2 {
		t.Errorf("%d rows", len(rows))
	}

	os.Remove(csv)
	f.mu.Lock()
	f.calls = nil
	f.mu.Unlock()
	err := run(append(remote, "-reps", "2", "-fault-at", "0.5", "-fault-cmd", "exit 3"), strings.NewReader("pw\n"), io.Discard)
	if err == nil || !strings.Contains(err.Error(), "rep 1: the fault: exit status 3") {
		t.Errorf("a failed fault: %v", err)
	}
	if _, err := os.Stat(csv); err == nil && len(readCSV(t, csv)) != 0 {
		t.Errorf("a failed fault's row: %q", readCSV(t, csv))
	}
	f.mu.Lock()
	if creates, deletes := slices.Index(f.calls, "/api/upload/create"), slices.Index(f.calls, "/api/fs/delete"); creates < 0 || deletes < creates ||
		strings.Count(strings.Join(f.calls, " "), "/api/upload/create") != 1 {
		t.Errorf("calls after a failed fault: %q", f.calls)
	}
	f.unavailable = 1
	f.mu.Unlock()
	err = run([]string{"-url", f.srv.URL, "-ca", f.caFile, "-csv", csv, "-size", "10", "-reps", "1", "-fault-at", "0.5", "-fault-cmd", "echo y >> " + ran},
		strings.NewReader("pw\n"), io.Discard)
	if err == nil || !strings.Contains(err.Error(), "rep 1: no file reached 0.5 of its parts, so the fault didn't happen") {
		t.Errorf("a fault that never came: %v", err)
	}
	if b, _ := os.ReadFile(ran); string(b) != "x\nx\n" {
		t.Errorf("the fault ran %q", b)
	}
	f.mu.Lock()
	f.refuseDeletes = true
	f.mu.Unlock()
	err = run(append(remote, "-reps", "1", "-fault-at", "0.5", "-fault-cmd", "exit 3"), strings.NewReader("pw\n"), io.Discard)
	if err == nil || !strings.Contains(err.Error(), "the fault: exit status 3") || !strings.Contains(err.Error(), "removing what rep 1 uploaded") {
		t.Errorf("a failed fault and a refused delete: %v", err)
	}
}

// capture runs f with os.Stdout and os.Stderr going to files, and returns what each got.
func capture(t *testing.T, f func()) (stdout, stderr string) {
	t.Helper()
	dir := t.TempDir()
	out, _ := os.Create(filepath.Join(dir, "out"))
	errf, _ := os.Create(filepath.Join(dir, "err"))
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = out, errf
	defer func() { os.Stdout, os.Stderr = oldOut, oldErr; out.Close(); errf.Close() }()
	f()
	o, _ := os.ReadFile(out.Name())
	e, _ := os.ReadFile(errf.Name())
	return string(o), string(e)
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
		{[]string{"-ca", f.caFile}, "", "-ca: only for -url and -tus"},
		{append(remote, "-fault-at", "1", "-fault-cmd", "true"), "pw\n", "-fault-at must be at least 0 and below 1"},
		{append(remote, "-fault-at", "NaN", "-fault-cmd", "true"), "pw\n", "-fault-at must be"},
		{append(remote, "-fault-at", "0.5"), "pw\n", "given with -fault-cmd"},
		{append(remote, "-fault-cmd", "true"), "pw\n", "given with -fault-cmd"},
		{append(remote, "-fault-at", "0.5", "-fault-cmd", "true", "-resume-at", "0.5"), "pw\n", "not with -resume-at"},
		{[]string{"-fault-at", "0.5", "-fault-cmd", "true"}, "", "-fault-at, -fault-cmd: only for -url"},
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

func TestTheLogLineSaysWhatTheEngineDid(t *testing.T) {
	got := engineSummary(transfer.Stats{PartsReceived: 1, Duplicates: 2, Busy: 3, WaitTimeouts: 4, QueueFull: 5,
		TooManyRequests: 6, TooManyUploads: 7, Waited: 8, WaitTime: 9 * time.Millisecond})
	want := "the engine: 1 parts, 2 duplicates, refused busy 3 (4 waits ran out, 5 found the queue full), too_many_requests 6, too_many_uploads 7; 8 parts waited for a slot, 9ms in all"
	if got != want {
		t.Errorf("%s\nwant %s", got, want)
	}
}

// tusServer is a tus server that takes uploads whole, and records the
// length of each PATCH and its protocol.
type tusServer struct {
	srv     *httptest.Server
	caFile  string
	mu      sync.Mutex
	held    map[string]int64
	patches []string
}

func newTusServer(t *testing.T) *tusServer {
	f := &tusServer{held: map[string]int64{}}
	n := 0
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch r.Method {
		case http.MethodPost:
			n++
			id := fmt.Sprintf("/files/u%d", n)
			f.held[id] = 0
			w.Header().Set("Location", id)
			w.WriteHeader(http.StatusCreated)
		case http.MethodHead:
			w.Header().Set("Upload-Offset", fmt.Sprint(f.held[r.URL.Path]))
		case http.MethodPatch:
			got, _ := io.Copy(io.Discard, r.Body)
			f.held[r.URL.Path] += got
			f.patches = append(f.patches, fmt.Sprintf("%s %d", r.Proto, got))
			w.Header().Set("Upload-Offset", fmt.Sprint(f.held[r.URL.Path]))
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	f.srv.EnableHTTP2 = true
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	f.caFile = filepath.Join(t.TempDir(), "ca.crt")
	os.WriteFile(f.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw}), 0o644)
	return f
}

// With -tus the file goes to the tus server in PATCHes of the engine's part
// size, or of -chunk, once per repetition, each with its row.
func TestTheTusMode(t *testing.T) {
	f := newTusServer(t)
	src := filepath.Join(t.TempDir(), "src.bin")
	size := transfer.PartSize(9<<20) + 1<<20
	if err := os.WriteFile(src, make([]byte, size), 0o644); err != nil {
		t.Fatal(err)
	}
	csv := filepath.Join(t.TempDir(), "out.csv")
	base := []string{"-tus", f.srv.URL + "/files/", "-ca", f.caFile, "-file", src, "-csv", csv}
	if err := run(append(base, "-reps", "2"), strings.NewReader(""), io.Discard); err != nil {
		t.Fatal(err)
	}
	part := transfer.PartSize(size)
	want := []string{fmt.Sprintf("HTTP/2.0 %d", part), fmt.Sprintf("HTTP/2.0 %d", size-part)}
	want = append(want, want...)
	if fmt.Sprint(f.patches) != fmt.Sprint(want) {
		t.Errorf("PATCHes %q, want %q", f.patches, want)
	}
	f.patches = nil
	if err := run(append(base, "-reps", "1", "-chunk", "0", "-transport", "https-h1", "-retry-for", "1s"), strings.NewReader(""), io.Discard); err != nil {
		t.Fatal(err)
	}
	if want := []string{fmt.Sprintf("HTTP/1.1 %d", size)}; fmt.Sprint(f.patches) != fmt.Sprint(want) {
		t.Errorf("PATCHes %q, want %q", f.patches, want)
	}
	f.patches = nil
	if err := run(append(base, "-reps", "1", "-chunk", "4M", "-resume-at", "0.5"), strings.NewReader(""), io.Discard); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(csv)
	rows := strings.Split(strings.TrimSpace(string(b)), "\n")
	if rows[0] != load.Header || len(rows) != 5 {
		t.Fatalf("rows %q", rows)
	}
	header := strings.Split(load.Header, ",")
	for i, want := range []struct{ scenario, rep, transport, resumed string }{
		{"tus_upload", "1", "https-h2", "0"}, {"tus_upload", "2", "https-h2", "0"}, {"tus_upload", "1", "https-h1", "0"},
		{"tus_upload_resume50", "1", "https-h2", "1"},
	} {
		row := strings.Split(rows[i+1], ",")
		col := func(name string) string { return row[slices.Index(header, name)] }
		if col("scenario") != want.scenario || col("rep") != want.rep || col("transport") != want.transport || col("resumed") != want.resumed ||
			col("size_bytes") != fmt.Sprint(size) || col("files") != "1" || col("concurrency") != "1" || col("http_code") != "201" {
			t.Errorf("row %d: %s", i+1, rows[i+1])
		}
	}
	if n := len(f.patches); n != 3 {
		t.Errorf("%d PATCHes of 4 MiB, want 3", n)
	}
}

func TestTheTusModeRefuses(t *testing.T) {
	f := newTusServer(t)
	src := filepath.Join(t.TempDir(), "src.bin")
	os.WriteFile(src, []byte("data"), 0o644)
	csv := filepath.Join(t.TempDir(), "out.csv")
	base := []string{"-tus", f.srv.URL + "/files/", "-ca", f.caFile, "-csv", csv}
	for _, c := range []struct {
		args []string
		want string
	}{
		{base, "-tus needs -file"},
		{append(base, "-file", src+".missing"), "no such file"},
		{append(base, "-file", src, "-chunk", "x"), "-chunk \"x\""},
		{append(base, "-file", src, "-chunk", "0", "-resume-at", "0.5"), "-resume-at needs chunks"},
		{append(base, "-file", src, "-users", "2"), "-users: only for the in-process mode and -url"},
		{append(base, "-file", src, "-url", f.srv.URL), "choose one server"},
		{append(base, "-file", src, "-transport", "h2"), "-transport must be"},
		{[]string{"-file", src}, "-file: only for -tus"},
		{append(base, "-file", src, "-tus", "http://x/files/"), "https://host:port/path"},
	} {
		if err := run(c.args, strings.NewReader(""), io.Discard); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: %v, want %q", c.args, err, c.want)
		}
	}
	if len(f.patches) != 0 {
		t.Errorf("a refused run sent %q", f.patches)
	}
	if b, _ := os.ReadFile(csv); strings.Count(string(b), "\n") > 1 {
		t.Errorf("a refused run wrote rows: %q", b)
	}
}
