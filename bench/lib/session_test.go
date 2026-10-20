package lib

import (
	"crypto/sha256"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nobletk/gocalbox/bench/load"
)

// keepResults removes, when the test ends, the files a script added to
// bench/results.
func keepResults(t *testing.T) {
	t.Helper()
	results := filepath.Join("..", "..", "bench", "results")
	before, _ := os.ReadDir(results)
	t.Cleanup(func() {
		after, _ := os.ReadDir(results)
		old := map[string]bool{}
		for _, e := range before {
			old[e.Name()] = true
		}
		for _, e := range after {
			if !old[e.Name()] {
				os.Remove(filepath.Join(results, e.Name()))
			}
		}
	})
}

// output finds the line "<label>: <path>" in a script's output and reads the
// file, relative to the repository root.
func output(t *testing.T, out, label string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if p, ok := strings.CutPrefix(line, label+": "); ok {
			b, err := os.ReadFile(filepath.Join("..", "..", strings.TrimSpace(p)))
			if err != nil {
				t.Fatal(err)
			}
			return string(b)
		}
	}
	t.Fatalf("no %s in:\n%s", label, out)
	return ""
}

func planOf(t *testing.T, dir, matrix string, env ...string) []string {
	t.Helper()
	m := filepath.Join(t.TempDir(), "m.txt")
	write(t, m, matrix)
	out, ok := scriptArgs(t, []string{"session.sh", m}, "", append([]string{"BENCH_DIR=" + dir, "PLAN_ONLY=1", "SERVER_SSH="}, env...)...)
	if !ok {
		t.Fatalf("session.sh: %s", out)
	}
	order := strings.Split(strings.TrimSpace(output(t, strings.Replace(out, "; order: ", "\norder: ", 1), "order")), "\n")
	var runs []string
	for _, line := range order[1:] {
		f := strings.Split(line, ",")
		if f[6] != "planned" {
			t.Fatalf("order line %s", line)
		}
		runs = append(runs, f[1]+" "+f[2]+" "+f[3])
	}
	return runs
}

const planMatrix = `# a comment
server a
server b BUILD_TAGS=bench GOCALBOX_BENCH_PART_SIZE=16M

cell e1 a engine size=1M
cell e2 b engine size=5G users=3
cell u1 a upload size=64K reps=2
cell ip - inprocess size=1M
`

// The order depends on the seed alone: the servers' groups, each with its
// warm-ups first, then its measured runs, every cell as often as asked.
func TestTheSessionsOrder(t *testing.T) {
	needBash(t)
	for _, tool := range []string{"shuf", "openssl", "numfmt"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("no %s", tool)
		}
	}
	keepResults(t)
	dir := benchDir(t)
	first := planOf(t, dir, planMatrix, "SEED=7", "REPS=4", "BIG_REPS=2", "WARMUP=1")
	again := planOf(t, dir, planMatrix, "SEED=7", "REPS=4", "BIG_REPS=2", "WARMUP=1")
	other := planOf(t, dir, planMatrix, "SEED=8", "REPS=4", "BIG_REPS=2", "WARMUP=1")
	if !slices.Equal(first, again) {
		t.Errorf("the same seed gave\n%q\nand\n%q", first, again)
	}
	if slices.Equal(first, other) {
		t.Errorf("seeds 7 and 8 gave the same order %q", first)
	}
	count := map[string]int{}
	for _, r := range first {
		f := strings.Fields(r)
		count[f[1]+" "+map[bool]string{true: "warm-up", false: "measured"}[f[2] == "0"]]++
	}
	want := map[string]int{"e1 warm-up": 1, "e1 measured": 4, "e2 warm-up": 1, "e2 measured": 2, "u1 warm-up": 1, "u1 measured": 2, "ip warm-up": 1, "ip measured": 4}
	if fmt.Sprint(count) != fmt.Sprint(want) {
		t.Errorf("runs %v, want %v", count, want)
	}
	// Each server's runs are together, its warm-ups first.
	seen := map[string]bool{}
	last, measured := "", false
	for _, r := range first {
		f := strings.Fields(r)
		if f[0] != last {
			if seen[f[0]] {
				t.Fatalf("server %s's runs are split: %q", f[0], first)
			}
			seen[f[0]], last, measured = true, f[0], false
		}
		if f[2] != "0" {
			measured = true
		} else if measured {
			t.Fatalf("a warm-up after a measured run: %q", first)
		}
	}
	only := planOf(t, dir, planMatrix, "SEED=7", "REPS=1", "BIG_REPS=1", "WARMUP=0", "CELLS=e,ip")
	slices.Sort(only)
	if strings.Join(only, ";") != "- ip 1;a e1 1;b e2 1" {
		t.Errorf("CELLS=e,ip: %q", only)
	}
}

// The shipped matrices are valid.
func TestTheSessionFilesAreValid(t *testing.T) {
	needBash(t)
	for _, tool := range []string{"shuf", "openssl", "numfmt"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("no %s", tool)
		}
	}
	keepResults(t)
	dir := benchDir(t)
	files, _ := filepath.Glob(filepath.Join("..", "..", "bench", "sessions", "*.txt"))
	if len(files) < 3 {
		t.Fatalf("matrices %v", files)
	}
	for _, f := range files {
		b, _ := os.ReadFile(f)
		if runs := planOf(t, dir, string(b), "SEED=1", "PRE_M6=HEAD"); len(runs) < 10 {
			t.Errorf("%s: %d runs", f, len(runs))
		}
	}
}

func TestTheSessionRefusesABadMatrix(t *testing.T) {
	needBash(t)
	keepResults(t)
	dir := benchDir(t)
	for _, c := range []struct {
		matrix string
		env    []string
		want   string
	}{
		{"server a\ncell x a scp size=1M\n", nil, "no tool scp"},
		{"server a\ncell x a engine size=1M colour=red\n", nil, "engine takes no colour"},
		{"server a\ncell x a engine size=1T\n", nil, "size must be"},
		{"server a\ncell x a engine\n", nil, "engine needs a size"},
		{"server a\ncell x a engine size=1M transport=http\n", nil, "transport must be"},
		{"server a\ncell x a engine size=1M users=0\n", nil, "users must be a number from 1"},
		{"server a\ncell x a engine size=1M resume-at=1\n", nil, "resume-at must be a share"},
		{"server a\ncell x a engine size=1M retry-for=2h\n", nil, "retry-for must be"},
		{"server a\ncell x a inprocess size=1M audit-parts=yes\n", nil, "audit-parts must be 0 or 1"},
		{"cell x a engine size=1M\n", nil, "no server named a"},
		{"server a\ncell x a inprocess size=1M\n", nil, "give - as its server"},
		{"server a\ncell x - inprocess size=1M\n", []string{"SERVER_SSH=me@host", "SERVER_HOST=h", "SERVER_BENCH=/b", "SERVER_REPO=/r"}, "runs only with the server here"},
		{"server a\ncell x a engine size=1M\ncell x a engine size=1M\n", nil, "cell x again"},
		{"server a\nserver a\n", nil, "server a again"},
		{"server a SERVER_REV=$NOT_SET_ANYWHERE\n", nil, "NOT_SET_ANYWHERE is not set"},
		{"server a WORK=/tmp\n", nil, "takes no WORK here"},
		{"server a SERVER_FLAGS=-x;rm\n", nil, "unusual characters"},
		{"server a\ncell x/y a engine size=1M\n", nil, "an ID of letters"},
		{"run x\n", nil, "starts with server or cell"},
		{"server a\n", nil, "no cell to run"},
		{"server a\ncell x a engine size=1M\n", []string{"CELLS=y"}, "no cell to run with CELLS=y"},
		{"server a\ncell x a engine size=1M\n", []string{"SERVER_SSH=me@host"}, "set SERVER_HOST"},
		{"server a\ncell x a engine size=1M\n", []string{"REPS=many"}, "REPS must be a number"},
		{"server a\ncell x a engine size=1M\n", []string{"GOCALBOX_BENCH_PART_SIZE=16M"}, "unset the GOCALBOX_BENCH_* variables"},
	} {
		m := filepath.Join(t.TempDir(), "m.txt")
		write(t, m, c.matrix)
		out, ok := scriptArgs(t, []string{"session.sh", m}, "", append([]string{"BENCH_DIR=" + dir, "PLAN_ONLY=1", "SERVER_SSH=", "SERVER_HOST="}, c.env...)...)
		if ok || !strings.Contains(out, c.want) {
			t.Errorf("%q %v: %s; want %q", c.matrix, c.env, out, c.want)
		}
	}
	out, ok := script(t, "session.sh", "", "BENCH_DIR="+t.TempDir())
	if ok || !strings.Contains(out, "usage") {
		t.Errorf("without a matrix: %s", out)
	}
}

// sessionTools skips a test of a whole session where its tools are missing.
func sessionTools(t *testing.T) {
	t.Helper()
	needBash(t)
	if testing.Short() {
		t.Skip("builds and runs the server")
	}
	for _, tool := range []string{"curl", "numfmt", "go", "openssl", "shuf", "tar"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("no %s", tool)
		}
	}
}

const runMatrix = `server plain
server bench BUILD_TAGS=bench GOCALBOX_BENCH_H2_STREAM_WINDOW=128K
cell e-h2  plain engine transport=https-h2 size=64M files=2 users=2
cell e-h1  bench engine transport=https-h1 size=64K
cell stop  bench engine size=17M resume-at=0.5 retry-for=30s
cell up    plain upload transport=https-h1 size=64K
cell down  plain download transport=https-h2 size=64K
cell down1 plain download transport=https-h1 size=64K
cell batch bench batch conc=4 files=5
`

// checkSession checks a session's results: a row for every run, each ok,
// with the server's CPU time where a server ran, and nothing left of the
// runs in the benchmark folders but the data and the servers' own folders.
func checkSession(t *testing.T, out string, dirs ...string) {
	t.Helper()
	csv := strings.Split(strings.TrimSpace(output(t, out, "results")), "\n")
	if csv[0] != load.Header {
		t.Fatalf("header %q", csv[0])
	}
	header := strings.Split(load.Header, ",")
	col := func(row []string, name string) string { return row[slices.Index(header, name)] }
	order := strings.Split(strings.TrimSpace(output(t, out, "order")), "\n")
	if len(order) != len(csv) {
		t.Errorf("%d runs in the order, %d rows", len(order)-1, len(csv)-1)
	}
	// Each run has its row, with its cell and repetition.
	var runs, rows []string
	for _, line := range order[1:] {
		if !strings.HasSuffix(line, ",ok") || strings.Count(line, ",") != 6 {
			t.Errorf("run %s", line)
		}
		f := strings.Split(line, ",")
		runs = append(runs, f[2]+" "+f[3])
	}
	for _, line := range csv[1:] {
		row := strings.Split(line, ",")
		rows = append(rows, col(row, "scenario")+" "+col(row, "rep"))
	}
	slices.Sort(runs)
	slices.Sort(rows)
	if !slices.Equal(runs, rows) {
		t.Errorf("runs %q, rows %q", runs, rows)
	}
	_, rest, _ := strings.Cut(out, "results: ")
	base, _, _ := strings.Cut(rest, "\n")
	base = filepath.Join("..", "..", strings.TrimSuffix(strings.TrimSpace(base), ".csv"))
	samples := map[string][][2]float64{}
	servers, _ := filepath.Glob(base + "-server-*-env.txt")
	for _, f := range servers {
		b, _ := os.ReadFile(f)
		if !strings.Contains(string(b), "server: ") || !strings.Contains(string(b), "load users: ") {
			t.Errorf("%s is incomplete:\n%s", f, b)
		}
		name := strings.TrimSuffix(strings.TrimPrefix(f, base+"-server-"), "-env.txt")
		sb, _ := os.ReadFile(base + "-server-" + name + "-samples.csv")
		for _, line := range strings.Split(strings.TrimSpace(string(sb)), "\n") {
			var tm, cpu float64
			if _, err := fmt.Sscanf(strings.ReplaceAll(line, ",", " "), "%f %f", &tm, &cpu); err == nil {
				samples[name] = append(samples[name], [2]float64{tm, cpu})
			}
		}
	}
	if len(servers) == 0 {
		t.Error("no server's environment file with the results")
	}
	cpuAt := func(s [][2]float64, tm float64) float64 {
		c := s[0][1]
		for _, x := range s {
			if x[0] <= tm {
				c = x[1]
			}
		}
		if tm >= s[len(s)-1][0] {
			c = s[len(s)-1][1]
		}
		return c
	}
	busy := false
	for _, line := range csv[1:] {
		row := strings.Split(line, ",")
		if len(row) != len(header) {
			t.Fatalf("%d columns: %s", len(row), line)
		}
		code, cpu, transport := col(row, "http_code"), col(row, "server_cpu_s"), col(row, "transport")
		if code != "201" && code != "200" || col(row, "started_unix") == "" {
			t.Errorf("row %s", line)
		}
		if (transport == "inprocess") != (cpu == "") {
			t.Errorf("server CPU %q for %s", cpu, transport)
		}
		if col(row, "scenario") == "stop" && col(row, "resumed") != "1" {
			t.Errorf("the stopped file's row: %s", line)
		}
		// An engine run's own start and length place it among its server's samples.
		if col(row, "part_p50_ms") != "" && transport != "inprocess" {
			var start, secs, got float64
			fmt.Sscan(col(row, "started_unix"), &start)
			fmt.Sscan(col(row, "seconds"), &secs)
			fmt.Sscan(cpu, &got)
			for _, s := range samples {
				if len(s) > 0 && s[0][0] <= start && start <= s[len(s)-1][0] {
					if want := cpuAt(s, start+secs) - cpuAt(s, start); math.Abs(got-want) > 1e-6 {
						t.Errorf("server CPU %s for a run from %.6f for %.6f s; the samples say %.4f", cpu, start, secs, want)
					}
				}
			}
			busy = busy || got > 0
		}
	}
	if !busy {
		t.Error("no engine run used any of its server's CPU")
	}
	env := output(t, out, "environment")
	for _, want := range []string{"seed: ", "cpu: ", "--- the matrix", "not ok: 0", "network at the end"} {
		if !strings.Contains(env, want) {
			t.Errorf("the environment file has no %q", want)
		}
	}
	for _, warning := range []string{"left files in its served folder", "the rest of its runs are skipped"} {
		if strings.Contains(env, warning) {
			t.Errorf("the environment file says %q:\n%s", warning, env)
		}
	}
	for _, dir := range dirs {
		for _, rel := range []string{"session/gocalbox-load", "load"} {
			if exists(filepath.Join(dir, rel)) {
				t.Errorf("left in the benchmark folder: %s", rel)
			}
		}
		entries, _ := os.ReadDir(filepath.Join(dir, "session"))
		for _, e := range entries {
			if e.Name() != "load.log" {
				t.Errorf("left in the session folder: %s", e.Name())
			}
		}
		if root, err := os.ReadDir(filepath.Join(dir, "server", "root")); err == nil {
			for _, e := range root {
				if !slices.Contains([]string{".gocalbox", "public", "users"}, e.Name()) {
					t.Errorf("left in the served folder: %s", e.Name())
				}
			}
		}
	}
}

// A session with the server on this machine, as session 1 runs.
func TestASessionWithTheServerHere(t *testing.T) {
	sessionTools(t)
	keepResults(t)
	dir := benchDir(t)
	write(t, filepath.Join(dir, "load", "stale.bin"), "old")
	write(t, filepath.Join(dir, "server", "root", "stale.bin"), "old")
	matrix := filepath.Join(t.TempDir(), "m.txt")
	write(t, matrix, runMatrix+"cell ip - inprocess size=1M files=3 audit-parts=1\n")
	bin := fakeIperf(t)
	out, ok := scriptArgs(t, []string{"session.sh", matrix}, bin, "BENCH_DIR="+dir, "PORT=18392", "REPS=1", "WARMUP=1",
		"DROP_CACHES=0", "IPERF=1", "SERVER_SSH=", "SERVER_HOST=", "CELLS=")
	if !ok {
		t.Fatalf("session.sh: %s", out)
	}
	checkSession(t, out, dir)
	env := output(t, out, "environment")
	for _, want := range []string{"at the start, Mbit/s: to the server 941, from the server 930",
		"at the end, Mbit/s: to the server 941, from the server 700",
		"rate from the server changed from 930 to 700 Mbit/s"} {
		if !strings.Contains(env, want) {
			t.Errorf("the environment file has no %q", want)
		}
	}
	_, rest, _ := strings.Cut(out, "results: ")
	csv, _, _ := strings.Cut(rest, "\n")
	for _, f := range []string{"server-plain-env.txt", "server-bench-requests.jsonl", "server-plain-samples.csv", "server-bench.log"} {
		if !exists(filepath.Join("..", "..", strings.TrimSuffix(csv, ".csv")+"-"+f)) {
			t.Errorf("no %s with the results", f)
		}
	}
	if b, _ := os.ReadFile(filepath.Join("..", "..", strings.TrimSuffix(csv, ".csv")+"-server-bench-requests.jsonl")); !strings.Contains(string(b), `"path":"/api/upload/part"`) {
		t.Errorf("the benchmark build's request log has no part: %.300s", b)
	}
	if !exists(filepath.Join(dir, "data", "fixed-64K.bin")) || !exists(filepath.Join(dir, ".gocalbox-bench")) {
		t.Error("the data or the marker is gone")
	}
}

// fakeIperf is an iperf3 whose rate from the server falls from 930 to 700
// Mbit/s between the session's start and end.
func fakeIperf(t *testing.T) string {
	t.Helper()
	bin := t.TempDir()
	write(t, filepath.Join(bin, "iperf3"), `#!/bin/bash
case " $* " in
  *" -s "*) exit 0 ;;
  *" -R "*) n=$(cat `+bin+`/reverse 2>/dev/null || echo 0); echo $((n + 1)) > `+bin+`/reverse
            rate=930; [ "$n" -ge 1 ] && rate=700 ;;
  *) rate=941 ;;
esac
echo "[  5]   0.00-10.00  sec  1100 MBytes   $((rate + 2)) Mbits/sec    0             sender"
echo "[  5]   0.00-10.00  sec  1099 MBytes   $rate Mbits/sec                  receiver"
`)
	os.Chmod(filepath.Join(bin, "iperf3"), 0o755)
	return bin
}

// fakeRemote is an ssh that runs the command here, as ssh would on the
// server, and logs its options.
func fakeRemote(t *testing.T) (bin, log string) {
	t.Helper()
	bin = t.TempDir()
	log = filepath.Join(bin, "ssh.log")
	write(t, filepath.Join(bin, "ssh"), `#!/bin/bash
echo "$*" >> `+log+`
while [ $# -gt 0 ]; do
  case $1 in
    -o | -O) [ "$1" = -O ] && exit 0; shift 2 ;;
    -f | -N | -n | -fN) [ "$1" = -fN ] && exit 0; shift ;;
    *) break ;;
  esac
done
shift
exec bash -c "$*"
`)
	os.Chmod(filepath.Join(bin, "ssh"), 0o755)
	return bin, log
}

// A session with the server reached over ssh, as session 2 runs: the
// server's folder is another benchmark folder, and every delete there goes
// through its helper.
func TestASessionOverSSH(t *testing.T) {
	sessionTools(t)
	keepResults(t)
	client, server := benchDir(t), benchDir(t)
	bin, log := fakeRemote(t)
	repo, _ := filepath.Abs(filepath.Join("..", ".."))
	matrix := filepath.Join(t.TempDir(), "m.txt")
	write(t, matrix, runMatrix)
	out, ok := scriptArgs(t, []string{"session.sh", matrix}, bin, "BENCH_DIR="+client, "SERVER_SSH=bench@server", "SERVER_HOST=localhost",
		"SERVER_BENCH="+server, "SERVER_REPO="+repo, "PORT=18393", "REPS=1", "WARMUP=0", "DROP_CACHES=0", "IPERF=0", "CELLS=")
	if !ok {
		t.Fatalf("session.sh: %s", out)
	}
	checkSession(t, out, client, server)
	b, _ := os.ReadFile(log)
	calls := string(b)
	if !strings.Contains(calls, "ControlMaster=yes") || !strings.Contains(calls, "-O exit") || !strings.Contains(calls, "safe.sh rm "+server) {
		t.Errorf("ssh calls:\n%s", calls)
	}
	if exists(filepath.Join(client, "server")) {
		t.Error("the server ran in the client's folder")
	}
}

// A transfer that moved other bytes than the source's is marked, in its row
// and in the order: every upload, and a download's warm-up, which hashes
// what it got.
func TestASessionMarksAWrongTransfer(t *testing.T) {
	sessionTools(t)
	keepResults(t)
	dir := benchDir(t)
	write(t, filepath.Join(dir, "data", "fixed-64K.bin"), strings.Repeat("x", 64<<10))
	write(t, filepath.Join(dir, "data", "fixed-64K.bin.sha256"), strings.Repeat("0", 64)+"\n")
	// A data file of the wrong length: its downloads are short.
	short := strings.Repeat("y", 1000)
	write(t, filepath.Join(dir, "data", "fixed-1K.bin"), short)
	write(t, filepath.Join(dir, "data", "fixed-1K.bin.sha256"), fmt.Sprintf("%x\n", sha256.Sum256([]byte(short))))
	matrix := filepath.Join(t.TempDir(), "m.txt")
	write(t, matrix, "server s\nserver small SERVER_FLAGS=-max-upload-mb=1\ncell up s upload size=64K\ncell down s download size=64K\ncell big small engine size=2M\ncell short s download size=1K\n")
	out, ok := scriptArgs(t, []string{"session.sh", matrix}, "", "BENCH_DIR="+dir, "PORT=18394", "REPS=1", "WARMUP=1",
		"DROP_CACHES=0", "IPERF=0", "SERVER_SSH=", "SERVER_HOST=", "CELLS=")
	if !ok || !strings.Contains(out, "warning: 7 runs were not ok") {
		t.Fatalf("session.sh: %s", out)
	}
	header := strings.Split(load.Header, ",")
	codes := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(output(t, out, "results")), "\n")[1:] {
		row := strings.Split(line, ",")
		codes[row[slices.Index(header, "scenario")]+" "+row[slices.Index(header, "rep")]] = row[slices.Index(header, "http_code")]
	}
	want := map[string]string{"up 0": "201 wrong_file", "up 1": "201 wrong_file", "down 0": "200 wrong_file", "down 1": "200", "big 0": "413x1", "big 1": "413x1",
		"short 0": "200 wrong_size", "short 1": "200 wrong_size"}
	if fmt.Sprint(codes) != fmt.Sprint(want) {
		t.Errorf("codes %v, want %v", codes, want)
	}
	order := output(t, out, "order")
	for _, line := range strings.Split(strings.TrimSpace(order), "\n") {
		if strings.Count(line, ",") != 6 {
			t.Errorf("an order line of other than 7 fields: %s", line)
		}
	}
	if strings.Count(order, ",stored ") != 2 || strings.Count(order, ",got other bytes") != 1 || strings.Count(order, ",answered 413x1") != 2 || strings.Count(order, ",got 1000 of 1024 bytes") != 2 {
		t.Errorf("order:\n%s", order)
	}
}
