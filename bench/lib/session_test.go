package lib

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

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
	if order[0] != "seq,server,cell,rep,round,t0,t1,outcome" {
		t.Fatalf("order header %q", order[0])
	}
	var runs []string
	for _, line := range order[1:] {
		f := strings.Split(line, ",")
		if len(f) != 8 || f[7] != "planned" {
			t.Fatalf("order line %s", line)
		}
		runs = append(runs, f[1]+" "+f[2]+" "+f[3]+" "+f[4])
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

// The order depends on the seed alone. The measured runs are spread over
// the rounds, each cell's evenly; in each round every server serves one
// block; a server's warm-ups open its first block.
func TestTheSessionsOrder(t *testing.T) {
	needBash(t)
	for _, tool := range []string{"shuf", "openssl", "numfmt"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("no %s", tool)
		}
	}
	keepResults(t)
	dir := benchDir(t)
	first := planOf(t, dir, planMatrix, "SEED=7", "REPS=4", "BIG_REPS=2", "WARMUP=1", "ROUNDS=4")
	again := planOf(t, dir, planMatrix, "SEED=7", "REPS=4", "BIG_REPS=2", "WARMUP=1", "ROUNDS=4")
	other := planOf(t, dir, planMatrix, "SEED=8", "REPS=4", "BIG_REPS=2", "WARMUP=1", "ROUNDS=4")
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
	// The round of each run, as the rounds should spread them: e1 and ip have a
	// repetition in each of the 4 rounds, e2 and u1 one in rounds 2 and 4.
	round := map[string]string{"e1 1": "1", "e1 2": "2", "e1 3": "3", "e1 4": "4", "ip 1": "1", "ip 2": "2", "ip 3": "3", "ip 4": "4",
		"e2 1": "2", "e2 2": "4", "u1 1": "2", "u1 2": "4"}
	checkRounds(t, first, round, 4)
	checkRounds(t, other, round, 4)
	// Each round shuffles the servers again.
	reordered := false
	for seed := 1; seed <= 6 && !reordered; seed++ {
		seen := map[string][]string{}
		for _, r := range planOf(t, dir, planMatrix, fmt.Sprintf("SEED=%d", seed), "REPS=4", "BIG_REPS=2", "WARMUP=0", "ROUNDS=4") {
			f := strings.Fields(r)
			if !slices.Contains(seen[f[3]], f[0]) {
				seen[f[3]] = append(seen[f[3]], f[0])
			}
		}
		reordered = !slices.Equal(seen["1"], seen["3"])
	}
	if !reordered {
		t.Error("rounds 1 and 3 had their servers in the same order for seeds 1 to 6")
	}
	// One round puts each server's runs in one block, its warm-ups first.
	single := planOf(t, dir, planMatrix, "SEED=7", "REPS=4", "BIG_REPS=2", "WARMUP=1", "ROUNDS=1")
	checkRounds(t, single, map[string]string{}, 1)
	if len(single) != len(first) {
		t.Errorf("%d runs in one round, %d in four", len(single), len(first))
	}
	only := planOf(t, dir, planMatrix, "SEED=7", "REPS=1", "BIG_REPS=1", "WARMUP=0", "CELLS=e,ip")
	slices.Sort(only)
	if strings.Join(only, ";") != "- ip 1 3;a e1 1 3;b e2 1 3" {
		t.Errorf("CELLS=e,ip: %q", only)
	}
	// Fewer repetitions than rounds, and a cell with none measured.
	sparse := planOf(t, dir, planMatrix, "SEED=7", "REPS=3", "BIG_REPS=0", "WARMUP=1", "ROUNDS=6", "CELLS=e,ip")
	checkRounds(t, sparse, map[string]string{"e1 1": "2", "e1 2": "4", "e1 3": "6", "ip 1": "2", "ip 2": "4", "ip 3": "6"}, 6)
	if len(sparse) != 9 {
		t.Errorf("%d runs: %q", len(sparse), sparse)
	}
	for _, rounds := range []string{"0", "x", "-1", "5x", "1.5", ""} {
		m := filepath.Join(t.TempDir(), "m.txt")
		write(t, m, planMatrix)
		out, ok := scriptArgs(t, []string{"session.sh", m}, "", "BENCH_DIR="+dir, "PLAN_ONLY=1", "SERVER_SSH=", "ROUNDS="+rounds)
		if rounds == "" {
			if !ok || !strings.Contains(out, "runs; order: ") {
				t.Errorf("ROUNDS unset: %s", out)
			}
			continue
		}
		if ok || !strings.Contains(out, "ROUNDS must be a number from 1") {
			t.Errorf("ROUNDS=%s: %s", rounds, out)
		}
	}
	// Five rounds by default.
	five := planOf(t, dir, planMatrix, "SEED=7", "REPS=5", "WARMUP=0", "CELLS=e1")
	checkRounds(t, five, map[string]string{"e1 1": "1", "e1 2": "2", "e1 3": "3", "e1 4": "4", "e1 5": "5"}, 5)
	// Repetitions written with a leading zero are decimal.
	zeros := planOf(t, dir, strings.Replace(planMatrix, "reps=2", "reps=08", 1), "SEED=7", "REPS=010", "BIG_REPS=09", "WARMUP=0", "ROUNDS=3")
	count = map[string]int{}
	for _, r := range zeros {
		count[strings.Fields(r)[1]]++
	}
	if want := map[string]int{"e1": 10, "e2": 9, "u1": 8, "ip": 10}; fmt.Sprint(count) != fmt.Sprint(want) {
		t.Errorf("runs %v, want %v", count, want)
	}
}

// Within a block the runs are shuffled, and each round shuffles its blocks anew.
func TestTheRunsOfABlockAreShuffled(t *testing.T) {
	needBash(t)
	for _, tool := range []string{"shuf", "openssl", "numfmt"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("no %s", tool)
		}
	}
	keepResults(t)
	dir := benchDir(t)
	matrix := "server a\ncell x a engine size=1M\ncell y a engine size=1M\ncell z a engine size=1M\n"
	unsorted, renewed := false, false
	for seed := 1; seed <= 8 && !(unsorted && renewed); seed++ {
		cells := map[string]string{}
		var blocks []string
		for _, r := range planOf(t, dir, matrix, fmt.Sprintf("SEED=%d", seed), "REPS=4", "WARMUP=0", "ROUNDS=2") {
			f := strings.Fields(r)
			cells[f[3]] += f[1]
			blocks = append(blocks, f[3]+" "+f[1]+" "+f[2])
		}
		unsorted = unsorted || !slices.IsSorted(blocks)
		renewed = renewed || cells["1"] != cells["2"]
	}
	if !unsorted {
		t.Error("for seeds 1 to 8, every block ran its cells in order")
	}
	if !renewed {
		t.Error("for seeds 1 to 8, both rounds ran their cells in the same order")
	}
}

// checkRounds checks a plan's rounds: a warm-up's is the first, a measured
// run's the one given, or the first with one round; the rounds never go
// back; each server serves one block in a round; and no warm-up of a server
// follows a measured run of it.
func checkRounds(t *testing.T, plan []string, round map[string]string, rounds int) {
	t.Helper()
	at, last := 1, ""
	seen := map[string]int{}
	measured := map[string]bool{}
	for _, r := range plan {
		f := strings.Fields(r)
		want, ok := round[f[1]+" "+f[2]]
		if f[2] == "0" || rounds == 1 {
			want, ok = "1", true
		}
		n, _ := strconv.Atoi(f[3])
		if !ok || f[3] != want || n < at || n > rounds {
			t.Fatalf("%q, after round %d, should be in round %s: %q", r, at, want, plan)
		}
		if n > at {
			at, last = n, ""
		}
		if f[0] != last {
			if seen[f[0]] == at {
				t.Fatalf("server %s serves two blocks in round %d: %q", f[0], at, plan)
			}
			seen[f[0]], last = at, f[0]
		}
		if f[2] != "0" {
			measured[f[0]] = true
		} else if measured[f[0]] {
			t.Fatalf("a warm-up of server %s after a measured run: %q", f[0], plan)
		}
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
		env := []string{"SEED=1", "PRE_M6=HEAD"}
		// Network cuts run only against a server over ssh, at its address.
		if strings.Contains(string(b), "fault=cut") {
			env = append(env, "SERVER_SSH=me@host", "SERVER_HOST=192.168.1.10", "SERVER_BENCH=/b", "SERVER_REPO=/r")
		}
		if runs := planOf(t, dir, string(b), env...); len(runs) < 10 {
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
		{"server a\ncell x a engine size=1M from-file=yes\n", nil, "from-file must be 0 or 1"},
		{"server a\ncell x a upload size=1M from-file=1\n", nil, "upload takes no from-file"},
		{"server a\ncell x - inprocess size=1M from-file=1\n", nil, "inprocess takes no from-file"},
		{"server a\ncell x a engine size=1M fault=reboot fault-at=0.5 retry-for=1m\n", nil, "fault must be kill or cut"},
		{"server a\ncell x a engine size=1M fault=kill fault-at=1 retry-for=1m\n", nil, "fault-at must be a share"},
		{"server a\ncell x a engine size=1M fault=kill fault-at=0.0 retry-for=1m\n", nil, "fault-at must be a share above 0"},
		{"server a\ncell x a engine size=1M resume-at=.00\n", nil, "resume-at must be a share above 0"},
		{"server a\ncell x a engine size=1M fault=cut fault-at=0.5 retry-for=1m\n", []string{"SERVER_SSH=me@host", "SERVER_HOST=192.168.1.010", "SERVER_BENCH=/b", "SERVER_REPO=/r"}, "SERVER_HOST must be the server's IP address"},
		{"server a\ncell x a engine size=1M fault=cut fault-at=0.5 retry-for=1m\n", []string{"SERVER_SSH=me@host", "SERVER_HOST=1:2:3:4:5:6:7", "SERVER_BENCH=/b", "SERVER_REPO=/r"}, "SERVER_HOST must be the server's IP address"},
		{"server a\ncell x a engine size=1M fault=cut fault-at=0.5 retry-for=1m\n", []string{"SERVER_SSH=me@host", "SERVER_HOST=256.1.1.1", "SERVER_BENCH=/b", "SERVER_REPO=/r"}, "SERVER_HOST must be the server's IP address"},
		{"server a\ncell x a engine size=1M fault=cut fault-at=0.5 retry-for=1m\n", []string{"SERVER_SSH=me@host", "SERVER_HOST=1.2.3.259", "SERVER_BENCH=/b", "SERVER_REPO=/r"}, "SERVER_HOST must be the server's IP address"},
		{"server a\ncell x a engine size=1M fault=cut fault-at=0.5 retry-for=1m\n", []string{"SERVER_SSH=me@host", "SERVER_HOST=1:::2", "SERVER_BENCH=/b", "SERVER_REPO=/r"}, "SERVER_HOST must be the server's IP address"},
		{"server a\ncell x a engine size=1M fault=cut fault-at=0.5 retry-for=1m\n", []string{"SERVER_SSH=me@host", "SERVER_HOST=1::2::3", "SERVER_BENCH=/b", "SERVER_REPO=/r"}, "SERVER_HOST must be the server's IP address"},
		{"server a\ncell x a engine size=1M fault=cut fault-at=0.5 retry-for=1m\n", []string{"SERVER_SSH=me@host", "SERVER_HOST=12345::1", "SERVER_BENCH=/b", "SERVER_REPO=/r"}, "SERVER_HOST must be the server's IP address"},
		{"server a\ncell x a engine size=1M fault=cut fault-at=0.5 retry-for=1m\n", []string{"SERVER_SSH=me@host", "SERVER_HOST=1:2:3:4:5:6:7:8::9", "SERVER_BENCH=/b", "SERVER_REPO=/r"}, "SERVER_HOST must be the server's IP address"},
		{"server a\ncell x a engine size=1M fault=cut fault-at=0.5 retry-for=1m\n", []string{"SERVER_SSH=me@host", "SERVER_HOST=1:2:3:4:5:6::7:8:9", "SERVER_BENCH=/b", "SERVER_REPO=/r"}, "SERVER_HOST must be the server's IP address"},
		{"server a\ncell x a engine size=1M fault=cut fault-at=0.5 retry-for=1m\n", []string{"SERVER_SSH=me@host", "SERVER_HOST=1:2:3:4:5:6:7::8", "SERVER_BENCH=/b", "SERVER_REPO=/r"}, "SERVER_HOST must be the server's IP address"},
		{"server a\ncell x a engine size=1M fault=kill retry-for=1m\n", nil, "a fault needs fault-at"},
		{"server a\ncell x a engine size=1M fault=kill fault-at=0.5\n", nil, "a fault needs retry-for"},
		{"server a\ncell x a engine size=1M fault=kill fault-at=0.5 retry-for=1m resume-at=0.5\n", nil, "can't be combined with resume-at"},
		{"server a\ncell x a engine size=1M fault-at=0.5 retry-for=1m\n", nil, "fault-at needs a fault"},
		{"server a\ncell x a engine size=1M fault=kill fault-at=0.5 retry-for=1m cut-for=5\n", nil, "cut-for needs fault=cut"},
		{"server a\ncell x a engine size=1M fault=cut fault-at=0.5 retry-for=1m cut-for=61\n", nil, "cut-for must be seconds from 1 to 60"},
		{"server a\ncell x a engine size=1M fault=cut fault-at=0.5 retry-for=1m cut-for=0\n", nil, "cut-for must be seconds from 1 to 60"},
		{"server a\ncell x a engine size=1M fault=cut fault-at=0.5 retry-for=1m\n", nil, "runs only with SERVER_SSH"},
		{"server a\ncell x a engine size=1M fault=cut fault-at=0.5 retry-for=1m\n", []string{"SERVER_SSH=me@host", "SERVER_HOST=server.lan", "SERVER_BENCH=/b", "SERVER_REPO=/r"}, "SERVER_HOST must be the server's IP address"},
		{"server a\ncell x a seek size=1M files=2\n", nil, "seek takes no files"},
		{"server a\ncell x a seek size=1M chunk=2M\n", nil, "chunk must be at most the size"},
		{"server a\ncell x a seek size=1M chunk=0\n", nil, "chunk must be bytes"},
		{"server a\ncell x a seek size=1M seeks=0\n", nil, "seeks must be a number from 1"},
		{"server a\ncell x a seek\n", nil, "seek needs a size"},
		{"server a\ncell x a upload size=1M fault=kill\n", nil, "upload takes no fault"},
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
	for _, host := range []string{"192.168.1.10", "2001:db8::7", "1:2:3:4:5:6:7:8"} {
		if runs := planOf(t, dir, "server a\ncell c a engine size=1M fault=cut fault-at=0.5 retry-for=1m\n", "SERVER_SSH=me@host", "SERVER_HOST="+host,
			"SERVER_BENCH=/b", "SERVER_REPO=/r", "REPS=1", "WARMUP=0"); len(runs) != 1 {
			t.Errorf("%s: runs %q", host, runs)
		}
	}
	// A cut cell that doesn't run needs no ssh.
	if runs := planOf(t, dir, "server a\ncell x a engine size=1M\ncell c a engine size=1M fault=cut fault-at=0.5 retry-for=1m\n", "CELLS=x", "SERVER_HOST=",
		"REPS=1", "WARMUP=0"); len(runs) != 1 {
		t.Errorf("runs %q", runs)
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
server bench BUILD_TAGS=bench GOCALBOX_BENCH_H2_STREAM_WINDOW=128K GOCALBOX_BENCH_SYNC=none
cell e-h2  plain engine transport=https-h2 size=64M files=2 users=2
cell e-src bench engine size=9M from-file=1
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
	if order[0] != "seq,server,cell,rep,round,t0,t1,outcome" {
		t.Errorf("order header %q", order[0])
	}
	var runs, rows []string
	block := map[string]string{}
	served := map[string][]string{}
	for _, line := range order[1:] {
		if !strings.HasSuffix(line, ",ok") || strings.Count(line, ",") != 7 {
			t.Errorf("run %s", line)
		}
		f := strings.Split(line, ",")
		runs = append(runs, f[2]+" "+f[3])
		block[f[2]+" "+f[3]] = f[1] + " " + f[4]
		if f[1] != "-" && !slices.Contains(served[f[1]], f[4]) {
			served[f[1]] = append(served[f[1]], f[4])
		}
	}
	// A server starts for each of its blocks, one per round it has runs in.
	for srv, rounds := range served {
		if n := strings.Count(out, "server "+srv+": starting\n"); n != len(rounds) {
			t.Errorf("server %s started %d times for its runs in rounds %q", srv, n, rounds)
		}
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
	// The servers' own environment files stay out of the results, which keep them in the session's.
	stamp := base[len(base)-len("20060102-150405"):]
	envs, _ := filepath.Glob(filepath.Join("..", "..", "bench", "results", "server-*-env.txt"))
	for _, f := range envs {
		name := strings.TrimSuffix(filepath.Base(f), "-env.txt")
		if name[len(name)-len(stamp):] >= stamp {
			t.Errorf("a server's environment file in the results: %s", f)
		}
	}
	// Each server's samples, by the block of runs, the server and round, they were taken in.
	samples := map[string][][2]float64{}
	servers, _ := filepath.Glob(base + "-server-*-env.txt")
	for _, f := range servers {
		b, _ := os.ReadFile(f)
		name := strings.TrimSuffix(strings.TrimPrefix(f, base+"-server-"), "-env.txt")
		var rounds []string
		crashes := 0
		for _, part := range strings.Split(string(b), "round: ")[1:] {
			r, env, _ := strings.Cut(part, "\n")
			if !strings.HasPrefix(env, "server: ") || !strings.Contains(env, "load users: ") {
				t.Errorf("%s is incomplete in round %s:\n%s", f, r, b)
			}
			rounds = append(rounds, r)
			var n int
			if _, c, ok := strings.Cut(env, "\ncrashes: "); !ok {
				t.Errorf("%s gives no crashes in round %s", f, r)
			} else if fmt.Sscan(c, &n); n > 0 {
				crashes += n
			}
		}
		sb, _ := os.ReadFile(base + "-server-" + name + "-samples.csv")
		var sampled []string
		for _, line := range strings.Split(strings.TrimSpace(string(sb)), "\n") {
			var tm, cpu float64
			var rss, round int
			if _, err := fmt.Sscanf(strings.ReplaceAll(line, ",", " "), "%f %f %d %d", &tm, &cpu, &rss, &round); err != nil || round < 1 {
				t.Errorf("sample of server %s: %q", name, line)
				continue
			}
			key := fmt.Sprintf("%s %d", name, round)
			if len(samples[key]) == 0 {
				sampled = append(sampled, fmt.Sprint(round))
			}
			samples[key] = append(samples[key], [2]float64{tm, cpu})
		}
		if len(rounds) == 0 || !slices.Equal(rounds, sampled) || !slices.Equal(rounds, served[name]) {
			t.Errorf("server %s: environments of rounds %q, samples of rounds %q, runs in rounds %q", name, rounds, sampled, served[name])
		}
		lb, _ := os.ReadFile(base + "-server-" + name + ".log")
		if n := strings.Count(string(lb), "Starting server on "); n != len(rounds)+crashes {
			t.Errorf("server %s's log holds %d starts, not %d and %d after crashes", name, n, len(rounds), crashes)
		}
		// A benchmark build's request log holds requests of each of its blocks.
		if rb, err := os.ReadFile(base + "-server-" + name + "-requests.jsonl"); err == nil {
			for _, r := range rounds {
				s := samples[name+" "+r]
				in := false
				for _, line := range strings.Split(strings.TrimSpace(string(rb)), "\n") {
					var req struct{ Start time.Time }
					if json.Unmarshal([]byte(line), &req) == nil {
						at := float64(req.Start.UnixNano()) / 1e9
						in = in || len(s) > 0 && s[0][0] <= at && at <= s[len(s)-1][0]
					}
				}
				if !in {
					t.Errorf("server %s's request log has nothing of its block in round %s", name, r)
				}
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
		if code != "201" && code != "200" && code != "206" || col(row, "started_unix") == "" {
			t.Errorf("row %s", line)
		}
		if (transport == "inprocess") != (cpu == "") {
			t.Errorf("server CPU %q for %s", cpu, transport)
		}
		if col(row, "scenario") == "stop" && col(row, "resumed") != "1" {
			t.Errorf("the stopped file's row: %s", line)
		}
		// An engine run's own start and length place it among its server's samples.
		if col(row, "part_p50_ms") != "" && transport != "inprocess" && code != "206" {
			var start, secs, got float64
			fmt.Sscan(col(row, "started_unix"), &start)
			fmt.Sscan(col(row, "seconds"), &secs)
			fmt.Sscan(cpu, &got)
			var in []string
			for key, s := range samples {
				if s[0][0] <= start && start <= s[len(s)-1][0] {
					in = append(in, key)
					if want := cpuAt(s, start+secs) - cpuAt(s, start); math.Abs(got-want) > 1e-6 {
						t.Errorf("server CPU %s for a run from %.6f for %.6f s; the samples say %.4f", cpu, start, secs, want)
					}
				}
			}
			if run := col(row, "scenario") + " " + col(row, "rep"); len(in) != 1 || in[0] != block[run] {
				t.Errorf("run %s of server and round %s falls among the samples of %q", run, block[run], in)
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
	for _, warning := range []string{"left files in its served folder", "the rest of its block's runs are skipped"} {
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
		if envs, _ := filepath.Glob(filepath.Join(dir, "server", "env-*")); len(envs) > 0 {
			t.Errorf("left in the server's folder: %q", envs)
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
	// The warm-ups run in the first of the default rounds, the one measured run in the third.
	b, _ := os.ReadFile(filepath.Join("..", "..", strings.TrimSuffix(csv, ".csv")+"-server-plain-env.txt"))
	if n := strings.Count(string(b), "server: "); n != 2 {
		t.Errorf("server plain served %d blocks, not 2", n)
	}
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
	checkPartFlushes(t, out, dir)
}

// checkPartFlushes checks that the session's benchmark server ran without
// its part flushes, as its matrix line says, and that the cell from a file,
// and no other, read the session's data file of its size.
func checkPartFlushes(t *testing.T, out, client string) {
	t.Helper()
	_, rest, _ := strings.Cut(out, "results: ")
	csv, _, _ := strings.Cut(rest, "\n")
	base := filepath.Join("..", "..", strings.TrimSuffix(csv, ".csv"))
	if b, _ := os.ReadFile(base + "-server-bench.log"); !strings.Contains(string(b), "flushes nothing before its answer (GOCALBOX_BENCH_SYNC)") {
		t.Errorf("the benchmark server's log doesn't say it flushes nothing: %.400s", b)
	}
	if b, _ := os.ReadFile(base + "-server-bench-env.txt"); !strings.Contains(string(b), "GOCALBOX_BENCH_SYNC=none") {
		t.Errorf("the benchmark server's environment file lacks its setting: %.400s", b)
	}
	if b, _ := os.ReadFile(base + "-server-plain.log"); strings.Contains(string(b), "flushes") {
		t.Errorf("the plain server's log: %.400s", b)
	}
	data := filepath.Join(client, "data", "fixed-9M.bin")
	fi, err := os.Stat(data)
	if err != nil {
		t.Fatal("no data file for the cell from a file")
	}
	// Made before the first run, so that writing it out doesn't fall in a measured one.
	first := math.Inf(1)
	for _, line := range strings.Split(strings.TrimSpace(output(t, out, "order")), "\n")[1:] {
		var t0 float64
		fmt.Sscan(strings.Split(line, ",")[5], &t0)
		first = min(first, t0)
	}
	if made := float64(fi.ModTime().UnixNano()) / 1e9; made > first {
		t.Errorf("the data file was made at %.3f, after the first run began at %.3f", made, first)
	}
	header := strings.Split(load.Header, ",")
	rows := 0
	for _, line := range strings.Split(strings.TrimSpace(output(t, out, "results")), "\n")[1:] {
		row := strings.Split(line, ",")
		if row[slices.Index(header, "scenario")] != "e-src" {
			continue
		}
		rows++
		if size := row[slices.Index(header, "size_bytes")]; size != "9437184" {
			t.Errorf("the cell from a file uploaded %s bytes", size)
		}
	}
	b, _ := os.ReadFile(filepath.Join(client, "session", "load.log"))
	if n := strings.Count(string(b), "every file uploaded is read from "+data+"\n"); rows == 0 || n != rows || strings.Count(string(b), "is read from") != n {
		t.Errorf("%d runs read from %s, for %d rows of the cell from a file:\n%s", n, data, rows, b)
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
	checkPartFlushes(t, out, client)
}

// A transfer that moved other bytes than the source's is marked, in its row
// and in the order: every upload; a download's warm-up, which hashes what it
// got; and every download of a file placed for it that isn't the source's.
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
	if !ok || !strings.Contains(out, "warning: 8 runs were not ok") || !strings.Contains(out, "warning: the 64K file placed for downloads on server s isn't the source's bytes") {
		t.Fatalf("session.sh: %s", out)
	}
	header := strings.Split(load.Header, ",")
	codes := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(output(t, out, "results")), "\n")[1:] {
		row := strings.Split(line, ",")
		codes[row[slices.Index(header, "scenario")]+" "+row[slices.Index(header, "rep")]] = row[slices.Index(header, "http_code")]
	}
	want := map[string]string{"up 0": "201 wrong_file", "up 1": "201 wrong_file", "down 0": "200 wrong_file", "down 1": "200 wrong_file", "big 0": "413x1", "big 1": "413x1",
		"short 0": "200 wrong_size", "short 1": "200 wrong_size"}
	if fmt.Sprint(codes) != fmt.Sprint(want) {
		t.Errorf("codes %v, want %v", codes, want)
	}
	order := output(t, out, "order")
	for _, line := range strings.Split(strings.TrimSpace(order), "\n") {
		if strings.Count(line, ",") != 7 {
			t.Errorf("an order line of other than 8 fields: %s", line)
		}
	}
	if strings.Count(order, ",stored ") != 2 || strings.Count(order, ",got other bytes") != 1 || strings.Count(order, ",the file placed for it isn't the source's bytes") != 1 || strings.Count(order, ",answered 413x1") != 2 || strings.Count(order, ",got 1000 of 1024 bytes") != 2 {
		t.Errorf("order:\n%s", order)
	}
}

// A benchmark folder whose path has a space in it.
func TestASessionInAFolderWithASpace(t *testing.T) {
	sessionTools(t)
	keepResults(t)
	dir := filepath.Join(t.TempDir(), "with space", "bench")
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	if out, ok := safe(t, t.TempDir(), "init", dir); !ok {
		t.Fatalf("init: %s", out)
	}
	matrix := filepath.Join(t.TempDir(), "m.txt")
	write(t, matrix, "server a\ncell e a engine size=32M files=2\ncell d a download size=64K\n")
	out, ok := scriptArgs(t, []string{"session.sh", matrix}, "", "BENCH_DIR="+dir, "PORT=18386", "REPS=2", "WARMUP=1", "ROUNDS=2",
		"DROP_CACHES=0", "IPERF=0", "SERVER_SSH=", "SERVER_HOST=", "CELLS=")
	if !ok {
		t.Fatalf("session.sh: %s", out)
	}
	checkSession(t, out, dir)
}

// A file placed for downloads that isn't the source's marks the downloads
// of its own block only.
func TestOnlyTheBlockOfAWrongPlacementIsMarked(t *testing.T) {
	sessionTools(t)
	keepResults(t)
	dir := benchDir(t)
	content := strings.Repeat("z", 64<<10)
	sum := filepath.Join(dir, "data", "fixed-64K.bin.sha256")
	write(t, filepath.Join(dir, "data", "fixed-64K.bin"), content)
	write(t, sum, strings.Repeat("0", 64)+"\n")
	// Once the first block's warm-up has run, the source's SHA-256 is right again.
	go func() {
		results := filepath.Join("..", "..", "bench", "results")
		for deadline := time.Now().Add(2 * time.Minute); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
			orders, _ := filepath.Glob(filepath.Join(results, "session-placed-*-order.csv"))
			if len(orders) == 0 {
				continue
			}
			if b, _ := os.ReadFile(orders[len(orders)-1]); strings.Count(string(b), "\n") >= 2 {
				os.WriteFile(sum, []byte(fmt.Sprintf("%x\n", sha256.Sum256([]byte(content)))), 0o644)
				return
			}
		}
	}()
	matrix := filepath.Join(t.TempDir(), "placed.txt")
	write(t, matrix, "server s\ncell down s download size=64K\n")
	out, ok := scriptArgs(t, []string{"session.sh", matrix}, "", "BENCH_DIR="+dir, "PORT=18387", "REPS=1", "WARMUP=1",
		"DROP_CACHES=0", "IPERF=0", "SERVER_SSH=", "SERVER_HOST=", "CELLS=")
	if !ok || strings.Count(out, "placed for downloads on server s isn't the source's bytes") != 1 {
		t.Fatalf("session.sh: %s", out)
	}
	header := strings.Split(load.Header, ",")
	codes := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(output(t, out, "results")), "\n")[1:] {
		row := strings.Split(line, ",")
		codes[row[slices.Index(header, "rep")]] = row[slices.Index(header, "http_code")]
	}
	if fmt.Sprint(codes) != fmt.Sprint(map[string]string{"0": "200 wrong_file", "1": "200"}) {
		t.Errorf("codes %v", codes)
	}
	if env := output(t, out, "environment"); !strings.Contains(env, "isn't the source's bytes") {
		t.Error("the warning isn't in the environment file")
	}
}
