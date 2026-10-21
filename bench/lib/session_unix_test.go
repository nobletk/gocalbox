//go:build unix

package lib

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A server that dies in the middle of a block has the rest of the block's
// runs skipped; the session keeps every row it measured, goes on with the
// next block, and starts the server again for its next round.
func TestASessionOutlivesAServerThatDies(t *testing.T) {
	sessionTools(t)
	keepResults(t)
	dir := benchDir(t)
	matrix := filepath.Join(t.TempDir(), "dies.txt")
	body := "server a\nserver b SERVER_FLAGS=-audit-parts\ncell e1 a engine size=64K\ncell e2 a engine size=64K\ncell e3 b engine size=64K\n"
	write(t, matrix, body)
	// A seed that runs server b's block first, so that server a's lost block isn't the session's first stop.
	seed := ""
	for n := 1; n <= 20 && seed == ""; n++ {
		if plan := planOf(t, dir, body, fmt.Sprintf("SEED=%d", n), "REPS=4", "WARMUP=0", "ROUNDS=2"); strings.HasPrefix(plan[0], "b ") {
			seed = fmt.Sprintf("SEED=%d", n)
		}
	}
	if seed == "" {
		t.Fatal("no seed from 1 to 20 runs server b first")
	}
	go func() {
		results := filepath.Join("..", "..", "bench", "results")
		for deadline := time.Now().Add(2 * time.Minute); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
			orders, _ := filepath.Glob(filepath.Join(results, "session-dies-*-order.csv"))
			if len(orders) == 0 {
				continue
			}
			// After the first run of server a's first block, which has three more.
			b, _ := os.ReadFile(orders[len(orders)-1])
			if !strings.Contains(string(b), ",a,") {
				continue
			}
			pid, _ := os.ReadFile(filepath.Join(dir, "server", "ready"))
			if n, err := strconv.Atoi(strings.TrimSpace(string(pid))); err == nil {
				syscall.Kill(n, syscall.SIGKILL)
				return
			}
		}
	}()
	out, ok := scriptArgs(t, []string{"session.sh", matrix}, "", "BENCH_DIR="+dir, "PORT=18398", "REPS=4", "WARMUP=0", "ROUNDS=2", seed,
		"DROP_CACHES=0", "IPERF=0", "SERVER_SSH=", "SERVER_HOST=", "CELLS=")
	if !ok || !strings.Contains(out, "server a stopped; the rest of its block's runs are skipped") ||
		strings.Count(out, "warning: server a had stopped before the end of its runs") != 1 || strings.Contains(out, "server b had stopped") {
		t.Fatalf("session.sh: %s", out)
	}
	order := strings.Split(strings.TrimSpace(output(t, out, "order")), "\n")[1:]
	csv := strings.Split(strings.TrimSpace(output(t, out, "results")), "\n")[1:]
	// A run that failed outright, such as one that couldn't log in, has no row.
	measured := 0
	var a []string
	for _, line := range order {
		f := strings.Split(line, ",")
		if !strings.HasPrefix(f[7], "skipped") && f[7] != "failed" {
			measured++
		} else if f[4] != "1" {
			t.Errorf("a run lost in round %s, not 1: %s", f[4], line)
		}
		switch f[1] {
		case "a":
			a = append(a, f[7])
		case "b":
			if f[7] != "ok" {
				t.Errorf("server b's run: %s", line)
			}
		}
	}
	if len(order) != 12 || len(csv) != measured || !strings.Contains(strings.Join(order, "\n"), "skipped: the server had stopped") {
		t.Errorf("%d runs, %d measured, %d rows:\n%s", len(order), measured, len(csv), strings.Join(order, "\n"))
	}
	// Server a: its first block lost from a run after its first, its second block whole.
	lost := slices.IndexFunc(a, func(o string) bool { return o != "ok" })
	if len(a) != 8 || lost < 1 || lost > 3 || slices.ContainsFunc(a[lost:4], func(o string) bool { return o == "ok" }) ||
		!slices.Equal(a[4:], []string{"ok", "ok", "ok", "ok"}) {
		t.Errorf("server a's runs: %q", a)
	}
	_, rest, _ := strings.Cut(out, "results: ")
	base, _, _ := strings.Cut(rest, "\n")
	for s, blocks := range map[string]int{"a": 2, "b": 2} {
		b, _ := os.ReadFile(filepath.Join("..", "..", strings.TrimSuffix(base, ".csv")+"-server-"+s+"-env.txt"))
		if n := strings.Count(string(b), "server: "); n != blocks {
			t.Errorf("server %s's environment file has %d blocks, not %d", s, n, blocks)
		}
	}
}

// Files left in a served folder after its runs are named in a warning.
func TestASessionWarnsOfFilesLeftBehind(t *testing.T) {
	sessionTools(t)
	keepResults(t)
	dir := benchDir(t)
	matrix := filepath.Join(t.TempDir(), "m.txt")
	write(t, matrix, "server a\ncell e a engine size=64K\n")
	go func() {
		for deadline := time.Now().Add(2 * time.Minute); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
			if exists(filepath.Join(dir, "server", "ready")) {
				write(t, filepath.Join(dir, "server", "root", "stray.bin"), "x")
				return
			}
		}
	}()
	out, ok := scriptArgs(t, []string{"session.sh", matrix}, "", "BENCH_DIR="+dir, "PORT=18399", "REPS=2", "WARMUP=0",
		"DROP_CACHES=0", "IPERF=0", "SERVER_SSH=", "SERVER_HOST=", "CELLS=")
	if !ok || !strings.Contains(out, "runs on server a left files in its served folder: ./stray.bin") {
		t.Errorf("session.sh: %s", out)
	}
	// Its two repetitions fall in rounds 2 and 4, one block after the other: the server starts for each.
	if n := strings.Count(out, "server a: starting\n"); n != 2 {
		t.Errorf("server a started %d times, not 2: %s", n, out)
	}
	if env := output(t, out, "environment"); !strings.Contains(env, "stray.bin") {
		t.Error("the warning isn't in the environment file")
	}
}

// A server that can't start ends the session, which keeps its environment
// file with the results and leaves nothing of it in the benchmark folder.
func TestASessionKeepsTheEnvironmentOfAServerThatCantStart(t *testing.T) {
	sessionTools(t)
	keepResults(t)
	dir := benchDir(t)
	// The port is taken by something that never answers.
	l, err := net.Listen("tcp", "127.0.0.1:18389")
	if err != nil {
		t.Skip(err)
	}
	defer l.Close()
	go func() {
		var held []net.Conn
		for {
			c, err := l.Accept()
			if err != nil {
				for _, c := range held {
					c.Close()
				}
				return
			}
			held = append(held, c)
		}
	}()
	start := time.Now()
	matrix := filepath.Join(t.TempDir(), "nostart.txt")
	write(t, matrix, "server a\ncell e a engine size=64K\n")
	out, ok := scriptArgs(t, []string{"session.sh", matrix}, "", "BENCH_DIR="+dir, "PORT=18389", "REPS=1", "WARMUP=0",
		"DROP_CACHES=0", "IPERF=0", "SERVER_SSH=", "SERVER_HOST=", "CELLS=")
	if ok || !strings.Contains(out, "bench/server.sh for server a stopped") {
		t.Fatalf("session.sh: %s", out)
	}
	if d := time.Since(start); d > time.Minute {
		t.Errorf("a server that couldn't start took %v to give up", d)
	}
	if strings.Contains(out, "had stopped before the end of its runs") {
		t.Errorf("a server that never started is said to have stopped: %s", out)
	}
	envs, _ := filepath.Glob(filepath.Join("..", "..", "bench", "results", "session-nostart-*-server-a-env.txt"))
	if len(envs) != 1 {
		t.Fatalf("environment files of server a with the results: %q", envs)
	}
	// Its one repetition is in the third of five rounds.
	if b, _ := os.ReadFile(envs[0]); !strings.HasPrefix(string(b), "round: 3\nserver: ") {
		t.Errorf("server a's environment file:\n%s", b)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "server", "env-*")); len(left) > 0 {
		t.Errorf("left in the server's folder: %q", left)
	}
}

// A server that can't start after another server's block has run is
// reported as one that couldn't start, not as one that stopped.
func TestAServerThatCantStartAfterAnotherIsReportedOnce(t *testing.T) {
	sessionTools(t)
	keepResults(t)
	dir := benchDir(t)
	body := "server a\nserver b SERVER_FLAGS=-no-such-flag\ncell e a engine size=64K\ncell f b engine size=64K\n"
	seed := ""
	for n := 1; n <= 20 && seed == ""; n++ {
		if plan := planOf(t, dir, body, fmt.Sprintf("SEED=%d", n), "REPS=1", "WARMUP=0", "ROUNDS=1"); strings.HasPrefix(plan[0], "a ") {
			seed = fmt.Sprintf("SEED=%d", n)
		}
	}
	if seed == "" {
		t.Fatal("no seed from 1 to 20 runs server a first")
	}
	matrix := filepath.Join(t.TempDir(), "second.txt")
	write(t, matrix, body)
	out, ok := scriptArgs(t, []string{"session.sh", matrix}, "", "BENCH_DIR="+dir, "PORT=18385", "REPS=1", "WARMUP=0", "ROUNDS=1", seed,
		"DROP_CACHES=0", "IPERF=0", "SERVER_SSH=", "SERVER_HOST=", "CELLS=")
	if ok || !strings.Contains(out, "[1/2] e rep 1: ok") || !strings.Contains(out, "bench/server.sh for server b stopped") {
		t.Fatalf("session.sh: %s", out)
	}
	if strings.Contains(out, "had stopped before the end of its runs") {
		t.Errorf("a server that never started is said to have stopped: %s", out)
	}
}
