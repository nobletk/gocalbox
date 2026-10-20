//go:build unix

package lib

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A server that dies in the middle of its runs has the rest of them
// skipped; the session keeps every row it measured, and goes on with the
// next server.
func TestASessionOutlivesAServerThatDies(t *testing.T) {
	sessionTools(t)
	keepResults(t)
	dir := benchDir(t)
	matrix := filepath.Join(t.TempDir(), "dies.txt")
	write(t, matrix, "server a\nserver b SERVER_FLAGS=-audit-parts\ncell e1 a engine size=64K\ncell e2 a engine size=64K\ncell e3 b engine size=64K\n")
	go func() {
		results := filepath.Join("..", "..", "bench", "results")
		for deadline := time.Now().Add(2 * time.Minute); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
			orders, _ := filepath.Glob(filepath.Join(results, "session-dies-*-order.csv"))
			if len(orders) == 0 {
				continue
			}
			b, _ := os.ReadFile(orders[len(orders)-1])
			if strings.Count(string(b), "\n") < 3 {
				continue
			}
			pid, _ := os.ReadFile(filepath.Join(dir, "server", "ready"))
			if n, err := strconv.Atoi(strings.TrimSpace(string(pid))); err == nil {
				syscall.Kill(n, syscall.SIGKILL)
				return
			}
		}
	}()
	out, ok := scriptArgs(t, []string{"session.sh", matrix}, "", "BENCH_DIR="+dir, "PORT=18398", "REPS=4", "WARMUP=0",
		"DROP_CACHES=0", "IPERF=0", "SERVER_SSH=", "SERVER_HOST=", "CELLS=")
	if !ok || !strings.Contains(out, "stopped; the rest of its runs are skipped") {
		t.Fatalf("session.sh: %s", out)
	}
	order := strings.Split(strings.TrimSpace(output(t, out, "order")), "\n")[1:]
	csv := strings.Split(strings.TrimSpace(output(t, out, "results")), "\n")[1:]
	// A run that failed outright, such as one that couldn't log in, has no row.
	measured, servers := 0, map[string]string{}
	for _, line := range order {
		f := strings.Split(line, ",")
		if !strings.HasPrefix(f[6], "skipped") && f[6] != "failed" {
			measured++
		}
		if f[6] != "ok" {
			servers[f[1]] = "lost"
		} else if servers[f[1]] == "" {
			servers[f[1]] = "ok"
		}
	}
	if len(order) != 12 || len(csv) != measured || !strings.Contains(strings.Join(order, "\n"), "skipped: the server had stopped") {
		t.Errorf("%d runs, %d measured, %d rows:\n%s", len(order), measured, len(csv), strings.Join(order, "\n"))
	}
	if len(servers) != 2 || (servers["a"] == "lost") == (servers["b"] == "lost") {
		t.Errorf("servers %v: one should have lost its runs, the other none", servers)
	}
	_, rest, _ := strings.Cut(out, "results: ")
	base, _, _ := strings.Cut(rest, "\n")
	for _, s := range []string{"a", "b"} {
		if !exists(filepath.Join("..", "..", strings.TrimSuffix(base, ".csv")+"-server-"+s+"-env.txt")) {
			t.Errorf("no environment file of server %s", s)
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
	if env := output(t, out, "environment"); !strings.Contains(env, "stray.bin") {
		t.Error("the warning isn't in the environment file")
	}
}
