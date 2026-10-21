package lib

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A session interrupted while it stops a server stops it again on its way
// out, quietly and without cutting the first stop short, and keeps the
// block's files with the results, once. The server's environment takes two
// seconds to describe, so that the second stop comes while the first runs.
func TestASessionInterruptedWhileStoppingAServerKeepsItsFiles(t *testing.T) {
	sessionTools(t)
	keepResults(t)
	dir := benchDir(t)
	matrix := filepath.Join(t.TempDir(), "halted.txt")
	write(t, matrix, "server a\ncell e a engine size=64K\n")
	cmd := exec.Command("bash", filepath.Join("bench", "session.sh"), matrix)
	cmd.Dir = filepath.Join("..", "..")
	bin := t.TempDir()
	write(t, filepath.Join(bin, "timedatectl"), "#!/bin/sh\nsleep 2\necho yes\n")
	os.Chmod(filepath.Join(bin, "timedatectl"), 0o755)
	cmd.Env = append(os.Environ(), "BENCH_DIR="+dir, "PORT=18388", "REPS=1", "WARMUP=0", "ROUNDS=1",
		"DROP_CACHES=0", "IPERF=0", "SERVER_SSH=", "SERVER_HOST=", "CELLS=", "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// The first bench/server.sh stop of this folder, found among the processes.
	stopping := func() bool {
		procs, _ := filepath.Glob("/proc/[0-9]*")
		for _, p := range procs {
			argv, _ := os.ReadFile(filepath.Join(p, "cmdline"))
			env, _ := os.ReadFile(filepath.Join(p, "environ"))
			if bytes.Contains(argv, []byte("bench/server.sh\x00stop")) && bytes.Contains(env, []byte("BENCH_DIR="+dir+"\x00")) {
				return true
			}
		}
		return false
	}
	halted := false
	for deadline := time.Now().Add(2 * time.Minute); time.Now().Before(deadline) && !halted; time.Sleep(5 * time.Millisecond) {
		if stopping() {
			cmd.Process.Signal(syscall.SIGTERM)
			halted = true
		}
	}
	cmd.Wait()
	if !halted {
		t.Fatalf("no bench/server.sh stop seen: %s", out.String())
	}
	runs, _ := filepath.Glob(filepath.Join("..", "..", "bench", "results", "session-halted-*.csv"))
	var base string
	for _, r := range runs {
		if !strings.HasSuffix(r, "-order.csv") {
			base = strings.TrimSuffix(r, ".csv")
		}
	}
	if base == "" {
		t.Fatalf("no results: %s", out.String())
	}
	env, _ := os.ReadFile(base + "-server-a-env.txt")
	if !strings.HasPrefix(string(env), "round: 1\nserver: ") || strings.Count(string(env), "round: ") != 1 || !strings.Contains(string(env), "audit records: ") {
		t.Errorf("server a's environment file:\n%s\n%s", env, out.String())
	}
	samples, _ := os.ReadFile(base + "-server-a-samples.csv")
	lines := strings.Split(strings.TrimSpace(string(samples)), "\n")
	if len(lines) < 2 || len(slices.Compact(slices.Clone(lines))) != len(lines) {
		t.Errorf("server a's samples, %d lines:\n%s", len(lines), samples)
	}
	if log, _ := os.ReadFile(base + "-server-a.log"); strings.Count(string(log), "Starting server on ") != 1 {
		t.Errorf("server a's log:\n%s", log)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "server", "env-*")); len(left) > 0 {
		t.Errorf("left in the server's folder: %q", left)
	}
	for _, f := range []string{"ready", "server.pid", "gocalbox.pid"} {
		if exists(filepath.Join(dir, "server", f)) {
			t.Errorf("left in the server's folder: %s\n%s", f, out.String())
		}
	}
	for _, said := range []string{"no bench/server.sh is running", "had stopped before the end of its runs"} {
		if strings.Contains(out.String(), said) {
			t.Errorf("the session said %q:\n%s", said, out.String())
		}
	}
}
