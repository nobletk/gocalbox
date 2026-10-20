package lib

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// script runs a script of bench/ from the repository root with env added,
// and with PATH starting at bin when bin isn't empty.
func script(t *testing.T, name, bin string, env ...string) (string, bool) {
	t.Helper()
	return scriptArgs(t, []string{name}, bin, env...)
}

// scriptArgs runs as script does, with arguments after the script's name.
func scriptArgs(t *testing.T, args []string, bin string, env ...string) (string, bool) {
	t.Helper()
	cmd := exec.Command("bash", append([]string{filepath.Join("bench", args[0])}, args[1:]...)...)
	cmd.Dir = filepath.Join("..", "..")
	cmd.Env = append(os.Environ(), env...)
	if bin != "" {
		cmd.Env = append(cmd.Env, "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	}
	out, err := cmd.CombinedOutput()
	return string(out), err == nil
}

// decoy is a folder that looks like an old WORK folder: the scripts used to
// empty its root and delete its audit log.
func decoy(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, p := range []string{"root/keep.txt", "audit.jsonl", "state.db", "run.env", "samples.csv",
		"baseline/root/keep.txt", "server/root/keep.txt", "server/audit.jsonl", "client/codes", "data/keep.bin"} {
		write(t, filepath.Join(dir, p), "mine")
	}
	return dir
}

func intact(t *testing.T, dir string) {
	t.Helper()
	for _, p := range []string{"root/keep.txt", "audit.jsonl", "state.db", "run.env", "samples.csv",
		"baseline/root/keep.txt", "server/root/keep.txt", "server/audit.jsonl", "client/codes", "data/keep.bin"} {
		if b, err := os.ReadFile(filepath.Join(dir, p)); err != nil || string(b) != "mine" {
			t.Errorf("%s: %q, %v", p, b, err)
		}
	}
	if exists(filepath.Join(dir, ".gocalbox-bench")) {
		t.Error("the folder was marked")
	}
}

// A fake ssh that records being run, so a test can tell the client stopped
// before reaching the server.
func fakeSSH(t *testing.T) (bin, log string) {
	t.Helper()
	bin = t.TempDir()
	log = filepath.Join(bin, "ssh.log")
	write(t, filepath.Join(bin, "ssh"), "#!/bin/sh\necho \"$@\" >> "+log+"\nexit 1\n")
	os.Chmod(filepath.Join(bin, "ssh"), 0o755)
	return bin, log
}

// Every script refuses a folder that isn't a benchmark folder, and the old
// WORK and SERVER_WORK, before writing or deleting anything.
func TestTheScriptsRefuseAnUnmarkedFolder(t *testing.T) {
	needBash(t)
	bin, sshLog := fakeSSH(t)
	client := []string{"SERVER_HOST=192.0.2.1", "SERVER_SSH=bench@192.0.2.1", "SERVER_BENCH=/nowhere"}
	for _, tc := range []struct {
		name string
		env  func(dir string) []string
		want string
	}{
		{"baseline.sh", func(d string) []string { return []string{"BENCH_DIR=" + d} }, "not a benchmark folder"},
		{"baseline.sh", func(d string) []string { return []string{"BENCH_DIR="} }, "no benchmark folder"},
		{"baseline.sh", func(d string) []string { return []string{"WORK=" + d} }, "WORK is replaced"},
		{"server.sh", func(d string) []string { return []string{"BENCH_DIR=" + d} }, "not a benchmark folder"},
		{"server.sh", func(d string) []string { return []string{"WORK=" + d, "BENCH_DIR=" + d} }, "WORK is replaced"},
		{"client.sh", func(d string) []string { return append([]string{"BENCH_DIR=" + d}, client...) }, "not a benchmark folder"},
		{"client.sh", func(d string) []string { return append([]string{"BENCH_DIR=" + d + "/root"}, client...) }, "not a benchmark folder"},
		{"client.sh", func(d string) []string { return append([]string{"WORK=" + d, "SERVER_WORK=" + d}, client...) }, "replaced"},
	} {
		dir := decoy(t)
		out, ok := script(t, tc.name, bin, tc.env(dir)...)
		if ok || !strings.Contains(out, tc.want) {
			t.Errorf("%s with %v: ok=%v, %s", tc.name, tc.env(dir), ok, out)
		}
		intact(t, dir)
	}
	if exists(sshLog) {
		b, _ := os.ReadFile(sshLog)
		t.Errorf("the client ran ssh: %s", b)
	}
}

// baseline.sh still measures, with everything it writes in the benchmark
// folder, and leaves nothing of a run but its results, its data and the
// server's own folder.
func TestBaselineRunsInTheBenchmarkFolder(t *testing.T) {
	needBash(t)
	if testing.Short() {
		t.Skip("builds and runs the server")
	}
	for _, tool := range []string{"curl", "numfmt", "go", "openssl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("no %s", tool)
		}
	}
	dir := benchDir(t)
	write(t, filepath.Join(dir, "baseline", "root", "stale.bin"), "old")
	results := filepath.Join("..", "..", "bench", "results")
	before, _ := os.ReadDir(results)
	out, ok := script(t, "baseline.sh", "", "BENCH_DIR="+dir, "SIZES=64K", "REPS=1", "PORT=18391", "DROP_CACHES=0")
	if !ok {
		t.Fatalf("baseline.sh: %s", out)
	}
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
	csv := ""
	for _, line := range strings.Split(out, "\n") {
		if p, ok := strings.CutPrefix(line, "results: "); ok {
			csv = p
		}
	}
	b, err := os.ReadFile(filepath.Join("..", "..", csv))
	if err != nil {
		t.Fatal(err)
	}
	rows := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(rows) != 1+2+3 {
		t.Fatalf("rows: %q", rows)
	}
	for _, r := range rows[1:] {
		if !strings.Contains(r, ",201,") && !strings.Contains(r, ",200,") {
			t.Errorf("row %s", r)
		}
	}
	if exists(filepath.Join(dir, "baseline", "root", "stale.bin")) {
		t.Error("the old run's file is still served")
	}
	root, _ := os.ReadDir(filepath.Join(dir, "baseline", "root"))
	for _, e := range root {
		if e.Name() != ".gocalbox" {
			t.Errorf("left in the served folder: %s", e.Name())
		}
	}
	if !exists(filepath.Join(dir, "data", "64K.bin")) || !exists(filepath.Join(dir, ".gocalbox-bench")) {
		t.Error("the data or the marker is gone")
	}
}
