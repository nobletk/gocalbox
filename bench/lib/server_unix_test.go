//go:build unix

package lib

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// serverSh starts bench/server.sh in the background, as session.sh does,
// with its output in a file: its children may outlive it.
func serverSh(t *testing.T, bin string, env ...string) (*exec.Cmd, func() string) {
	t.Helper()
	cmd := exec.Command("bash", filepath.Join("bench", "server.sh"))
	cmd.Dir = filepath.Join("..", "..")
	cmd.Env = append(os.Environ(), env...)
	if bin != "" {
		cmd.Env = append(cmd.Env, "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	}
	f, err := os.Create(filepath.Join(t.TempDir(), "console.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout, cmd.Stderr = f, f
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		f.Close()
		// A server the test's server.sh left running.
		scriptArgs(t, []string{"server.sh", "stop"}, "", env...)
	})
	return cmd, func() string { b, _ := os.ReadFile(f.Name()); return string(b) }
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(2 * time.Minute); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("waited two minutes for %s", what)
}

func serverTools(t *testing.T) {
	t.Helper()
	needBash(t)
	if testing.Short() {
		t.Skip("builds and runs the server")
	}
	for _, tool := range []string{"curl", "go", "tar"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("no %s", tool)
		}
	}
}

// server.sh empties its served folder at its start, refuses a second
// server.sh on the same folder, and its stop also ends a server whose
// server.sh was killed.
func TestServerShKeepsToOneServerPerFolder(t *testing.T) {
	serverTools(t)
	keepResults(t)
	dir := benchDir(t)
	write(t, filepath.Join(dir, "server", "root", "stale.bin"), "old")
	first, out := serverSh(t, "", "BENCH_DIR="+dir, "PORT=18395", "BIND=127.0.0.1")
	waitFor(t, "the server", func() bool { return exists(filepath.Join(dir, "server", "ready")) })
	if exists(filepath.Join(dir, "server", "root", "stale.bin")) {
		t.Error("the served folder wasn't emptied")
	}
	write(t, filepath.Join(dir, "server", "root", "served.bin"), "mine")
	second, sout := serverSh(t, "", "BENCH_DIR="+dir, "PORT=18396", "BIND=127.0.0.1")
	if err := second.Wait(); err == nil || !strings.Contains(sout(), "another bench/server.sh") {
		t.Errorf("a second server.sh: %v, %s", err, sout())
	}
	if !exists(filepath.Join(dir, "server", "root", "served.bin")) {
		t.Error("the second server.sh deleted the first one's files")
	}
	b, _ := os.ReadFile(filepath.Join(dir, "server", "ready"))
	server, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	first.Process.Kill()
	first.Wait()
	if syscall.Kill(server, 0) != nil {
		t.Fatalf("the server ended with its server.sh: %s", out())
	}
	third, tout := serverSh(t, "", "BENCH_DIR="+dir, "PORT=18396", "BIND=127.0.0.1")
	if err := third.Wait(); err == nil || !strings.Contains(tout(), "or a server it left") {
		t.Errorf("a server.sh beside a server left running: %v, %s", err, tout())
	}
	if out, ok := scriptArgs(t, []string{"server.sh", "stop"}, "", "BENCH_DIR="+dir); !ok || !strings.Contains(out, "left running") {
		t.Errorf("stop: %s", out)
	}
	waitFor(t, "the server's end", func() bool { return syscall.Kill(server, 0) != nil })
	if out, ok := scriptArgs(t, []string{"server.sh", "stop"}, "", "BENCH_DIR="+dir); ok || !strings.Contains(out, "no bench/server.sh is running") {
		t.Errorf("stop with nothing running: %s", out)
	}
}

// stop reaches only the processes server.sh recorded: a PID now another
// process's, even another server.sh's, is left alone.
func TestServerShStopsOnlyWhatItStarted(t *testing.T) {
	needBash(t)
	dir := benchDir(t)
	other := exec.Command("bash", "-c", "exec -a bench/server.sh sleep 60")
	if err := other.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { other.Process.Kill(); other.Wait() }()
	pid := other.Process.Pid
	for _, f := range []string{"server.pid", "gocalbox.pid"} {
		write(t, filepath.Join(dir, "server", f), fmt.Sprintf("%d 1\n", pid))
		if out, ok := scriptArgs(t, []string{"server.sh", "stop"}, "", "BENCH_DIR="+dir); ok || !strings.Contains(out, "no bench/server.sh is running") {
			t.Errorf("%s naming another process: %s", f, out)
		}
		os.Remove(filepath.Join(dir, "server", f))
	}
	if syscall.Kill(pid, 0) != nil {
		t.Error("another process was stopped")
	}
}

// server.sh refuses benchmark settings for a build that would ignore them,
// and a build that is no benchmark build though asked to be.
func TestServerShRefusesSettingsItWouldIgnore(t *testing.T) {
	needBash(t)
	dir := benchDir(t)
	out, ok := script(t, "server.sh", "", "BENCH_DIR="+dir, "GOCALBOX_BENCH_PART_SIZE=16M", "BUILD_TAGS=")
	if ok || !strings.Contains(out, "need BUILD_TAGS=bench") {
		t.Errorf("settings without the benchmark build: %s", out)
	}
	serverTools(t)
	keepResults(t)
	goTool, _ := exec.LookPath("go")
	bin := t.TempDir()
	// A go that drops the build tags, as a commit from before the benchmark build would.
	write(t, filepath.Join(bin, "go"), `#!/bin/bash
args=()
while [ $# -gt 0 ]; do
  if [ "$1" = -tags ]; then shift 2; continue; fi
  args+=("$1"); shift
done
exec `+goTool+` "${args[@]}"
`)
	os.Chmod(filepath.Join(bin, "go"), 0o755)
	cmd, sout := serverSh(t, bin, "BENCH_DIR="+dir, "PORT=18397", "BIND=127.0.0.1", "BUILD_TAGS=bench")
	if err := cmd.Wait(); err == nil || !strings.Contains(sout(), "is no benchmark build") {
		t.Errorf("a build that ignores the tag: %v, %s", err, sout())
	}
}

// server.sh writes its environment file into ENV_DIR when given one, as
// session.sh asks, and into bench/results otherwise.
func TestServerShWritesItsEnvironmentWhereAsked(t *testing.T) {
	serverTools(t)
	keepResults(t)
	results := filepath.Join("..", "..", "bench", "results")
	envs := func(dir string) []string { m, _ := filepath.Glob(filepath.Join(dir, "server-*-env.txt")); return m }
	before := len(envs(results))
	dir := benchDir(t)
	asked := filepath.Join(dir, "server", "envs")
	for _, c := range []struct {
		env  []string
		into string
	}{
		{[]string{"ENV_DIR=" + asked}, asked},
		{nil, results},
	} {
		was := len(envs(c.into))
		cmd, out := serverSh(t, "", append([]string{"BENCH_DIR=" + dir, "PORT=18390", "BIND=127.0.0.1"}, c.env...)...)
		waitFor(t, "the server", func() bool { return exists(filepath.Join(dir, "server", "ready")) })
		// Reaped as it ends: stop waits until its process is gone.
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		if o, ok := scriptArgs(t, []string{"server.sh", "stop"}, "", "BENCH_DIR="+dir); !ok {
			t.Fatalf("stop: %s", o)
		}
		<-done
		got := envs(c.into)
		if len(got) != was+1 {
			t.Fatalf("%v: %d environment files in %s, not %d: %s", c.env, len(got), c.into, was+1, out())
		}
		if b, _ := os.ReadFile(got[len(got)-1]); !strings.Contains(string(b), "server: ") || !strings.Contains(out(), "environment written to ") {
			t.Errorf("%v: %s\n%s", c.env, b, out())
		}
		if c.into == asked && len(envs(results)) != before {
			t.Errorf("ENV_DIR given, but an environment file went to the results")
		}
	}
}
