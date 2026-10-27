package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func build(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "subreaper")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	return bin
}

// childrenCPU is a process's CPU time of children reaped, in clock ticks.
func childrenCPU(t *testing.T, pid int) int {
	t.Helper()
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	f := strings.Fields(s[strings.LastIndex(s, ") ")+2:])
	cu, _ := strconv.Atoi(f[13])
	cs, _ := strconv.Atoi(f[14])
	return cu + cs
}

// A process the command leaves behind is reaped here, with its CPU time,
// while the command still runs.
func TestAnOrphansTimeIsCountedHere(t *testing.T) {
	done := filepath.Join(t.TempDir(), "done")
	cmd := exec.Command(build(t), "/bin/sh", "-c",
		`(/bin/sh -c 'i=0; while [ $i -lt 300000 ]; do i=$((i + 1)); done; : > "$0"' "$1" &); sleep 30`, "sh", done)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	for deadline := time.Now().Add(time.Minute); ; time.Sleep(50 * time.Millisecond) {
		if _, err := os.Stat(done); err == nil && childrenCPU(t, cmd.Process.Pid) > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the orphan's CPU wasn't counted: %d ticks", childrenCPU(t, cmd.Process.Pid))
		}
	}
}

// SIGTERM goes on to the command, and its status comes back.
func TestTheCommandsSignalsAndStatus(t *testing.T) {
	bin := build(t)
	cmd := exec.Command(bin, "/bin/sh", "-c", `trap 'exit 7' TERM; while :; do sleep 0.05; done`)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	cmd.Process.Signal(syscall.SIGTERM)
	if err := cmd.Wait(); cmd.ProcessState.ExitCode() != 7 {
		t.Errorf("exit %d (%v), want 7", cmd.ProcessState.ExitCode(), err)
	}
	cmd = exec.Command(bin, "/bin/sh", "-c", "kill -KILL $$")
	cmd.Run()
	if got := cmd.ProcessState.ExitCode(); got != 128+9 {
		t.Errorf("a command killed: exit %d, want 137", got)
	}
	if out, err := exec.Command(bin).CombinedOutput(); err == nil || !strings.Contains(string(out), "usage") {
		t.Errorf("no command: %v, %s", err, out)
	}
	if out, err := exec.Command(bin, "/no/such/command").CombinedOutput(); err == nil || !strings.Contains(string(out), "no such file") {
		t.Errorf("a missing command: %v, %s", err, out)
	}
}
