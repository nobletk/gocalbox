// Command subreaper runs a server as a child subreaper, so that the
// processes it leaves behind are this process's children once orphaned,
// and their CPU time is counted in this process's time of children reaped.
// OpenSSH's sshd needs it: a connection's monitor exits without waiting for
// the process that ran the session, whose time would otherwise reach no
// process the benchmark samples.
//
//	subreaper COMMAND [ARGUMENT ...]
//
// SIGTERM, SIGINT and SIGHUP are passed on to the command. It exits once the
// command has, with its status.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

// prSetChildSubreaper is PR_SET_CHILD_SUBREAPER of prctl(2).
const prSetChildSubreaper = 36

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: subreaper COMMAND [ARGUMENT ...]")
		os.Exit(2)
	}
	if _, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, prSetChildSubreaper, 1, 0); e != 0 {
		fmt.Fprintln(os.Stderr, "subreaper:", e)
		os.Exit(1)
	}
	// Before the command starts, so that no signal for it is lost.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	cmd := exec.Command(os.Args[1], os.Args[2:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "subreaper:", err)
		os.Exit(1)
	}
	go func() {
		for s := range sig {
			cmd.Process.Signal(s)
		}
	}()
	os.Exit(reap(cmd.Process.Pid))
}

// reap waits for every child, the orphans it adopts included, until the
// command ends, and returns the status to exit with.
func reap(pid int) int {
	for {
		var ws syscall.WaitStatus
		got, err := syscall.Wait4(-1, &ws, 0, nil)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "subreaper:", err)
			return 1
		}
		if got != pid {
			continue
		}
		if ws.Signaled() {
			return 128 + int(ws.Signal())
		}
		return ws.ExitStatus()
	}
}
