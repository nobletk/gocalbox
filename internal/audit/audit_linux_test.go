package audit

import (
	"path/filepath"
	"syscall"
	"testing"
)

func TestLogIsNotOpenedForAppending(t *testing.T) {
	w, err := Open(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, w.locked.Fd(), syscall.F_GETFL, 0)
	if errno != 0 {
		t.Fatal(errno)
	}
	if flags&syscall.O_APPEND != 0 {
		t.Error("the log is open for appending, which Windows can neither lock nor truncate")
	}
}
