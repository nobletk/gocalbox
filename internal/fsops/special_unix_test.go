//go:build unix

package fsops

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestSpecialFilesAreNotOpenedOrListed(t *testing.T) {
	e := newEnv(t)
	e.write("a.txt", "x")
	pipe := filepath.Join(e.root, "pipe")
	if err := syscall.Mkfifo(pipe, 0o644); err != nil {
		t.Skipf("no FIFOs: %v", err)
	}
	t.Cleanup(func() { releaseFIFO(pipe) })
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, err := e.svc.Open(bg, "pipe")
		is(t, err, ErrNotFound, "open FIFO")
		_, err = e.svc.List(bg, "pipe")
		is(t, err, ErrNotDir, "list FIFO")
		entries, err := e.svc.List(bg, "")
		if err != nil || len(entries) != 1 || entries[0].Name != "a.txt" {
			t.Errorf("listing = %+v, %v", entries, err)
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("opening a FIFO blocked")
	}
}

func TestETagFollowsTheFile(t *testing.T) {
	e := newEnv(t)
	p := filepath.Join(e.root, "f.bin")
	at := time.Unix(1_800_000_000, 0)
	tag := func() string {
		f, err := e.svc.Open(bg, "f.bin")
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		return f.ETag()
	}

	os.WriteFile(p, []byte("aaaa"), 0o644)
	os.Chtimes(p, at, at)
	first := tag()
	if tag() != first {
		t.Fatal("ETag differs for an unchanged file")
	}
	os.Chtimes(p, at.Add(time.Millisecond), at.Add(time.Millisecond))
	if tag() == first {
		t.Error("ETag ignores a sub-second change of mtime")
	}
	os.Chtimes(p, at, at)
	os.WriteFile(filepath.Join(e.root, "new.bin"), []byte("bbbb"), 0o644)
	os.Chtimes(filepath.Join(e.root, "new.bin"), at, at)
	os.Rename(filepath.Join(e.root, "new.bin"), p)
	if tag() == first {
		t.Error("ETag ignores a replacement with the same size and mtime")
	}
}

func TestOpenedFilesAreBlocking(t *testing.T) {
	e := newEnv(t)
	e.write("a.txt", "x")
	f, err := e.svc.Open(bg, "a.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rc, err := f.Content().(*os.File).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var flags uintptr
	rc.Control(func(fd uintptr) {
		flags, _, _ = syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_GETFL, 0)
	})
	if flags&syscall.O_NONBLOCK != 0 {
		t.Error("file served in non-blocking mode")
	}
}

// releaseFIFO lets an open of pipe that is waiting for a writer return, so a
// regression fails the test instead of hanging it.
func releaseFIFO(pipe string) {
	for range 3 {
		if f, err := os.OpenFile(pipe, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			f.Close()
		}
	}
}
