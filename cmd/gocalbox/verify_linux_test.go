package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// A file the kernel can't read is an error, not a verdict; one whose size
// isn't what it reads, as files under /proc are, can't be checked either.
func TestVerifyUploadReportsWhatItCouldntRead(t *testing.T) {
	for path, want := range map[string]string{
		"/proc/self/mem": "input/output error",
		"/proc/version":  "changed while it was read: 0 bytes when opened",
	} {
		err := verifyUpload(path, 8<<20, emptyComposite)
		var unchecked *uncheckedError
		if err == nil || !strings.Contains(err.Error(), want) || !errors.As(err, &unchecked) {
			t.Errorf("%s: %v, want %q", path, err, want)
		}
	}
}

// opensOf counts the times path is opened while do runs.
func opensOf(t *testing.T, path string, do func()) int {
	t.Helper()
	fd, err := unix.InotifyInit1(unix.IN_NONBLOCK)
	if err != nil {
		t.Skip(err)
	}
	defer unix.Close(fd)
	if _, err := unix.InotifyAddWatch(fd, path, unix.IN_OPEN); err != nil {
		t.Skip(err)
	}
	do()
	time.Sleep(50 * time.Millisecond)
	buf := make([]byte, 4096)
	n, _ := unix.Read(fd, buf)
	count := 0
	for off := 0; off+unix.SizeofInotifyEvent <= n; {
		ev := (*unix.InotifyEvent)(unsafe.Pointer(&buf[off]))
		if ev.Mask&unix.IN_OPEN != 0 {
			count++
		}
		off += unix.SizeofInotifyEvent + int(ev.Len)
	}
	return count
}

// A FIFO or a device isn't opened at all: opening one may act on it.
func TestWhatIsntAFileIsNeverOpened(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0o644); err != nil {
		t.Fatal(err)
	}
	paths := []string{fifo}
	// A node of its own for the null device: other processes open
	// /dev/null all the time, and the watch would count them too.
	null := filepath.Join(dir, "null")
	// On a nodev mount the node can't be opened, so opening it by mistake
	// would go unseen.
	err := unix.Mknod(null, unix.S_IFCHR|0o666, int(unix.Mkdev(1, 3)))
	if err == nil {
		var f *os.File
		if f, err = os.Open(null); err == nil {
			f.Close()
			paths = append(paths, null)
		}
	}
	if err != nil {
		t.Logf("no device node of its own, so no device is tried: %v", err)
	}
	for _, path := range paths {
		var err error
		if n := opensOf(t, path, func() { err = verifyUpload(path, 8<<20, emptyComposite) }); n != 0 || err == nil {
			t.Errorf("%s: opened %d times; %v", path, n, err)
		}
	}
}

// A file another process holds a write lease on, as Samba does for an
// oplock, is verified once the lease is broken, rather than refused.
func TestAFileUnderAWriteLeaseIsVerifiedOnceTheLeaseIsBroken(t *testing.T) {
	file := filepath.Join(t.TempDir(), "f")
	os.WriteFile(file, []byte("abc"), 0o644)
	holder, err := os.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	fd := holder.Fd()
	if _, err := unix.FcntlInt(fd, unix.F_SETLEASE, unix.F_WRLCK); err != nil {
		t.Skipf("no lease: %v", err)
	}
	released := make(chan struct{})
	go func() {
		defer close(released)
		time.Sleep(200 * time.Millisecond)
		unix.FcntlInt(fd, unix.F_SETLEASE, unix.F_UNLCK)
	}()
	defer func() { <-released }()
	done := make(chan error, 1)
	go func() {
		done <- verifyUpload(file, 8<<20, "4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358")
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("a file under a write lease: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("verifyUpload still waiting 30 s after the lease was released")
	}
}
