//go:build unix

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const emptyComposite = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// A device or a FIFO isn't a stored file, even when it reads as an empty
// one, and a FIFO is refused without waiting for a writer.
func TestVerifyUploadRefusesWhatIsntAFile(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := unix.Mkfifo(fifo, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{os.DevNull, fifo} {
		done := make(chan error, 1)
		go func() { done <- verifyUpload(path, 8<<20, emptyComposite) }()
		select {
		case err := <-done:
			var unchecked *uncheckedError
			if err == nil || !strings.Contains(err.Error(), "is not a regular file") || !errors.As(err, &unchecked) {
				t.Errorf("%s: %v", path, err)
			}
		case <-time.After(5 * time.Second):
			w, _ := os.OpenFile(fifo, os.O_WRONLY, 0)
			w.Close()
			t.Fatalf("%s: still waiting after 5 s", path)
		}
	}

	// A FIFO put in the file's place after its check is opened without
	// waiting, and refused.
	file := filepath.Join(t.TempDir(), "f")
	os.WriteFile(file, nil, 0o644)
	beforeVerifyOpen = func() { os.Rename(fifo, file) }
	defer func() { beforeVerifyOpen = nil }()
	done := make(chan error, 1)
	go func() { done <- verifyUpload(file, 8<<20, emptyComposite) }()
	select {
	case err := <-done:
		var unchecked *uncheckedError
		if err == nil || !strings.Contains(err.Error(), "is not a regular file") || !errors.As(err, &unchecked) {
			t.Errorf("a FIFO put in the file's place: %v", err)
		}
	case <-time.After(5 * time.Second):
		w, _ := os.OpenFile(file, os.O_WRONLY, 0)
		w.Close()
		t.Fatal("a FIFO put in the file's place: still waiting after 5 s")
	}
}

// A regular file opened without waiting is read in blocking mode.
func TestARegularFileIsReadInBlockingMode(t *testing.T) {
	file := filepath.Join(t.TempDir(), "f")
	os.WriteFile(file, []byte("abc"), 0o644)
	f, err := openToVerify(file)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rc, err := f.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var flags int
	rc.Control(func(fd uintptr) { flags, err = unix.FcntlInt(fd, unix.F_GETFL, 0) })
	if err != nil || flags&unix.O_NONBLOCK != 0 {
		t.Errorf("flags %#x, %v: the file is still non-blocking", flags, err)
	}
}
