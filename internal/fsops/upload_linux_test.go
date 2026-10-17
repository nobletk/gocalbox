package fsops

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func bindMount(t *testing.T, source, target string, flags uintptr) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("mounting needs root")
	}
	if err := syscall.Mount(source, target, "", syscall.MS_BIND, ""); err != nil {
		t.Skipf("cannot bind-mount: %v", err)
	}
	t.Cleanup(func() { syscall.Unmount(target, syscall.MNT_DETACH) })
	if flags != 0 {
		if err := syscall.Mount("", target, "", syscall.MS_REMOUNT|syscall.MS_BIND|flags, ""); err != nil {
			t.Skipf("cannot remount: %v", err)
		}
	}
}

// A bind mount keeps the device number, so only the mount ID tells that a
// link into it would fail.
func TestPrepareUploadRefusesABindMount(t *testing.T) {
	a := newAccessEnv(t)
	bound := filepath.Join(a.root, "public", "bound")
	os.Mkdir(bound, 0o755)
	bindMount(t, t.TempDir(), bound, 0)
	shown(t, errOf3(a.svc.PrepareUpload(as(alice), "public/bound", "a.txt")), ErrCrossDevice, "into a bind mount")
	ok(t, errOf3(a.svc.PrepareUpload(as(alice), "public", "a.txt")), "next to it")
}

// If the folder is found on another file system only when the file is
// placed, the link's EXDEV is the answer, and nothing is placed.
func TestAdoptAcrossAMountFails(t *testing.T) {
	a := newAccessEnv(t)
	bound := filepath.Join(a.root, "public", "bound")
	os.Mkdir(bound, 0o755)
	bindMount(t, t.TempDir(), bound, 0)
	staged := a.stage("x")
	fakeVolumes(t)
	_, _, err := a.svc.Adopt(as(alice), staged, "public/bound", "a.txt", func(string) error { return nil })
	shown(t, err, ErrCrossDevice, "a link across a mount")
	if a.exists("public/bound/a.txt") || !a.exists(staged) {
		t.Error("something was placed")
	}
}

func TestPrepareUploadRefusesAReadOnlyFolder(t *testing.T) {
	a := newAccessEnv(t)
	ro := filepath.Join(a.root, "public", "ro")
	os.Mkdir(ro, 0o755)
	bindMount(t, ro, ro, syscall.MS_RDONLY)
	fakeVolumes(t)
	_, _, err := a.svc.PrepareUpload(as(alice), "public/ro", "a.txt")
	if !errors.Is(err, ErrReadOnly) || !errors.Is(err, fs.ErrPermission) {
		t.Errorf("into a read-only folder: %v", err)
	}
}

// A bind mount of a folder on the served disk takes its bytes from the same
// free space, so the ledger measures it, though links across it fail.
func TestTheLedgerMeasuresABindMountOfTheServedDisk(t *testing.T) {
	e, _, _ := newSpaceEnv(t, func() (int64, error) { return 10 << 20, nil }, 4<<20)
	src, dst := filepath.Join(e.root, "media"), filepath.Join(e.root, "media-view")
	os.Mkdir(src, 0o755)
	os.Mkdir(dst, 0o755)
	bindMount(t, src, dst, 0)
	_, _, err := e.svc.Create(bg, "media-view", "big.bin", strings.NewReader("x"), 7<<20)
	is(t, err, ErrInsufficientStorage, "7 MiB into a bind mount with 6 MiB above the reserve")
}

// An immutable folder refuses writes even to root: found before the upload,
// not when it is placed.
func TestPrepareUploadRefusesAnImmutableFolder(t *testing.T) {
	a := newAccessEnv(t)
	d := filepath.Join(a.root, "users", "alice", "frozen")
	os.Mkdir(d, 0o755)
	if out, err := exec.Command("chattr", "+i", d).CombinedOutput(); err != nil {
		t.Skipf("cannot make a folder immutable: %v %s", err, out)
	}
	t.Cleanup(func() { exec.Command("chattr", "-i", d).Run() })
	if _, _, err := a.svc.PrepareUpload(as(alice), "users/alice/frozen", "a.txt"); !errors.Is(err, fs.ErrPermission) {
		t.Errorf("into an immutable folder: %v", err)
	}
}
