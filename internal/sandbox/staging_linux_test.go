package sandbox

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func mount(t *testing.T, source, target, fstype string, flags uintptr, data string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("mounting needs root")
	}
	if err := syscall.Mount(source, target, fstype, flags, data); err != nil {
		t.Skipf("cannot mount: %v", err)
	}
	t.Cleanup(func() { syscall.Unmount(target, syscall.MNT_DETACH) })
}

// A bind mount keeps the device number; only the mount ID tells it apart,
// and a link across it fails.
func TestVolumeOfTellsABindMountApart(t *testing.T) {
	dir, elsewhere := t.TempDir(), t.TempDir()
	bound := filepath.Join(dir, "bound")
	os.Mkdir(bound, 0o755)
	mount(t, elsewhere, bound, "", syscall.MS_BIND, "")
	os.WriteFile(filepath.Join(dir, "f"), []byte("x"), 0o644)

	r := openRoot(t, dir)
	a, err := VolumeOf(r, ".")
	if err != nil {
		t.Fatal(err)
	}
	b, err := VolumeOf(r, "bound")
	if err != nil {
		t.Fatal(err)
	}
	if a.dev != b.dev {
		t.Skip("the bind mount has its own device number here")
	}
	if a == b {
		t.Errorf("a bind mount looks like the same volume: %+v", a)
	}
	if err := r.Link("f", "bound/f"); err == nil {
		t.Error("a link across the bind mount worked; the test proves nothing")
	}
}

func TestCheckStagingRefusesAMountedStagingFolder(t *testing.T) {
	for _, d := range []string{ReservedName, TmpDir} {
		t.Run(d, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, filepath.FromSlash(d))
			os.MkdirAll(target, 0o700)
			mount(t, "tmpfs", target, "tmpfs", 0, "size=1m,mode=0700")
			if s := check(t, dir); s.Usable() || !strings.Contains(s.Problem.Error(), "another file system") {
				t.Errorf("problem %v", s.Problem)
			}
		})
	}
}

func TestCheckStagingOnAReadOnlyFolder(t *testing.T) {
	dir := t.TempDir()
	mount(t, dir, dir, "", syscall.MS_BIND, "")
	mount(t, "", dir, "", syscall.MS_REMOUNT|syscall.MS_BIND|syscall.MS_RDONLY, "")
	if s := check(t, dir); s.Usable() {
		t.Error("a read-only served folder gave a usable staging folder")
	}
}

// When the folders pass but preparing them fails, the folder can't be used,
// yet the lock stays held, so a second server is still refused.
func TestCheckStagingKeepsTheLockWhenPreparingFails(t *testing.T) {
	dir := t.TempDir()
	check(t, dir).Close()
	tmp := filepath.Join(dir, filepath.FromSlash(TmpDir))
	if out, err := exec.Command("chattr", "+i", tmp).CombinedOutput(); err != nil {
		t.Skipf("cannot make a folder immutable: %v %s", err, out)
	}
	t.Cleanup(func() { exec.Command("chattr", "-i", tmp).Run() })
	s := check(t, dir)
	if s.Usable() {
		t.Fatal("usable although nothing can be written in tmp")
	}
	if _, err := CheckStaging(openRoot(t, dir)); !errors.Is(err, ErrStagingLocked) {
		t.Errorf("a second server: %v", err)
	}
}
