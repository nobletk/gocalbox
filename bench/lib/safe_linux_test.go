package lib

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// A disk mounted in the benchmark folder is never emptied: neither the mount
// point nor a folder above it.
func TestADiskMountedInsideIsLeftAlone(t *testing.T) {
	needBash(t)
	if os.Geteuid() != 0 {
		t.Skip("mounting needs root")
	}
	dir := benchDir(t)
	mnt := filepath.Join(dir, "root", "usb")
	os.MkdirAll(mnt, 0o755)
	if err := syscall.Mount("tmpfs", mnt, "tmpfs", 0, "size=1m"); err != nil {
		t.Skipf("mount: %v", err)
	}
	defer syscall.Unmount(mnt, syscall.MNT_DETACH)
	write(t, filepath.Join(mnt, "keep.txt"), "mine")
	if out, ok := safe(t, t.TempDir(), "rm", dir, mnt); ok {
		t.Errorf("rm of the mount point: %s", out)
	}
	if _, ok := safe(t, t.TempDir(), "rm", dir, filepath.Join(dir, "root")); ok {
		t.Error("rm of a folder holding a mount point succeeded")
	}
	if out, ok := safe(t, t.TempDir(), "empty", dir, mnt); ok {
		t.Errorf("empty of the mount point: %s", out)
	}
	if !exists(filepath.Join(mnt, "keep.txt")) {
		t.Error("a file on the mounted disk was deleted")
	}
}

// The Go helper leaves a mounted disk alone too.
func TestRemoveLeavesADiskMountedInsideAlone(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("mounting needs root")
	}
	f, err := Use(marked(t))
	if err != nil {
		t.Fatal(err)
	}
	mnt := filepath.Join(f.Dir, "load", "usb")
	os.MkdirAll(mnt, 0o755)
	if err := syscall.Mount("tmpfs", mnt, "tmpfs", 0, "size=1m"); err != nil {
		t.Skipf("mount: %v", err)
	}
	defer syscall.Unmount(mnt, syscall.MNT_DETACH)
	write(t, filepath.Join(mnt, "keep.txt"), "mine")
	if err := f.Remove(mnt); err == nil {
		t.Error("Remove of the mount point succeeded")
	}
	if err := f.Remove(filepath.Join(f.Dir, "load")); err == nil {
		t.Error("Remove of a folder holding a mount point succeeded")
	}
	if !exists(filepath.Join(mnt, "keep.txt")) {
		t.Error("a file on the mounted disk was deleted")
	}
}

// bindOutside bind-mounts a folder outside the benchmark folder dir at
// dir/root/bind dir: the same file system, so the same device number.
func bindOutside(t *testing.T, dir string) (outside, mnt string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("mounting needs root")
	}
	outside = filepath.Join(t.TempDir(), "out side")
	write(t, filepath.Join(outside, "keep.txt"), "mine")
	mnt = filepath.Join(dir, "root", "bind dir")
	os.MkdirAll(mnt, 0o755)
	if err := syscall.Mount(outside, mnt, "", syscall.MS_BIND, ""); err != nil {
		t.Skipf("bind mount: %v", err)
	}
	t.Cleanup(func() { syscall.Unmount(mnt, syscall.MNT_DETACH) })
	return outside, mnt
}

// A bind mount inside the folder is never entered, by either helper: not at
// the mount point, not above it, not through it.
func TestABindMountInsideIsLeftAlone(t *testing.T) {
	needBash(t)
	dir := benchDir(t)
	outside, mnt := bindOutside(t, dir)
	write(t, filepath.Join(dir, "root", "other", "x.bin"), "x")
	for _, p := range []string{filepath.Join(dir, "root"), mnt, filepath.Join(mnt, "keep.txt")} {
		if out, ok := safe(t, t.TempDir(), "rm", dir, p); ok {
			t.Errorf("rm %s: %s", p, out)
		}
	}
	if out, ok := safe(t, t.TempDir(), "empty", dir, filepath.Join(dir, "root")); ok {
		t.Errorf("empty of the folder holding the mount: %s", out)
	}
	f, err := Use(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{filepath.Join(dir, "root"), mnt, filepath.Join(mnt, "keep.txt")} {
		if err := f.Remove(p); err == nil {
			t.Errorf("Remove(%s) was allowed", p)
		}
	}
	if b, err := os.ReadFile(filepath.Join(outside, "keep.txt")); err != nil || string(b) != "mine" {
		t.Errorf("a file outside the benchmark folder was deleted: %q, %v", b, err)
	}
	// Beside the mount, deleting works.
	if out, ok := safe(t, t.TempDir(), "rm", dir, filepath.Join(dir, "root", "other")); !ok || exists(filepath.Join(dir, "root", "other")) {
		t.Errorf("rm beside the mount: %s", out)
	}
}

// A file on another disk mounted inside is refused by itself too.
func TestAFileOnAMountedDiskIsRefused(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("mounting needs root")
	}
	f, err := Use(marked(t))
	if err != nil {
		t.Fatal(err)
	}
	mnt := filepath.Join(f.Dir, "usb")
	os.MkdirAll(mnt, 0o755)
	if err := syscall.Mount("tmpfs", mnt, "tmpfs", 0, "size=1m"); err != nil {
		t.Skipf("mount: %v", err)
	}
	defer syscall.Unmount(mnt, syscall.MNT_DETACH)
	write(t, filepath.Join(mnt, "keep.txt"), "mine")
	if err := f.Remove(filepath.Join(mnt, "keep.txt")); err == nil || !exists(filepath.Join(mnt, "keep.txt")) {
		t.Errorf("Remove of a file on the mounted disk: %v", err)
	}
}

func TestMountPointsAreUnescaped(t *testing.T) {
	for in, want := range map[string]string{`/a\040b`: "/a b", `/t\011\012\134`: "/t\t\n\\", `/x\0`: `/x\0`, `/w\04`: `/w\04`,
		`/y\8a1`: `/y\8a1`, `/z\189`: `/z\189`, "/plain": "/plain"} {
		if got := unescapeMount(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

// Without a mount table to read, the shell helper refuses to delete, as the
// Go one does: it can't tell a bind mount from the folder's own disk.
func TestNoMountTableNoDelete(t *testing.T) {
	needBash(t)
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Skip("no unshare")
	}
	dir := benchDir(t)
	write(t, filepath.Join(dir, "root", "keep.bin"), "x")
	sh, _ := filepath.Abs("safe.sh")
	out, err := exec.Command(unshare, "--mount", "bash", "-c",
		`mount --make-rprivate / && umount -l /proc && exec bash "$0" rm "$1" "$1/root"`, sh, dir).CombinedOutput()
	if strings.Contains(string(out), "umount") || strings.Contains(string(out), "mount:") {
		t.Skipf("cannot hide /proc here: %s", out)
	}
	if err == nil || !strings.Contains(string(out), "mount table can't be read") || !exists(filepath.Join(dir, "root", "keep.bin")) {
		t.Errorf("without /proc: %v, %s", err, out)
	}
}

// Both helpers read a marker the same way.
func TestBothHelpersReadAMarkerAlike(t *testing.T) {
	needBash(t)
	const line = "gocalbox-bench 0123456789abcdef0123456789abcdef"
	for content, ok := range map[string]bool{
		line + "\n": true, line: true, line + "\r\n": true,
		line + "\n\n": false, line + "\x00\n": false, line + "\r": false, line + "\n\r\n": false, " " + line + "\n": false,
	} {
		dir := filepath.Join(t.TempDir(), "bench")
		write(t, filepath.Join(dir, Mark), content)
		_, err := Use(dir)
		_, shell := safe(t, t.TempDir(), "rm", dir, filepath.Join(dir, "missing"))
		if (err == nil) != ok || shell != ok {
			t.Errorf("%q: Go %v, shell %v; want %v", content, err, shell, ok)
		}
	}
}

// A benchmark folder on a mounted disk, as on the USB stick, works: only
// mounts inside the folder are refused.
func TestAFolderOnAMountedDiskWorks(t *testing.T) {
	needBash(t)
	if os.Geteuid() != 0 {
		t.Skip("mounting needs root")
	}
	disk := t.TempDir()
	if err := syscall.Mount("tmpfs", disk, "tmpfs", 0, "size=4m"); err != nil {
		t.Skipf("mount: %v", err)
	}
	defer syscall.Unmount(disk, syscall.MNT_DETACH)
	dir := filepath.Join(disk, "bench")
	if out, ok := safe(t, t.TempDir(), "init", dir); !ok {
		t.Fatalf("init: %s", out)
	}
	write(t, filepath.Join(dir, "a", "x.bin"), "x")
	write(t, filepath.Join(dir, "b", "x.bin"), "x")
	if out, ok := safe(t, t.TempDir(), "rm", dir, filepath.Join(dir, "a")); !ok || exists(filepath.Join(dir, "a")) {
		t.Errorf("rm on the mounted disk: %s", out)
	}
	f, err := Use(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Remove(filepath.Join(dir, "b")); err != nil || exists(filepath.Join(dir, "b")) {
		t.Errorf("Remove on the mounted disk: %v", err)
	}
}

// Without a mount table to read, the Go helper deletes nothing.
func TestNoMountTableNoRemove(t *testing.T) {
	f, err := Use(marked(t))
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(f.Dir, "x.bin"), "x")
	defer func(old string) { mountTable = old }(mountTable)
	mountTable = filepath.Join(t.TempDir(), "missing")
	if err := f.Remove(filepath.Join(f.Dir, "x.bin")); err == nil || !exists(filepath.Join(f.Dir, "x.bin")) {
		t.Errorf("Remove without a mount table: %v", err)
	}
}

// Deleting stops at the first entry that can't go, leaving the rest.
func TestRemoveStopsAtTheFirstFailure(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root for chattr")
	}
	chattr, err := exec.LookPath("chattr")
	if err != nil {
		t.Skip("no chattr")
	}
	f, err := Use(marked(t))
	if err != nil {
		t.Fatal(err)
	}
	stuck := filepath.Join(f.Dir, "x", "a", "stuck.bin")
	write(t, stuck, "x")
	write(t, filepath.Join(f.Dir, "x", "z", "later.bin"), "x")
	if out, err := exec.Command(chattr, "+i", stuck).CombinedOutput(); err != nil {
		t.Skipf("chattr: %v %s", err, out)
	}
	defer exec.Command(chattr, "-i", stuck).Run()
	if err := f.Remove(filepath.Join(f.Dir, "x")); err == nil {
		t.Fatal("Remove of a folder holding an immutable file succeeded")
	}
	if !exists(filepath.Join(f.Dir, "x", "z", "later.bin")) {
		t.Error("Remove went on past the entry it couldn't delete")
	}
}
