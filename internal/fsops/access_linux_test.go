package fsops

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/nobletk/gocalbox/internal/sandbox"
)

func TestAFolderOnAnotherFileSystemIsDeletedInPlace(t *testing.T) {
	a := newAccessEnv(t)
	mnt := filepath.Join(a.root, "public", "mnt")
	os.Mkdir(mnt, 0o755)
	if err := syscall.Mount("tmpfs", mnt, "tmpfs", 0, ""); err != nil {
		t.Skipf("cannot mount a file system: %v", err)
	}
	t.Cleanup(func() { syscall.Unmount(mnt, syscall.MNT_DETACH) })
	a.write("public/mnt/sub/a.txt", "a")
	ok(t, errOf(a.svc.Delete(as(admin), "public/mnt/sub")), "delete a folder on another file system")
	if a.exists("public/mnt/sub") {
		t.Error("the folder is left")
	}
	if left, err := os.ReadDir(filepath.Join(a.root, trashDir)); err != nil || len(left) != 0 {
		t.Errorf("trash: %v, %v", left, err)
	}
}

// A FAT volume finds a file by a short name that its listings don't show,
// such as GO3F2A~1 for .gocalbox after collisions. A bind mount gives the
// reserved folder such a second name, and hiding it from listings does the
// rest.
func TestChangesCantReachTheReservedFolderByAnUnlistedName(t *testing.T) {
	a := newAccessEnv(t)
	a.write(".gocalbox/trash/0123/deleted.txt", "x")
	a.write("public/.gocalbox/staging.bin", "x")
	a.upload(alice, "public", "a.txt", "a")
	a.upload(admin, "public", "b.txt", "b")
	for alias, target := range map[string]string{"GO3F2A~1": ".gocalbox", "public/GO3F2A~1": "public/.gocalbox"} {
		dir := filepath.Join(a.root, alias)
		os.Mkdir(dir, 0o755)
		if err := syscall.Mount(filepath.Join(a.root, target), dir, "", syscall.MS_BIND, ""); err != nil {
			t.Skipf("cannot bind-mount: %v", err)
		}
		t.Cleanup(func() { syscall.Unmount(dir, syscall.MNT_DETACH) })
	}
	orig := readNames
	readNames = func(root *os.Root, dir string) ([]string, error) {
		names, err := orig(root, dir)
		return slices.DeleteFunc(names, func(n string) bool { return n == "GO3F2A~1" }), err
	}
	t.Cleanup(func() { readNames = orig })

	shown(t, errOf3(a.svc.Create(as(admin), "GO3F2A~1/trash", "x.txt", strings.NewReader("x"), -1)), sandbox.ErrReserved, "the admin uploads into the trash")
	shown(t, errOf(a.svc.Mkdir(as(admin), "GO3F2A~1", "made")), sandbox.ErrReserved, "the admin creates a folder in .gocalbox")
	shown(t, errOf(a.svc.Move(as(admin), "public/b.txt", "GO3F2A~1/b.txt")), sandbox.ErrReserved, "the admin moves a file into .gocalbox")
	shown(t, errOf3(a.svc.Create(as(alice), "public/GO3F2A~1", "x.txt", strings.NewReader("x"), -1)), sandbox.ErrReserved, "alice uploads into public/.gocalbox")
	shown(t, errOf(a.svc.Mkdir(as(alice), "public/GO3F2A~1", "made")), sandbox.ErrReserved, "alice creates a folder in public/.gocalbox")
	shown(t, errOf(a.svc.Move(as(alice), "public/a.txt", "public/GO3F2A~1/a.txt")), sandbox.ErrReserved, "alice moves her file into public/.gocalbox")
	shown(t, errOf(a.svc.Delete(as(admin), "GO3F2A~1/trash/0123")), sandbox.ErrReserved, "the admin deletes in the trash")
	shown(t, errOf(a.svc.Move(as(admin), "GO3F2A~1/trash/0123", "public/0123")), sandbox.ErrReserved, "the admin moves a folder out of the trash")
	for _, p := range []string{".gocalbox/trash/x.txt", ".gocalbox/made", ".gocalbox/b.txt", "public/.gocalbox/x.txt", "public/.gocalbox/made", "public/.gocalbox/a.txt"} {
		if a.exists(p) {
			t.Errorf("%s was made", p)
		}
	}
	if !a.exists(".gocalbox/trash/0123/deleted.txt") {
		t.Error("the trash was changed")
	}
}
