package fsops

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/nobletk/gocalbox/internal/sandbox"
)

func TestTheReservedFolderCantBeReachedByItsShortName(t *testing.T) {
	a := newAccessEnv(t)
	long := filepath.Join(a.root, sandbox.ReservedName)
	if err := os.Mkdir(long, 0o700); err != nil {
		t.Fatal(err)
	}
	from, _ := syscall.UTF16PtrFromString(long)
	buf := make([]uint16, syscall.MAX_PATH)
	n, err := syscall.GetShortPathName(from, &buf[0], uint32(len(buf)))
	short := filepath.Base(syscall.UTF16ToString(buf[:n]))
	if err != nil || short == sandbox.ReservedName {
		t.Skipf("the volume keeps no short names: %v", err)
	}
	shown(t, errOf(a.svc.Move(as(admin), short, "public/staging")), sandbox.ErrReserved, "move "+short)
	shown(t, errOf(a.svc.Delete(as(admin), short)), sandbox.ErrReserved, "delete "+short)
	shown(t, errOf(a.svc.List(as(admin), short)), sandbox.ErrReserved, "list "+short)
	if _, err := os.Stat(long); err != nil {
		t.Error(err)
	}
}
