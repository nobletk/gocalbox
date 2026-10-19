package fsops

import (
	"strings"
	"testing"

	"github.com/nobletk/gocalbox/internal/sandbox"
)

// Names Windows reads as devices, or as a file's stream, are invalid names:
// refused before the folder is touched, never taken for a path that leaves
// the root.
func TestDeviceAndStreamNamesAreInvalid(t *testing.T) {
	for _, name := range []string{"CON", "con", "Nul", "COM1", "LPT9", "CONIN$", "a:b", "x.txt:hidden"} {
		if ValidName(name) {
			t.Errorf("ValidName(%q) = true", name)
		}
	}
	for _, name := range []string{"console", "CON1", "COMX", "nul_file.txt"} {
		if !ValidName(name) {
			t.Errorf("ValidName(%q) = false", name)
		}
	}

	a := newAccessEnv(t)
	a.upload(alice, "public", "a.txt", "a")
	direct := newAccessEnv(t)
	directUploads(direct.svc)
	for _, name := range []string{"CON", "nul", "COM1", "a:b"} {
		shown(t, errOf3(a.svc.Create(as(alice), "public", name, untouched{t}, -1)), ErrInvalidName, "a staged upload named "+name)
		shown(t, errOf3(direct.svc.Create(as(alice), "public", name, untouched{t}, -1)), ErrInvalidName, "a direct upload named "+name)
		shown(t, errOf(a.svc.Mkdir(as(alice), "public", name)), ErrInvalidName, "a folder named "+name)
		shown(t, errOf(a.svc.Move(as(alice), "public/a.txt", "public/"+name)), ErrInvalidName, "a file renamed "+name)
		shown(t, errOf3(a.svc.PrepareUpload(as(alice), "public", name)), ErrInvalidName, "a resumable upload named "+name)
	}
	if names := a.names(alice, "public"); strings.Join(names, ",") != "a.txt" {
		t.Errorf("listing: %v", names)
	}
}

// A move's new name is judged apart from the folders before it, though a
// device name or a colon in it makes the whole path one Windows can't hold,
// and a stream of the reserved name makes it reserved: as a new folder's
// name, it is an invalid name.
// A folder that is such a name makes an invalid path. A path that leaves the
// root through "..", or is an absolute path of Windows, still leaves it.
func TestAMoveToADeviceOrStreamNameIsAnInvalidName(t *testing.T) {
	a := newAccessEnv(t)
	a.upload(alice, "public", "a.txt", "a")
	for _, to := range []string{"CON", "public/CON", "/public/nul", "public/sub/COM1/", "public/b/../CONIN$", "public/x.txt:hidden",
		"public/C:x", "a:b", "C:", "C:x", "/C:", `public\CON`, ".gocalbox:x", "public/.gocalbox::$DATA", "GOCALB~1:x"} {
		shown(t, errOf(a.svc.Move(as(alice), "public/a.txt", to)), ErrInvalidName, "a move to "+to)
	}
	for _, to := range []string{"public/.gocalbox", ".gocalbox::$INDEX_ALLOCATION/tmp", ".gocalbox/CON", ".gocalbox:x/CON"} {
		shown(t, errOf(a.svc.Move(as(alice), "public/a.txt", to)), sandbox.ErrReserved, "a move to "+to)
	}
	for _, to := range []string{"a:x/..", "CON/x", "public/CON/x", "public/a:b/x", "public/a:\x00"} {
		shown(t, errOf(a.svc.Move(as(alice), "public/a.txt", to)), sandbox.ErrInvalidPath, "a move to "+to)
	}
	for _, to := range []string{"..", "../", "/..", "public/../..", "../CON", "/../CON", "public/../../nul",
		"C:/", "C:/x", "C:/CON", "C:/../x", "C:/../CON", `C:\x`} {
		shown(t, errOf(a.svc.Move(as(alice), "public/a.txt", to)), sandbox.ErrTraversal, "a move to "+to)
	}
	if a.read("public/a.txt") != "a" {
		t.Errorf("the file moved: %q", a.read("public/a.txt"))
	}
}

// A path through a name Windows can't hold is an invalid path wherever it is
// read or written, decided before anything is resolved, so that it tells
// nothing about the folders on the way. An absolute path of Windows leaves
// the root, and the reserved folder stays reserved.
func TestAPathThroughADeviceNameIsAnInvalidPath(t *testing.T) {
	a := newAccessEnv(t)
	a.upload(alice, "public", "a.txt", "a")
	for _, p := range []string{"CON", "public/CON", "a:b", "public/a:b/c", "public/x.txt:hidden", "users/bob/CON"} {
		shown(t, errOf(a.svc.List(as(alice), p)), sandbox.ErrInvalidPath, "a listing of "+p)
		shown(t, errOf(a.svc.Open(as(alice), p)), sandbox.ErrInvalidPath, "a download of "+p)
		shown(t, errOf(a.svc.Delete(as(alice), p)), sandbox.ErrInvalidPath, "a delete of "+p)
		shown(t, errOf(a.svc.Move(as(alice), p, "public/b.txt")), sandbox.ErrInvalidPath, "a move from "+p)
		shown(t, errOf3(a.svc.Create(as(alice), p, "x.txt", untouched{t}, -1)), sandbox.ErrInvalidPath, "an upload into "+p)
		shown(t, errOf(a.svc.Mkdir(as(alice), p, "x")), sandbox.ErrInvalidPath, "a folder made in "+p)
		shown(t, errOf3(a.svc.PrepareUpload(as(alice), p, "x.txt")), sandbox.ErrInvalidPath, "a resumable upload into "+p)
	}
	for _, p := range []string{"C:/Windows/win.ini", `C:\Windows`, `\\server\share\CON`, "../CON"} {
		shown(t, errOf(a.svc.Open(as(alice), p)), sandbox.ErrTraversal, "a download of "+p)
	}
	shown(t, errOf(a.svc.Open(as(admin), ".gocalbox/CON")), sandbox.ErrReserved, "a download from the reserved folder")
	if names := a.names(alice, "public"); strings.Join(names, ",") != "a.txt" {
		t.Errorf("listing: %v", names)
	}
}

// A name Windows can't hold, though valid elsewhere, is refused before the
// body of a staged upload is read, by the name test.
func TestANameWindowsRefusesIsRefusedBeforeTheBody(t *testing.T) {
	a := newAccessEnv(t)
	for _, name := range []string{"a*b.txt", "a?b", "a<b", "a>b", "a|b", `a"b`} {
		shown(t, errOf3(a.svc.Create(as(alice), "public", name, untouched{t}, -1)), ErrInvalidName, "an upload named "+name)
	}
}
