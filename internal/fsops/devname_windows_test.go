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

// A move's new name is judged apart from the folders before it: a device
// name or a colon makes the whole path one that leaves the root. A path that
// leaves the root through its folders stays one.
func TestAMoveToADeviceOrStreamNameIsAnInvalidName(t *testing.T) {
	a := newAccessEnv(t)
	a.upload(alice, "public", "a.txt", "a")
	for _, to := range []string{"CON", "public/CON", "/public/nul", "public/sub/COM1/", "public/b/../CONIN$", "public/x.txt:hidden", "public/C:x", "a:b", "C:", "C:x", "/C:"} {
		shown(t, errOf(a.svc.Move(as(alice), "public/a.txt", to)), ErrInvalidName, "a move to "+to)
	}
	for _, to := range []string{"..", "../", "/..", "public/../..", "../CON", "/../CON", "public/../../nul", "C:/x", "C:/CON", "C:/../x", `public\CON`} {
		shown(t, errOf(a.svc.Move(as(alice), "public/a.txt", to)), sandbox.ErrTraversal, "a move to "+to)
	}
	shown(t, errOf(a.svc.Move(as(alice), "public/a.txt", "a:x/..")), sandbox.ErrTraversal, "a move to a:x/..")
	shown(t, errOf(a.svc.Move(as(alice), "public/a.txt", "public/a:\x00")), sandbox.ErrInvalidPath, "a move to a name with a NUL")
	if a.read("public/a.txt") != "a" {
		t.Errorf("the file moved: %q", a.read("public/a.txt"))
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
