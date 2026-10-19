package fsops

import (
	"strings"
	"testing"
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

// A name Windows can't hold, though valid elsewhere, is refused before the
// body of a staged upload is read, by the name test.
func TestANameWindowsRefusesIsRefusedBeforeTheBody(t *testing.T) {
	a := newAccessEnv(t)
	for _, name := range []string{"a*b.txt", "a?b", "a<b", "a>b", "a|b", `a"b`} {
		shown(t, errOf3(a.svc.Create(as(alice), "public", name, untouched{t}, -1)), ErrInvalidName, "an upload named "+name)
	}
}
