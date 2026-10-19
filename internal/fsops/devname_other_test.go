//go:build !windows

package fsops

import (
	"strings"
	"testing"

	"github.com/nobletk/gocalbox/internal/sandbox"
)

// Names that are devices or streams only on Windows are names like any
// other elsewhere.
func TestWindowsDeviceNamesAreNamesElsewhere(t *testing.T) {
	a := newAccessEnv(t)
	for _, name := range []string{"CON", "NUL", "COM1", "a:b"} {
		if !ValidName(name) {
			t.Errorf("ValidName(%q) = false", name)
		}
		a.upload(alice, "public", name, "x")
		if a.read("public/"+name) != "x" {
			t.Errorf("the upload named %q: %q", name, a.read("public/"+name))
		}
	}
	if left := a.tmp(); len(left) != 0 {
		t.Errorf("the staging folder holds %s", strings.Join(left, ", "))
	}
}

// Elsewhere a move to such a name is a move like any other, and a path that
// leaves the root through its folders still leaves it.
func TestAMoveToAWindowsDeviceNameIsAMoveElsewhere(t *testing.T) {
	a := newAccessEnv(t)
	a.upload(alice, "public", "a.txt", "a")
	for _, to := range []string{"public/CON", "public/x.txt:hidden"} {
		ok(t, errOf(a.svc.Move(as(alice), "public/a.txt", to)), "a move to "+to)
		if a.read(to) != "a" {
			t.Errorf("the file moved to %s: %q", to, a.read(to))
		}
		ok(t, errOf(a.svc.Move(as(alice), to, "public/a.txt")), "a move back from "+to)
	}
	for _, to := range []string{"..", "../", "/..", "public/../..", "../CON", "/../CON", "public/../../nul"} {
		shown(t, errOf(a.svc.Move(as(alice), "public/a.txt", to)), sandbox.ErrTraversal, "a move to "+to)
	}
	shown(t, errOf(a.svc.Move(as(alice), "public/a.txt", `public/a\b`)), ErrInvalidName, "a move to a name with a backslash")
}
