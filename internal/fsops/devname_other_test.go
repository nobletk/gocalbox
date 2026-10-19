//go:build !windows

package fsops

import (
	"strings"
	"testing"
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
