//go:build !windows

package sandbox

import (
	"errors"
	"testing"
)

// Names Windows can't hold are names like any other elsewhere, a stream
// spelling of the reserved name is another name, and a path that leaves the
// root through ".." still leaves it.
func TestWindowsNamesAreNamesElsewhere(t *testing.T) {
	for _, p := range []string{"CON", "public/CON", "a:b/c", "C:", "C:/x", "C:x", `a\CON`, "public/x.txt:s", "a:x/.."} {
		if _, err := Clean(p); err != nil {
			t.Errorf("Clean(%q): %v", p, err)
		}
	}
	for _, p := range []string{"..", "../CON", "/../CON", "a:b/../../x", "C:/../.."} {
		if _, err := Clean(p); !errors.Is(err, ErrTraversal) {
			t.Errorf("Clean(%q) = %v, want ErrTraversal", p, err)
		}
	}
	if IsReserved(".gocalbox:x") {
		t.Error(`IsReserved(".gocalbox:x") = true`)
	}
	for _, p := range []string{"//CON", "//public/a:b"} {
		if _, err := Clean(p); err != nil {
			t.Errorf("Clean(%q): %v", p, err)
		}
	}
}
