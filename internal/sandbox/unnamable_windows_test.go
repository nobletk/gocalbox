package sandbox

import (
	"errors"
	"testing"
)

// A path that stays in the root but names what Windows can't hold, a device
// or a name with a colon, is an invalid path, not one that leaves the root.
// A path that leaves through ".." or is an absolute path of Windows still
// leaves it, and one into the reserved folder is still reserved.
func TestAnUnnamablePathIsInvalidNotOutside(t *testing.T) {
	sb, _, _ := setup(t)
	for p, want := range map[string]error{
		"CON": ErrUnnamable, "public/CON": ErrUnnamable, "/public/nul": ErrUnnamable, "CON/x": ErrUnnamable,
		"a/CONIN$/b": ErrUnnamable, "a:b": ErrUnnamable, "a:b/c": ErrUnnamable, "C:": ErrUnnamable,
		"C:x": ErrUnnamable, "/C:": ErrUnnamable, "public/x.txt:s": ErrUnnamable, "a:x/..": ErrUnnamable,
		`a\CON`: ErrUnnamable,

		"..": ErrTraversal, "../CON": ErrTraversal, "/../CON": ErrTraversal, "a/../../CON": ErrTraversal,
		`..\CON`: ErrTraversal, "a:b/../../x": ErrTraversal, "C:/": ErrTraversal, "C:/x": ErrTraversal,
		`C:\x`: ErrTraversal, "/C:/x": ErrTraversal, "C:/../CON": ErrTraversal, `\\server\share\CON`: ErrTraversal,
		`/\server\CON`: ErrTraversal, `\\?\C:\x`: ErrTraversal, "//?/C:/x": ErrTraversal, `\\.\COM1`: ErrTraversal,
		"//./COM1": ErrTraversal, `\??\C:\x`: ErrTraversal, "/??/C:/x": ErrTraversal, `\/server/CON`: ErrTraversal,
		`\\:`: ErrTraversal, "../.gocalbox/CON": ErrTraversal,

		// Leading separators are read as the root, as for any path: two
		// slashes before a name are no share.
		"//:": ErrUnnamable, "//CON": ErrUnnamable, "//public/CON": ErrUnnamable, "///public/x:y": ErrUnnamable, "//server/share/CON": ErrUnnamable,
		// A drive counts only at the start, followed by a separator.
		"./C:/x": ErrUnnamable, "a/../C:/x": ErrUnnamable, "C:..": ErrUnnamable, "C:./x": ErrUnnamable,

		".gocalbox/CON": ErrReserved, "public/.gocalbox/nul": ErrReserved, ".gocalbox::$INDEX_ALLOCATION/tmp": ErrReserved,
		".gocalbox:$I30:$INDEX_ALLOCATION/tmp": ErrReserved, "GOCALB~1::$INDEX_ALLOCATION/uploads": ErrReserved,
		".gocalbox:x": ErrReserved, ".GoCalBox. :x/y": ErrReserved,
	} {
		_, err := Clean(p)
		_, rerr := sb.Resolve(p)
		_, eerr := sb.ResolveEntry(p)
		for _, e := range []error{err, rerr, eerr} {
			if !errors.Is(e, want) {
				t.Errorf("%q: err = %v, want %v", p, e, want)
			}
			if want == ErrTraversal && errors.Is(e, ErrInvalidPath) {
				t.Errorf("%q: err = %v is also an invalid path", p, e)
			}
		}
	}
	for _, name := range []string{".gocalbox::$INDEX_ALLOCATION", "GOCALB~1:x", ".gocalbox. :s"} {
		if !IsReserved(name) {
			t.Errorf("IsReserved(%q) = false", name)
		}
	}
	if !errors.Is(ErrUnnamable, ErrInvalidPath) {
		t.Error("ErrUnnamable isn't an invalid path")
	}
}
