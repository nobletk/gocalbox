package sandbox

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestReservedNameAtAnyDepth(t *testing.T) {
	sb, root, _ := setup(t)
	os.Mkdir(filepath.Join(root, ReservedName), 0o700)
	for _, p := range []string{
		".gocalbox", "/.gocalbox/trash", "docs/.gocalbox", "docs/.GoCalBox/x", "a/b/.GOCALBOX",
		"docs/../.gocalbox", ".gocalbox/../docs/../.gocalbox/x",
		".gocalbox./trash", "docs/.gocalbox ", "GOCALB~1/trash", "docs/gocalb~2/x",
	} {
		if _, err := sb.Resolve(p); !errors.Is(err, ErrReserved) {
			t.Errorf("Resolve(%q) err = %v", p, err)
		}
		if _, err := sb.ResolveEntry(p); !errors.Is(err, ErrReserved) {
			t.Errorf("ResolveEntry(%q) err = %v", p, err)
		}
		if _, err := Clean(p); !errors.Is(err, ErrReserved) {
			t.Errorf("Clean(%q) err = %v", p, err)
		}
	}
	for _, p := range []string{"docs/gocalbox", "docs/.gocalbox2", "docs/x.gocalbox", ".gocalbox/.."} {
		if _, err := sb.Resolve(p); err != nil {
			t.Errorf("Resolve(%q): %v", p, err)
		}
	}

	mustSymlink(t, filepath.Join(root, ReservedName), filepath.Join(root, "docs", "staging"))
	if _, err := sb.Resolve("docs/staging/x"); !errors.Is(err, ErrReserved) {
		t.Errorf("a symlink into the reserved folder: %v", err)
	}
	if _, err := sb.ResolveEntry("docs/staging/x"); !errors.Is(err, ErrReserved) {
		t.Errorf("an entry below a symlink into the reserved folder: %v", err)
	}
	if p, err := sb.ResolveEntry("docs/staging"); err != nil || p.Rel != "docs/staging" {
		t.Errorf("the symlink itself: %+v, %v", p, err)
	}
}

func TestIsReserved(t *testing.T) {
	for name, want := range map[string]bool{
		".gocalbox": true, ".GOCALBOX": true, ".GoCalbox": true,
		".gocalbox.": true, ".gocalbox ": true, ".gocalbox. .": true,
		"GOCALB~1": true, "gocalb~12": true, "GoCalB~3.": true,
		"gocalbox": false, ".gocalbox2": false, " .gocalbox": false, "..gocalbox": false, "": false,
		"GOCALB~": false, "GOCALB~1a": false, "GOCALB~1.txt": false, "XGOCALB~1": false, "GOCAL~1": false,
	} {
		if got := IsReserved(name); got != want {
			t.Errorf("IsReserved(%q) = %v", name, got)
		}
	}
}

func TestCleanReadsNothing(t *testing.T) {
	for in, want := range map[string]string{"": ".", "/": ".", "/a//b/./c/": "a/b/c", "a/../b": "b"} {
		if got, err := Clean(in); err != nil || got != want {
			t.Errorf("Clean(%q) = %q, %v", in, got, err)
		}
	}
	for in, want := range map[string]error{"../x": ErrTraversal, "a/../../x": ErrTraversal, "a\x00": ErrInvalidPath} {
		if _, err := Clean(in); !errors.Is(err, want) {
			t.Errorf("Clean(%q) err = %v, want %v", in, err, want)
		}
	}
}
