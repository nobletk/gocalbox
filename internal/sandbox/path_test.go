package sandbox

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mustSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks not supported: %v", err)
	}
}

func setup(t *testing.T) (sb *Sandbox, root, outside string) {
	t.Helper()
	base := t.TempDir()
	root = filepath.Join(base, "root")
	outside = filepath.Join(base, "outside")
	for _, d := range []string{root, filepath.Join(root, "docs"), outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("s"), 0o644); err != nil {
		t.Fatal(err)
	}
	sb, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sb.Close() })
	return sb, sb.Root(), outside
}

func TestResolveTraversal(t *testing.T) {
	sb, _, _ := setup(t)
	for _, p := range []string{"..", "../", "../x", "docs/../../x", "a/b/../../../x", "/../x", "..\\..", "docs/../.."} {
		if p == "..\\.." && filepath.Separator == '/' {
			continue // backslash is an ordinary character on Unix
		}
		if _, err := sb.Resolve(p); !errors.Is(err, ErrTraversal) {
			t.Errorf("Resolve(%q) err = %v, want ErrTraversal", p, err)
		}
		if _, err := sb.ResolveEntry(p); !errors.Is(err, ErrTraversal) {
			t.Errorf("ResolveEntry(%q) err = %v, want ErrTraversal", p, err)
		}
	}
}

func TestResolveValid(t *testing.T) {
	sb, root, _ := setup(t)
	cases := map[string]string{
		"":                  ".",
		".":                 ".",
		"/":                 ".",
		"docs":              "docs",
		"/docs":             "docs",
		"docs/new/deep.txt": "docs/new/deep.txt", // does not exist yet
		"docs/../docs":      "docs",
		"./docs//x/.":       "docs/x",
		"/etc/passwd":       "etc/passwd", // absolute means relative to the root
	}
	for in, rel := range cases {
		got, err := sb.Resolve(in)
		if err != nil || got.Rel != rel || got.Abs != filepath.Join(root, filepath.FromSlash(rel)) {
			t.Errorf("Resolve(%q) = %+v, %v; want Rel %q", in, got, err, rel)
		}
	}
}

func TestCanonicalPathIsTheSameForEverySpelling(t *testing.T) {
	sb, root, _ := setup(t)
	mustSymlink(t, filepath.Join(root, "docs"), filepath.Join(root, "alias"))
	mustSymlink(t, "docs", filepath.Join(root, "relalias"))

	for _, p := range []string{"docs/a.txt", "/docs/a.txt", "x/../docs/a.txt", "alias/a.txt", "relalias/a.txt", "alias/../docs/a.txt"} {
		got, err := sb.Resolve(p)
		if err != nil || got.Rel != "docs/a.txt" {
			t.Errorf("Resolve(%q) = %+v, %v; want Rel docs/a.txt", p, got, err)
		}
	}
	// An entry is named by its own location, not its target's.
	if got, err := sb.ResolveEntry("alias"); err != nil || got.Rel != "alias" {
		t.Errorf("ResolveEntry(alias) = %+v, %v", got, err)
	}
	if got, err := sb.ResolveEntry("alias/new.txt"); err != nil || got.Rel != "docs/new.txt" {
		t.Errorf("ResolveEntry(alias/new.txt) = %+v, %v", got, err)
	}
}

func TestPathContains(t *testing.T) {
	p := func(rel string) Path { return Path{Rel: rel} }
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{".", "x", true},
		{".", ".", true},
		{"docs", "docs", true},
		{"docs", "docs/a", true},
		{"docs", "docsx", false},
		{"docs/a", "docs", false},
	} {
		if got := p(tc.a).Contains(p(tc.b)); got != tc.want {
			t.Errorf("%q.Contains(%q) = %v", tc.a, tc.b, got)
		}
	}
}

func TestNewWithRelativeRootDot(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)

	sb, err := New(".")
	if err != nil {
		t.Fatal(err)
	}
	defer sb.Close()
	got, err := sb.Resolve("sub")
	if err != nil || got.Abs != filepath.Join(sb.Root(), "sub") {
		t.Errorf("Resolve(sub) with root '.' = %+v, %v", got, err)
	}
}

func TestNewRejectsFileAndMissing(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "f")
	os.WriteFile(f, nil, 0o644)
	if _, err := New(f); err == nil {
		t.Error("New(file) should fail")
	}
	if _, err := New(filepath.Join(dir, "missing")); err == nil {
		t.Error("New(missing) should fail")
	}
}

func TestResolveEntryRejectsRoot(t *testing.T) {
	sb, _, _ := setup(t)
	for _, p := range []string{"", ".", "/", "docs/..", "./"} {
		if _, err := sb.ResolveEntry(p); !errors.Is(err, ErrRootTarget) {
			t.Errorf("ResolveEntry(%q) err = %v, want ErrRootTarget", p, err)
		}
	}
}

func TestSymlinkEscape(t *testing.T) {
	sb, root, outside := setup(t)
	mustSymlink(t, outside, filepath.Join(root, "dirlink"))
	mustSymlink(t, filepath.Join(outside, "secret.txt"), filepath.Join(root, "filelink"))
	mustSymlink(t, filepath.Join(outside, "new"), filepath.Join(root, "dangling"))
	mustSymlink(t, filepath.Join(root, "docs"), filepath.Join(root, "inside"))

	for _, p := range []string{"dirlink", "dirlink/secret.txt", "dirlink/new/file", "filelink", "docs/../dirlink"} {
		if _, err := sb.Resolve(p); !errors.Is(err, ErrTraversal) {
			t.Errorf("Resolve(%q) err = %v, want ErrTraversal", p, err)
		}
	}
	for _, p := range []string{"dangling", "dangling/x"} {
		if _, err := sb.Resolve(p); !errors.Is(err, ErrBrokenLink) {
			t.Errorf("Resolve(%q) err = %v, want ErrBrokenLink", p, err)
		}
	}
	if _, err := sb.ResolveEntry("dangling"); err != nil {
		t.Errorf("ResolveEntry(dangling): %v", err)
	}
	for _, p := range []string{"dirlink/secret.txt", "dirlink/new"} {
		if _, err := sb.ResolveEntry(p); !errors.Is(err, ErrTraversal) {
			t.Errorf("ResolveEntry(%q) err = %v, want ErrTraversal", p, err)
		}
	}
	if got, err := sb.Resolve("inside"); err != nil || got.Rel != "docs" {
		t.Errorf("Resolve(inside) = %+v, %v", got, err)
	}
}

func TestResolveEntryDoesNotFollowLeafSymlink(t *testing.T) {
	sb, root, outside := setup(t)
	mustSymlink(t, outside, filepath.Join(root, "dirlink"))

	got, err := sb.ResolveEntry("dirlink")
	if err != nil {
		t.Fatalf("ResolveEntry(dirlink): %v", err)
	}
	if got.Abs != filepath.Join(root, "dirlink") || got.Rel != "dirlink" {
		t.Errorf("got %+v", got)
	}
}

func TestSymlinkedRootIsResolved(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	os.Mkdir(real, 0o755)
	os.Mkdir(filepath.Join(real, "docs"), 0o755)
	link := filepath.Join(base, "link")
	mustSymlink(t, real, link)

	sb, err := New(link)
	if err != nil {
		t.Fatal(err)
	}
	defer sb.Close()
	if _, err := sb.Resolve("docs"); err != nil {
		t.Errorf("Resolve(docs) through symlinked root: %v", err)
	}
}

func TestNulByte(t *testing.T) {
	sb, _, _ := setup(t)
	if _, err := sb.Resolve("a\x00b"); !errors.Is(err, ErrInvalidPath) {
		t.Errorf("err = %v, want ErrInvalidPath", err)
	}
}

// os.Root re-checks containment at the moment of each operation, so a folder
// replaced by an escaping symlink after validation is still refused.
func TestOSRootRefusesSymlinkSwappedInAfterValidation(t *testing.T) {
	sb, root, outside := setup(t)
	p, err := sb.Resolve("docs/secret.txt")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "docs")); err != nil {
		t.Fatal(err)
	}
	mustSymlink(t, outside, filepath.Join(root, "docs"))

	f, err := sb.OSRoot().Open(p.Native())
	if err == nil {
		f.Close()
		t.Fatal("opened a file outside the root through a swapped-in symlink")
	}
	// Guards FromRoot against a change of os.Root's error text.
	if !errors.Is(FromRoot(err), ErrTraversal) {
		t.Errorf("FromRoot(%v) is not ErrTraversal", err)
	}
	if err := FromRoot(os.ErrNotExist); err != os.ErrNotExist {
		t.Errorf("FromRoot changed an unrelated error: %v", err)
	}
}

func TestWithin(t *testing.T) {
	sep := string(filepath.Separator)
	base := sep + "a" + sep + "b"
	for target, want := range map[string]bool{
		base:                                 true,
		base + sep + "c":                     true,
		sep + "a" + sep + "bc":               false, // sibling sharing a prefix
		sep + "a":                            false,
		sep + "x":                            false,
		base + sep + ".." + sep + "x":        false,
		base + sep + "..hidden":              true,
		base + sep + "c" + sep + ".." + "..": true,
	} {
		if got := Within(base, filepath.Clean(target)); got != want {
			t.Errorf("Within(%q, %q) = %v, want %v", base, target, got, want)
		}
	}
}

func TestOverlongPathsAreInvalid(t *testing.T) {
	root := t.TempDir()
	os.Mkdir(filepath.Join(root, "a"), 0o755)
	sb, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer sb.Close()
	long := strings.Repeat("n", 300)
	for _, p := range []string{long, long + "/x", "a/" + long} {
		if _, err := sb.Resolve(p); !errors.Is(err, ErrInvalidPath) {
			t.Errorf("Resolve(%d bytes): %v, want ErrInvalidPath", len(p), err)
		}
		if _, err := sb.ResolveEntry(p + "/y"); !errors.Is(err, ErrInvalidPath) {
			t.Errorf("ResolveEntry(%d bytes): %v, want ErrInvalidPath", len(p), err)
		}
	}
}

func TestResolveExisting(t *testing.T) {
	base, _ := filepath.EvalSymlinks(t.TempDir())
	real := filepath.Join(base, "real")
	os.Mkdir(real, 0o755)
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks not supported: %v", err)
	}
	for in, want := range map[string]string{
		filepath.Join(link, "a", "b"): filepath.Join(real, "a", "b"),
		filepath.Join(real, "a"):      filepath.Join(real, "a"),
		link:                          real,
		filepath.Join(base, "x", "y"): filepath.Join(base, "x", "y"),
	} {
		if got, err := ResolveExisting(in); err != nil || got != want {
			t.Errorf("ResolveExisting(%s) = %s, %v; want %s", in, got, err, want)
		}
	}
}
