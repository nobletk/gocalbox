package lib

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// marked makes a benchmark folder as bench/init.sh does, without bash.
func marked(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "bench")
	write(t, filepath.Join(dir, Mark), "gocalbox-bench 0123456789abcdef0123456789abcdef\n")
	return dir
}

func link(t *testing.T, target, name string) {
	t.Helper()
	if err := os.Symlink(target, name); err != nil {
		t.Skipf("cannot make links here: %v", err)
	}
}

func TestUseTakesOnlyAMarkedFolder(t *testing.T) {
	dir := marked(t)
	f, err := Use(dir)
	if err != nil || f.ID != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("Use: %+v, %v", f, err)
	}
	if real, _ := filepath.EvalSymlinks(dir); f.Dir != real {
		t.Errorf("Dir %s, want %s", f.Dir, real)
	}
	crlf := filepath.Join(t.TempDir(), "crlf")
	write(t, filepath.Join(crlf, Mark), "gocalbox-bench 0123456789abcdef0123456789abcdef\r\n")
	if _, err := Use(crlf); err != nil {
		t.Errorf("a marker with a Windows line end: %v", err)
	}

	base := t.TempDir()
	unmarked := filepath.Join(base, "unmarked")
	os.Mkdir(unmarked, 0o755)
	bad := filepath.Join(base, "bad")
	write(t, filepath.Join(bad, Mark), "gocalbox-bench nothex\n")
	extra := filepath.Join(base, "extra")
	write(t, filepath.Join(extra, Mark), "gocalbox-bench 0123456789abcdef0123456789abcdef\nmore\n")
	lead := filepath.Join(base, "lead")
	write(t, filepath.Join(lead, Mark), "junk\ngocalbox-bench 0123456789abcdef0123456789abcdef\n")
	upper := filepath.Join(base, "upper")
	write(t, filepath.Join(upper, Mark), "gocalbox-bench 0123456789ABCDEF0123456789ABCDEF\n")
	markDir := filepath.Join(base, "markdir")
	os.MkdirAll(filepath.Join(markDir, Mark), 0o755)
	file := filepath.Join(base, "file")
	write(t, file, "x")
	for _, d := range []string{"", "relative", unmarked, bad, extra, lead, upper, markDir, file, filepath.Join(base, "missing"), string(filepath.Separator)} {
		if _, err := Use(d); err == nil {
			t.Errorf("Use(%q) was allowed", d)
		}
	}

	linked := filepath.Join(base, "linked")
	os.Mkdir(linked, 0o755)
	link(t, filepath.Join(dir, Mark), filepath.Join(linked, Mark))
	link(t, dir, filepath.Join(base, "to-bench"))
	for _, d := range []string{linked, filepath.Join(base, "to-bench")} {
		if _, err := Use(d); err == nil {
			t.Errorf("Use(%q) was allowed", d)
		}
	}
}

func TestRemoveDeletesOnlyInsideTheFolder(t *testing.T) {
	dir := marked(t)
	f, err := Use(dir)
	if err != nil {
		t.Fatal(err)
	}
	dir = f.Dir
	outside := t.TempDir()
	write(t, filepath.Join(outside, "keep.txt"), "mine")
	home, _ := os.UserHomeDir()

	write(t, filepath.Join(dir, "root", "a.bin"), "x")
	write(t, filepath.Join(dir, "root", "sub", "b.bin"), "x")
	if err := f.Remove(filepath.Join(dir, "root", "a.bin"), filepath.Join(dir, "root", "sub")+string(filepath.Separator)); err != nil {
		t.Fatal(err)
	}
	if exists(filepath.Join(dir, "root", "a.bin")) || exists(filepath.Join(dir, "root", "sub")) {
		t.Error("Remove left what it was asked to delete")
	}
	if err := f.Remove(filepath.Join(dir, "missing")); err != nil {
		t.Errorf("a missing path: %v", err)
	}

	sep := string(filepath.Separator)
	// A folder beside it whose name begins with the benchmark folder's.
	beside := dir + "-old"
	write(t, filepath.Join(beside, "keep.txt"), "mine")
	refused := []string{
		sep, outside, filepath.Join(outside, "keep.txt"), beside, filepath.Join(beside, "keep.txt"),
		filepath.Join(dir, "..", filepath.Base(outside)),
		filepath.Join(dir, "root", "..", ".."),
		dir + sep + "root" + sep + "..", dir + sep + ".", dir + sep + "root" + sep + "." + sep + "..",
		dir, dir + sep, dir + sep + sep,
		filepath.Join(dir, Mark),
		"root", "",
	}
	if home != "" {
		refused = append(refused, home)
	}
	for _, p := range refused {
		if err := f.Remove(p); err == nil {
			t.Errorf("Remove(%q) was allowed", p)
		}
	}
	if err := f.Remove(); err == nil {
		t.Error("Remove with nothing to delete")
	}
	write(t, filepath.Join(dir, "later.bin"), "x")
	if err := f.Remove(sep, filepath.Join(dir, "later.bin")); err == nil || !exists(filepath.Join(dir, "later.bin")) {
		t.Errorf("Remove went on past a refused path: %v", err)
	}
	if !exists(filepath.Join(outside, "keep.txt")) || !exists(filepath.Join(beside, "keep.txt")) || !exists(filepath.Join(dir, Mark)) || !exists(filepath.Join(dir, "root")) {
		t.Error("Remove deleted what it refused")
	}

	link(t, outside, filepath.Join(dir, "out"))
	link(t, filepath.Join(outside, "keep.txt"), filepath.Join(dir, "file-link"))
	for _, p := range []string{filepath.Join(dir, "out"), filepath.Join(dir, "out", "keep.txt"), filepath.Join(dir, "file-link")} {
		if err := f.Remove(p); err == nil {
			t.Errorf("Remove(%q) was allowed", p)
		}
	}
	if !exists(filepath.Join(outside, "keep.txt")) {
		t.Error("a file outside the benchmark folder was deleted")
	}
}

// Links inside a folder being deleted are removed, not followed.
func TestRemoveNeverFollowsALink(t *testing.T) {
	dir := marked(t)
	f, err := Use(dir)
	if err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	write(t, filepath.Join(outside, "keep.txt"), "mine")
	root := filepath.Join(f.Dir, "load", "root")
	write(t, filepath.Join(root, "a.bin"), "x")
	link(t, outside, filepath.Join(root, "dir-link"))
	link(t, filepath.Join(outside, "keep.txt"), filepath.Join(root, "file-link"))
	if err := f.Remove(filepath.Join(f.Dir, "load")); err != nil {
		t.Fatal(err)
	}
	if exists(filepath.Join(f.Dir, "load")) {
		t.Error("the folder is still there")
	}
	if b, err := os.ReadFile(filepath.Join(outside, "keep.txt")); err != nil || string(b) != "mine" {
		t.Errorf("a link's target was touched: %q, %v", b, err)
	}
}

// The folder's links resolve before the check: a path through a link to the
// folder is inside it.
func TestAPathThroughALinkToTheFolderIsInside(t *testing.T) {
	dir := marked(t)
	f, err := Use(dir)
	if err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "alias")
	link(t, f.Dir, alias)
	write(t, filepath.Join(f.Dir, "x.bin"), "x")
	got, err := f.Inside(filepath.Join(alias, "x.bin"))
	if err != nil || got != filepath.Join(f.Dir, "x.bin") {
		t.Fatalf("Inside: %q, %v", got, err)
	}
	if err := f.Remove(filepath.Join(alias, "x.bin")); err != nil || exists(filepath.Join(f.Dir, "x.bin")) {
		t.Errorf("Remove: %v", err)
	}
	if err := f.Remove(alias); err == nil || !strings.Contains(err.Error(), "a link") {
		t.Errorf("Remove of the link itself: %v", err)
	}
}

// A marker must be a file of its own, and its ID 32 hex digits; a relative
// path names no benchmark folder, even one that has the marker.
func TestUseRefusesNearMisses(t *testing.T) {
	base := t.TempDir()
	short := filepath.Join(base, "short")
	write(t, filepath.Join(short, Mark), "gocalbox-bench 0123456789abcdef0123456789abcde\n")
	shortLink := filepath.Join(base, "short-link")
	write(t, filepath.Join(shortLink, "m"), "gocalbox-bench 0123456789abcdef0123456789abcdef\n")
	link(t, "m", filepath.Join(shortLink, Mark))
	for _, d := range []string{short, shortLink} {
		if _, err := Use(d); err == nil {
			t.Errorf("Use(%s) was allowed", d)
		}
	}
	dir := marked(t)
	t.Chdir(filepath.Dir(dir))
	if _, err := Use(filepath.Base(dir)); err == nil {
		t.Error("a relative path was taken")
	}
}

// A folder reached through a link in its parents is used by its real path,
// and paths through either spelling are inside it.
func TestAFolderReachedThroughALinkedParent(t *testing.T) {
	dir := marked(t)
	alias := filepath.Join(t.TempDir(), "alias")
	link(t, filepath.Dir(dir), alias)
	f, err := Use(filepath.Join(alias, filepath.Base(dir)))
	if err != nil {
		t.Fatal(err)
	}
	if real, _ := filepath.EvalSymlinks(dir); f.Dir != real {
		t.Errorf("Dir %s, want %s", f.Dir, real)
	}
	write(t, filepath.Join(dir, "a.bin"), "x")
	write(t, filepath.Join(dir, "b.bin"), "x")
	if err := f.Remove(filepath.Join(dir, "a.bin"), filepath.Join(alias, filepath.Base(dir), "b.bin")); err != nil {
		t.Fatal(err)
	}
	if exists(filepath.Join(dir, "a.bin")) || exists(filepath.Join(dir, "b.bin")) {
		t.Error("a file is still there")
	}
}
