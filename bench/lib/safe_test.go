package lib

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func needBash(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the shell scripts run on Linux")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
}

// safe runs safe.sh with args, with HOME set to home, and returns its output
// and whether it succeeded.
func safe(t *testing.T, home string, args ...string) (string, bool) {
	t.Helper()
	cmd := exec.Command("bash", append([]string{"safe.sh"}, args...)...)
	cmd.Env = append(os.Environ(), "HOME="+home)
	out, err := cmd.CombinedOutput()
	return string(out), err == nil
}

// run sources safe.sh in a script, with the benchmark folder dir in use.
func run(t *testing.T, dir, script string) (string, bool) {
	t.Helper()
	cmd := exec.Command("bash", "-c", `set -u; . ./safe.sh; bench_use "$1" || exit 1; `+script, "test", dir)
	out, err := cmd.CombinedOutput()
	return string(out), err == nil
}

func write(t *testing.T, p, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

func benchDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "bench")
	if out, ok := safe(t, t.TempDir(), "init", dir); !ok {
		t.Fatalf("init: %s", out)
	}
	return dir
}

func TestInitMarksANewOrEmptyFolderOnly(t *testing.T) {
	needBash(t)
	base := t.TempDir()
	home := t.TempDir()

	dir := filepath.Join(base, "new")
	if out, ok := safe(t, home, "init", dir); !ok {
		t.Fatalf("a new folder: %s", out)
	}
	mark, err := os.ReadFile(filepath.Join(dir, ".gocalbox-bench"))
	if err != nil || !regexp.MustCompile(`^gocalbox-bench [0-9a-f]{32}\n$`).Match(mark) {
		t.Fatalf("marker %q, %v", mark, err)
	}
	if out, ok := safe(t, home, "init", dir); !ok {
		t.Errorf("a benchmark folder again: %s", out)
	}
	if again, _ := os.ReadFile(filepath.Join(dir, ".gocalbox-bench")); string(again) != string(mark) {
		t.Errorf("the marker changed: %q", again)
	}

	empty := filepath.Join(base, "empty")
	os.Mkdir(empty, 0o755)
	if out, ok := safe(t, home, "init", empty); !ok {
		t.Errorf("an empty folder: %s", out)
	}

	full := filepath.Join(base, "full")
	write(t, filepath.Join(full, "keep.txt"), "mine")
	if _, ok := safe(t, home, "init", full); ok {
		t.Error("a folder holding a file was made a benchmark folder")
	}
	if exists(filepath.Join(full, ".gocalbox-bench")) {
		t.Error("the folder holding a file was marked")
	}
	hidden := filepath.Join(base, "hidden")
	write(t, filepath.Join(hidden, ".config"), "mine")
	if _, ok := safe(t, home, "init", hidden); ok {
		t.Error("a folder holding a hidden file was made a benchmark folder")
	}

	if _, ok := safe(t, home, "init", "relative/dir"); ok {
		t.Error("a relative path was accepted")
	}
	link := filepath.Join(base, "link")
	os.Symlink(filepath.Join(base, "new"), link)
	if _, ok := safe(t, home, "init", link); ok {
		t.Error("a link was accepted as the benchmark folder")
	}
	if _, ok := safe(t, home, "init", ""); ok {
		t.Error("an empty path was accepted")
	}
}

func TestOnlyAMarkedFolderIsUsed(t *testing.T) {
	needBash(t)
	base := t.TempDir()
	unmarked := filepath.Join(base, "unmarked")
	write(t, filepath.Join(unmarked, "root", "keep.txt"), "mine")
	bad := filepath.Join(base, "bad")
	write(t, filepath.Join(bad, ".gocalbox-bench"), "gocalbox-bench nothex\n")
	write(t, filepath.Join(bad, "root", "keep.txt"), "mine")
	// A marker that is a link with a short target, so its own size is small.
	shortLink := filepath.Join(base, "short-link")
	write(t, filepath.Join(shortLink, "m"), "gocalbox-bench 0123456789abcdef0123456789abcdef\n")
	os.Symlink("m", filepath.Join(shortLink, ".gocalbox-bench"))
	write(t, filepath.Join(shortLink, "root", "keep.txt"), "mine")
	extra := filepath.Join(base, "extra")
	write(t, filepath.Join(extra, ".gocalbox-bench"), "junk\ngocalbox-bench 0123456789abcdef0123456789abcdef\n")
	write(t, filepath.Join(extra, "root", "keep.txt"), "mine")
	linked := filepath.Join(base, "linked")
	os.Mkdir(linked, 0o755)
	os.Symlink(filepath.Join(benchDir(t), ".gocalbox-bench"), filepath.Join(linked, ".gocalbox-bench"))
	write(t, filepath.Join(linked, "root", "keep.txt"), "mine")
	for _, dir := range []string{unmarked, bad, extra, linked, shortLink, "", "relative"} {
		if out, ok := safe(t, base, "rm", dir, filepath.Join(dir, "root")); ok {
			t.Errorf("rm in %q: %s", dir, out)
		}
		if out, ok := safe(t, base, "empty", dir, filepath.Join(dir, "root")); ok {
			t.Errorf("empty in %q: %s", dir, out)
		}
	}
	for _, dir := range []string{unmarked, bad, extra, linked, shortLink} {
		if !exists(filepath.Join(dir, "root", "keep.txt")) {
			t.Errorf("%s: a file was deleted", dir)
		}
	}
}

func TestRmDeletesOnlyInsideTheFolder(t *testing.T) {
	needBash(t)
	dir := benchDir(t)
	outside := t.TempDir()
	write(t, filepath.Join(outside, "keep.txt"), "mine")
	home := t.TempDir()
	write(t, filepath.Join(home, "keep.txt"), "mine")

	write(t, filepath.Join(dir, "root", "a.bin"), "x")
	write(t, filepath.Join(dir, "root", "sub", "b.bin"), "x")
	if out, ok := safe(t, home, "rm", dir, filepath.Join(dir, "root", "a.bin"), filepath.Join(dir, "root", "sub")); !ok {
		t.Fatalf("rm inside: %s", out)
	}
	if exists(filepath.Join(dir, "root", "a.bin")) || exists(filepath.Join(dir, "root", "sub")) {
		t.Error("rm left what it was asked to delete")
	}
	if out, ok := safe(t, home, "rm", dir, filepath.Join(dir, "missing")); !ok {
		t.Errorf("rm of a missing path: %s", out)
	}

	os.Symlink(outside, filepath.Join(dir, "out"))
	os.Symlink(filepath.Join(outside, "keep.txt"), filepath.Join(dir, "file-link"))
	// A folder beside it whose name begins with the benchmark folder's.
	beside := dir + "-old"
	write(t, filepath.Join(beside, "keep.txt"), "mine")
	refused := []string{
		beside, filepath.Join(beside, "keep.txt"),
		"/", home, outside, filepath.Join(outside, "keep.txt"),
		filepath.Join(dir, "..", filepath.Base(outside)),
		filepath.Join(dir, "root", "..", ".."),
		dir + "/root/..", dir + "/.", dir + "/root/../..", dir + "/root/./..",
		dir, dir + "/",
		filepath.Join(dir, ".gocalbox-bench"),
		filepath.Join(dir, "out"), filepath.Join(dir, "out", "keep.txt"),
		filepath.Join(dir, "file-link"),
		"root", "",
	}
	for _, p := range refused {
		if out, ok := safe(t, home, "rm", dir, p); ok {
			t.Errorf("rm %q was allowed: %s", p, out)
		}
	}
	if out, ok := safe(t, home, "rm", dir); ok {
		t.Errorf("rm with nothing to delete: %s", out)
	}
	if !exists(filepath.Join(outside, "keep.txt")) || !exists(filepath.Join(home, "keep.txt")) || !exists(filepath.Join(beside, "keep.txt")) {
		t.Error("a file outside the benchmark folder was deleted")
	}
	if !exists(filepath.Join(dir, ".gocalbox-bench")) || !exists(filepath.Join(dir, "root")) {
		t.Error("the benchmark folder lost its marker or its contents")
	}

	// A refused path among others stops the command before what follows it.
	write(t, filepath.Join(dir, "later.bin"), "x")
	if _, ok := safe(t, home, "rm", dir, "/", filepath.Join(dir, "later.bin")); ok {
		t.Error("rm with a refused path succeeded")
	}
	if !exists(filepath.Join(dir, "later.bin")) {
		t.Error("rm went on past a refused path")
	}
}

func TestAnUnsetVariableDeletesNothing(t *testing.T) {
	needBash(t)
	dir := benchDir(t)
	write(t, filepath.Join(dir, "root", "a.bin"), "x")
	for _, script := range []string{
		`bench_rm "$UNSET/root"`,
		`bench_rm "${EMPTY:-}"`,
		`bench_empty "${EMPTY:-}"`,
		`BENCH_DIR= bench_rm "$1/root"`,
	} {
		if out, ok := run(t, dir, script); ok {
			t.Errorf("%s: %s", script, out)
		}
	}
	if !exists(filepath.Join(dir, "root", "a.bin")) {
		t.Error("a file was deleted")
	}
}

func TestEmptyKeepsHiddenEntriesAndTheFolder(t *testing.T) {
	needBash(t)
	dir := benchDir(t)
	root := filepath.Join(dir, "server", "root")
	write(t, filepath.Join(root, "a.bin"), "x")
	write(t, filepath.Join(root, "sub", "b.bin"), "x")
	write(t, filepath.Join(root, ".gocalbox", "lock"), "x")
	outside := t.TempDir()
	write(t, filepath.Join(outside, "keep.txt"), "mine")
	os.Symlink(outside, filepath.Join(root, "link"))
	if out, ok := safe(t, t.TempDir(), "empty", dir, root); !ok {
		t.Fatalf("empty: %s", out)
	}
	entries, _ := os.ReadDir(root)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if strings.Join(names, ",") != ".gocalbox" {
		t.Errorf("left %v", names)
	}
	if !exists(filepath.Join(outside, "keep.txt")) {
		t.Error("the link's target was deleted")
	}
	if out, ok := safe(t, t.TempDir(), "empty", dir, outside); ok {
		t.Errorf("empty outside: %s", out)
	}
	if out, ok := safe(t, t.TempDir(), "empty", dir, dir); ok {
		t.Errorf("empty of the folder itself: %s", out)
	}
}

// safeIn runs safe.sh from the folder cwd.
func safeIn(t *testing.T, cwd string, args ...string) (string, bool) {
	t.Helper()
	sh, _ := filepath.Abs("safe.sh")
	cmd := exec.Command("bash", append([]string{sh}, args...)...)
	cmd.Dir = cwd
	out, err := cmd.CombinedOutput()
	return string(out), err == nil
}

// init takes one absolute path to a real folder, and leaves no marker where
// it refuses; every folder it makes gets an ID of its own.
func TestInitRefusesARelativePathOrALink(t *testing.T) {
	needBash(t)
	base := t.TempDir()
	target := filepath.Join(base, "target")
	os.Mkdir(target, 0o755)
	os.Symlink(target, filepath.Join(base, "link"))
	for _, args := range [][]string{{"init", "rel"}, {"init", "target"}, {"init", filepath.Join(base, "link")}} {
		if out, ok := safeIn(t, base, args...); ok {
			t.Errorf("%v: %s", args, out)
		}
	}
	init := filepath.Join("..", "..", "bench", "init.sh")
	if out, err := exec.Command("bash", init, filepath.Join(base, "a"), filepath.Join(base, "b")).CombinedOutput(); err == nil || !strings.Contains(string(out), "usage") {
		t.Errorf("init.sh with two folders: %v, %s", err, out)
	}
	for _, p := range []string{filepath.Join(base, "rel"), filepath.Join(target, ".gocalbox-bench"), filepath.Join(base, "a"), filepath.Join(base, "b")} {
		if exists(p) {
			t.Errorf("a refused init made %s", p)
		}
	}
	one, two := benchDir(t), benchDir(t)
	a, _ := os.ReadFile(filepath.Join(one, ".gocalbox-bench"))
	b, _ := os.ReadFile(filepath.Join(two, ".gocalbox-bench"))
	if string(a) == string(b) {
		t.Errorf("two folders got the same marker %q", a)
	}
}

// The folder must be named by an absolute path that is no link, and so must
// what is deleted, even from inside the folder.
func TestRelativePathsAndLinksNameNoFolder(t *testing.T) {
	needBash(t)
	dir := benchDir(t)
	write(t, filepath.Join(dir, "root", "keep.txt"), "mine")
	parent := filepath.Dir(dir)
	os.Symlink(dir, filepath.Join(parent, "alias"))
	for _, c := range []struct {
		cwd  string
		args []string
	}{
		{parent, []string{"rm", filepath.Base(dir), filepath.Join(dir, "root")}},
		{parent, []string{"rm", filepath.Join(parent, "alias"), filepath.Join(dir, "root")}},
		{dir, []string{"rm", dir, "root"}},
		{dir, []string{"rm", dir, "./root"}},
		{parent, []string{"empty", dir, dir + "/."}},
		{parent, []string{"empty", dir, filepath.Join(dir, "root", "keep.txt")}},
	} {
		if out, ok := safeIn(t, c.cwd, c.args...); ok {
			t.Errorf("in %s, %v: %s", c.cwd, c.args, out)
		}
	}
	if !exists(filepath.Join(dir, "root", "keep.txt")) || !exists(filepath.Join(dir, ".gocalbox-bench")) {
		t.Error("a refused command deleted something")
	}
}
