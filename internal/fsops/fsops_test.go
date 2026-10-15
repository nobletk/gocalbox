package fsops

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/sandbox"
)

var bg = context.Background()

type env struct {
	t       *testing.T
	svc     *Service
	sb      *sandbox.Sandbox
	root    string
	outside string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "root")
	outside := filepath.Join(base, "outside")
	for _, d := range []string{root, outside} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("top secret"), 0o644)
	sb, err := sandbox.New(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sb.Close() })
	return &env{t: t, svc: asAdmin(New(sb, nil)), sb: sb, root: sb.Root(), outside: outside}
}

func (e *env) write(rel, content string) {
	e.t.Helper()
	p := filepath.Join(e.root, rel)
	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) read(rel string) string {
	b, err := os.ReadFile(filepath.Join(e.root, rel))
	if err != nil {
		return "<" + err.Error() + ">"
	}
	return string(b)
}

func (e *env) exists(rel string) bool {
	_, err := os.Lstat(filepath.Join(e.root, rel))
	return err == nil
}

func (e *env) symlink(target, rel string) {
	e.t.Helper()
	if err := os.Symlink(target, filepath.Join(e.root, rel)); err != nil {
		e.t.Skipf("symlinks not supported: %v", err)
	}
}

func is(t *testing.T, err, want error, what string) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Errorf("%s: err = %v, want %v", what, err, want)
	}
}

func errOf[T any](_ T, err error) error { return err }

func TestValidName(t *testing.T) {
	for name, ok := range map[string]bool{
		"a.txt": true, ".env": true, "with space": true, "ünï.txt": true, "a (1).txt": true,
		strings.Repeat("n", 255): true, strings.Repeat("é", 127): true,
		"": false, ".": false, "..": false, "a/b": false, "a\\b": false, "a\x00": false,
		"line\nbreak": false, "tab\there": false, "\x1b[31mred": false, "del\x7f": false, "c1\u0085": false,
		"  ": false, " lead": false, "trail ": false, "trail\u00a0": false,
		"evil\u202etxt.exe": false, "rtl\u200f": false, "iso\u2066x": false,
		strings.Repeat("n", 256): false, strings.Repeat("é", 128): false, "bad\xffutf8": false,
	} {
		if got := ValidName(name); got != ok {
			t.Errorf("ValidName(%q) = %v, want %v", name, got, ok)
		}
	}
}

func TestListEmptyIsNonNil(t *testing.T) {
	e := newEnv(t)
	entries, err := e.svc.List(bg, "")
	if err != nil || entries == nil || len(entries) != 0 {
		t.Errorf("List(root) = %#v, %v; want empty non-nil slice", entries, err)
	}
}

func TestList(t *testing.T) {
	e := newEnv(t)
	e.write("sub/inner.txt", "12345")
	e.write("f.txt", "x")
	e.write("b.txt", "x")

	entries, err := e.svc.List(bg, "")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	got := map[string]Entry{}
	for _, en := range entries {
		names = append(names, en.Name)
		got[en.Name] = en
	}
	if strings.Join(names, ",") != "b.txt,f.txt,sub" {
		t.Errorf("entries not sorted by name: %v", names)
	}
	if !got["sub"].IsDir || got["f.txt"].IsDir {
		t.Errorf("unexpected entries: %+v", entries)
	}

	entries, err = e.svc.List(bg, "sub")
	if err != nil || len(entries) != 1 || entries[0].Size != 5 {
		t.Errorf("List(sub) = %+v, %v", entries, err)
	}

	_, err = e.svc.List(bg, "missing")
	is(t, err, ErrNotFound, "missing dir")
	_, err = e.svc.List(bg, "f.txt")
	is(t, err, ErrNotDir, "file as dir")
	_, err = e.svc.List(bg, "../outside")
	is(t, err, sandbox.ErrTraversal, "traversal")
}

func TestListSymlinks(t *testing.T) {
	e := newEnv(t)
	e.write("docs/a.txt", "hi")
	e.symlink(filepath.Join(e.root, "docs"), "docs-link")
	e.symlink(e.outside, "escape")
	e.symlink(filepath.Join(e.outside, "secret.txt"), "escape-file")
	e.symlink(filepath.Join(e.root, "gone"), "broken")

	entries, err := e.svc.List(bg, "")
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, en := range entries {
		names[en.Name] = true
		if en.Name == "docs-link" && !en.IsDir {
			t.Error("link to directory should be listed as directory")
		}
	}
	if !names["docs-link"] || names["escape"] || names["escape-file"] || names["broken"] {
		t.Errorf("unexpected listing: %v", names)
	}

	// Absolute links inside the root work although os.Root refuses to
	// follow absolute links: operations use the canonical path.
	if entries, err := e.svc.List(bg, "docs-link"); err != nil || len(entries) != 1 {
		t.Errorf("List(docs-link) = %+v, %v", entries, err)
	}
}

func TestOpen(t *testing.T) {
	e := newEnv(t)
	e.write("docs/a.txt", "hello")
	e.symlink(e.outside, "escape")
	e.symlink(filepath.Join(e.root, "docs", "a.txt"), "alias.txt")

	for _, p := range []string{"docs/a.txt", "alias.txt"} {
		f, err := e.svc.Open(bg, p)
		if err != nil {
			t.Fatalf("Open(%s): %v", p, err)
		}
		b, _ := io.ReadAll(f.Content())
		f.Close()
		if string(b) != "hello" || f.Info().Size() != 5 {
			t.Errorf("Open(%s): content %q, size %d", p, b, f.Info().Size())
		}
	}

	for _, p := range []string{"", "docs", "nope.txt"} {
		is(t, errOf(e.svc.Open(bg, p)), ErrNotFound, "Open("+p+")")
	}
	is(t, errOf(e.svc.Open(bg, "escape/secret.txt")), sandbox.ErrTraversal, "open through escaping link")
	is(t, errOf(e.svc.Open(bg, "../outside/secret.txt")), sandbox.ErrTraversal, "open traversal")
}

func TestCreateAutoRename(t *testing.T) {
	e := newEnv(t)
	for i, want := range []string{"x.txt", "x (1).txt", "x (2).txt"} {
		got, size, err := e.svc.Create(bg, "", "x.txt", strings.NewReader(fmt.Sprint("c", i)), -1)
		if err != nil || got != want || size != 2 {
			t.Fatalf("Create #%d = %q, %d, %v; want %q", i, got, size, err, want)
		}
		if e.read(want) != fmt.Sprint("c", i) {
			t.Errorf("%s = %q", want, e.read(want))
		}
	}

	e.svc.Create(bg, "", ".env", strings.NewReader("1"), -1)
	got, _, _ := e.svc.Create(bg, "", ".env", strings.NewReader("2"), -1)
	if got != ".env (1)" {
		t.Errorf("dotfile duplicate = %q", got)
	}

	os.Mkdir(filepath.Join(e.root, "docs"), 0o755)
	if got, _, err := e.svc.Create(bg, "/x/../docs/", "n.txt", strings.NewReader(""), -1); err != nil || got != "docs/n.txt" {
		t.Errorf("Create returns canonical path: %q, %v", got, err)
	}
}

func TestCreateErrors(t *testing.T) {
	e := newEnv(t)
	e.write("file.txt", "x")
	e.symlink(e.outside, "escape")

	create := func(dir, name string) error {
		_, _, err := e.svc.Create(bg, dir, name, strings.NewReader("x"), -1)
		return err
	}
	is(t, create("", ".."), ErrInvalidName, "bad name")
	is(t, create("", "a/b"), ErrInvalidName, "name with slash")
	is(t, create("missing", "a.txt"), ErrParentNotFound, "missing dir")
	is(t, create("file.txt", "a.txt"), ErrParentNotFound, "dir is a file")
	is(t, create("../outside", "a.txt"), sandbox.ErrTraversal, "traversal")
	is(t, create("escape", "a.txt"), sandbox.ErrTraversal, "symlink escape")

	if _, err := os.Stat(filepath.Join(e.outside, "a.txt")); err == nil {
		t.Error("file was created outside the sandbox")
	}
}

type failingReader struct {
	data string
	err  error
	done bool
}

func (r *failingReader) Read(p []byte) (int, error) {
	if r.done {
		return 0, r.err
	}
	r.done = true
	return copy(p, r.data), nil
}

func TestCreateRemovesPartialFileOnError(t *testing.T) {
	e := newEnv(t)
	boom := errors.New("connection reset")

	_, _, err := e.svc.Create(bg, "", "partial.bin", &failingReader{data: "half", err: boom}, -1)
	is(t, err, boom, "reader error is propagated")
	if e.exists("partial.bin") {
		t.Error("partial file left on disk")
	}
}

func TestCreateConcurrentSameNameGetsDistinctFiles(t *testing.T) {
	e := newEnv(t)
	const n = 25

	var wg sync.WaitGroup
	names := make(chan string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name, _, err := e.svc.Create(bg, "", "same.txt", strings.NewReader(fmt.Sprint("content-", i)), -1)
			if err != nil {
				t.Error(err)
				return
			}
			names <- name
		}(i)
	}
	wg.Wait()
	close(names)

	seen := map[string]bool{}
	for name := range names {
		if seen[name] {
			t.Errorf("name %q handed out twice", name)
		}
		seen[name] = true
	}
	if len(seen) != n {
		t.Errorf("got %d distinct files, want %d", len(seen), n)
	}
}

func TestMkdir(t *testing.T) {
	e := newEnv(t)
	e.write("existing.txt", "x")
	e.symlink(e.outside, "escape")
	mkdir := func(parent, name string) error { return errOf(e.svc.Mkdir(bg, parent, name)) }

	for _, name := range []string{"", ".", "..", "a/b", "a\\b"} {
		is(t, mkdir("", name), ErrInvalidName, "name "+name)
	}
	if p, err := e.svc.Mkdir(bg, "", "docs"); err != nil || p != "docs" {
		t.Fatalf("Mkdir = %q, %v", p, err)
	}
	is(t, mkdir("", "docs"), ErrExists, "twice")
	is(t, mkdir("", "existing.txt"), ErrExists, "over file")
	if p, err := e.svc.Mkdir(bg, "./docs/", "child"); err != nil || p != "docs/child" {
		t.Fatalf("nested Mkdir = %q, %v", p, err)
	}
	is(t, mkdir("nope", "child"), ErrParentNotFound, "missing parent")
	is(t, mkdir("existing.txt", "child"), ErrParentNotFound, "parent is a file")
	is(t, mkdir("../outside", "x"), sandbox.ErrTraversal, "traversal")
	is(t, mkdir("escape", "x"), sandbox.ErrTraversal, "symlink escape")
}

func TestDelete(t *testing.T) {
	e := newEnv(t)
	e.write("dir/inner.txt", "I")
	e.write("f.txt", "F")
	e.symlink(e.outside, "dirlink")
	e.symlink(filepath.Join(e.outside, "secret.txt"), "filelink")
	del := func(p string) error { return errOf(e.svc.Delete(bg, p)) }

	is(t, del("missing"), ErrNotFound, "missing")
	is(t, del("../outside/secret.txt"), sandbox.ErrTraversal, "traversal")
	is(t, del("dirlink/secret.txt"), sandbox.ErrTraversal, "through link")
	for _, root := range []string{"", ".", "/", "dir/.."} {
		is(t, del(root), sandbox.ErrRootTarget, "root as "+root)
	}
	if !e.exists("f.txt") || !e.exists("dir/inner.txt") {
		t.Fatal("rejected deletes must not touch anything")
	}

	for _, p := range []string{"dir", "f.txt", "dirlink", "filelink"} {
		if got, err := e.svc.Delete(bg, p); err != nil || got != p {
			t.Errorf("Delete(%s) = %q, %v", p, got, err)
		}
		if e.exists(p) {
			t.Errorf("%s still exists", p)
		}
	}
	if _, err := os.Stat(filepath.Join(e.outside, "secret.txt")); err != nil {
		t.Error("deleting symlinks removed the target outside the sandbox")
	}
}

func TestMove(t *testing.T) {
	e := newEnv(t)
	e.write("a.txt", "A")
	e.write("b.txt", "B")
	e.write("dir/inner.txt", "I")
	os.Mkdir(filepath.Join(e.root, "target"), 0o755)
	e.symlink(e.outside, "escape")
	move := func(from, to string) error { return errOf(e.svc.Move(bg, from, to)) }

	is(t, move("a.txt", "b.txt"), ErrExists, "onto existing")
	if e.read("b.txt") != "B" {
		t.Errorf("b.txt overwritten: %q", e.read("b.txt"))
	}
	is(t, move("a.txt", "a.txt"), ErrExists, "onto itself")
	is(t, move("dir", "dir/sub"), ErrMoveIntoSelf, "into itself")
	is(t, move("nope", "x"), ErrNotFound, "missing source")
	is(t, move("a.txt", "missing/a.txt"), ErrParentNotFound, "missing target folder")
	is(t, move("a.txt", "b.txt/a.txt"), ErrParentNotFound, "parent is a file")
	is(t, move("", "x"), sandbox.ErrRootTarget, "root as source")
	is(t, move("a.txt", ""), sandbox.ErrRootTarget, "root as destination")
	is(t, move("a.txt", "../a.txt"), sandbox.ErrTraversal, "move out")
	is(t, move("a.txt", "escape/a.txt"), sandbox.ErrTraversal, "move through link")
	is(t, move("../outside/secret.txt", "s.txt"), sandbox.ErrTraversal, "move in")

	if got, err := e.svc.Move(bg, "a.txt", "renamed.txt"); err != nil || got != "renamed.txt" {
		t.Fatalf("rename = %q, %v", got, err)
	}
	if got, err := e.svc.Move(bg, "renamed.txt", "/target//renamed.txt"); err != nil || got != "target/renamed.txt" {
		t.Fatalf("move = %q, %v", got, err)
	}
	if err := move("dir", "target/dir"); err != nil {
		t.Fatal(err)
	}
	if !e.exists("target/dir/inner.txt") || !e.exists("target/renamed.txt") || e.exists("a.txt") {
		t.Error("files not where expected after moves")
	}
}

func TestConcurrentMovesToSameDestinationOnlyOneWins(t *testing.T) {
	e := newEnv(t)
	const n = 20
	for i := 0; i < n; i++ {
		e.write(fmt.Sprintf("src%d.txt", i), fmt.Sprint("content-", i))
	}

	var wg sync.WaitGroup
	var wins, conflicts atomic.Int32
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			switch _, err := e.svc.Move(bg, fmt.Sprintf("src%d.txt", i), "dest.txt"); {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, ErrExists):
				conflicts.Add(1)
			default:
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()

	if wins.Load() != 1 || conflicts.Load() != n-1 {
		t.Errorf("wins=%d conflicts=%d, want 1 and %d", wins.Load(), conflicts.Load(), n-1)
	}
	remaining := 0
	for i := 0; i < n; i++ {
		if e.exists(fmt.Sprintf("src%d.txt", i)) {
			remaining++
		}
	}
	if remaining != n-1 {
		t.Errorf("%d sources remain, want %d (something was overwritten)", remaining, n-1)
	}
}

func TestMoveNeverReplacesAFolderCreatedConcurrently(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < 300; i++ {
		e.write("src/f.txt", "x")
		var wg sync.WaitGroup
		var mkErr, mvErr error
		wg.Add(2)
		go func() { defer wg.Done(); _, mkErr = e.svc.Mkdir(bg, "", "dst") }()
		go func() { defer wg.Done(); _, mvErr = e.svc.Move(bg, "src", "dst") }()
		wg.Wait()
		if mkErr == nil && mvErr == nil {
			t.Fatalf("round %d: both Mkdir and Move succeeded, so one replaced the other", i)
		}
		os.RemoveAll(filepath.Join(e.root, "src"))
		os.RemoveAll(filepath.Join(e.root, "dst"))
	}
}

func TestPathsThroughFilesAndLinkLoopsAreNotInternalErrors(t *testing.T) {
	e := newEnv(t)
	e.write("a.txt", "x")
	e.symlink("loop-b", "loop-a")
	e.symlink("loop-a", "loop-b")

	is(t, errOf(e.svc.List(bg, "a.txt/x")), ErrNotFound, "list through a file")
	is(t, errOf(e.svc.Open(bg, "a.txt/x")), ErrNotFound, "open through a file")
	is(t, errOf(e.svc.Delete(bg, "a.txt/x")), ErrNotFound, "delete through a file")
	is(t, errOf(e.svc.Move(bg, "a.txt/x", "y")), ErrNotFound, "move through a file")
	is(t, errOf(e.svc.Mkdir(bg, "a.txt", "x")), ErrParentNotFound, "mkdir in a file")
	for _, p := range []string{"loop-a", "loop-a/x"} {
		is(t, errOf(e.svc.Open(bg, p)), sandbox.ErrBrokenLink, "open "+p)
		is(t, errOf(e.svc.List(bg, p)), sandbox.ErrBrokenLink, "list "+p)
	}
}

func TestMoveValidatesTheNewName(t *testing.T) {
	e := newEnv(t)
	e.write("a.txt", "x")

	for _, dst := range []string{"b\nc.txt", `b\c.txt`, `d/b\c.txt`, " lead.txt", strings.Repeat("n", 256)} {
		_, err := e.svc.Move(bg, "a.txt", dst)
		is(t, err, ErrInvalidName, fmt.Sprintf("move to %q", dst))
	}
	if !e.exists("a.txt") {
		t.Fatal("a rejected move moved the file")
	}
	// Windows file names can't contain a newline, so no such legacy name
	// exists there.
	if runtime.GOOS == "windows" {
		return
	}
	// A name that predates the rules can still be fixed by renaming it.
	e.write("old\nname.txt", "legacy")
	if _, err := e.svc.Move(bg, "old\nname.txt", "fixed.txt"); err != nil {
		t.Errorf("renaming a legacy name: %v", err)
	}
}

func TestAutoRenameKeepsLongNamesWithinTheLimit(t *testing.T) {
	e := newEnv(t)
	for _, name := range []string{strings.Repeat("x", 251) + ".txt", strings.Repeat("é", 125) + ".txt"} {
		var stored []string
		for i := 0; i < 3; i++ {
			rel, _, err := e.svc.Create(bg, "", name, strings.NewReader("x"), -1)
			if err != nil {
				t.Fatalf("upload %d of a %d-byte name: %v", i+1, len(name), err)
			}
			stored = append(stored, rel)
		}
		for i, rel := range stored[1:] {
			if len(rel) > maxNameBytes || !ValidName(rel) || !strings.HasSuffix(rel, fmt.Sprintf(" (%d).txt", i+1)) {
				t.Errorf("duplicate %d stored as %q (%d bytes)", i+1, rel, len(rel))
			}
		}
	}
}

func TestAutoRenameGivesUpWithErrExists(t *testing.T) {
	defer func(n int) { maxAutoRename = n }(maxAutoRename)
	maxAutoRename = 3
	e := newEnv(t)
	for i := 0; i < 3; i++ {
		if _, _, err := e.svc.Create(bg, "", "a.txt", strings.NewReader("x"), -1); err != nil {
			t.Fatal(err)
		}
	}
	_, _, err := e.svc.Create(bg, "", "a.txt", strings.NewReader("x"), -1)
	is(t, err, ErrExists, "fourth upload with three variants allowed")

	_, _, err = e.svc.Create(bg, "", "b."+strings.Repeat("e", 252), strings.NewReader("x"), -1)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = e.svc.Create(bg, "", "b."+strings.Repeat("e", 252), strings.NewReader("x"), -1)
	is(t, err, ErrExists, "duplicate whose extension leaves no room for a number")
}

func TestOverlongPathsAreInvalidNotInternal(t *testing.T) {
	e := newEnv(t)
	long := strings.Repeat("n", 300)
	_, err := e.svc.Open(bg, long)
	is(t, err, sandbox.ErrInvalidPath, "open")
	_, err = e.svc.List(bg, long+"/x")
	is(t, err, sandbox.ErrInvalidPath, "list")
	_, err = e.svc.Delete(bg, long)
	is(t, err, sandbox.ErrInvalidPath, "delete")
}

func TestNamesTheFileSystemRefusesAreInvalid(t *testing.T) {
	err := nameErr(&fs.PathError{Op: "openat", Path: "x", Err: syscall.ENAMETOOLONG})
	is(t, err, ErrInvalidName, "ENAMETOOLONG")
	if outcomeOf(err) != events.OutcomeInvalid {
		t.Errorf("outcome = %s", outcomeOf(err))
	}
	other := errors.New("disk on fire")
	if nameErr(other) != other {
		t.Error("unrelated error changed")
	}
}
