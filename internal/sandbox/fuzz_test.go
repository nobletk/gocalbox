package sandbox

import (
	"errors"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
)

// fuzzFixture builds a root full of symlink traps: inside, escaping (absolute
// and relative), dangling, looping and pointing at the root's parent.
func fuzzFixture(f *testing.F) (sb *Sandbox, root string) {
	base := f.TempDir()
	rootDir := filepath.Join(base, "root")
	outside := filepath.Join(base, "outside")

	for _, d := range []string{
		filepath.Join(rootDir, "docs", "sub"),
		filepath.Join(rootDir, "deep", "er", "est"),
		outside,
	} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			f.Fatal(err)
		}
	}
	os.WriteFile(filepath.Join(rootDir, "docs", "file.txt"), []byte("in"), 0o644)
	os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("out"), 0o644)

	links := map[string]string{
		"link-in":     filepath.Join(rootDir, "docs"), // inside, absolute
		"link-in-rel": "docs/sub",                     // inside, relative
		"escape":      outside,                        // outside, absolute
		"escape-file": filepath.Join(outside, "secret.txt"),
		"rel-escape":  "../outside",                   // outside, relative
		"up":          "..",                           // the root's parent
		"dangling":    filepath.Join(outside, "nope"), // target does not exist
		"loop-a":      "loop-b",
		"loop-b":      "loop-a",
		"docs/back":   "../..", // from inside a folder to the root's parent
		"deep/er/out": "../../../../outside",
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(rootDir, name)); err != nil {
			f.Skipf("symlinks not supported: %v", err)
		}
	}

	sb, err := New(rootDir)
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { sb.Close() })
	return sb, sb.Root()
}

// lexicallyEscapes is an oracle independent of the implementation: does p,
// read relative to the root, climb above it with "..".
func lexicallyEscapes(p string) bool {
	depth := 0
	for _, seg := range strings.Split(strings.TrimLeft(p, "/"), "/") {
		switch seg {
		case "", ".":
		case "..":
			depth--
			if depth < 0 {
				return true
			}
		default:
			depth++
		}
	}
	return false
}

// realPrefixWithin checks on disk that the longest existing part of p resolves,
// and resolves to somewhere inside root.
func realPrefixWithin(t *testing.T, root, p string) {
	t.Helper()
	cur := p
	for {
		if _, err := os.Lstat(cur); err == nil {
			real, err := filepath.EvalSymlinks(cur)
			if err != nil {
				t.Fatalf("%q exists but cannot be resolved (%v), yet it was accepted", p, err)
			}
			if !Within(root, real) {
				t.Fatalf("%q resolves on disk to %q, outside the root %q", p, real, root)
			}
			return
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return
		}
		cur = parent
	}
}

func checkPath(t *testing.T, root, in string, got Path) {
	t.Helper()
	if !Within(root, got.Abs) {
		t.Fatalf("%q resolved to %q, outside root", in, got.Abs)
	}
	if got.Rel != "." && (!filepath.IsLocal(got.Rel) || path.Clean(got.Rel) != got.Rel) {
		t.Fatalf("%q: Rel %q is not canonical", in, got.Rel)
	}
	if filepath.Join(root, got.Native()) != got.Abs {
		t.Fatalf("%q: Rel %q and Abs %q disagree", in, got.Rel, got.Abs)
	}
}

func seedPaths(f *testing.F) {
	for _, s := range []string{
		"", ".", "..", "../", "../x", "../outside", "../outside/secret.txt", "a/../../x",
		"/", "/etc/passwd", "//etc//passwd", "docs", "docs/file.txt", "docs/../docs/file.txt",
		"docs/..", "docs/../..", "docs/back", "docs/back/outside/secret.txt", "deep/er/est",
		"deep/er/out/secret.txt", "link-in", "link-in/file.txt", "link-in/../..", "link-in-rel/x",
		"escape", "escape/secret.txt", "escape/new/file", "escape-file", "rel-escape/secret.txt",
		"up", "up/outside/secret.txt", "up/root/docs", "dangling", "dangling/x", "loop-a", "loop-a/x",
		"a\x00b", "docs/\x00", "\x00", "..\\..", "docs\\..\\..", "%2e%2e/%2e%2e", "..%2f..%2f",
		"docs/.", "./docs/./file.txt", "docs//file.txt", "....//....//", ".../", "..;/", "docs/file.txt/",
		"docs/file.txt/..", "ünïcödé/日本語", strings.Repeat("a/", 500), strings.Repeat("../", 500),
		"docs/" + strings.Repeat("../", 3) + "outside",
	} {
		f.Add(s)
	}
}

// FuzzResolve checks for arbitrary input that Resolve and ResolveEntry never
// panic, that what they accept lies inside the root (textually and on disk),
// that Rel is canonical and agrees with Abs, that ResolveEntry never returns
// the root, and that ".." escapes and NUL bytes are always rejected.
//
// go test -fuzz=FuzzResolve ./internal/sandbox
func FuzzResolve(f *testing.F) {
	if filepath.Separator != '/' {
		f.Skip("path oracle assumes '/' separators")
	}
	sb, root := fuzzFixture(f)
	seedPaths(f)

	f.Fuzz(func(t *testing.T, p string) {
		got, err := sb.Resolve(p)
		if err == nil {
			checkPath(t, root, p, got)
			realPrefixWithin(t, root, got.Abs)
		}

		entry, entryErr := sb.ResolveEntry(p)
		if entryErr == nil {
			checkPath(t, root, p, entry)
			if entry.Rel == "." {
				t.Fatalf("ResolveEntry(%q) returned the root", p)
			}
			realPrefixWithin(t, root, filepath.Dir(entry.Abs))
		}

		if strings.ContainsRune(p, 0) {
			if !errors.Is(err, ErrInvalidPath) || !errors.Is(entryErr, ErrInvalidPath) {
				t.Fatalf("NUL byte in %q accepted: %v / %v", p, err, entryErr)
			}
			return
		}
		if lexicallyEscapes(p) {
			if !errors.Is(err, ErrTraversal) || !errors.Is(entryErr, ErrTraversal) {
				t.Fatalf("%q climbs out of the root but was not rejected as traversal: %v / %v", p, err, entryErr)
			}
		}
	})
}
