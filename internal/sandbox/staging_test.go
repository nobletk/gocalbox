package sandbox

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func openRoot(t *testing.T, dir string) *os.Root {
	t.Helper()
	r, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	return r
}

func check(t *testing.T, dir string) *Staging {
	t.Helper()
	s, err := CheckStaging(openRoot(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestCheckStagingCreatesTheFolders(t *testing.T) {
	dir := t.TempDir()
	s := check(t, dir)
	if !s.Usable() || s.Warning != "" {
		t.Fatalf("problem %v, warning %q", s.Problem, s.Warning)
	}
	for _, d := range stagingDirs {
		info, err := os.Lstat(filepath.Join(dir, filepath.FromSlash(d)))
		if err != nil || !info.IsDir() {
			t.Fatalf("%s: %v", d, err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
			t.Errorf("%s has mode %v", d, info.Mode().Perm())
		}
	}
	if !s.Links {
		t.Error("hard links reported missing on the test volume")
	}
	if s.MaxFileSize != 0 {
		t.Errorf("a file-size limit of %d on the test volume", s.MaxFileSize)
	}
	if entries, _ := os.ReadDir(filepath.Join(dir, filepath.FromSlash(TmpDir))); len(entries) != 0 {
		t.Errorf("the checks left %v in %s", entries, TmpDir)
	}
}

// One server per folder: the second check fails while the first holds the
// lock, also within one process, and works once it is released.
func TestCheckStagingLocksTheFolder(t *testing.T) {
	dir := t.TempDir()
	first, err := CheckStaging(openRoot(t, dir))
	if err != nil || !first.Usable() {
		t.Fatal(err, first.Problem)
	}
	if _, err := CheckStaging(openRoot(t, dir)); !errors.Is(err, ErrStagingLocked) {
		t.Fatalf("a second server: %v", err)
	}
	left := filepath.Join(dir, filepath.FromSlash(TmpDir), TempName())
	os.WriteFile(left, []byte("the first server's"), 0o600)
	if _, err := CheckStaging(openRoot(t, dir)); !errors.Is(err, ErrStagingLocked) {
		t.Fatalf("a second server: %v", err)
	}
	if _, err := os.Stat(left); err != nil {
		t.Errorf("the refused server cleared the first one's temporary files: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	first.Close()
	again := check(t, dir)
	if !again.Usable() {
		t.Fatalf("after the first released it: %v", again.Problem)
	}
}

func TestCheckStagingRemovesWhatEarlierRunsLeft(t *testing.T) {
	dir := t.TempDir()
	tmp := filepath.Join(dir, filepath.FromSlash(TmpDir))
	os.MkdirAll(tmp, 0o700)
	ours := []string{"n-0123456789abcdef0123456789abcdef", "s-0123456789abcdef0123456789abcdef"}
	if err := os.WriteFile(filepath.Join(tmp, ours[0]), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(tmp, ours[1], "deep"), 0o700); err != nil {
		t.Fatal(err)
	}
	// Each name differs from ours in more than letter case, or a volume that
	// ignores case would hold it as one of ours.
	others := []string{"n-0123", "notes.txt", "S-FEDCBA9876543210FEDCBA9876543210"}
	for _, n := range others {
		if err := os.WriteFile(filepath.Join(tmp, n), []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	s := check(t, dir)
	for _, n := range ours {
		if _, err := os.Lstat(filepath.Join(tmp, n)); !os.IsNotExist(err) {
			t.Errorf("%s left: %v", n, err)
		}
	}
	for _, n := range others {
		if _, err := os.Lstat(filepath.Join(tmp, n)); err != nil {
			t.Errorf("%s removed: %v", n, err)
		}
	}
	slices.Sort(s.Unknown)
	slices.Sort(others)
	if !slices.Equal(s.Unknown, others) {
		t.Errorf("unknown entries %v, want %v", s.Unknown, others)
	}
}

// A .gocalbox, or a folder in it, that isn't a real folder can't be used:
// following it could delete or expose files elsewhere in the served folder.
func TestCheckStagingRefusesWhatIsntAFolder(t *testing.T) {
	for _, which := range stagingDirs {
		t.Run(which, func(t *testing.T) {
			dir := t.TempDir()
			victim := filepath.Join(dir, "public", "victim")
			os.MkdirAll(filepath.Join(victim, "trash"), 0o755)
			os.WriteFile(filepath.Join(victim, "trash", "user-file.txt"), []byte("mine"), 0o644)
			for _, d := range stagingDirs {
				if d == which {
					break
				}
				os.Mkdir(filepath.Join(dir, filepath.FromSlash(d)), 0o700)
			}
			rel, _ := filepath.Rel(filepath.Dir(filepath.Join(dir, filepath.FromSlash(which))), victim)
			if err := os.Symlink(rel, filepath.Join(dir, filepath.FromSlash(which))); err != nil {
				t.Skipf("no symlinks here: %v", err)
			}
			s := check(t, dir)
			if s.Usable() || !strings.Contains(s.Problem.Error(), "symlink") {
				t.Fatalf("problem %v", s.Problem)
			}
			if data, err := os.ReadFile(filepath.Join(victim, "trash", "user-file.txt")); err != nil || string(data) != "mine" {
				t.Errorf("the folder the link points to was changed: %v", err)
			}
			if entries, _ := os.ReadDir(victim); len(entries) != 1 {
				t.Errorf("the check wrote into the folder the link points to: %v", entries)
			}
		})
	}

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ReservedName), []byte("x"), 0o644)
	if s := check(t, dir); s.Usable() || !strings.Contains(s.Problem.Error(), "file") {
		t.Errorf("a file named %s: %v", ReservedName, s.Problem)
	}
}

func TestCheckStagingRefusesALockThatIsntAFile(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, filepath.FromSlash(lockName)), 0o700)
	if s := check(t, dir); s.Usable() {
		t.Error("a folder named lock was accepted")
	}

	dir = t.TempDir()
	os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("mine"), 0o644)
	os.Mkdir(filepath.Join(dir, ReservedName), 0o700)
	if err := os.Symlink(filepath.Join("..", "notes.txt"), filepath.Join(dir, filepath.FromSlash(lockName))); err != nil {
		t.Skipf("no symlinks here: %v", err)
	}
	if s := check(t, dir); s.Usable() || !strings.Contains(s.Problem.Error(), "symlink") {
		t.Errorf("a symlink named lock: %v", s.Problem)
	}
}

func TestVolumeOf(t *testing.T) {
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, "sub"), 0o755)
	r := openRoot(t, dir)
	a, err := VolumeOf(r, ".")
	if err != nil {
		t.Fatal(err)
	}
	b, err := VolumeOf(r, "sub")
	if err != nil || a != b {
		t.Errorf("one file system, two volumes: %v and %v, %v", a, b, err)
	}
	if _, err := VolumeOf(r, "missing"); err == nil {
		t.Error("a missing folder has a volume")
	}
}

func TestTempName(t *testing.T) {
	a, b := TempName(), TempName()
	if a == b || !tempName.MatchString(a) || !strings.HasPrefix(a, "n-") {
		t.Errorf("TempName gave %q and %q", a, b)
	}
}
