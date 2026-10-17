//go:build unix

package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckStagingMakesItsFoldersPrivate(t *testing.T) {
	dir := t.TempDir()
	for _, d := range stagingDirs {
		os.Mkdir(filepath.Join(dir, filepath.FromSlash(d)), 0o755)
		os.Chmod(filepath.Join(dir, filepath.FromSlash(d)), 0o777)
	}
	s := check(t, dir)
	if !s.Usable() || s.Warning != "" {
		t.Fatalf("problem %v, warning %q", s.Problem, s.Warning)
	}
	for _, d := range stagingDirs {
		if info, _ := os.Stat(filepath.Join(dir, filepath.FromSlash(d))); info.Mode().Perm() != 0o700 {
			t.Errorf("%s left with mode %v", d, info.Mode().Perm())
		}
	}
}

// A .gocalbox someone else owns is refused on a volume that keeps owners,
// however its folder for tests is set up.
func TestCheckStagingRefusesAnotherUsersFolder(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("giving a folder to another user needs root")
	}
	const other = 54321
	for _, tc := range []struct {
		name string
		tmp  os.FileMode
	}{
		{"open tmp", 0o777},
		{"setgid tmp", 0o777 | os.ModeSetgid},
		{"private tmp", 0o700},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, d := range stagingDirs {
				p := filepath.Join(dir, filepath.FromSlash(d))
				os.Mkdir(p, 0o700)
				os.Chown(p, other, other)
			}
			os.Chmod(filepath.Join(dir, filepath.FromSlash(TmpDir)), tc.tmp)
			s := check(t, dir)
			if s.Usable() || !strings.Contains(s.Problem.Error(), "belongs to user ID 54321") {
				t.Errorf("problem %v, warning %q", s.Problem, s.Warning)
			}
		})
	}
}

// On a volume that sets owners and modes from its mount options, the folder
// is accepted as it is, with a warning that says how to make it private.
func TestCheckStagingAcceptsAVolumeThatSetsModes(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("giving a folder to another user needs root")
	}
	setByMount := true
	saved := volumeSetsModes
	volumeSetsModes = func(*os.Root) (bool, error) { return setByMount, nil }
	t.Cleanup(func() { volumeSetsModes = saved })

	dir := t.TempDir()
	for _, d := range stagingDirs {
		p := filepath.Join(dir, filepath.FromSlash(d))
		os.Mkdir(p, 0o700)
		os.Chown(p, 54321, 54321)
	}
	s := check(t, dir)
	if !s.Usable() || !strings.Contains(s.Warning, "dmask=077") || !strings.Contains(s.Warning, "belongs to user ID 54321") {
		t.Fatalf("problem %v, warning %q", s.Problem, s.Warning)
	}
	s.Close()

	setByMount = false
	if s := check(t, dir); s.Usable() {
		t.Error("accepted on a volume that keeps owners")
	}

	volumeSetsModes = func(*os.Root) (bool, error) { return true, os.ErrPermission }
	if s := check(t, dir); s.Usable() || !strings.Contains(s.Problem.Error(), "no folder to test its volume") {
		t.Errorf("accepted although the volume couldn't be tested: %v", s.Problem)
	}
}
