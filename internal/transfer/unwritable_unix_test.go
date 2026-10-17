//go:build unix

package transfer

import (
	"os"
	"os/exec"
	"testing"
)

// unwritable makes a file that the server can't open for writing, root
// included, and reports whether it worked.
func unwritable(t *testing.T, path string) bool {
	t.Helper()
	os.Chmod(path, 0o444)
	if os.Geteuid() == 0 {
		if err := exec.Command("chattr", "+i", path).Run(); err != nil {
			return false
		}
		t.Cleanup(func() { exec.Command("chattr", "-i", path).Run() })
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err == nil {
		f.Close()
		return false
	}
	return true
}

func writable(t *testing.T, path string) {
	t.Helper()
	if os.Geteuid() == 0 {
		exec.Command("chattr", "-i", path).Run()
	}
	os.Chmod(path, 0o600)
}
