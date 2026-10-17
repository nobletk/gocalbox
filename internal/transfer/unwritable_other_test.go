//go:build !unix

package transfer

import (
	"os"
	"testing"
)

// unwritable makes a file that can't be opened for writing, and reports
// whether it worked.
func unwritable(t *testing.T, path string) bool {
	t.Helper()
	os.Chmod(path, 0o444)
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err == nil {
		f.Close()
		return false
	}
	return true
}

func writable(t *testing.T, path string) {
	t.Helper()
	os.Chmod(path, 0o600)
}
