package sandbox

import (
	"errors"
	"io/fs"
	"path/filepath"
	"syscall"
	"testing"
)

func TestIsBadName(t *testing.T) {
	for _, err := range append([]error{syscall.ENAMETOOLONG}, windowsBadNames...) {
		if !IsBadName(&fs.PathError{Op: "open", Path: "x", Err: err}) {
			t.Errorf("IsBadName(%v) = false", err)
		}
	}
	for _, err := range []error{fs.ErrNotExist, fs.ErrPermission, errors.New("disk on fire")} {
		if IsBadName(&fs.PathError{Op: "open", Path: "x", Err: err}) {
			t.Errorf("IsBadName(%v) = true", err)
		}
	}
}

func TestBackslashMeansTheSameOnEverySystem(t *testing.T) {
	sb, _, _ := setup(t)
	p, err := sb.Resolve(`docs\x.txt`)
	if filepath.Separator == '\\' {
		if !errors.Is(err, ErrInvalidPath) {
			t.Errorf(`Resolve(docs\x.txt) = %+v, %v; want ErrInvalidPath, not the file x.txt in docs`, p, err)
		}
		return
	}
	if err != nil || p.Rel != `docs\x.txt` {
		t.Errorf(`Resolve(docs\x.txt) = %+v, %v; want one name in the root`, p, err)
	}
}
