package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTheScratchFolderMustBeThisCommands(t *testing.T) {
	dir := t.TempDir()
	keep := filepath.Join(dir, "repo", "go.mod")
	os.MkdirAll(filepath.Dir(keep), 0o755)
	os.WriteFile(keep, nil, 0o644)
	if err := emptyWork(filepath.Dir(keep)); err == nil {
		t.Error("a folder of other files was accepted")
	}
	if _, err := os.Stat(keep); err != nil {
		t.Errorf("a refused folder lost its files: %v", err)
	}

	work := filepath.Join(dir, "work")
	if err := emptyWork(work); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(work, "left"), nil, 0o644)
	if err := emptyWork(work); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(work, "left")); !os.IsNotExist(err) {
		t.Errorf("the scratch folder wasn't emptied: %v", err)
	}
}

func TestParseSize(t *testing.T) {
	for in, want := range map[string]int64{"10": 10, "64K": 64 << 10, "64M": 64 << 20, "2G": 2 << 30} {
		if got, err := parseSize(in); err != nil || got != want {
			t.Errorf("%s: %d, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "-1", "1T", "M"} {
		if _, err := parseSize(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
