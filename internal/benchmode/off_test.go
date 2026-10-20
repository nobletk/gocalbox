//go:build !bench

package benchmode

import (
	"os"
	"path/filepath"
	"testing"
)

// A build without the bench tag reads none of the benchmark settings, however
// they are set.
func TestANormalBuildReadsNoSetting(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "requests.jsonl")
	t.Setenv(EnvConnWindow, "1M")
	t.Setenv(EnvStreamWindow, "64K")
	t.Setenv(EnvPartSize, "16M")
	t.Setenv(EnvRequestLog, logPath)
	if Enabled {
		t.Fatal("Enabled")
	}
	if err := Init(); err != nil {
		t.Fatal(err)
	}
	if c, s := H2Windows(7, 9); c != 7 || s != 9 {
		t.Errorf("H2Windows = %d, %d", c, s)
	}
	if p := PartSize(); p != 0 {
		t.Errorf("PartSize = %d", p)
	}
	if w := RequestLog(); w != nil {
		t.Errorf("RequestLog = %v", w)
	}
	if _, err := os.Stat(logPath); !os.IsNotExist(err) {
		t.Errorf("the request log was made: %v", err)
	}
	t.Setenv(EnvPartSize, "3")
	if err := Init(); err != nil {
		t.Errorf("an invalid setting stopped a normal build: %v", err)
	}
}
