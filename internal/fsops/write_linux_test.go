package fsops

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A server that runs as an ordinary user but may write through a capability,
// such as one systemd gives with AmbientCapabilities=CAP_DAC_OVERRIDE, can
// write where the mode bits alone would say no; the write check agrees.
func TestTheWriteCheckCountsCapabilities(t *testing.T) {
	if dir := os.Getenv("GOCALBOX_WRITE_CHECK"); dir != "" {
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		if err := writable(root, "locked"); err != nil {
			t.Fatalf("writable as user %d with CAP_DAC_OVERRIDE: %v", os.Geteuid(), err)
		}
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("running as another user needs root")
	}
	setpriv, err := exec.LookPath("setpriv")
	if err != nil {
		t.Skip("setpriv is missing")
	}
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, "locked"), 0o755)
	cmd := exec.Command(setpriv, "--reuid=65534", "--regid=65534", "--clear-groups",
		"--inh-caps=+dac_override", "--ambient-caps=+dac_override",
		os.Args[0], "-test.run=^TestTheWriteCheckCountsCapabilities$", "-test.count=1")
	cmd.Env = append(os.Environ(), "GOCALBOX_WRITE_CHECK="+dir)
	out, err := cmd.CombinedOutput()
	if strings.Contains(string(out), "setpriv:") {
		t.Skipf("setpriv can't drop to another user here: %s", out)
	}
	if err != nil {
		t.Errorf("%v\n%s", err, out)
	}
}
