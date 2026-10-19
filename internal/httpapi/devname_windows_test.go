package httpapi

import (
	"strings"
	"testing"
)

// A file named like a device is an invalid name, not a path that leaves the
// root.
func TestADeviceNameIsAnInvalidName(t *testing.T) {
	out := captureLog(t)
	e := newEnvOpts(t, Options{})
	// The multipart reader reduces a file name to its base name, which on
	// Windows drops a leading drive letter and colon: "a:b" arrives as "b".
	for _, name := range []string{"CON", "nul", "COM1", "x.txt:hidden", "ab:c"} {
		if code, body := e.upload("", name, "x"); code != 400 || errorCode(body) != "invalid_name" {
			t.Errorf("an upload named %q = %d %s", name, code, body)
		}
	}
	if log := out.String(); strings.Contains(log, "SECURITY ALERT") {
		t.Errorf("log: %q", log)
	}
}
