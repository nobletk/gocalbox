package httpapi

import (
	"strings"
	"testing"
)

// A file or folder named like a device is an invalid name, not a path that
// leaves the root.
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
	e.write("a.txt", "a")
	for _, name := range []string{"CON", "nul", "COM1", "x.txt:hidden", "ab:c"} {
		if code, body := e.postJSON("/api/fs/mkdir", CreateFolderRequest{Name: name}); code != 400 || errorCode(body) != "invalid_name" {
			t.Errorf("a folder named %q = %d %s", name, code, body)
		}
		if code, body := e.postJSON("/api/fs/rename", MoveRequest{OldPath: "a.txt", NewPath: name}); code != 400 || errorCode(body) != "invalid_name" {
			t.Errorf("a.txt renamed %q = %d %s", name, code, body)
		}
		if code, body := e.postJSON("/api/fs/move", MoveRequest{OldPath: "a.txt", NewPath: "sub/" + name}); code != 400 || errorCode(body) != "invalid_name" {
			t.Errorf("a.txt moved to sub/%s = %d %s", name, code, body)
		}
	}
	for _, name := range []string{"a:b", "C:", "C:x"} {
		if code, body := e.postJSON("/api/fs/rename", MoveRequest{OldPath: "a.txt", NewPath: name}); code != 400 || errorCode(body) != "invalid_name" {
			t.Errorf("a.txt renamed %q = %d %s", name, code, body)
		}
	}
	if log := out.String(); strings.Contains(log, "SECURITY ALERT") {
		t.Errorf("log: %q", log)
	}
	if code, body := e.postJSON("/api/fs/move", MoveRequest{OldPath: "a.txt", NewPath: "../CON"}); code != 403 || errorCode(body) != "path_outside_root" {
		t.Errorf("a.txt moved to ../CON = %d %s", code, body)
	}
	if log := out.String(); !strings.Contains(log, "SECURITY ALERT") {
		t.Errorf("no alert for a move outside the root: %q", log)
	}
}
