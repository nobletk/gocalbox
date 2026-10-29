package transfer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The completion's flush leaves no file open behind it, which Windows would
// refuse to place.
func TestTheFlushAtTheCompletionClosesTheData(t *testing.T) {
	fl := &flushLog{}
	en := newEnv(t, withPartSyncs(false, false, fl))
	f := newFile(2 * testPartSize)
	up := en.create(alice, "public", "a.bin", f)
	en.sendAll(alice, up.UploadID, f)
	res, err := en.e.Complete(as(alice), up.UploadID, f.composite())
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if fl.count(dataName) != 1 {
		t.Fatalf("the data was flushed %d times", fl.count(dataName))
	}
	placed := filepath.Join(en.dir, filepath.FromSlash(res.Path))
	fds, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for _, fd := range fds {
		target, _ := os.Readlink(filepath.Join("/proc/self/fd", fd.Name()))
		if strings.HasPrefix(target, placed) || strings.Contains(target, up.UploadID) && strings.Contains(target, dataName) {
			t.Errorf("descriptor %s is still open on %s", fd.Name(), target)
		}
	}
}
