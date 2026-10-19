package fsops

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// A folder that became another mount while the body arrived gets the staged
// file copied into it, whether the volume check or the link finds it.
func TestAStagedUploadIsCopiedIntoAFolderMountedMeanwhile(t *testing.T) {
	for _, seen := range []string{"by the volume check", "by the link"} {
		t.Run(seen, func(t *testing.T) {
			a := newAccessEnv(t)
			d := filepath.Join(a.root, "public", "d")
			os.Mkdir(d, 0o755)
			mounted := t.TempDir()
			pw, done := slowUpload(t, a.svc, alice, "public/d", "a.bin")
			pw.Write([]byte("abc"))
			a.stagedSize(3)
			bindMount(t, mounted, d, 0)
			if seen == "by the link" {
				fakeVolumes(t)
			}
			pw.Write([]byte("def"))
			pw.Close()
			if u := <-done; u.err != nil || u.stored != "public/d/a.bin" || u.size != 6 {
				t.Fatalf("the upload: %+v", u)
			}
			if b, err := os.ReadFile(filepath.Join(mounted, "a.bin")); err != nil || string(b) != "abcdef" {
				t.Errorf("the file on the mount: %q, %v", b, err)
			}
			if a.uploader("public/d/a.bin") != alice {
				t.Error("no record for the copied file")
			}
			if left := a.tmp(); len(left) != 0 {
				t.Errorf("the staging folder holds %v", left)
			}
		})
	}
}

// A folder the server may not write to is refused before the body.
func TestAnImmutableFolderIsRefusedBeforeTheBody(t *testing.T) {
	e := newEnv(t)
	d := filepath.Join(e.root, "frozen")
	os.Mkdir(d, 0o755)
	if out, err := exec.Command("chattr", "+i", d).CombinedOutput(); err != nil {
		t.Skipf("chattr: %v %s", err, out)
	}
	t.Cleanup(func() { exec.Command("chattr", "-i", d).Run() })
	_, _, err := e.svc.Create(bg, "frozen", "a.bin", untouched{t}, -1)
	is(t, err, os.ErrPermission, "an immutable folder")
	if left := e.tmp(); len(left) != 0 {
		t.Errorf("the staging folder holds %v", left)
	}
}
