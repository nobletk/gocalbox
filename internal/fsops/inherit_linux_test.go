package fsops

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/nobletk/gocalbox/internal/sandbox"
	"golang.org/x/sys/unix"
)

// defaultACL is a default ACL giving the group gid read, write and
// execute, and others the permissions others, in the kernel's xattr form.
func defaultACL(gid uint32, others uint16) []byte {
	b := binary.LittleEndian.AppendUint32(nil, 2)
	add := func(tag, perm uint16, id uint32) {
		b = binary.LittleEndian.AppendUint16(b, tag)
		b = binary.LittleEndian.AppendUint16(b, perm)
		b = binary.LittleEndian.AppendUint32(b, id)
	}
	add(0x01, 7, 0xffffffff) // the owner
	add(0x04, 5, 0xffffffff) // the owning group
	add(0x08, 7, gid)        // the group gid
	add(0x10, 7, 0xffffffff) // the mask
	add(0x20, others, 0xffffffff)
	return b
}

// attrs describes what a file got from its folder: group, mode and access
// ACL.
func attrs(t *testing.T, path string) string {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	acl := make([]byte, 256)
	n, err := unix.Getxattr(path, accessACL, acl)
	if err != nil {
		n = 0
	}
	return fmt.Sprintf("gid %d, mode %v, ACL %x", info.Sys().(*syscall.Stat_t).Gid, info.Mode(), acl[:n])
}

// folders makes the folders whose files get something of them: a
// set-group-ID folder of group 4242, one with a default ACL, and one with
// both.
func folders(t *testing.T, a *accessEnv) []string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("giving a folder another group needs root")
	}
	dirs := []string{"public/sg", "public/acl", "public/both", "public/plain"}
	for _, d := range dirs {
		p := filepath.Join(a.root, d)
		os.Mkdir(p, 0o755)
		if d != "public/acl" && d != "public/plain" {
			os.Chown(p, 0, 4242)
			os.Chmod(p, 0o775|os.ModeSetgid)
		}
		if d == "public/acl" || d == "public/both" {
			if err := unix.Setxattr(p, "system.posix_acl_default", defaultACL(4243, 5), 0); err != nil {
				t.Skipf("no ACLs here: %v", err)
			}
		}
	}
	os.Chown(filepath.Join(a.root, "public/plain"), 0, 4242)
	return dirs
}

// A placed file gets from its folder what a file written there gets: its
// group from a set-group-ID folder, its permissions and ACL from a default
// ACL. Both upload paths and the resumable upload's placement agree.
func TestAPlacedFileGetsWhatItsFolderGives(t *testing.T) {
	a := newAccessEnv(t)
	dirs := folders(t, a)
	// What the staging folder gives is taken away too.
	tmp := filepath.Join(a.root, ".gocalbox", "tmp")
	os.Chown(tmp, 0, 4244)
	os.Chmod(tmp, 0o700|os.ModeSetgid)
	if err := unix.Setxattr(tmp, "system.posix_acl_default", defaultACL(4245, 0), 0); err != nil {
		t.Skipf("no ACLs here: %v", err)
	}
	os.MkdirAll(filepath.Join(a.root, ".gocalbox", "uploads"), 0o700)
	unix.Setxattr(filepath.Join(a.root, ".gocalbox", "uploads"), "system.posix_acl_default", defaultACL(4245, 0), 0)
	staged := map[string]string{}
	for _, d := range dirs {
		a.upload(alice, d, "staged.bin", "x")
		if _, _, err := a.svc.Adopt(as(alice), a.stage("x"), d, "adopted.bin", func(string) error { return nil }); err != nil {
			t.Fatal(err)
		}
		staged[d] = attrs(t, filepath.Join(a.root, d, "staged.bin"))
	}
	directUploads(a.svc)
	for _, d := range dirs {
		a.upload(alice, d, "direct.bin", "x")
		want := attrs(t, filepath.Join(a.root, d, "direct.bin"))
		if staged[d] != want {
			t.Errorf("%s: the staged upload has %s, a file written there %s", d, staged[d], want)
		}
		if got := attrs(t, filepath.Join(a.root, d, "adopted.bin")); got != want {
			t.Errorf("%s: the resumable upload has %s, a file written there %s", d, got, want)
		}
	}
	if !strings.Contains(staged["public/sg"], "gid 4242") || strings.HasSuffix(staged["public/acl"], "ACL ") {
		t.Errorf("the folders gave nothing: %v", staged)
	}
}

// Where the server couldn't give the file the folder's group, the upload is
// written in its folder, as before staging, and gets it from the kernel.
func TestAnUploadWhoseGroupCantBeGivenIsWrittenInPlace(t *testing.T) {
	a := newAccessEnv(t)
	folders(t, a)
	orig := mayChgrp
	mayChgrp = func(gid int) bool { return gid != 4242 }
	t.Cleanup(func() { mayChgrp = orig })
	pw, done := slowUpload(t, a.svc, alice, "public/sg", "slow.bin")
	pw.Write([]byte("abc"))
	deadline := time.Now().Add(10 * time.Second)
	for a.read("public/sg/slow.bin") != "abc" {
		if time.Now().After(deadline) {
			t.Fatal("the upload isn't written in its folder")
		}
		time.Sleep(2 * time.Millisecond)
	}
	if left := a.tmp(); slices.ContainsFunc(left, func(n string) bool { return strings.HasPrefix(n, "s-") }) {
		t.Errorf("staged: %v", left)
	}
	pw.Close()
	if u := <-done; u.err != nil {
		t.Fatal(u.err)
	}
	if got := attrs(t, filepath.Join(a.root, "public/sg/slow.bin")); !strings.HasPrefix(got, "gid 4242") {
		t.Errorf("the file has %s", got)
	}
	a.upload(alice, "public/plain", "plain.bin", "x")
	if got := attrs(t, filepath.Join(a.root, "public/plain/plain.bin")); !strings.HasPrefix(got, "gid 0,") {
		t.Errorf("a folder whose group isn't given: the file has %s", got)
	}
}

// Without unnamed files, only a set-group-ID folder's group is given;
// permissions and ACL are the staged file's, as a file written there has
// them where the staging folder gives nothing of its own.
func TestWithoutUnnamedFilesOnlyASetgidGroupIsGiven(t *testing.T) {
	a := newAccessEnv(t)
	folders(t, a)
	orig := openUnnamed
	openUnnamed = func(int) (int, error) { return -1, unix.EOPNOTSUPP }
	t.Cleanup(func() { openUnnamed = orig })
	dirs := []string{"public/sg", "public/plain"}
	for _, d := range dirs {
		a.upload(alice, d, "staged.bin", "x")
	}
	directUploads(a.svc)
	for _, d := range dirs {
		a.upload(alice, d, "direct.bin", "x")
		staged, direct := attrs(t, filepath.Join(a.root, d, "staged.bin")), attrs(t, filepath.Join(a.root, d, "direct.bin"))
		if staged != direct {
			t.Errorf("%s: the staged upload has %s, a file written there %s", d, staged, direct)
		}
	}
	if got := attrs(t, filepath.Join(a.root, "public/sg/staged.bin")); !strings.HasPrefix(got, "gid 4242,") {
		t.Errorf("the set-group-ID folder's group wasn't given: %s", got)
	}
}

// Without unnamed files, an upload into a folder that isn't set-group-ID is
// staged all the same: its file keeps the group it was created with.
func TestWithoutUnnamedFilesAnUploadIsStillStaged(t *testing.T) {
	a := newAccessEnv(t)
	folders(t, a)
	orig := openUnnamed
	openUnnamed = func(int) (int, error) { return -1, unix.EOPNOTSUPP }
	t.Cleanup(func() { openUnnamed = orig })
	if !stagedWhileArriving(t, a.env, a.svc, alice, "public/plain") {
		t.Error("written directly")
	}
}

// stagedWhileArriving starts an upload into dir, writes part of its body,
// and tells whether it is staged rather than written in its folder.
func stagedWhileArriving(t *testing.T, e *env, svc *Service, user, dir string) bool {
	t.Helper()
	pw, done := slowUpload(t, svc, user, dir, "a.bin")
	pw.Write([]byte("abc"))
	staged := false
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(2 * time.Millisecond) {
		staged = slices.ContainsFunc(e.tmp(), func(n string) bool { return strings.HasPrefix(n, "s-") })
		if staged || e.read(dir+"/a.bin") == "abc" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: the upload is neither staged nor in its folder", dir)
		}
	}
	pw.Close()
	if u := <-done; u.err != nil {
		t.Fatalf("%s: %v", dir, u.err)
	}
	return staged
}

// A file system without unnamed files is found by its error, whatever it is.
func TestInheritedFromFallsBackOnAnyError(t *testing.T) {
	a := newAccessEnv(t)
	orig := openUnnamed
	openUnnamed = func(int) (int, error) { return -1, errors.New("no") }
	t.Cleanup(func() { openUnnamed = orig })
	in, err := inheritedFrom(a.svc.root, "public")
	if err != nil || in.full || in.gid != -1 {
		t.Errorf("inherited %+v, %v", in, err)
	}
}

// As root, an upload into a set-group-ID folder of a group the server isn't
// in is staged: root may give its file any group.
func TestRootStagesIntoASetgidFolderOfAnyGroup(t *testing.T) {
	a := newAccessEnv(t)
	folders(t, a)
	pw, done := slowUpload(t, a.svc, alice, "public/sg", "slow.bin")
	pw.Write([]byte("abc"))
	a.stagedSize(3)
	if a.exists("public/sg/slow.bin") {
		t.Error("the upload is in its folder while its body arrives")
	}
	pw.Close()
	if u := <-done; u.err != nil {
		t.Fatal(u.err)
	}
	if got := attrs(t, filepath.Join(a.root, "public/sg/slow.bin")); !strings.HasPrefix(got, "gid 4242,") {
		t.Errorf("the file has %s", got)
	}
}

// bigDefaultACL names n groups, so that the access ACL a file gets from it
// is larger than fgetxattr's first buffer.
func bigDefaultACL(n int) []byte {
	b := binary.LittleEndian.AppendUint32(nil, 2)
	add := func(tag, perm uint16, id uint32) {
		b = binary.LittleEndian.AppendUint16(b, tag)
		b = binary.LittleEndian.AppendUint16(b, perm)
		b = binary.LittleEndian.AppendUint32(b, id)
	}
	add(0x01, 7, 0xffffffff)
	add(0x04, 5, 0xffffffff)
	for i := range n {
		add(0x08, 5, uint32(6000+i))
	}
	add(0x10, 7, 0xffffffff)
	add(0x20, 5, 0xffffffff)
	return b
}

func TestABigACLIsGivenWhole(t *testing.T) {
	a := newAccessEnv(t)
	folders(t, a)
	d := filepath.Join(a.root, "public", "big")
	os.Mkdir(d, 0o755)
	if err := unix.Setxattr(d, "system.posix_acl_default", bigDefaultACL(40), 0); err != nil {
		t.Skipf("no ACLs here: %v", err)
	}
	a.upload(alice, "public/big", "staged.bin", "x")
	directUploads(a.svc)
	a.upload(alice, "public/big", "direct.bin", "x")
	if n, err := unix.Getxattr(filepath.Join(d, "direct.bin"), accessACL, nil); err != nil || n <= 256 {
		t.Fatalf("the folder's ACL takes %d bytes, %v", n, err)
	}
	full := func(p string) string {
		n, _ := unix.Getxattr(p, accessACL, nil)
		acl := make([]byte, max(n, 0))
		unix.Getxattr(p, accessACL, acl)
		return fmt.Sprintf("%s %x", attrs(t, p), acl)
	}
	if staged, direct := full(filepath.Join(d, "staged.bin")), full(filepath.Join(d, "direct.bin")); staged != direct {
		t.Errorf("the staged upload has %s, a file written there %s", staged, direct)
	}
}

// When what the folder gives can't be read whole, the resumable upload is
// placed all the same, with a warning, and the file keeps its own mode.
func TestAFailedInheritanceStillPlaces(t *testing.T) {
	var buf logBuffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	a := newAccessEnv(t)
	orig := openUnnamed
	// The folder itself, opened only for its path: fstat works on it, reading
	// an attribute doesn't.
	openUnnamed = func(dirfd int) (int, error) {
		return unix.Openat(dirfd, ".", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	}
	t.Cleanup(func() { openUnnamed = orig })
	staged := a.stage("x")
	before, err := os.Stat(filepath.Join(a.root, filepath.FromSlash(staged)))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.svc.Adopt(as(alice), staged, "public", "a.bin", func(string) error { return nil }); err != nil {
		t.Fatalf("the placement: %v", err)
	}
	after, err := os.Stat(filepath.Join(a.root, "public", "a.bin"))
	if err != nil || after.Mode() != before.Mode() {
		t.Errorf("mode %v, %v before", after.Mode(), before.Mode())
	}
	if !strings.Contains(buf.String(), "keeps the group and permissions it got in the staging folder") {
		t.Errorf("no warning: %q", buf.String())
	}
}

// The staged file is closed when the upload is written directly instead,
// and when the ledger refuses the upload.
func TestTheStagedFileIsClosedWhenItIsntUsed(t *testing.T) {
	fds := func() int { entries, _ := os.ReadDir("/proc/self/fd"); return len(entries) }
	// A collection would close a leaked file through its finalizer.
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	a := newAccessEnv(t)
	folders(t, a)
	orig := mayChgrp
	mayChgrp = func(gid int) bool { return gid != 4242 }
	t.Cleanup(func() { mayChgrp = orig })
	a.upload(alice, "public", "warm.bin", "x")
	before := fds()
	a.upload(alice, "public/sg", "a.bin", "x")
	if after := fds(); after != before {
		t.Errorf("written directly: %d open files before, %d after", before, after)
	}

	e, _, _ := newSpaceEnv(t, func() (int64, error) { return 10 << 20, nil }, 4<<20)
	e.svc.Create(bg, "", "warm.bin", strings.NewReader("x"), -1)
	before = fds()
	if _, _, err := e.svc.Create(bg, "", "big.bin", untouched{t}, 7<<20); err == nil {
		t.Fatal("not refused")
	}
	if after := fds(); after != before {
		t.Errorf("refused by the ledger: %d open files before, %d after", before, after)
	}
}

const asUserEnv = "GOCALBOX_TEST_AS_USER"

// The rules for a server that isn't root run in a copy of this test binary
// started as user 5000, of group 5000 and member of group 5001 only, on
// folders this test makes: set-group-ID folders of group 5001, 5002 and
// 5003, and a plain one, with tmp/ set-group-ID of group 5003.
func TestInheritanceForAServerThatIsntRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("starting the test as another user needs root")
	}
	base, err := os.MkdirTemp("", "gocalbox-user-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	os.Chmod(base, 0o755)
	root := filepath.Join(base, "root")
	tmp := filepath.Join(root, ".gocalbox", "tmp")
	os.MkdirAll(tmp, 0o700)
	for _, d := range []string{root, filepath.Join(root, ".gocalbox"), tmp} {
		os.Chown(d, 5000, 5000)
	}
	os.Chown(tmp, 5000, 5003)
	os.Chmod(tmp, 0o700|os.ModeSetgid)
	for name, gid := range map[string]int{"member": 5001, "other": 5002, "tmps": 5003, "plain": 0} {
		d := filepath.Join(root, name)
		os.Mkdir(d, 0o777)
		os.Chmod(d, 0o777)
		if gid != 0 {
			os.Chown(d, 0, gid)
			os.Chmod(d, 0o777|os.ModeSetgid)
		}
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(base, "fsops.test")
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, data, 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "-test.run=^TestInheritanceAsAnOrdinaryUser$", "-test.v", "-test.count=1")
	cmd.Env = append(os.Environ(), asUserEnv+"="+root)
	cmd.Dir = base
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 5000, Gid: 5000, Groups: []uint32{5001}}}
	out, err := cmd.CombinedOutput()
	if errors.Is(err, fs.ErrPermission) {
		t.Skipf("the copy of the test binary can't be run here: %v", err)
	}
	if err != nil || !strings.Contains(string(out), "--- PASS: TestInheritanceAsAnOrdinaryUser") {
		t.Errorf("as user 5000: %v\n%s", err, out)
	}
}

// TestInheritanceAsAnOrdinaryUser runs only when started by
// TestInheritanceForAServerThatIsntRoot.
func TestInheritanceAsAnOrdinaryUser(t *testing.T) {
	root := os.Getenv(asUserEnv)
	if root == "" {
		t.Skip("started by TestInheritanceForAServerThatIsntRoot only")
	}
	sb, err := sandbox.New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer sb.Close()
	svc := asAdmin(New(sb, nil))
	e := &env{t: t, svc: svc, sb: sb, root: sb.Root()}
	for _, tc := range []struct {
		dir    string
		staged bool
		gid    string
	}{
		{"member", true, "gid 5001,"},
		{"other", false, "gid 5002,"},
		{"tmps", true, "gid 5003,"},
		{"plain", true, "gid 5000,"},
	} {
		if staged := stagedWhileArriving(t, e, svc, "", tc.dir); staged != tc.staged {
			t.Errorf("%s: staged %v, want %v", tc.dir, staged, tc.staged)
		}
		if got := attrs(t, filepath.Join(root, tc.dir, "a.bin")); !strings.HasPrefix(got, tc.gid) {
			t.Errorf("%s: the file has %s, want %s", tc.dir, got, tc.gid)
		}
		os.Remove(filepath.Join(root, tc.dir, "a.bin"))
	}

	// Without unnamed files, a plain folder still takes a staged file.
	orig := openUnnamed
	openUnnamed = func(int) (int, error) { return -1, unix.EOPNOTSUPP }
	if !stagedWhileArriving(t, e, svc, "", "plain") {
		t.Error("plain, without unnamed files: written directly")
	}
	openUnnamed = orig

	var buf logBuffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	staged := path.Join(sandbox.UploadsDir, strings.Repeat("ab", 16), "data")
	e.write(staged, "x")
	if _, _, err := svc.Adopt(bg, staged, "other", "r.bin", func(string) error { return nil }); err != nil {
		t.Fatalf("the resumable upload into a folder whose group can't be given: %v", err)
	}
	if !e.exists("other/r.bin") || !strings.Contains(buf.String(), "keeps the group and permissions it got in the staging folder") {
		t.Errorf("placed %v; log %q", e.exists("other/r.bin"), buf.String())
	}
}
