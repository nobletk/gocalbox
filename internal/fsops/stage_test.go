package fsops

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nobletk/gocalbox/internal/authz"
	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/sandbox"
)

// directUploads turns the staging folder off, so that uploads are written
// in their folder from the start.
func directUploads(s *Service) {
	WithStaging(&sandbox.Staging{Problem: errors.New("no staging folder in this test")})(s)
}

// tmp lists what the staging folder's tmp holds.
func (e *env) tmp() []string {
	e.t.Helper()
	entries, err := os.ReadDir(filepath.Join(e.root, filepath.FromSlash(sandbox.TmpDir)))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		e.t.Fatal(err)
	}
	var names []string
	for _, d := range entries {
		names = append(names, d.Name())
	}
	return names
}

// stagedSize waits until the one staged upload holds n bytes.
func (e *env) stagedSize(n int64) {
	e.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		names := e.tmp()
		if len(names) == 1 && strings.HasPrefix(names[0], "s-") {
			info, err := os.Stat(filepath.Join(e.root, filepath.FromSlash(sandbox.TmpDir), names[0]))
			if err == nil && info.Size() == n {
				return
			}
		}
		if time.Now().After(deadline) {
			e.t.Fatalf("the staging folder holds %v, want one staged upload of %d bytes", names, n)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// slowUpload starts an upload whose body the test writes.
func slowUpload(t *testing.T, svc *Service, user, dir, name string) (*body, <-chan uploaded) {
	pr, pw := io.Pipe()
	done := make(chan uploaded, 1)
	go func() {
		var u uploaded
		u.stored, u.size, u.err = svc.Create(as(user), dir, name, pr, -1)
		done <- u
	}()
	return &body{t: t, pw: pw, done: done}, done
}

// body is the body of a slow upload. A write fails the test, rather than
// wait forever, if the upload ends before reading it.
type body struct {
	t    *testing.T
	pw   *io.PipeWriter
	done <-chan uploaded
}

func (b *body) Write(p []byte) {
	b.t.Helper()
	written := make(chan struct{})
	go func() {
		b.pw.Write(p)
		close(written)
	}()
	select {
	case <-written:
	case u := <-b.done:
		b.pw.CloseWithError(errors.New("the upload had ended"))
		b.t.Fatalf("the upload ended before reading its body: %q, %d, %v", u.stored, u.size, u.err)
	}
}

func (b *body) Close() { b.pw.Close() }

type uploaded struct {
	stored string
	size   int64
	err    error
}

func TestAStagedUploadIsListedOnlyOnceWhole(t *testing.T) {
	a := newAccessEnv(t)
	pw, done := slowUpload(t, a.svc, alice, "public", "slow.bin")
	pw.Write([]byte("abc"))
	a.stagedSize(3)
	for _, user := range []string{alice, admin} {
		if names := a.names(user, "public"); slices.Contains(names, "slow.bin") {
			t.Errorf("%s sees the upload before it ends: %v", user, names)
		}
	}
	if _, found := a.record("public/slow.bin"); found {
		t.Error("the upload has a record before it ends")
	}
	pw.Write([]byte("def"))
	pw.Close()
	u := <-done
	if u.err != nil || u.stored != "public/slow.bin" || u.size != 6 {
		t.Fatalf("the upload: %+v", u)
	}
	if ev := a.rec.last(t); ev.Type != events.FileUploaded || ev.Outcome != events.OutcomeOK || ev.Path != "public/slow.bin" || ev.Resolved != "public/slow.bin" || ev.Size != 6 {
		t.Errorf("event: %+v", ev)
	}
	if got := a.listing(alice, "public")["slow.bin"]; got != "name-of-u-alice rename,move,delete" {
		t.Errorf("alice's listing of the upload: %q", got)
	}
	info, err := os.Stat(filepath.Join(a.root, "public/slow.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if rec, _ := a.record("public/slow.bin"); rec.User != alice || rec.Size == nil || *rec.Size != 6 || rec.MTime == nil || *rec.MTime != info.ModTime().UnixNano() {
		t.Errorf("record: %+v", rec)
	}
	if a.read("public/slow.bin") != "abcdef" {
		t.Errorf("content %q", a.read("public/slow.bin"))
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o644 {
		t.Errorf("mode %v", info.Mode())
	}
	if left := a.tmp(); len(left) != 0 {
		t.Errorf("the staging folder holds %v", left)
	}
}

func TestAStagedUploadTakesItsNameWhenItEnds(t *testing.T) {
	a := newAccessEnv(t)
	pw, done := slowUpload(t, a.svc, alice, "public", "x.bin")
	pw.Write([]byte("alice's"))
	a.stagedSize(int64(len("alice's")))
	a.upload(bob, "public", "x.bin", "bob's")
	pw.Close()
	u := <-done
	if u.err != nil || u.stored != "public/x (1).bin" {
		t.Fatalf("the upload that ended last: %+v", u)
	}
	if a.read("public/x.bin") != "bob's" || a.uploader("public/x.bin") != bob {
		t.Error("bob's file or record changed")
	}
	if a.read("public/x (1).bin") != "alice's" || a.uploader("public/x (1).bin") != alice {
		t.Error("alice's file or record is wrong")
	}
	if ev := a.rec.last(t); ev.Path != "public/x (1).bin" || ev.Resolved != "public/x (1).bin" || ev.Actor.ID != alice {
		t.Errorf("event: %+v", ev)
	}
}

func TestAStagedUploadThatFailsLeavesNothing(t *testing.T) {
	for _, tc := range []struct {
		what    string
		body    io.Reader
		flush   error
		want    error
		written bool // the failure names the file's write
	}{
		{"a body that broke off", &failingReader{data: "half", err: fmt.Errorf("%w: unexpected EOF", ErrBodyAborted)}, nil, ErrBodyAborted, false},
		{"an unmarked reader error", &failingReader{data: "half", err: errors.New("connection reset")}, nil, nil, true},
		{"a flush that failed", strings.NewReader("whole"), errors.New("flush failed"), nil, true},
	} {
		t.Run(tc.what, func(t *testing.T) {
			a := newAccessEnv(t)
			if tc.flush != nil {
				orig := syncStaged
				syncStaged = func(*os.File) error { return tc.flush }
				t.Cleanup(func() { syncStaged = orig })
			}
			stored, _, err := a.svc.Create(as(alice), "public", "partial.bin", tc.body, -1)
			if err == nil || stored != "" {
				t.Fatalf("the upload: %q, %v", stored, err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
			if got := strings.HasPrefix(err.Error(), "write file: "); got != tc.written {
				t.Errorf("err = %q: named as a write %v, want %v", err, got, tc.written)
			}
			if a.exists("public/partial.bin") || a.uploader("public/partial.bin") != "" {
				t.Error("the failed upload left its file or record")
			}
			if left := a.tmp(); len(left) != 0 {
				t.Errorf("the staging folder holds %v", left)
			}
			if ev := a.rec.last(t); ev.Outcome != events.OutcomeError || ev.Detail != err.Error() || ev.Path != "public/partial.bin" {
				t.Errorf("event: %+v", ev)
			}
		})
	}
}

// The upload is decided again when it ends, on the folder as it then is.
func TestAStagedUploadIsDecidedAgainWhenItEnds(t *testing.T) {
	for _, tc := range []struct {
		what   string
		change func(a *accessEnv)
		want   error
		hidden bool
	}{
		{"demoted to viewer", func(a *accessEnv) { a.policy.roles[alice] = authz.Viewer }, ErrForbidden, false},
		{"the folder deleted", func(a *accessEnv) { os.RemoveAll(filepath.Join(a.root, "public/d")) }, ErrParentNotFound, false},
		{"the folder moved", func(a *accessEnv) {
			if _, err := a.svc.Move(as(admin), "public/d", "public/e"); err != nil {
				a.t.Fatal(err)
			}
		}, ErrParentNotFound, false},
		{"the binding removed", func(a *accessEnv) {
			a.policy.bindings = authz.NewBindings([]authz.Binding{{Subject: alice, Folder: "users/alice", Grant: authz.GrantContributor, Home: true}})
		}, ErrParentNotFound, true},
		{"the account gone", func(a *accessEnv) { delete(a.policy.roles, alice) }, ErrParentNotFound, true},
	} {
		t.Run(tc.what, func(t *testing.T) {
			a := newAccessEnv(t)
			a.mkdir(alice, "public", "d")
			pw, done := slowUpload(t, a.svc, alice, "public/d", "a.bin")
			pw.Write([]byte("abc"))
			a.stagedSize(3)
			tc.change(a)
			pw.Close()
			u := <-done
			if !errors.Is(u.err, tc.want) || isHidden(u.err) != tc.hidden || u.stored != "" || u.size != 3 {
				t.Errorf("the upload: %+v, want %v (hidden %v)", u, tc.want, tc.hidden)
			}
			for _, p := range []string{"public/d/a.bin", "public/e/a.bin"} {
				if a.exists(p) {
					t.Errorf("%s was placed", p)
				}
			}
			if left := a.tmp(); len(left) != 0 {
				t.Errorf("the staging folder holds %v", left)
			}
			if ev := a.rec.last(t); ev.Type != events.FileUploaded || ev.Size != 3 {
				t.Errorf("event: %+v", ev)
			}
		})
	}
}

// A folder that took the path of the upload's folder while the body arrived
// is the one the upload goes into.
func TestAStagedUploadGoesWhereItsPathLeadsWhenItEnds(t *testing.T) {
	a := newAccessEnv(t)
	a.mkdir(alice, "public", "d")
	pw, done := slowUpload(t, a.svc, alice, "public/d", "a.bin")
	pw.Write([]byte("abc"))
	a.stagedSize(3)
	if _, err := a.svc.Move(as(admin), "public/d", "public/e"); err != nil {
		t.Fatal(err)
	}
	a.mkdir(bob, "public", "d")
	pw.Close()
	if u := <-done; u.err != nil || u.stored != "public/d/a.bin" {
		t.Fatalf("the upload: %+v", u)
	}
	if a.read("public/d/a.bin") != "abc" || a.exists("public/e/a.bin") {
		t.Error("the upload isn't in the folder its path leads to")
	}
}

func TestAStagedUploadIsRenamedWhereLinksDontWork(t *testing.T) {
	a := newAccessEnv(t)
	WithStaging(&sandbox.Staging{Links: false})(a.svc)
	stored, size, err := a.svc.Create(as(alice), "public", "a.bin", strings.NewReader("renamed"), -1)
	if err != nil || stored != "public/a.bin" || size != 7 {
		t.Fatalf("the upload: %q, %d, %v", stored, size, err)
	}
	if a.read("public/a.bin") != "renamed" || a.uploader("public/a.bin") != alice {
		t.Error("the placed file or its record is wrong")
	}
	if left := a.tmp(); len(left) != 0 {
		t.Errorf("the staging folder holds %v", left)
	}
}

// An upload into a folder on another file system is written in place, so
// it is listed while it arrives, and nothing is staged.
func TestAnUploadIntoAnotherFileSystemIsWrittenInPlace(t *testing.T) {
	a := newAccessEnv(t)
	fakeVolumes(t, "public")
	pw, done := slowUpload(t, a.svc, alice, "public", "slow.bin")
	pw.Write([]byte("abc"))
	deadline := time.Now().Add(10 * time.Second)
	for a.read("public/slow.bin") != "abc" {
		if time.Now().After(deadline) {
			t.Fatal("the upload isn't written in its folder")
		}
		time.Sleep(2 * time.Millisecond)
	}
	if names := a.names(alice, "public"); !slices.Contains(names, "slow.bin") {
		t.Errorf("listing during the upload: %v", names)
	}
	if left := a.tmp(); len(left) != 0 {
		t.Errorf("the staging folder holds %v", left)
	}
	pw.Close()
	if u := <-done; u.err != nil || u.stored != "public/slow.bin" {
		t.Fatalf("the upload: %+v", u)
	}
}

// eofHook runs fn when its body ends.
type eofHook struct {
	r  io.Reader
	fn func()
}

func (h eofHook) Read(p []byte) (int, error) {
	n, err := h.r.Read(p)
	if err == io.EOF {
		h.fn()
	}
	return n, err
}

// readHook runs fn before each read of its body.
type readHook struct {
	r  io.Reader
	fn func()
}

func (h readHook) Read(p []byte) (int, error) {
	h.fn()
	return h.r.Read(p)
}

// A folder that moved to another file system while the body arrived gets
// the staged file copied into it.
func TestAStagedUploadIsCopiedIntoAFolderNowOnAnotherFileSystem(t *testing.T) {
	a := newAccessEnv(t)
	var moved atomic.Bool
	orig := sameVolume
	sameVolume = func(root *os.Root, x, y string) (bool, bool, error) {
		if moved.Load() && path.Base(filepath.ToSlash(y)) == "public" {
			return false, false, nil
		}
		return orig(root, x, y)
	}
	t.Cleanup(func() { sameVolume = orig })
	body := eofHook{strings.NewReader("copied"), func() { moved.Store(true) }}
	stored, size, err := a.svc.Create(as(alice), "public", "a.bin", body, -1)
	if err != nil || stored != "public/a.bin" || size != 6 {
		t.Fatalf("the upload: %q, %d, %v", stored, size, err)
	}
	if a.read("public/a.bin") != "copied" {
		t.Errorf("content %q", a.read("public/a.bin"))
	}
	info, _ := os.Stat(filepath.Join(a.root, "public/a.bin"))
	if rec, _ := a.record("public/a.bin"); rec.User != alice || rec.Size == nil || *rec.Size != 6 || info == nil || *rec.MTime != info.ModTime().UnixNano() {
		t.Errorf("record: %+v", rec)
	}
	if left := a.tmp(); len(left) != 0 {
		t.Errorf("the staging folder holds %v", left)
	}
	if evs := a.rec.all(); len(evs) != 1 || evs[0].Outcome != events.OutcomeOK || evs[0].Resolved != "public/a.bin" {
		t.Errorf("events: %+v", evs)
	}
}

// The staged copy is measured like any upload on the served disk.
func TestAStagedUploadUsesTheLedger(t *testing.T) {
	var free atomic.Int64
	free.Store(10 << 20)
	e, _, l := newSpaceEnv(t, func() (int64, error) { return free.Load(), nil }, 4<<20)
	_, _, err := e.svc.Create(bg, "", "big.bin", strings.NewReader("x"), 7<<20)
	is(t, err, ErrInsufficientStorage, "7 MiB with 6 MiB above the floor")
	if left := e.tmp(); len(left) != 0 {
		t.Errorf("a refused upload staged %v", left)
	}

	l.CheckEvery = 1
	body := &failingReader{data: "abc", err: io.EOF}
	free.Store(4 << 20)
	_, _, err = e.svc.Create(bg, "", "unknown.bin", readHook{body, func() { free.Store(3 << 20) }}, -1)
	is(t, err, ErrInsufficientStorage, "a body of unknown size that reaches the floor")
	if e.exists("unknown.bin") {
		t.Error("the refused upload was placed")
	}
	if left := e.tmp(); len(left) != 0 {
		t.Errorf("the staging folder holds %v", left)
	}
	if l.Reserved() != 0 {
		t.Errorf("reservation not released: %d", l.Reserved())
	}
}

func TestAStagedUploadAsksAgainOnceItHoldsTheLock(t *testing.T) {
	e := newEnv(t)
	a := &pausesAfter{fakeAuditor: fakeAuditor{t: t}, n: 1}
	e.svc = asAdmin(New(e.sb, &recorder{}, WithAudit(a)))
	a.svc = e.svc
	if _, _, err := e.svc.Create(bg, "", "up.txt", strings.NewReader("x"), 1); !errors.Is(err, events.ErrChangesPaused) {
		t.Errorf("paused while the body arrived = %v", err)
	}
	if e.exists("up.txt") {
		t.Error("the upload was placed after changes were paused")
	}
	if left := e.tmp(); len(left) != 0 {
		t.Errorf("the staging folder holds %v", left)
	}
}

// Without a usable staging folder, an upload is written in its folder and
// nothing is kept where .gocalbox points.
func TestAnUploadWithoutAStagingFolderIsWrittenInPlace(t *testing.T) {
	a := newAccessEnv(t)
	WithStaging(&sandbox.Staging{Problem: errors.New("a symlink")})(a.svc)
	os.RemoveAll(filepath.Join(a.root, sandbox.ReservedName))
	a.mkdir(admin, "public", "victim")
	if err := os.Symlink(filepath.Join("public", "victim"), filepath.Join(a.root, sandbox.ReservedName)); err != nil {
		t.Skipf("no symlinks here: %v", err)
	}
	a.upload(alice, "public", "a.bin", "direct")
	if a.read("public/a.bin") != "direct" {
		t.Errorf("content %q", a.read("public/a.bin"))
	}
	if got := a.listing(admin, "public/victim"); !maps.Equal(got, map[string]string{}) {
		t.Errorf("the folder .gocalbox points to holds %v", got)
	}
}

// A name taken by a folder while the upload ran is skipped like a file.
func TestAStagedUploadSkipsAFolderThatTookItsName(t *testing.T) {
	a := newAccessEnv(t)
	pw, done := slowUpload(t, a.svc, alice, "public", "x")
	pw.Write([]byte("abc"))
	a.stagedSize(3)
	a.mkdir(bob, "public", "x")
	pw.Close()
	if u := <-done; u.err != nil || u.stored != "public/x (1)" {
		t.Fatalf("the upload: %+v", u)
	}
	if info, err := os.Stat(filepath.Join(a.root, "public/x")); err != nil || !info.IsDir() {
		t.Errorf("bob's folder: %v, %v", info, err)
	}
}

// Each refusal the direct write gave before reading the body, the staged
// upload gives before reading it too.
func TestAStagedUploadIsRefusedBeforeItsBody(t *testing.T) {
	a := newAccessEnv(t)
	a.write("public/file", "x")
	for _, tc := range []struct {
		what, user, dir, name string
		want                  error
	}{
		{"a viewer", carol, "media", "a.bin", ErrForbidden},
		{"a reserved name", alice, "public", ".gocalbox", sandbox.ErrReserved},
		{"an invalid name", alice, "public", "bad\x01name", ErrInvalidName},
		{"a folder that is a file", alice, "public/file", "a.bin", ErrParentNotFound},
		{"no account", "u-nobody", "public", "a.bin", ErrParentNotFound},
	} {
		if _, _, err := a.svc.Create(as(tc.user), tc.dir, tc.name, untouched{t}, -1); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", tc.what, err, tc.want)
		}
	}
	e, _, au := newAuditedEnv(t)
	au.paused = true
	if _, _, err := e.svc.Create(bg, "", "a.bin", untouched{t}, -1); !errors.Is(err, events.ErrChangesPaused) {
		t.Errorf("changes paused: %v", err)
	}
	if left := a.tmp(); len(left) != 0 {
		t.Errorf("the staging folder holds %v", left)
	}
}

// nobody is the policy of a server that knows no user, as for a disabled
// one: no subject and no bindings at all.
type nobody struct{}

func (nobody) Subject(context.Context) (Subject, bool) { return Subject{}, false }
func (nobody) UserName(string) (string, bool)          { return "", false }

func TestAnUploadWithoutAnAccountIsRefusedAsForAMissingFolder(t *testing.T) {
	e := newEnv(t)
	e.svc.SetPolicy(nobody{})
	e.write("d/keep", "")
	e.symlink(e.outside, "out")
	for _, dir := range []string{"", "d", "out", "missing"} {
		_, _, err := e.svc.Create(bg, dir, "a.bin", untouched{t}, -1)
		hidden(t, err, ErrParentNotFound, "no account, into "+dir)
	}
}

// tmp is made again, private to the server, if it was removed.
func TestTmpIsMadeAgainPrivate(t *testing.T) {
	e := newEnv(t)
	tmp := filepath.Join(e.root, filepath.FromSlash(sandbox.TmpDir))
	if _, _, err := e.svc.Create(bg, "", "a.bin", strings.NewReader("x"), -1); err != nil {
		t.Fatal(err)
	}
	os.RemoveAll(tmp)
	if _, _, err := e.svc.Create(bg, "", "b.bin", strings.NewReader("x"), -1); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(tmp); err != nil || runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
		t.Errorf("tmp: %v, %v", info, err)
	}
}

// movedAway makes the folder named dir count as being on another file
// system, and, with disk, as sharing the served disk, once moved is set.
func movedAway(t *testing.T, dir string, disk bool, moved *atomic.Bool) {
	orig := sameVolume
	sameVolume = func(root *os.Root, x, y string) (bool, bool, error) {
		if moved.Load() && path.Base(filepath.ToSlash(y)) == dir {
			return false, disk, nil
		}
		return orig(root, x, y)
	}
	t.Cleanup(func() { sameVolume = orig })
}

// shrinkingFree is a body of n zero bytes that takes what it delivers from
// the free space.
type shrinkingFree struct {
	left int64
	free *atomic.Int64
}

func (s *shrinkingFree) Read(p []byte) (int, error) {
	if s.left == 0 {
		return 0, io.EOF
	}
	n := int(min(int64(len(p)), s.left))
	clear(p[:n])
	s.left -= int64(n)
	s.free.Add(-int64(n))
	return n, nil
}

// The copy into a folder that moved to a bind mount of the served disk is
// measured for the whole file before it starts, and the staged upload's
// reservation is given back first.
func TestTheCopyIsMeasuredInsteadOfTheStagedUpload(t *testing.T) {
	for _, tc := range []struct {
		minFree, size, hint int64
		fits                bool
	}{{2 << 20, 3 << 20, 8 << 20, true}, {7 << 20, 2 << 20, 3 << 20, false}} {
		t.Run(fmt.Sprintf("fits %v", tc.fits), func(t *testing.T) {
			var free atomic.Int64
			free.Store(10 << 20)
			e, _, l := newSpaceEnv(t, func() (int64, error) { return free.Load(), nil }, tc.minFree)
			e.write("d/keep", "")
			var moved atomic.Bool
			movedAway(t, "d", true, &moved)
			body := eofHook{&shrinkingFree{left: tc.size, free: &free}, func() { moved.Store(true) }}
			stored, size, err := e.svc.Create(bg, "d", "a.bin", body, tc.hint)
			if tc.fits && (err != nil || stored != "d/a.bin" || size != tc.size) {
				t.Errorf("a copy that fits: %q, %d, %v", stored, size, err)
			}
			if !tc.fits && (!errors.Is(err, ErrInsufficientStorage) || e.exists("d/a.bin") || size != tc.size) {
				t.Errorf("a copy that doesn't fit: %d, %v; written %v", size, err, e.exists("d/a.bin"))
			}
			if l.Reserved() != 0 {
				t.Errorf("reservation not released: %d", l.Reserved())
			}
		})
	}
}

// A folder that vanished before the copy: nothing is written anywhere, and
// the received size is reported.
func TestACopyIntoAVanishedFolderPlacesNothing(t *testing.T) {
	e, rec, _ := newAuditedEnv(t)
	e.write("d/keep", "")
	var moved atomic.Bool
	orig := sameVolume
	sameVolume = func(root *os.Root, x, y string) (bool, bool, error) {
		if moved.Load() && path.Base(filepath.ToSlash(y)) == "d" {
			os.RemoveAll(filepath.Join(e.root, "d"))
			return false, false, nil
		}
		return orig(root, x, y)
	}
	t.Cleanup(func() { sameVolume = orig })
	body := eofHook{strings.NewReader("abc"), func() { moved.Store(true) }}
	stored, size, err := e.svc.Create(bg, "d", "a.bin", body, -1)
	if !errors.Is(err, ErrParentNotFound) || stored != "" || size != 3 {
		t.Errorf("the upload: %q, %d, %v", stored, size, err)
	}
	if e.exists("a.bin") || len(e.tmp()) != 0 {
		t.Errorf("written into the root: %v; staged: %v", e.exists("a.bin"), e.tmp())
	}
	if ev := rec.last(t); ev.Size != 3 {
		t.Errorf("event: %+v", ev)
	}
}

// A staged file gone before the copy fails the upload, which reports the
// size of the body it received.
func TestACopyWhoseStagedFileIsGoneFails(t *testing.T) {
	e := newEnv(t)
	e.write("d/keep", "")
	var moved atomic.Bool
	orig := sameVolume
	sameVolume = func(root *os.Root, x, y string) (bool, bool, error) {
		if moved.Load() && path.Base(filepath.ToSlash(y)) == "d" {
			for _, name := range e.tmp() {
				os.Remove(filepath.Join(e.root, filepath.FromSlash(sandbox.TmpDir), name))
			}
			return false, false, nil
		}
		return orig(root, x, y)
	}
	t.Cleanup(func() { sameVolume = orig })
	stored, size, err := e.svc.Create(bg, "d", "a.bin", eofHook{strings.NewReader("abc"), func() { moved.Store(true) }}, -1)
	if err == nil || stored != "" || size != 3 || e.exists("d/a.bin") {
		t.Errorf("the upload: %q, %d, %v", stored, size, err)
	}
}

// The copy closes the staged file it opened.
func TestTheCopyClosesTheStagedFile(t *testing.T) {
	if _, err := os.ReadDir("/proc/self/fd"); err != nil {
		t.Skip("no /proc/self/fd here")
	}
	fds := func() int { entries, _ := os.ReadDir("/proc/self/fd"); return len(entries) }
	// A collection would close a leaked file through its finalizer.
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	e := newEnv(t)
	e.write("d/keep", "")
	var moved atomic.Bool
	movedAway(t, "d", false, &moved)
	if _, _, err := e.svc.Create(bg, "", "warm.bin", strings.NewReader("x"), -1); err != nil {
		t.Fatal(err)
	}
	before := fds()
	if _, _, err := e.svc.Create(bg, "d", "a.bin", eofHook{strings.NewReader("abc"), func() { moved.Store(true) }}, -1); err != nil {
		t.Fatal(err)
	}
	if after := fds(); after != before {
		t.Errorf("open files: %d before, %d after", before, after)
	}
}

// Without hard links the staged file is renamed, and there is no name left
// to remove: nothing is logged.
func TestTheRenamePathLogsNothing(t *testing.T) {
	var buf logBuffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	e := newEnv(t)
	WithStaging(&sandbox.Staging{Links: false})(e.svc)
	if _, _, err := e.svc.Create(bg, "", "a.bin", strings.NewReader("x"), -1); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); got != "" {
		t.Errorf("log: %s", got)
	}
}

type logBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// The direct write still reserves on the ledger, and gives the room back.
func TestADirectUploadIsMeasured(t *testing.T) {
	e, _, l := newSpaceEnv(t, func() (int64, error) { return 10 << 20, nil }, 4<<20)
	directUploads(e.svc)
	_, _, err := e.svc.Create(bg, "", "big.bin", untouched{t}, 7<<20)
	is(t, err, ErrInsufficientStorage, "7 MiB with 6 MiB above the floor, written in place")
	if _, _, err := e.svc.Create(bg, "", "fits.bin", strings.NewReader("x"), 6<<20); err != nil {
		t.Fatal(err)
	}
	if l.Reserved() != 0 {
		t.Errorf("reservation not released: %d", l.Reserved())
	}
}

// A failing disk is named so on the direct path.
func TestADirectWriteThatFailsIsAWrite(t *testing.T) {
	var free atomic.Int64
	free.Store(10 << 20)
	e, _, l := newSpaceEnv(t, func() (int64, error) { return free.Load(), nil }, 4<<20)
	directUploads(e.svc)
	l.CheckEvery = 1
	body := readHook{&failingReader{data: "abc", err: io.EOF}, func() { free.Store(3 << 20) }}
	_, _, err := e.svc.Create(bg, "", "a.bin", body, -1)
	if !errors.Is(err, ErrInsufficientStorage) || !strings.HasPrefix(err.Error(), "write file: ") {
		t.Errorf("err = %v", err)
	}
}

// Another process that takes each name chosen for a staged upload, three
// times in a row, gets it refused as already existing; it isn't written
// directly instead.
func TestAStagedUploadThatLosesItsNameThreeTimesIsRefused(t *testing.T) {
	e := newEnv(t)
	e.write("d/keep", "")
	var ended atomic.Bool
	var taken int
	orig := sameVolume
	sameVolume = func(root *os.Root, x, y string) (bool, bool, error) {
		if ended.Load() && path.Base(filepath.ToSlash(y)) == "d" {
			name := "a.bin"
			if taken > 0 {
				name = fmt.Sprintf("a (%d).bin", taken)
			}
			e.write("d/"+name, "another process's")
			taken++
		}
		return orig(root, x, y)
	}
	t.Cleanup(func() { sameVolume = orig })
	stored, _, err := e.svc.Create(bg, "d", "a.bin", eofHook{strings.NewReader("abc"), func() { ended.Store(true) }}, -1)
	if !errors.Is(err, ErrExists) || stored != "" {
		t.Errorf("the upload: %q, %v", stored, err)
	}
	if len(e.tmp()) != 0 {
		t.Errorf("staged: %v", e.tmp())
	}
}

// A body that broke off is named so on the direct path too.
func TestADirectBodyThatBrokeOffIsNotAWrite(t *testing.T) {
	e := newEnv(t)
	directUploads(e.svc)
	_, _, err := e.svc.Create(bg, "", "a.bin", &failingReader{data: "half", err: fmt.Errorf("%w: unexpected EOF", ErrBodyAborted)}, -1)
	if !errors.Is(err, ErrBodyAborted) || strings.HasPrefix(err.Error(), "write file: ") {
		t.Errorf("err = %v", err)
	}
}

// barrier ends its body only once every upload of a round has read its
// own, so that all of them choose a name at once.
type barrier struct {
	r     io.Reader
	ready *sync.WaitGroup
	start <-chan struct{}
	once  sync.Once
}

func (b *barrier) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	if err == io.EOF {
		b.once.Do(func() { b.ready.Done(); <-b.start })
	}
	return n, err
}

// Many staged uploads of one name ending together all land, each under a
// name of its own.
func TestManyStagedUploadsOfOneNameAllLand(t *testing.T) {
	e := newEnv(t)
	const n = 64
	for round := range 5 {
		var ready, done sync.WaitGroup
		start := make(chan struct{})
		ready.Add(n)
		names := make(chan string, n)
		for i := range n {
			done.Add(1)
			go func() {
				defer done.Done()
				body := &barrier{r: strings.NewReader(fmt.Sprint(round, "-", i)), ready: &ready, start: start}
				stored, _, err := e.svc.Create(bg, "", fmt.Sprintf("r%d.txt", round), body, -1)
				if err != nil {
					t.Errorf("round %d: %v", round, err)
				}
				names <- stored
			}()
		}
		ready.Wait()
		close(start)
		done.Wait()
		close(names)
		seen := map[string]bool{}
		for name := range names {
			if seen[name] {
				t.Errorf("round %d: %q handed out twice", round, name)
			}
			seen[name] = true
		}
	}
}
