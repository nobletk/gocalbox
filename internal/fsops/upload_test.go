package fsops

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nobletk/gocalbox/internal/authz"
	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/sandbox"
	"github.com/nobletk/gocalbox/internal/state"
)

// stage writes content as a staged upload and returns its path.
func (a *accessEnv) stage(content string) string {
	a.t.Helper()
	staged := path.Join(sandbox.UploadsDir, fmt.Sprintf("%032x", time.Now().UnixNano()), "data")
	a.write(staged, content)
	return staged
}

func (a *accessEnv) tmpEntries() []os.DirEntry {
	entries, _ := os.ReadDir(filepath.Join(a.root, filepath.FromSlash(sandbox.TmpDir)))
	return entries
}

func logTo(paths *[]string) func(string) error {
	return func(p string) error { *paths = append(*paths, p); return nil }
}

func TestWho(t *testing.T) {
	a := newAccessEnv(t)
	for _, tc := range []struct {
		user      string
		admin, ok bool
	}{{admin, true, true}, {alice, false, true}, {"u-nobody", false, false}} {
		id, isAdmin, ok := a.svc.Who(as(tc.user))
		if isAdmin != tc.admin || ok != tc.ok || (ok && id != tc.user) {
			t.Errorf("%s: %q, admin %v, ok %v", tc.user, id, isAdmin, ok)
		}
	}
}

func TestUserNameCountsOnlyDeletedUsersAsGone(t *testing.T) {
	svc := New(newEnv(t).sb, nil)
	if name, ok := svc.UserName(alice); name != "" || !ok {
		t.Errorf("without a policy: %q, %v", name, ok)
	}
	a := newAccessEnv(t)
	if _, ok := a.svc.UserName("u-deleted"); ok {
		t.Error("a user the policy doesn't know is not gone")
	}
}

func TestPrepareUploadDecidesLikeAnUpload(t *testing.T) {
	a := newAccessEnv(t)
	a.write("public/file.txt", "x")
	os.MkdirAll(filepath.Join(a.root, "Users", "Alice"), 0o755)

	clean, folder, err := a.svc.PrepareUpload(as(alice), "/users/alice/", "a.txt")
	if err != nil || clean != "users/alice" || folder != "users/alice" {
		t.Fatalf("alice into her home: %q, %q, %v", clean, folder, err)
	}
	if a.exists("users/alice/a.txt") || len(a.tmpEntries()) != 0 {
		t.Errorf("PrepareUpload left something behind: %v", a.tmpEntries())
	}
	if n := len(a.rec.all()); n != 0 {
		t.Errorf("PrepareUpload published %d events", n)
	}

	hidden(t, errOf3(a.svc.PrepareUpload(as(alice), "users/bob", "a.txt")), ErrParentNotFound, "alice into bob's home")
	hidden(t, errOf3(a.svc.PrepareUpload(as(alice), "users/bob/missing", "a.txt")), ErrParentNotFound, "alice into a missing folder in bob's home")
	shown(t, errOf3(a.svc.PrepareUpload(as(alice), "users/alice/missing", "a.txt")), ErrParentNotFound, "alice into a missing folder of hers")
	shown(t, errOf3(a.svc.PrepareUpload(as(admin), "public/file.txt", "a.txt")), ErrParentNotFound, "into a file")
	shown(t, errOf3(a.svc.PrepareUpload(as(bob), "projects/team", "a.txt")), ErrForbidden, "bob into a folder he only views")
	shown(t, errOf3(a.svc.PrepareUpload(as(carol), "public", "a.txt")), ErrForbidden, "a viewer into public")
	hidden(t, errOf3(a.svc.PrepareUpload(as("u-nobody"), "public", "a.txt")), ErrParentNotFound, "an unknown user")
	for _, name := range []string{"", "a/b", "..", " lead", strings.Repeat("x", 256)} {
		shown(t, errOf3(a.svc.PrepareUpload(as(admin), "public", name)), ErrInvalidName, fmt.Sprintf("name %q", name))
	}
	for _, name := range []string{".gocalbox", ".GoCalBox.", "GOCALB~1"} {
		shown(t, errOf3(a.svc.PrepareUpload(as(admin), "public", name)), sandbox.ErrReserved, fmt.Sprintf("name %q", name))
	}
	shown(t, errOf3(a.svc.PrepareUpload(as(admin), "../outside", "a.txt")), sandbox.ErrTraversal, "a folder outside the root")
	if _, _, err := a.svc.PrepareUpload(as(admin), ".gocalbox/uploads", "a.txt"); !errors.Is(err, sandbox.ErrReserved) {
		t.Errorf("into the staging folder: %v", err)
	}
	if len(a.tmpEntries()) != 0 {
		t.Errorf("refusals left %v in the staging folder", a.tmpEntries())
	}
}

func TestPrepareUploadRefusesAnotherFileSystem(t *testing.T) {
	a := newAccessEnv(t)
	os.MkdirAll(filepath.Join(a.root, "public", "ext"), 0o755)
	fakeVolumes(t, "ext")
	shown(t, errOf3(a.svc.PrepareUpload(as(alice), "public/ext", "a.txt")), ErrCrossDevice, "into another file system")
}

// The name is tried in the staging folder; without it, nothing is prepared.
func TestPrepareUploadTriesTheName(t *testing.T) {
	a := newAccessEnv(t)
	tmp := filepath.Join(a.root, filepath.FromSlash(sandbox.TmpDir))
	os.RemoveAll(tmp)
	os.WriteFile(tmp, []byte("not a folder"), 0o600)
	if _, _, err := a.svc.PrepareUpload(as(alice), "users/alice", "a.txt"); err == nil {
		t.Error("prepared without trying the name")
	}
}

// A folder whose volume can't be told counts as the served one: the link
// that places the file is then what finds another file system.
func TestPrepareUploadWithAnUnknownVolume(t *testing.T) {
	a := newAccessEnv(t)
	orig := sameVolume
	sameVolume = func(*os.Root, string, string) (bool, bool, error) { return false, false, errors.New("no identity") }
	t.Cleanup(func() { sameVolume = orig })
	ok(t, errOf3(a.svc.PrepareUpload(as(alice), "users/alice", "a.txt")), "an unknown volume")
}

func TestPrepareUploadWhilePaused(t *testing.T) {
	a := newAccessEnv(t)
	audit := &fakeAuditor{t: t, svc: a.svc, paused: true}
	WithAudit(audit)(a.svc)
	if _, _, err := a.svc.PrepareUpload(as(alice), "users/alice", "a.txt"); !errors.Is(err, events.ErrChangesPaused) {
		t.Errorf("while paused: %v", err)
	}
}

func TestMayUpload(t *testing.T) {
	a := newAccessEnv(t)
	ok(t, a.svc.MayUpload(as(alice), "users/alice/videos"), "alice into her home")
	ok(t, a.svc.MayUpload(as(admin), "secret"), "an admin anywhere")
	hidden(t, a.svc.MayUpload(as(alice), "users/bob"), ErrParentNotFound, "alice into bob's home")
	shown(t, a.svc.MayUpload(as(bob), "projects/team"), ErrForbidden, "bob into a folder he views")
	shown(t, a.svc.MayUpload(as(admin), "public/.gocalbox"), sandbox.ErrReserved, "into a reserved folder")
	hidden(t, a.svc.MayUpload(as("u-nobody"), "public"), ErrParentNotFound, "an unknown user")

	a.policy.roles[alice] = authz.Viewer
	shown(t, a.svc.MayUpload(as(alice), "users/alice"), ErrForbidden, "alice after her demotion")
}

func TestAdoptPlacesTheFileForItsOwner(t *testing.T) {
	a := newAccessEnv(t)
	staged := a.stage("hello")
	var logged []string
	p, ev, err := a.svc.Adopt(as(alice), staged, "/users/alice", "a.txt", logTo(&logged))
	if err != nil || p != "users/alice/a.txt" {
		t.Fatalf("Adopt: %q, %v", p, err)
	}
	if a.read(p) != "hello" || len(logged) != 1 || logged[0] != p {
		t.Errorf("content %q, logged %v", a.read(p), logged)
	}
	if !a.exists(staged) {
		t.Error("the staged name is gone; it is the caller's to remove")
	}
	rec, found := a.record(p)
	info, _ := os.Stat(filepath.Join(a.root, p))
	if !found || rec.User != alice || rec.Dir || rec.Size == nil || *rec.Size != 5 || rec.MTime == nil || *rec.MTime != info.ModTime().UnixNano() {
		t.Errorf("record %+v", rec)
	}
	if ev.Type != events.FileUploaded || ev.Outcome != events.OutcomeOK || ev.Path != "/users/alice/a.txt" ||
		ev.Resolved != p || ev.Size != 5 || ev.Actor.ID != alice {
		t.Errorf("event %+v", ev)
	}
	if n := len(a.rec.all()); n != 0 {
		t.Errorf("Adopt published %d events itself", n)
	}

	p2, ev2, err := a.svc.Adopt(as(alice), a.stage("again"), "users/alice", "a.txt", logTo(&logged))
	if err != nil || p2 != "users/alice/a (1).txt" || a.read(p) != "hello" {
		t.Errorf("a second upload of one name: %q, %v", p2, err)
	}
	if ev2.Path != "users/alice/a (1).txt" || ev2.Resolved != p2 {
		t.Errorf("the second upload's event names %q, %q", ev2.Path, ev2.Resolved)
	}
}

func TestAdoptRefusals(t *testing.T) {
	a := newAccessEnv(t)
	never := func(string) error { t.Error("a refused Adopt logged a name"); return nil }
	staged := a.stage("x")
	for _, tc := range []struct {
		user, dir, name string
		want            error
	}{
		{alice, "users/bob", "a.txt", ErrParentNotFound},
		{bob, "projects/team", "a.txt", ErrForbidden},
		{alice, "users/alice/missing", "a.txt", ErrParentNotFound},
		{alice, "users/alice", "a/b", ErrInvalidName},
		{"u-nobody", "public", "a.txt", ErrParentNotFound},
	} {
		if _, _, err := a.svc.Adopt(as(tc.user), staged, tc.dir, tc.name, never); !errors.Is(err, tc.want) {
			t.Errorf("%s into %s/%s: %v, want %v", tc.user, tc.dir, tc.name, err, tc.want)
		}
	}
	for _, bad := range []string{"public/x", sandbox.UploadsDir + "/../../public/x", sandbox.UploadsDir + "/missing/data"} {
		a.write("public/x", "x")
		if _, _, err := a.svc.Adopt(as(admin), bad, "public", "y.txt", never); err == nil {
			t.Errorf("adopted %q", bad)
		}
	}
	if !a.exists(staged) {
		t.Error("a refused Adopt touched the staged file")
	}
}

func TestAdoptPlacesNothingWhenTheLogFails(t *testing.T) {
	a := newAccessEnv(t)
	staged := a.stage("x")
	boom := errors.New("disk full")
	if _, _, err := a.svc.Adopt(as(alice), staged, "users/alice", "a.txt", func(string) error { return boom }); !errors.Is(err, boom) {
		t.Errorf("error %v", err)
	}
	if a.exists("users/alice/a.txt") {
		t.Error("placed although its name wasn't logged")
	}
}

// While the chosen name is being logged, the lock is free: another upload
// may take the name, the folder may move, and the user's rights may change.
func TestAdoptDecidesAgainAfterLogging(t *testing.T) {
	t.Run("the name is taken", func(t *testing.T) {
		a := newAccessEnv(t)
		var logged []string
		p, _, err := a.svc.Adopt(as(alice), a.stage("mine"), "users/alice", "a.txt", func(p string) error {
			logged = append(logged, p)
			if len(logged) == 1 {
				a.write(p, "theirs")
			}
			return nil
		})
		if err != nil || p != "users/alice/a (1).txt" || a.read("users/alice/a.txt") != "theirs" || len(logged) != 2 {
			t.Errorf("%q, %v, logged %v", p, err, logged)
		}
	})

	t.Run("names keep being taken", func(t *testing.T) {
		a := newAccessEnv(t)
		var logged []string
		_, _, err := a.svc.Adopt(as(alice), a.stage("mine"), "users/alice", "a.txt", func(p string) error {
			logged = append(logged, p)
			a.write(p, "theirs")
			return nil
		})
		if !errors.Is(err, ErrExists) || len(logged) != adoptRounds {
			t.Errorf("%v after %d rounds", err, len(logged))
		}
		for _, p := range logged {
			if a.read(p) != "theirs" {
				t.Errorf("%s was replaced", p)
			}
		}
	})

	t.Run("the folder moves", func(t *testing.T) {
		a := newAccessEnv(t)
		os.MkdirAll(filepath.Join(a.root, "users", "alice", "x"), 0o755)
		os.MkdirAll(filepath.Join(a.root, "users", "alice", "y"), 0o755)
		a.symlink("x", "users/alice/link")
		var logged []string
		p, _, err := a.svc.Adopt(as(alice), a.stage("mine"), "users/alice/link", "a.txt", func(p string) error {
			logged = append(logged, p)
			if len(logged) == 1 {
				os.Remove(filepath.Join(a.root, "users", "alice", "link"))
				os.Symlink("y", filepath.Join(a.root, "users", "alice", "link"))
			}
			return nil
		})
		if err != nil || p != "users/alice/y/a.txt" || a.exists("users/alice/x/a.txt") {
			t.Errorf("%q, %v, logged %v", p, err, logged)
		}
	})

	t.Run("the user is demoted", func(t *testing.T) {
		a := newAccessEnv(t)
		_, _, err := a.svc.Adopt(as(alice), a.stage("mine"), "users/alice", "a.txt", func(string) error {
			a.policy.roles[alice] = authz.Viewer
			return nil
		})
		shown(t, err, ErrForbidden, "after a demotion while logging")
		if a.exists("users/alice/a.txt") {
			t.Error("placed for a viewer")
		}
	})

	t.Run("changes were paused before", func(t *testing.T) {
		a := newAccessEnv(t)
		WithAudit(&fakeAuditor{t: t, svc: a.svc, paused: true})(a.svc)
		_, _, err := a.svc.Adopt(as(alice), a.stage("mine"), "users/alice", "a.txt", func(string) error {
			t.Error("a name was logged while changes were paused")
			return nil
		})
		if !errors.Is(err, events.ErrChangesPaused) {
			t.Errorf("paused: %v", err)
		}
	})

	t.Run("changes are paused", func(t *testing.T) {
		a := newAccessEnv(t)
		audit := &fakeAuditor{t: t, svc: a.svc}
		WithAudit(audit)(a.svc)
		_, _, err := a.svc.Adopt(as(alice), a.stage("mine"), "users/alice", "a.txt", func(string) error {
			audit.paused = true
			return nil
		})
		if !errors.Is(err, events.ErrChangesPaused) || a.exists("users/alice/a.txt") {
			t.Errorf("paused while logging: %v", err)
		}
	})

	t.Run("the folder is now on another file system", func(t *testing.T) {
		a := newAccessEnv(t)
		os.MkdirAll(filepath.Join(a.root, "users", "alice", "ext"), 0o755)
		_, _, err := a.svc.Adopt(as(alice), a.stage("mine"), "users/alice/ext", "a.txt", func(string) error {
			fakeVolumes(t, "ext")
			return nil
		})
		shown(t, err, ErrCrossDevice, "moved to another file system")
	})
}

// Without hard links the staged file is renamed, which would replace a file
// that took its name; so the name is checked under the lock first.
func TestAdoptRenamesWithoutHardLinks(t *testing.T) {
	a := newAccessEnv(t)
	WithStaging(&sandbox.Staging{Links: false})(a.svc)
	staged := a.stage("mine")
	var logged []string
	p, _, err := a.svc.Adopt(as(alice), staged, "users/alice", "a.txt", func(p string) error {
		logged = append(logged, p)
		if len(logged) == 1 {
			a.write(p, "theirs")
		}
		return nil
	})
	if err != nil || p != "users/alice/a (1).txt" || a.read(p) != "mine" || a.read("users/alice/a.txt") != "theirs" {
		t.Fatalf("%q, %v", p, err)
	}
	if a.exists(staged) {
		t.Error("the staged file is still there after a rename")
	}
	if a.uploader(p) != alice {
		t.Errorf("record %q", a.uploader(p))
	}
}

// A placement whose record can't be written is taken back, and the upload
// can be finished again later.
func TestAdoptTakesBackAPlacementWithoutARecord(t *testing.T) {
	for _, links := range []bool{true, false} {
		t.Run(fmt.Sprintf("links %v", links), func(t *testing.T) {
			a := newAccessEnv(t)
			a.svc.links = links
			staged := a.stage("mine")
			a.db.Close()
			if _, _, err := a.svc.Adopt(as(alice), staged, "users/alice", "a.txt", func(string) error { return nil }); err == nil || !strings.Contains(err.Error(), "record uploader") {
				t.Fatalf("placed without a record: %v", err)
			}
			if a.exists("users/alice/a.txt") || a.read(staged) != "mine" {
				t.Error("the placement wasn't taken back")
			}
		})
	}
}

func TestRecordAdopted(t *testing.T) {
	a := newAccessEnv(t)
	a.write("users/alice/a.txt", "hello")
	info, _ := os.Stat(filepath.Join(a.root, "users", "alice", "a.txt"))
	mtime := info.ModTime().UnixNano()

	ok(t, a.svc.RecordAdopted(alice, "users/alice/a.txt", 5, mtime), "a missing record")
	if rec, _ := a.record("users/alice/a.txt"); rec.User != alice || rec.Size == nil || *rec.Size != 5 {
		t.Fatalf("record %+v", rec)
	}
	first, _ := a.record("users/alice/a.txt")
	ok(t, a.svc.RecordAdopted(alice, "users/alice/a.txt", 5, mtime), "the record already there")
	if again, _ := a.record("users/alice/a.txt"); !again.Created.Equal(first.Created) {
		t.Error("the owner's own record was rewritten")
	}

	a.db.Update(func(tx *state.Tx) error {
		return tx.PutUploader("users/alice/a.txt", withIdentity(newRecord(bob, false), info))
	})
	ok(t, a.svc.RecordAdopted(alice, "users/alice/a.txt", 5, mtime), "a record of someone else for the same file")
	if a.uploader("users/alice/a.txt") != alice {
		t.Errorf("the stale record stayed: %q", a.uploader("users/alice/a.txt"))
	}

	a.write("users/alice/b.txt", "changed")
	a.putRecord("users/alice/b.txt", bob)
	if err := a.svc.RecordAdopted(alice, "users/alice/b.txt", 5, mtime); !errors.Is(err, ErrNotFound) {
		t.Errorf("a file that isn't the one placed: %v", err)
	}
	if a.uploader("users/alice/b.txt") != bob {
		t.Error("the record of a file that isn't the one placed was replaced")
	}
	for _, bad := range []string{"../x", "/users/alice/a.txt", "users/alice/../alice/a.txt", ".gocalbox/uploads/x", "."} {
		if err := a.svc.RecordAdopted(alice, bad, 5, mtime); !errors.Is(err, ErrInvalidName) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

// The single-request upload and Adopt number names the same way.
func TestCandidates(t *testing.T) {
	var got []string
	for c := range candidates(".env") {
		if got = append(got, c); len(got) == 3 {
			break
		}
	}
	if strings.Join(got, "|") != ".env|.env (1)|.env (2)" {
		t.Errorf("candidates %q", got)
	}
	got = nil
	for c := range candidates("a.tar.gz") {
		if got = append(got, c); len(got) == 2 {
			break
		}
	}
	if strings.Join(got, "|") != "a.tar.gz|a.tar (1).gz" {
		t.Errorf("candidates %q", got)
	}
}

func TestTheEngineCallsNeedAStagingFolder(t *testing.T) {
	a := newAccessEnv(t)
	staged := a.stage("x")
	WithStaging(&sandbox.Staging{Problem: errors.New("a symlink")})(a.svc)
	if _, _, err := a.svc.PrepareUpload(as(alice), "users/alice", "a.txt"); !errors.Is(err, ErrNoStaging) {
		t.Errorf("PrepareUpload: %v", err)
	}
	if _, _, err := a.svc.Adopt(as(alice), staged, "users/alice", "a.txt", func(string) error { return nil }); !errors.Is(err, ErrNoStaging) {
		t.Errorf("Adopt: %v", err)
	}
}

// On a case-insensitive volume the record is keyed by the spelling the
// folder stores, whatever spelling the upload named.
func TestAdoptRecordsTheStoredSpelling(t *testing.T) {
	a := newAccessEnv(t)
	if _, err := os.Stat(filepath.Join(a.root, "USERS", "ALICE")); err != nil {
		t.Skip("the test volume tells letter case apart")
	}
	p, _, err := a.svc.Adopt(as(alice), a.stage("x"), "USERS/ALICE", "a.txt", func(string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if a.uploader("users/alice/a.txt") != alice {
		t.Errorf("placed at %q, but the record isn't under the stored spelling", p)
	}
}

// When taking the placement back fails too, the file is placed: Adopt
// answers success, and the file, without a record, is left to admins.
func TestAdoptWhenTakingThePlacementBackFails(t *testing.T) {
	for _, links := range []bool{true, false} {
		t.Run(fmt.Sprintf("links %v", links), func(t *testing.T) {
			a := newAccessEnv(t)
			a.svc.links = links
			staged := a.stage("mine")
			orig := readNames
			armed := true
			readNames = func(root *os.Root, dir string) ([]string, error) {
				if armed && dir == "users/alice" {
					armed = false
					// The record's key can't be read, and the undo has nothing
					// to go back to.
					if links {
						os.Remove(filepath.Join(a.root, filepath.FromSlash(staged)))
					} else {
						os.RemoveAll(filepath.Join(a.root, filepath.FromSlash(path.Dir(staged))))
					}
					return nil, errors.New("cannot read the folder")
				}
				return orig(root, dir)
			}
			t.Cleanup(func() { readNames = orig })
			p, ev, err := a.svc.Adopt(as(alice), staged, "users/alice", "a.txt", func(string) error { return nil })
			if err != nil || p != "users/alice/a.txt" || ev.Size != 4 || a.read(p) != "mine" {
				t.Fatalf("%q, %+v, %v", p, ev, err)
			}
			if _, found := a.record(p); found {
				t.Error("a record was written although its key couldn't be read")
			}
		})
	}
}

// policyThatEnds acts as the wrapped policy for its first n answers, then as
// for an account an admin disabled or deleted meanwhile.
type policyThatEnds struct {
	*usersPolicy
	calls, n int
}

func (p *policyThatEnds) Subject(ctx context.Context) (Subject, bool) {
	if p.calls++; p.calls > p.n {
		return Subject{}, false
	}
	return p.usersPolicy.Subject(ctx)
}

// Wherever the account ends during Adopt, the call returns, leaves the lock
// free, and either places the file with the owner's record or places
// nothing.
func TestAdoptWhileTheAccountEnds(t *testing.T) {
	a := newAccessEnv(t)
	count := &policyThatEnds{usersPolicy: a.policy, n: 1 << 30}
	a.svc.SetPolicy(count)
	if _, _, err := a.svc.Adopt(as(alice), a.stage("x"), "users/alice", "count.txt", func(string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	for n := range count.calls {
		a := newAccessEnv(t)
		a.svc.SetPolicy(&policyThatEnds{usersPolicy: a.policy, n: n})
		p, _, err := a.svc.Adopt(as(alice), a.stage("x"), "users/alice", "a.txt", func(string) error { return nil })
		if !a.svc.mu.TryLock() {
			t.Fatalf("after %d answers: the lock is still held", n)
		}
		a.svc.mu.Unlock()
		switch {
		case err == nil && a.uploader(p) != alice:
			t.Errorf("after %d answers: placed with the record %q", n, a.uploader(p))
		case err != nil && a.exists("users/alice/a.txt"):
			t.Errorf("after %d answers: %v, but the file was placed", n, err)
		}
	}
}

func TestAdoptRefusesReservedNamesAndStrayPaths(t *testing.T) {
	a := newAccessEnv(t)
	never := func(string) error { t.Error("a name was logged"); return nil }
	for _, name := range []string{"GOCALB~1", ".gocalbox.", ".GOCALBOX"} {
		if _, _, err := a.svc.Adopt(as(alice), a.stage("x"), "users/alice", name, never); !errors.Is(err, sandbox.ErrReserved) {
			t.Errorf("%q: %v", name, err)
		}
	}
	for _, p := range []string{sandbox.UploadsDir + `/..\..\users\bob\secret.txt`, sandbox.UploadsDir + "/a/../../x", "public/x", sandbox.ReservedName + "/lock"} {
		if isStaged(p) {
			t.Errorf("%q counts as staged", p)
		}
	}
}

// A section that panics under the lock still releases it.
func TestAdoptReleasesTheLockWhenASectionPanics(t *testing.T) {
	a := newAccessEnv(t)
	orig := readNames
	readNames = func(*os.Root, string) ([]string, error) { panic("injected") }
	t.Cleanup(func() { readNames = orig })
	func() {
		defer func() { recover() }()
		a.svc.Adopt(as(alice), a.stage("x"), "users/alice", "a.txt", func(string) error { return nil })
	}()
	if !a.svc.mu.TryLock() {
		t.Fatal("the lock is still held after a panic")
	}
	a.svc.mu.Unlock()
}
