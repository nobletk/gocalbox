package fsops

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nobletk/gocalbox/internal/authz"
	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/sandbox"
	"github.com/nobletk/gocalbox/internal/state"
)

const (
	admin = "u-admin"
	alice = "u-alice" // contributor, home users/alice
	bob   = "u-bob"   // contributor, home users/bob, viewer of projects/team
	carol = "u-carol" // viewer of /public and of media
)

type accessEnv struct {
	*env
	db     *state.DB
	rec    *recorder
	policy *usersPolicy
}

func newAccessEnv(t *testing.T) *accessEnv {
	t.Helper()
	e := newEnv(t)
	db, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	for _, d := range []string{"users/alice", "users/bob", "public", "media", "secret", "projects/team", "projects/other"} {
		if err := os.MkdirAll(filepath.Join(e.root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	p := &usersPolicy{
		roles: map[string]authz.Role{admin: authz.Admin, alice: authz.Contributor, bob: authz.Contributor, carol: authz.Viewer},
		bindings: authz.NewBindings([]authz.Binding{
			{Subject: alice, Folder: "users/alice", Grant: authz.GrantContributor, Home: true},
			{Subject: bob, Folder: "users/bob", Grant: authz.GrantContributor, Home: true},
			{Subject: authz.Everyone, Folder: "public", Grant: authz.GrantContributor},
			{Subject: carol, Folder: "media", Grant: authz.GrantViewer},
			{Subject: bob, Folder: "projects/team", Grant: authz.GrantViewer},
		}),
	}
	staging, err := sandbox.CheckStaging(e.sb.OSRoot())
	if err != nil || !staging.Usable() {
		t.Fatal(err, staging.Problem)
	}
	t.Cleanup(func() { staging.Close() })
	rec := &recorder{}
	e.svc = New(e.sb, rec, WithRecords(db), WithStaging(staging))
	e.svc.SetPolicy(p)
	return &accessEnv{env: e, db: db, rec: rec, policy: p}
}

func as(user string) context.Context { return events.WithActor(bg, events.Actor{ID: user}) }

func (a *accessEnv) upload(user, dir, name, content string) {
	a.t.Helper()
	if _, _, err := a.svc.Create(as(user), dir, name, strings.NewReader(content), -1); err != nil {
		a.t.Fatalf("%s uploads %s/%s: %v", user, dir, name, err)
	}
}

func (a *accessEnv) mkdir(user, parent, name string) {
	a.t.Helper()
	if _, err := a.svc.Mkdir(as(user), parent, name); err != nil {
		a.t.Fatalf("%s creates %s/%s: %v", user, parent, name, err)
	}
}

func (a *accessEnv) record(key string) (state.Uploader, bool) {
	a.t.Helper()
	var rec state.Uploader
	var ok bool
	err := a.db.View(func(tx *state.Tx) error {
		var err error
		rec, ok, err = tx.Uploader(key)
		return err
	})
	if err != nil {
		a.t.Fatal(err)
	}
	return rec, ok
}

func (a *accessEnv) uploader(key string) string {
	a.t.Helper()
	rec, _ := a.record(key)
	return rec.User
}

func (a *accessEnv) putRecord(key, user string) {
	a.t.Helper()
	err := a.db.Update(func(tx *state.Tx) error {
		return tx.PutUploader(key, state.Uploader{User: user, Created: time.Now().UTC()})
	})
	if err != nil {
		a.t.Fatal(err)
	}
}

// listing describes each entry of dir as user sees it: its uploader, or "-"
// for none, and its actions.
func (a *accessEnv) listing(user, dir string) map[string]string {
	a.t.Helper()
	entries, err := a.svc.List(as(user), dir)
	if err != nil {
		a.t.Fatalf("%s lists %s: %v", user, dir, err)
	}
	out := map[string]string{}
	for _, e := range entries {
		uploader := "-"
		if e.Uploader != nil {
			uploader = *e.Uploader
		}
		out[e.Name] = uploader + " " + strings.Join(e.Actions, ",")
	}
	return out
}

func (a *accessEnv) names(user, dir string) []string {
	return slices.Sorted(maps.Keys(a.listing(user, dir)))
}

func (a *accessEnv) canRead(user, p string) error {
	f, err := a.svc.Open(as(user), p)
	if err == nil {
		f.Close()
	}
	return err
}

// hidden checks that err answers as for a path that doesn't exist.
func hidden(t *testing.T, err, want error, what string) {
	t.Helper()
	if !errors.Is(err, want) || !isHidden(err) {
		t.Errorf("%s: err = %v, want %v as for a missing path", what, err, want)
	}
}

// shown checks that err is want, and not the answer for a hidden path.
func shown(t *testing.T, err, want error, what string) {
	t.Helper()
	if !errors.Is(err, want) || isHidden(err) {
		t.Errorf("%s: err = %v, want %v", what, err, want)
	}
}

func ok(t *testing.T, err error, what string) {
	t.Helper()
	if err != nil {
		t.Errorf("%s: %v", what, err)
	}
}

func TestRolesEndToEnd(t *testing.T) {
	a := newAccessEnv(t)
	a.upload(alice, "users/alice", "a.txt", "home")
	a.upload(alice, "public", "p.txt", "shared")

	shown(t, errOf(a.svc.Delete(as(bob), "public/p.txt")), ErrForbidden, "bob deletes alice's file")
	shown(t, errOf(a.svc.Move(as(bob), "public/p.txt", "public/q.txt")), ErrForbidden, "bob renames alice's file")
	ok(t, a.canRead(bob, "public/p.txt"), "bob reads alice's public file")
	hidden(t, a.canRead(bob, "users/alice/a.txt"), ErrNotFound, "bob reads alice's home")

	a.upload(admin, "users/alice", "from-admin.txt", "x")
	shown(t, errOf(a.svc.Move(as(alice), "users/alice/from-admin.txt", "users/alice/mine.txt")), ErrForbidden,
		"alice renames the admin's file in her home")
	ok(t, errOf(a.svc.Delete(as(alice), "users/alice/from-admin.txt")), "alice deletes the admin's file in her home")

	ok(t, a.canRead(carol, "public/p.txt"), "the viewer reads /public")
	ok(t, errOf(a.svc.List(as(carol), "media")), "the viewer lists her folder")
	shown(t, errOf3(a.svc.Create(as(carol), "public", "c.txt", strings.NewReader("c"), -1)), ErrForbidden, "the viewer uploads")
	shown(t, errOf(a.svc.Mkdir(as(carol), "public", "c")), ErrForbidden, "the viewer creates a folder")
	shown(t, errOf(a.svc.Delete(as(carol), "public/p.txt")), ErrForbidden, "the viewer deletes")
	shown(t, errOf(a.svc.Move(as(carol), "public/p.txt", "public/c.txt")), ErrForbidden, "the viewer renames")
	hidden(t, a.canRead(carol, "users/alice/a.txt"), ErrNotFound, "the viewer reads a home")

	ok(t, errOf(a.svc.Move(as(admin), "public/p.txt", "public/moved.txt")), "the admin moves alice's file")
	if a.uploader("public/moved.txt") != alice || a.uploader("public/p.txt") != "" {
		t.Errorf("after the admin's move the records are %q, %q", a.uploader("public/moved.txt"), a.uploader("public/p.txt"))
	}
	ok(t, errOf(a.svc.Move(as(alice), "public/moved.txt", "users/alice/back.txt")), "alice moves her file home")

	a.policy.roles[alice] = authz.Viewer
	shown(t, errOf(a.svc.Delete(as(alice), "users/alice/back.txt")), ErrForbidden, "demoted alice deletes her file")
	ok(t, a.canRead(alice, "users/alice/back.txt"), "demoted alice reads her file")
	a.policy.roles[alice] = authz.Contributor
	ok(t, errOf(a.svc.Delete(as(alice), "users/alice/back.txt")), "alice deletes her file")
	if a.exists("users/alice/back.txt") || a.uploader("users/alice/back.txt") != "" {
		t.Error("the deleted file or its record is left")
	}
}

func TestListingsCarryUploaderAndActions(t *testing.T) {
	a := newAccessEnv(t)
	a.upload(alice, "public", "alice.txt", "a")
	a.upload(bob, "public", "bob.txt", "b")
	a.mkdir(alice, "public", "dir")
	a.write("public/console.txt", "c")
	a.write("public/gone.txt", "g")
	a.putRecord("public/gone.txt", "u-deleted")
	a.write("users/alice/console.txt", "c")
	a.write(".gocalbox/staging/x", "x")
	a.write("public/.GoCalbox/x", "x")

	all := "rename,move,delete"
	for _, tc := range []struct {
		user, dir string
		want      map[string]string
	}{
		{alice, "public", map[string]string{
			"alice.txt": "name-of-u-alice " + all, "bob.txt": "name-of-u-bob ", "dir": "name-of-u-alice " + all,
			"console.txt": "- ", "gone.txt": DeletedUser + " ",
		}},
		{admin, "public", map[string]string{
			"alice.txt": "name-of-u-alice " + all, "bob.txt": "name-of-u-bob " + all, "dir": "name-of-u-alice " + all,
			"console.txt": "- " + all, "gone.txt": DeletedUser + " " + all,
		}},
		{carol, "public", map[string]string{
			"alice.txt": "name-of-u-alice ", "bob.txt": "name-of-u-bob ", "dir": "name-of-u-alice ",
			"console.txt": "- ", "gone.txt": DeletedUser + " ",
		}},
		{alice, "users/alice", map[string]string{"console.txt": "- delete"}},
		{admin, ".", map[string]string{"media": "- ", "projects": "- ", "public": "- ", "secret": "- " + all, "users": "- "}},
		{alice, "users", map[string]string{"alice": "- "}},
	} {
		if got := a.listing(tc.user, tc.dir); !maps.Equal(got, tc.want) {
			t.Errorf("%s lists %s:\n got %v\nwant %v", tc.user, tc.dir, got, tc.want)
		}
	}
}

func TestFilteredListingsShowTheWayToBoundFolders(t *testing.T) {
	a := newAccessEnv(t)
	a.write("users/stray.txt", "x")
	for _, tc := range []struct {
		user, dir string
		want      []string
	}{
		{alice, ".", []string{"public", "users"}},
		{alice, "users", []string{"alice"}},
		{bob, ".", []string{"projects", "public", "users"}},
		{bob, "projects", []string{"team"}},
		{carol, ".", []string{"media", "public"}},
		{admin, ".", []string{"media", "projects", "public", "secret", "users"}},
		{admin, "users", []string{"alice", "bob", "stray.txt"}},
	} {
		if got := a.names(tc.user, tc.dir); !slices.Equal(got, tc.want) {
			t.Errorf("%s lists %s: %v, want %v", tc.user, tc.dir, got, tc.want)
		}
	}
	hidden(t, errOf(a.svc.List(as(carol), "users")), ErrNotFound, "the viewer lists /users")
	hidden(t, errOf(a.svc.List(as(alice), "secret")), ErrNotFound, "alice lists an unbound folder")
	hidden(t, a.canRead(alice, "users/stray.txt"), ErrNotFound, "alice reads a file in a traversed folder")
}

func TestUnreadablePathsAnswerAsMissing(t *testing.T) {
	a := newAccessEnv(t)
	a.write("users/bob/b.txt", "b")
	a.write("users/bob/sub/c.txt", "c")
	a.upload(alice, "public", "a.txt", "a")

	cases := []struct {
		what     string
		op       func(user string) error
		hiddenAs error
	}{
		{"list", func(u string) error { return errOf(a.svc.List(as(u), "users/bob")) }, ErrNotFound},
		{"list a missing folder", func(u string) error { return errOf(a.svc.List(as(u), "users/bob/none")) }, ErrNotFound},
		{"list a file", func(u string) error { return errOf(a.svc.List(as(u), "users/bob/b.txt")) }, ErrNotFound},
		{"read", func(u string) error { return a.canRead(u, "users/bob/b.txt") }, ErrNotFound},
		{"read a missing file", func(u string) error { return a.canRead(u, "users/bob/none.txt") }, ErrNotFound},
		{"read a folder", func(u string) error { return a.canRead(u, "users/bob/sub") }, ErrNotFound},
		{"read through a file", func(u string) error { return a.canRead(u, "users/bob/b.txt/x") }, ErrNotFound},
		{"upload", func(u string) error {
			return errOf3(a.svc.Create(as(u), "users/bob", "x.txt", strings.NewReader("x"), -1))
		}, ErrParentNotFound},
		{"upload into a missing folder", func(u string) error {
			return errOf3(a.svc.Create(as(u), "users/bob/none", "x.txt", strings.NewReader("x"), -1))
		}, ErrParentNotFound},
		{"mkdir", func(u string) error { return errOf(a.svc.Mkdir(as(u), "users/bob", "d")) }, ErrParentNotFound},
		{"mkdir existing", func(u string) error { return errOf(a.svc.Mkdir(as(u), "users/bob", "sub")) }, ErrParentNotFound},
		{"delete", func(u string) error { return errOf(a.svc.Delete(as(u), "users/bob/b.txt")) }, ErrNotFound},
		{"delete a missing file", func(u string) error { return errOf(a.svc.Delete(as(u), "users/bob/none")) }, ErrNotFound},
		{"delete a home", func(u string) error { return errOf(a.svc.Delete(as(u), "users/bob")) }, ErrNotFound},
		{"move out", func(u string) error { return errOf(a.svc.Move(as(u), "users/bob/b.txt", "public/b.txt")) }, ErrNotFound},
		{"move in", func(u string) error { return errOf(a.svc.Move(as(u), "public/a.txt", "users/bob/a.txt")) }, ErrParentNotFound},
		{"move onto a file", func(u string) error { return errOf(a.svc.Move(as(u), "public/a.txt", "users/bob/b.txt")) }, ErrParentNotFound},
		{"move onto itself", func(u string) error { return errOf(a.svc.Move(as(u), "users/bob/b.txt", "users/bob/b.txt")) }, ErrNotFound},
	}
	for _, tc := range cases {
		hidden(t, tc.op(alice), tc.hiddenAs, "alice: "+tc.what)
		if ev := a.rec.last(t); ev.Outcome != events.OutcomeDenied {
			t.Errorf("alice: %s recorded as %s", tc.what, ev.Outcome)
		}
	}
	if !a.exists("users/bob/b.txt") || a.exists("users/bob/x.txt") || a.exists("users/bob/a.txt") || !a.exists("public/a.txt") {
		t.Error("a hidden operation changed something")
	}
	for _, tc := range cases {
		if err := tc.op(admin); isHidden(err) {
			t.Errorf("admin: %s: %v", tc.what, err)
		}
	}
}

func TestResolutionErrorsShowOnlyInReadableFolders(t *testing.T) {
	a := newAccessEnv(t)
	os.Mkdir(filepath.Join(a.root, sandbox.ReservedName), 0o700)
	for _, dir := range []string{"users/bob", "public"} {
		a.symlink(a.outside, dir+"/out")
		a.symlink(filepath.Join(a.root, "nowhere"), dir+"/broken")
		a.symlink(filepath.Join(a.root, dir, "loop"), dir+"/loop")
		a.symlink(filepath.Join(a.root, sandbox.ReservedName), dir+"/reserved")
	}
	for _, tc := range []struct {
		name string
		want error
	}{
		{"out/secret.txt", sandbox.ErrTraversal},
		{"broken/x", sandbox.ErrBrokenLink},
		{"loop/x", sandbox.ErrBrokenLink},
		{"reserved/x", sandbox.ErrReserved},
	} {
		hidden(t, a.canRead(alice, "users/bob/"+tc.name), ErrNotFound, "alice reads users/bob/"+tc.name)
		hidden(t, errOf3(a.svc.Create(as(alice), "users/bob/"+path0(tc.name), "x", strings.NewReader("x"), -1)), ErrParentNotFound,
			"alice uploads through users/bob/"+tc.name)
		shown(t, a.canRead(bob, "users/bob/"+tc.name), tc.want, "bob reads users/bob/"+tc.name)
		shown(t, a.canRead(alice, "public/"+tc.name), tc.want, "alice reads public/"+tc.name)
		shown(t, a.canRead(admin, "users/bob/"+tc.name), tc.want, "the admin reads users/bob/"+tc.name)
	}
	for _, typed := range []string{".gocalbox/x", "public/.gocalbox", "public/.GOCALBOX/x", "users/bob/.gocalbox"} {
		shown(t, a.canRead(alice, typed), sandbox.ErrReserved, "alice reads "+typed)
		shown(t, a.canRead(admin, typed), sandbox.ErrReserved, "the admin reads "+typed)
	}
	shown(t, errOf3(a.svc.Create(as(alice), "public", ".gocalbox", strings.NewReader("x"), -1)), sandbox.ErrReserved, "upload named .gocalbox")
	shown(t, errOf(a.svc.Mkdir(as(admin), "public", ".Gocalbox")), sandbox.ErrReserved, "folder named .Gocalbox")
	a.upload(alice, "public", "a.txt", "a")
	shown(t, errOf(a.svc.Move(as(alice), "public/a.txt", "public/.gocalbox")), sandbox.ErrReserved, "rename to .gocalbox")
	if ev := a.rec.last(t); ev.Outcome != events.OutcomeDenied {
		t.Errorf("a reserved path recorded as %s", ev.Outcome)
	}
}

func path0(p string) string { return strings.Split(p, "/")[0] }

func TestForbiddenWhereTheUserCanSee(t *testing.T) {
	a := newAccessEnv(t)
	a.upload(alice, "public", "a.txt", "a")
	for _, tc := range []struct {
		what string
		err  error
	}{
		{"alice uploads into /users", errOf3(a.svc.Create(as(alice), "users", "x.txt", strings.NewReader("x"), -1))},
		{"alice creates a folder in the root", errOf(a.svc.Mkdir(as(alice), "", "x"))},
		{"alice creates a folder in /users", errOf(a.svc.Mkdir(as(alice), "users", "x"))},
		{"alice moves a file into /users", errOf(a.svc.Move(as(alice), "public/a.txt", "users/a.txt"))},
		{"bob uploads into projects/team", errOf3(a.svc.Create(as(bob), "projects/team", "x.txt", strings.NewReader("x"), -1))},
		{"bob deletes alice's file", errOf(a.svc.Delete(as(bob), "public/a.txt"))},
		{"carol uploads into /public", errOf3(a.svc.Create(as(carol), "public", "x.txt", strings.NewReader("x"), -1))},
	} {
		shown(t, tc.err, ErrForbidden, tc.what)
		if ev := a.rec.last(t); ev.Outcome != events.OutcomeDenied {
			t.Errorf("%s recorded as %s", tc.what, ev.Outcome)
		}
	}
	if a.exists("users/x.txt") || a.exists("x") || a.exists("users/a.txt") || !a.exists("public/a.txt") {
		t.Error("a forbidden operation changed something")
	}
}

func TestBoundFoldersCantBeMovedOrDeleted(t *testing.T) {
	a := newAccessEnv(t)
	for _, tc := range []struct{ user, path string }{
		{admin, "users"}, {admin, "users/alice"}, {admin, "public"}, {admin, "media"}, {admin, "projects"}, {admin, "projects/team"},
		{alice, "users"}, {alice, "users/alice"}, {bob, "projects"}, {bob, "projects/team"}, {carol, "media"},
	} {
		shown(t, errOf(a.svc.Delete(as(tc.user), tc.path)), ErrBoundFolder, tc.user+" deletes "+tc.path)
		shown(t, errOf(a.svc.Move(as(tc.user), tc.path, "public/moved")), ErrBoundFolder, tc.user+" moves "+tc.path)
		if ev := a.rec.last(t); ev.Outcome != events.OutcomeDenied {
			t.Errorf("%s moves %s: recorded as %s", tc.user, tc.path, ev.Outcome)
		}
	}
	hidden(t, errOf(a.svc.Delete(as(carol), "users")), ErrNotFound, "the viewer deletes /users")
	hidden(t, errOf(a.svc.Delete(as(alice), "users/bob")), ErrNotFound, "alice deletes bob's home")
	for _, p := range []string{"users/alice", "users/bob", "public", "media", "projects/team"} {
		if !a.exists(p) {
			t.Errorf("%s is gone", p)
		}
	}
	ok(t, errOf(a.svc.Delete(as(admin), "projects/other")), "the admin deletes an unbound folder next to a bound one")
}

func TestFolderChangesCheckEveryEntryBelow(t *testing.T) {
	a := newAccessEnv(t)
	a.mkdir(alice, "public", "dir")
	a.mkdir(alice, "public/dir", "sub")
	a.upload(alice, "public/dir/sub", "a.txt", "a")
	a.upload(bob, "public/dir/sub", "b.txt", "b")

	shown(t, errOf(a.svc.Delete(as(alice), "public/dir")), ErrForbidden, "alice deletes a folder holding bob's file")
	shown(t, errOf(a.svc.Move(as(alice), "public/dir", "public/dir2")), ErrForbidden, "alice moves a folder holding bob's file")
	if !a.exists("public/dir/sub/b.txt") || a.exists("public/dir2") {
		t.Fatal("a refused folder change changed something")
	}
	ok(t, errOf(a.svc.Delete(as(bob), "public/dir/sub/b.txt")), "bob deletes his file")
	ok(t, errOf(a.svc.Move(as(alice), "public/dir", "public/dir2")), "alice moves her folder")
	ok(t, errOf(a.svc.Delete(as(alice), "public/dir2")), "alice deletes her folder")

	a.mkdir(alice, "public", "d2")
	a.write("public/d2/console.txt", "c")
	shown(t, errOf(a.svc.Delete(as(alice), "public/d2")), ErrForbidden, "alice deletes a folder holding an unowned file")

	a.mkdir(admin, "users/alice", "from-admin")
	a.upload(admin, "users/alice/from-admin", "x.txt", "x")
	shown(t, errOf(a.svc.Move(as(alice), "users/alice/from-admin", "users/alice/mine")), ErrForbidden,
		"alice moves the admin's folder in her home")
	ok(t, errOf(a.svc.Delete(as(alice), "users/alice/from-admin")), "alice deletes the admin's folder in her home")
	if a.exists("users/alice/from-admin") || a.uploader("users/alice/from-admin/x.txt") != "" {
		t.Error("the folder or its records are left")
	}
}

func TestUploaderRecordsFollowTheTree(t *testing.T) {
	a := newAccessEnv(t)
	a.mkdir(alice, "public", "r")
	a.upload(alice, "public/r", "x.txt", "x")
	a.mkdir(alice, "public/r", "sub")
	a.upload(alice, "public/r/sub", "y.txt", "y")
	a.upload(alice, "public", "r.txt", "r")
	a.mkdir(bob, "public", "rr")
	a.putRecord("public/s", bob)
	a.putRecord("public/s/old", bob)

	ok(t, errOf(a.svc.Move(as(admin), "public/r", "public/s")), "the admin moves alice's folder")
	for key, want := range map[string]string{
		"public/s": alice, "public/s/x.txt": alice, "public/s/sub": alice, "public/s/sub/y.txt": alice, "public/s/old": "",
		"public/r": "", "public/r/x.txt": "", "public/r.txt": alice, "public/rr": bob,
	} {
		if got := a.uploader(key); got != want {
			t.Errorf("record of %s: %q, want %q", key, got, want)
		}
	}
	ok(t, errOf(a.svc.Delete(as(alice), "public/s")), "alice deletes her folder")
	for _, key := range []string{"public/s", "public/s/x.txt", "public/s/sub/y.txt"} {
		if got := a.uploader(key); got != "" {
			t.Errorf("record of %s left: %q", key, got)
		}
	}
	if a.uploader("public/r.txt") != alice || a.uploader("public/rr") != bob {
		t.Error("the delete removed a sibling's record")
	}
}

func TestChangedFilesLoseTheirUploader(t *testing.T) {
	a := newAccessEnv(t)
	a.upload(alice, "public", "size.txt", "12345")
	a.upload(alice, "public", "time.txt", "12345")
	a.write("public/size.txt", "123456")
	later := time.Now().Add(time.Hour)
	if err := os.Chtimes(filepath.Join(a.root, "public/time.txt"), later, later); err != nil {
		t.Fatal(err)
	}
	a.write("public/pending.txt", "p")
	a.putRecord("public/pending.txt", alice)

	want := map[string]string{"size.txt": "- ", "time.txt": "- ", "pending.txt": "name-of-u-alice rename,move,delete"}
	if got := a.listing(alice, "public"); !maps.Equal(got, want) {
		t.Errorf("listing: %v, want %v", got, want)
	}
	shown(t, errOf(a.svc.Delete(as(alice), "public/size.txt")), ErrForbidden, "a file replaced with another size")
	shown(t, errOf(a.svc.Delete(as(alice), "public/time.txt")), ErrForbidden, "a file with another modification time")
	ok(t, errOf(a.svc.Delete(as(alice), "public/pending.txt")), "a record without identity")
}

func TestAnUploadRecordsItsIdentityWhenItEnds(t *testing.T) {
	a := newAccessEnv(t)
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() {
		_, _, err := a.svc.Create(as(alice), "public", "slow.bin", pr, -1)
		done <- err
	}()
	pw.Write([]byte("abc"))
	if rec, found := a.record("public/slow.bin"); !found || rec.User != alice || rec.Size != nil || rec.MTime != nil {
		t.Errorf("record during the upload: %+v, %v", rec, found)
	}
	pw.Write([]byte("def"))
	pw.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(a.root, "public/slow.bin"))
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := a.record("public/slow.bin")
	if rec.Size == nil || *rec.Size != 6 || rec.MTime == nil || *rec.MTime != info.ModTime().UnixNano() {
		t.Errorf("record after the upload: %+v", rec)
	}
}

func TestAnUploadMovedMeanwhileKeepsItsRecord(t *testing.T) {
	a := newAccessEnv(t)
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() {
		_, _, err := a.svc.Create(as(alice), "public", "slow.bin", pr, -1)
		done <- err
	}()
	pw.Write([]byte("abc"))
	if _, err := a.svc.Move(as(admin), "public/slow.bin", "public/moved.bin"); err != nil {
		pw.Close()
		<-done
		if runtime.GOOS == "windows" {
			t.Skipf("an open file can't be moved: %v", err)
		}
		t.Fatal(err)
	}
	a.upload(bob, "public", "slow.bin", "bob's")
	pw.Close()
	if err := <-done; !errors.Is(err, ErrUploadMoved) {
		t.Errorf("the upload whose file was moved: %v", err)
	}
	if ev := a.rec.last(t); ev.Type != events.FileUploaded || ev.Actor.ID != alice || ev.Outcome != events.OutcomeAborted || ev.Resolved != "public/slow.bin" {
		t.Errorf("event: %+v", ev)
	}
	want := map[string]string{"moved.bin": "name-of-u-alice rename,move,delete", "slow.bin": "name-of-u-bob "}
	if got := a.listing(alice, "public"); !maps.Equal(got, want) {
		t.Errorf("listing: %v, want %v", got, want)
	}
	if a.read("public/slow.bin") != "bob's" {
		t.Error("bob's file was changed")
	}
}

func TestAFailedUploadLeavesNoRecord(t *testing.T) {
	a := newAccessEnv(t)
	_, _, err := a.svc.Create(as(alice), "public", "partial.bin", &failingReader{data: "half", err: errors.New("connection reset")}, -1)
	if err == nil {
		t.Fatal("the upload succeeded")
	}
	if a.exists("public/partial.bin") || a.uploader("public/partial.bin") != "" {
		t.Error("the failed upload left its file or record")
	}
}

func TestFailingRecordsUndoTheChange(t *testing.T) {
	a := newAccessEnv(t)
	a.write("public/m.txt", "m")
	a.write("public/del.txt", "d")
	a.db.Close()
	if _, err := a.svc.Mkdir(as(admin), "public", "nd"); err == nil || a.exists("public/nd") {
		t.Errorf("mkdir: %v, folder left: %v", err, a.exists("public/nd"))
	}
	if _, _, err := a.svc.Create(as(admin), "public", "nf.txt", strings.NewReader("x"), -1); err == nil || a.exists("public/nf.txt") {
		t.Errorf("upload: %v, file left: %v", err, a.exists("public/nf.txt"))
	}
	if _, err := a.svc.Move(as(admin), "public/m.txt", "public/n.txt"); err == nil || !a.exists("public/m.txt") || a.exists("public/n.txt") {
		t.Errorf("move: %v, not moved back", err)
	}
	ok(t, errOf(a.svc.Delete(as(admin), "public/del.txt")), "a delete whose records can't be removed")
	if a.exists("public/del.txt") {
		t.Error("the file is left")
	}
	if err := errOf(a.svc.Delete(as(alice), "public/m.txt")); err == nil || isHidden(err) || errors.Is(err, ErrForbidden) {
		t.Errorf("a decision without records: %v", err)
	}
}

func TestDeletedFoldersGoThroughTheTrash(t *testing.T) {
	a := newAccessEnv(t)
	a.mkdir(admin, "public", "big")
	a.write("public/big/a/b/c.txt", "c")
	ok(t, errOf(a.svc.Delete(as(admin), "public/big")), "delete a folder")
	if a.exists("public/big") {
		t.Error("the folder is left")
	}
	left, err := os.ReadDir(filepath.Join(a.root, trashDir))
	if err != nil || len(left) != 0 {
		t.Errorf("trash: %v, %v", left, err)
	}
	shown(t, errOf(a.svc.List(as(admin), trashDir)), sandbox.ErrReserved, "list the trash")

	a.write(trashDir+"/0123456789abcdef/x", "x")
	a.write(trashDir+"/notes/x", "x")
	if err := a.svc.EmptyTrash(); err != nil || a.exists(trashDir+"/0123456789abcdef") {
		t.Errorf("EmptyTrash: %v", err)
	}
	if !a.exists(trashDir + "/notes/x") {
		t.Error("EmptyTrash removed a name the server doesn't give")
	}
	os.RemoveAll(filepath.Join(a.root, trashDir))
	if err := a.svc.EmptyTrash(); err != nil {
		t.Errorf("EmptyTrash without a trash: %v", err)
	}
}

// Without a usable staging folder, nothing goes into the trash: a folder is
// deleted where it is, and the trash is left as it is.
func TestFoldersAreDeletedInPlaceWithoutAStagingFolder(t *testing.T) {
	a := newAccessEnv(t)
	WithStaging(&sandbox.Staging{Problem: errors.New("a symlink")})(a.svc)
	a.write("public/victim/trash/0123456789abcdef/mine.txt", "mine")
	a.write("public/other/trash", "a file where the trash would be")
	os.RemoveAll(filepath.Join(a.root, sandbox.ReservedName))
	if err := os.Symlink(filepath.Join("public", "victim"), filepath.Join(a.root, sandbox.ReservedName)); err != nil {
		t.Skipf("no symlinks here: %v", err)
	}
	if err := a.svc.EmptyTrash(); err != nil {
		t.Errorf("EmptyTrash: %v", err)
	}
	if a.read("public/victim/trash/0123456789abcdef/mine.txt") != "mine" {
		t.Error("EmptyTrash followed the symlink")
	}

	os.Remove(filepath.Join(a.root, sandbox.ReservedName))
	os.Symlink(filepath.Join("public", "other"), filepath.Join(a.root, sandbox.ReservedName))
	a.mkdir(admin, "public", "big")
	a.write("public/big/a/b/c.txt", "c")
	ok(t, errOf(a.svc.Delete(as(admin), "public/big")), "delete a folder")
	if a.exists("public/big") {
		t.Error("the folder is left")
	}
}

func TestEverySpellingOfAPathIsDecidedAlike(t *testing.T) {
	a := newAccessEnv(t)
	a.upload(alice, "public", "a.txt", "a")
	a.write("users/bob/b.txt", "b")
	groups := [][]string{
		{"public/a.txt", "/public/a.txt", "public//a.txt", "public/./a.txt", "users/../public/a.txt"},
		{"users/bob/b.txt", "/users/bob/./b.txt", "public/../users/bob/b.txt", "users//bob/b.txt"},
		{"users/alice", "users/alice/", "/users/./alice"},
	}
	if err := os.Symlink(filepath.Join(a.root, "public"), filepath.Join(a.root, "alias")); err == nil {
		groups[0] = append(groups[0], "alias/a.txt", "secret/../alias/a.txt")
		groups = append(groups, []string{"public", "alias"})
	}
	for _, user := range []string{admin, alice, bob, carol} {
		for _, group := range groups {
			var first string
			for i, p := range group {
				got := class(a.canRead(user, p)) + " " + class(errOf(a.svc.List(as(user), p)))
				if i == 0 {
					first = got
				} else if got != first {
					t.Errorf("%s: %s gives %s, %s gives %s", user, group[0], first, p, got)
				}
			}
		}
	}
}

func class(err error) string {
	if err == nil {
		return "ok"
	}
	for _, known := range []error{ErrNotFound, ErrParentNotFound, ErrNotDir, ErrForbidden, ErrBoundFolder, sandbox.ErrReserved} {
		if errors.Is(err, known) {
			return fmt.Sprintf("%v(hidden %v)", known, isHidden(err))
		}
	}
	return "other: " + err.Error()
}

func TestWithoutAPolicyNothingIsAllowed(t *testing.T) {
	e := newEnv(t)
	e.svc = New(e.sb, nil)
	e.write("dir/a.txt", "a")
	hidden(t, errOf(e.svc.List(bg, "dir")), ErrNotFound, "list")
	hidden(t, errOf(e.svc.Open(bg, "dir/a.txt")), ErrNotFound, "read")
	hidden(t, errOf3(e.svc.Create(bg, "dir", "b.txt", strings.NewReader("b"), -1)), ErrParentNotFound, "upload")
	hidden(t, errOf(e.svc.Mkdir(bg, "dir", "d")), ErrParentNotFound, "mkdir")
	hidden(t, errOf(e.svc.Delete(bg, "dir/a.txt")), ErrNotFound, "delete")
	hidden(t, errOf(e.svc.Move(bg, "dir/a.txt", "dir/c.txt")), ErrNotFound, "move")
	if !e.exists("dir/a.txt") || e.exists("dir/b.txt") || e.exists("dir/d") || e.exists("dir/c.txt") {
		t.Error("something changed")
	}

	a := newAccessEnv(t)
	a.write("public/a.txt", "a")
	hidden(t, a.canRead("u-unknown", "public/a.txt"), ErrNotFound, "a request for an unknown user")
	hidden(t, a.canRead(events.AnonymousID, "public/a.txt"), ErrNotFound, "a request without a user")
}

func TestProvisionClearsTheRecordsOfTheFoldersItTakes(t *testing.T) {
	a := newAccessEnv(t)
	a.putRecord("users/dave", bob)
	a.putRecord("users/dave/x", bob)
	os.Mkdir(filepath.Join(a.root, "users/erin"), 0o755)
	a.putRecord("users/erin", bob)
	a.putRecord("public", admin)
	err := a.svc.Provision(bg, []Folder{
		{Path: "public", IfExists: Reuse},
		{Path: "users/dave", IfExists: Refuse},
		{Path: "users/erin", IfExists: TakeOverEmpty},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{"users/dave": "", "users/dave/x": "", "users/erin": "", "public": admin} {
		if got := a.uploader(key); got != want {
			t.Errorf("record of %s: %q, want %q", key, got, want)
		}
	}
}

func TestListingsLeaveOutLinksToUnreadablePlaces(t *testing.T) {
	a := newAccessEnv(t)
	a.write("users/bob/b.txt", "b")
	a.mkdir(alice, "public", "sub")
	a.symlink(filepath.Join(a.root, "users/bob"), "public/to-bob")
	a.symlink(filepath.Join(a.root, "users/bob/b.txt"), "public/to-bob-file")
	a.symlink(filepath.Join(a.root, "public/sub"), "public/to-sub")
	a.symlink(filepath.Join(a.root, "users"), "public/to-users")
	for user, want := range map[string][]string{
		alice: {"sub", "to-sub", "to-users"},
		bob:   {"sub", "to-bob", "to-bob-file", "to-sub", "to-users"},
		carol: {"sub", "to-sub"},
	} {
		if got := a.names(user, "public"); !slices.Equal(got, want) {
			t.Errorf("%s lists /public: %v, want %v", user, got, want)
		}
	}
}

func TestStoredSpellingOnTheVolume(t *testing.T) {
	a := newAccessEnv(t)
	if !caseInsensitive(t, a.root) {
		a.upload(alice, "public", "Report.pdf", "a")
		a.upload(bob, "public", "report.pdf", "b")
		if a.uploader("public/Report.pdf") != alice || a.uploader("public/report.pdf") != bob {
			t.Error("two files differing in case don't keep two records")
		}
		shown(t, errOf(a.svc.Delete(as(bob), "public/Report.pdf")), ErrForbidden, "bob deletes alice's Report.pdf")
		ok(t, errOf(a.svc.Delete(as(bob), "public/report.pdf")), "bob deletes his report.pdf")
		t.Skip("the volume is case-sensitive; the rest needs one that isn't")
	}
	a.upload(alice, "PUBLIC", "Report.pdf", "a")
	if a.uploader("public/Report.pdf") != alice {
		t.Errorf("an upload through another spelling isn't recorded under the stored one")
	}
	shown(t, errOf(a.svc.Delete(as(bob), "public/REPORT.PDF")), ErrForbidden, "bob deletes alice's file by another spelling")
	shown(t, errOf(a.svc.Move(as(bob), "Public/report.pdf", "public/mine.pdf")), ErrForbidden, "bob renames it by another spelling")
	for _, p := range []string{"USERS/Alice", "Users/alice", "PUBLIC"} {
		shown(t, errOf(a.svc.Delete(as(admin), p)), ErrBoundFolder, "the admin deletes "+p)
	}
	ok(t, errOf(a.svc.Move(as(alice), "PUBLIC/report.PDF", "public/Renamed.pdf")), "alice renames her file by another spelling")
	if a.uploader("public/Renamed.pdf") != alice || a.uploader("public/Report.pdf") != "" {
		t.Error("the record didn't follow the rename")
	}
	ok(t, errOf(a.svc.Delete(as(alice), "public/RENAMED.pdf")), "alice deletes her file by another spelling")
	if a.uploader("public/Renamed.pdf") != "" {
		t.Error("the record is left")
	}
	a.mkdir(alice, "public", "d")
	shown(t, errOf(a.svc.Move(as(alice), "public/d", "PUBLIC/D/sub")), ErrMoveIntoSelf, "a move into itself by another spelling")
	shown(t, errOf(a.svc.Move(as(alice), "public/d", "PUBLIC/d")), ErrExists, "a move onto itself by another spelling")
	a.mkdir(alice, "Public", "Upper.d")
	if a.uploader("public/Upper.d") != alice {
		t.Error("a folder created through another spelling isn't recorded under the stored one")
	}
}

func caseInsensitive(t *testing.T, dir string) bool {
	t.Helper()
	probe := filepath.Join(dir, "CaseProbe")
	if err := os.WriteFile(probe, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(probe)
	_, err := os.Lstat(filepath.Join(dir, "caseprobe"))
	return err == nil
}

func TestAFailedUploadSparesWhatTookItsName(t *testing.T) {
	for _, tc := range []struct {
		what  string
		clear func(a *accessEnv) error
		take  func(a *accessEnv)
	}{
		{"renamed, then a file", func(a *accessEnv) error { return errOf(a.svc.Move(as(alice), "public/x.bin", "public/y.bin")) },
			func(a *accessEnv) { a.upload(bob, "public", "x.bin", "bob's") }},
		{"deleted, then a folder", func(a *accessEnv) error { return errOf(a.svc.Delete(as(alice), "public/x.bin")) },
			func(a *accessEnv) { a.mkdir(bob, "public", "x.bin") }},
	} {
		t.Run(tc.what, func(t *testing.T) {
			a := newAccessEnv(t)
			pr, pw := io.Pipe()
			done := make(chan error, 1)
			go func() {
				_, _, err := a.svc.Create(as(alice), "public", "x.bin", pr, -1)
				done <- err
			}()
			pw.Write([]byte("abc"))
			if err := tc.clear(a); err != nil {
				pw.Close()
				<-done
				if runtime.GOOS == "windows" {
					t.Skipf("an open file can't be moved or deleted: %v", err)
				}
				t.Fatal(err)
			}
			tc.take(a)
			pw.CloseWithError(errors.New("connection reset"))
			if err := <-done; err == nil {
				t.Fatal("the upload succeeded")
			}
			if !a.exists("public/x.bin") || a.uploader("public/x.bin") != bob {
				t.Errorf("bob's entry or record is gone: %v, %q", a.exists("public/x.bin"), a.uploader("public/x.bin"))
			}
		})
	}
}

func TestAFailedIdentityWriteFailsTheUpload(t *testing.T) {
	a := newAccessEnv(t)
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() {
		_, _, err := a.svc.Create(as(alice), "public", "slow.bin", pr, -1)
		done <- err
	}()
	pw.Write([]byte("abc"))
	a.db.Close()
	pw.Close()
	if err := <-done; err == nil || a.exists("public/slow.bin") {
		t.Errorf("upload: %v, file left: %v", err, a.exists("public/slow.bin"))
	}
}

func TestAFolderRecordDoesntMatchAFile(t *testing.T) {
	a := newAccessEnv(t)
	a.mkdir(alice, "public", "f")
	os.Remove(filepath.Join(a.root, "public/f"))
	a.write("public/f", "from the console")
	if got := a.listing(alice, "public"); got["f"] != "- " {
		t.Errorf("listing: %v", got)
	}
	shown(t, errOf(a.svc.Delete(as(alice), "public/f")), ErrForbidden, "alice deletes a console file where her folder was")
}

func TestStoredErrorsInUnreadableFoldersAreHidden(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs permissions that bind the server")
	}
	for _, tc := range []struct {
		dir  string
		mode os.FileMode
	}{{"users/bob", 0o600}, {"users", 0o311}, {"users/bob/d", 0o300}} {
		t.Run(tc.dir, func(t *testing.T) {
			a := newAccessEnv(t)
			a.write("users/bob/d/x/y", "y")
			a.upload(alice, "public", "a.txt", "a")
			d := filepath.Join(a.root, tc.dir)
			if err := os.Chmod(d, tc.mode); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.Chmod(d, 0o755) })
			for _, p := range []string{"users/bob/d/x", "users/bob/none/x", "users/bob/d"} {
				hidden(t, errOf(a.svc.Delete(as(alice), p)), ErrNotFound, "alice deletes "+p)
				hidden(t, errOf(a.svc.Move(as(alice), p, "public/x")), ErrNotFound, "alice moves "+p)
				hidden(t, errOf(a.svc.Move(as(alice), "public/a.txt", p+"/new")), ErrParentNotFound, "alice moves a file into "+p)
				hidden(t, errOf(a.svc.Mkdir(as(alice), p, "n")), ErrParentNotFound, "alice creates a folder in "+p)
				hidden(t, errOf3(a.svc.Create(as(alice), p, "n", strings.NewReader("n"), -1)), ErrParentNotFound, "alice uploads into "+p)
			}
		})
	}
	a := newAccessEnv(t)
	a.write("users/bob/d/x/y", "y")
	d := filepath.Join(a.root, "users/bob/d")
	if err := os.Chmod(d, 0o300); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(d, 0o755) })
	if err := errOf(a.svc.Delete(as(bob), "users/bob/d/x")); err == nil || isHidden(err) {
		t.Errorf("bob deletes in his unreadable folder: %v", err)
	}
}

func TestStoredNameFindsTheSameFile(t *testing.T) {
	e := newEnv(t)
	e.write("d/Report.pdf", "r")
	e.write("d/a.txt", "a")
	if err := os.Link(filepath.Join(e.root, "d/Report.pdf"), filepath.Join(e.root, "d/zz-link")); err != nil {
		t.Skipf("hard links not supported: %v", err)
	}
	report, _ := os.Lstat(filepath.Join(e.root, "d/Report.pdf"))
	txt, _ := os.Lstat(filepath.Join(e.root, "d/a.txt"))
	for _, tc := range []struct {
		name  string
		info  os.FileInfo
		names []string
		want  string
	}{
		{"a.txt", txt, []string{"Report.pdf", "a.txt", "zz-link"}, "a.txt"},
		{"report.pdf", report, []string{"a.txt", "zz-link", "Report.pdf"}, "Report.pdf"},
		{"other name", report, []string{"a.txt", "zz-link"}, "zz-link"},
		{"missing", txt, []string{"Report.pdf", "zz-link"}, "missing"},
	} {
		if got := e.svc.storedName("d", tc.name, tc.info, slices.Clone(tc.names)); got != tc.want {
			t.Errorf("storedName(%q) = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestChangesReadOnlyFoldersTheUserCanRead(t *testing.T) {
	a := newAccessEnv(t)
	a.write("users/bob/tax.pdf", "x")
	a.write("users/bob/plans/x", "x")
	a.write("secret/plans/x", "x")
	a.upload(alice, "public", "a.txt", "a")
	var mu sync.Mutex
	var read []string
	orig := readNames
	readNames = func(root *os.Root, dir string) ([]string, error) {
		mu.Lock()
		read = append(read, dir)
		mu.Unlock()
		return orig(root, dir)
	}
	t.Cleanup(func() { readNames = orig })
	for _, dir := range []string{"users/bob", "secret"} {
		hidden(t, errOf(a.svc.Delete(as(alice), dir+"/plans/x")), ErrNotFound, "alice deletes in "+dir)
		hidden(t, errOf(a.svc.Move(as(alice), dir+"/plans/x", "public/x")), ErrNotFound, "alice moves out of "+dir)
		hidden(t, errOf(a.svc.Move(as(alice), "public/a.txt", dir+"/plans/a.txt")), ErrParentNotFound, "alice moves her file into "+dir)
		hidden(t, errOf(a.svc.Mkdir(as(alice), dir+"/plans", "x")), ErrParentNotFound, "alice creates a folder in "+dir)
		hidden(t, errOf3(a.svc.Create(as(alice), dir+"/plans", "x.txt", strings.NewReader("x"), -1)), ErrParentNotFound, "alice uploads into "+dir)
		hidden(t, errOf(a.svc.Delete(as(carol), dir+"/plans/x")), ErrNotFound, "carol deletes in "+dir)
	}
	shown(t, errOf(a.svc.Mkdir(as(alice), "users", "x")), ErrForbidden, "alice creates a folder in /users")
	ok(t, errOf(a.svc.Move(as(alice), "public/a.txt", "users/alice/a.txt")), "alice moves her file home")
	mu.Lock()
	defer mu.Unlock()
	for _, dir := range read {
		if a.policy.bindings.Granted(alice, dir) < authz.GrantViewer {
			t.Errorf("a change read %s, which alice can't read", dir)
		}
	}
	if !slices.Contains(read, "public") || !slices.Contains(read, "users/alice") {
		t.Errorf("the move read %v; the readNames hook isn't in use", read)
	}
}

// switchablePolicy lets a test change a role while requests wait.
type switchablePolicy struct {
	mu       sync.Mutex
	roles    map[string]authz.Role
	bindings *authz.Bindings
}

func (p *switchablePolicy) Subject(ctx context.Context) (Subject, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	id := events.ActorFrom(ctx).ID
	role, ok := p.roles[id]
	return Subject{ID: id, Role: role, Bindings: p.bindings}, ok
}

func (p *switchablePolicy) UserName(id string) (string, bool) { return "name-of-" + id, true }

func TestARoleChangedWhileAChangeWaitsCounts(t *testing.T) {
	a := newAccessEnv(t)
	a.upload(alice, "public", "mine.txt", "a")
	a.upload(alice, "public", "also-mine.txt", "a")
	p := &switchablePolicy{roles: maps.Clone(a.policy.roles), bindings: a.policy.bindings}
	a.svc.SetPolicy(p)

	a.svc.mu.Lock()
	errs := make(chan error, 4)
	go func() { errs <- errOf(a.svc.Mkdir(as(alice), "public", "late")) }()
	go func() { errs <- errOf3(a.svc.Create(as(alice), "public", "late.txt", strings.NewReader("x"), -1)) }()
	go func() { errs <- errOf(a.svc.Delete(as(alice), "public/mine.txt")) }()
	go func() { errs <- errOf(a.svc.Move(as(alice), "public/also-mine.txt", "public/renamed.txt")) }()
	time.Sleep(100 * time.Millisecond)
	p.mu.Lock()
	p.roles[alice] = authz.Viewer
	p.mu.Unlock()
	a.svc.mu.Unlock()
	for range 4 {
		shown(t, <-errs, ErrForbidden, "a change waiting while alice was made a viewer")
	}
	for _, p := range []string{"public/late", "public/late.txt", "public/renamed.txt"} {
		if a.exists(p) {
			t.Errorf("%s was made", p)
		}
	}
	if !a.exists("public/mine.txt") || !a.exists("public/also-mine.txt") {
		t.Error("alice's files were changed")
	}
}

func TestAFailedUploadSparesTheSameUsersNewerUpload(t *testing.T) {
	a := newAccessEnv(t)
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() {
		_, _, err := a.svc.Create(as(alice), "public", "x.bin", pr, -1)
		done <- err
	}()
	pw.Write([]byte("abc"))
	if err := errOf(a.svc.Delete(as(alice), "public/x.bin")); err != nil {
		pw.Close()
		<-done
		if runtime.GOOS == "windows" {
			t.Skipf("an open file can't be deleted: %v", err)
		}
		t.Fatal(err)
	}
	a.upload(alice, "public", "x.bin", "newer")
	pw.CloseWithError(errors.New("connection reset"))
	if err := <-done; err == nil {
		t.Fatal("the first upload succeeded")
	}
	if rec, found := a.record("public/x.bin"); !found || rec.User != alice || rec.Size == nil {
		t.Errorf("the newer upload's record: %+v, %v", rec, found)
	}
	if a.read("public/x.bin") != "newer" {
		t.Error("the newer upload's file was changed")
	}
}

func TestAnUploadEndingAfterItsPlaceChangedRemovesOnlyItsOwnRecord(t *testing.T) {
	a := newAccessEnv(t)
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() {
		_, _, err := a.svc.Create(as(alice), "public", "x.bin", pr, -1)
		done <- err
	}()
	pw.Write([]byte("abc"))
	if err := os.Remove(filepath.Join(a.root, "public/x.bin")); err != nil {
		pw.Close()
		<-done
		if runtime.GOOS == "windows" {
			t.Skipf("an open file can't be deleted: %v", err)
		}
		t.Fatal(err)
	}
	os.Mkdir(filepath.Join(a.root, "public/x.bin"), 0o755)
	a.upload(bob, "public/x.bin", "b.txt", "bob's")
	pw.Close()
	if err := <-done; !errors.Is(err, ErrUploadMoved) {
		t.Errorf("the upload: %v", err)
	}
	if a.uploader("public/x.bin/b.txt") != bob {
		t.Error("bob's record below the upload's name is gone")
	}
	if _, found := a.record("public/x.bin"); found {
		t.Error("the upload's own record is left")
	}
}

func TestTheTrashIsTheServersAlone(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no Unix permissions")
	}
	a := newAccessEnv(t)
	a.mkdir(alice, "public", "d")
	ok(t, errOf(a.svc.Delete(as(alice), "public/d")), "alice deletes her folder")
	info, err := os.Stat(filepath.Join(a.root, trashDir))
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Errorf("trash: %v, %v", info, err)
	}
}

func TestAnInvalidNameTellsNothingAboutTheTargetFolder(t *testing.T) {
	a := newAccessEnv(t)
	a.upload(alice, "public", "a.txt", "a")
	a.write("users/bob/real/x", "x")
	a.symlink(filepath.Join(a.root, "nowhere"), "users/bob/broken")
	a.symlink(a.outside, "users/bob/out")
	for _, dir := range []string{"users/bob/real", "users/bob/missing", "users/bob/broken", "users/bob/out"} {
		shown(t, errOf3(a.svc.Create(as(alice), dir, " bad", strings.NewReader("x"), -1)), ErrInvalidName, "alice uploads an invalid name into "+dir)
		shown(t, errOf(a.svc.Move(as(alice), "public/a.txt", dir+"/ bad")), ErrInvalidName, "alice moves her file to an invalid name in "+dir)
		shown(t, errOf(a.svc.Move(as(alice), dir+"/x", "public/ bad")), ErrInvalidName, "alice moves from "+dir+" to an invalid name")
	}
	shown(t, errOf3(a.svc.Create(as(alice), "../x", " bad", strings.NewReader("x"), -1)), sandbox.ErrTraversal, "an upload outside the root")
	shown(t, errOf(a.svc.Move(as(alice), "../x", "public/ bad")), sandbox.ErrTraversal, "a move from outside the root")
}

func TestEveryFormOfTheReservedNameIsRefused(t *testing.T) {
	a := newAccessEnv(t)
	a.upload(alice, "public", "a.txt", "a")
	for _, name := range []string{".gocalbox.", ".GoCalBox..", "GOCALB~1", "gocalb~12"} {
		shown(t, errOf(a.svc.Mkdir(as(admin), "public", name)), sandbox.ErrReserved, "the admin creates the folder "+name)
		shown(t, errOf3(a.svc.Create(as(alice), "public", name, strings.NewReader("x"), -1)), sandbox.ErrReserved, "alice uploads "+name)
		shown(t, errOf(a.svc.Move(as(alice), "public/a.txt", "public/"+name)), sandbox.ErrReserved, "alice renames her file to "+name)
		shown(t, a.canRead(admin, name+"/trash"), sandbox.ErrReserved, "the admin reads "+name+"/trash")
	}
	if names := a.names(admin, "public"); !slices.Equal(names, []string{"a.txt"}) {
		t.Errorf("public holds %v", names)
	}
}
