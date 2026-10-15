package auth

import (
	"context"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/fsops"
	"github.com/nobletk/gocalbox/internal/sandbox"
	"github.com/nobletk/gocalbox/internal/state"
)

func role(r state.Role) *state.Role { return &r }
func flag(b bool) *bool             { return &b }

func (f *fixture) write(t *testing.T, rel, content string) {
	t.Helper()
	p := filepath.Join(f.root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestTheLastEnabledAdminStays(t *testing.T) {
	f := newFixture(t)
	id, actx := f.setupAdmin(t)
	alice := id.User.ID
	check := func(when string) {
		t.Helper()
		for _, upd := range []UserUpdate{{Role: role(state.RoleContributor)}, {Role: role(state.RoleViewer)}, {Disabled: flag(true)}} {
			if _, err := f.acc.UpdateUser(actx, id, alice, upd); !errors.Is(err, ErrLastAdmin) {
				t.Errorf("%s: update %+v: %v", when, upd, err)
			}
		}
		if _, err := f.acc.DeleteUser(actx, id, alice); !errors.Is(err, ErrLastAdmin) {
			t.Errorf("%s: delete: %v", when, err)
		}
		if u := f.user(t, "alice"); u.Role != state.RoleAdmin || u.Disabled || !f.exists("users/alice") {
			t.Errorf("%s: alice is now %+v", when, u)
		}
	}
	check("alone")

	bob := f.addUser(t, "bob", state.RoleAdmin)
	if _, err := f.acc.UpdateUser(actx, id, bob.ID, UserUpdate{Disabled: flag(true)}); err != nil {
		t.Fatal(err)
	}
	check("with a disabled admin")
	if _, err := f.acc.UpdateUser(actx, id, bob.ID, UserUpdate{Role: role(state.RoleViewer), Disabled: flag(true)}); err != nil {
		t.Errorf("demoting a disabled admin: %v", err)
	}
	if _, err := f.acc.UpdateUser(actx, id, bob.ID, UserUpdate{Role: role(state.RoleAdmin), Disabled: flag(false)}); err != nil {
		t.Fatal(err)
	}
	info, err := f.acc.UpdateUser(actx, id, alice, UserUpdate{Role: role(state.RoleContributor)})
	if err != nil || info.Role != state.RoleContributor {
		t.Errorf("demoting oneself with another admin: %+v, %v", info, err)
	}
	if _, err := f.acc.Users(id); !errors.Is(err, ErrNotAdmin) {
		t.Errorf("after demoting oneself: %v", err)
	}
}

// Two admins demoting, disabling or deleting each other at once leave one.
func TestTheLastAdminGuardHoldsUnderRacingChanges(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(f *fixture, actx context.Context, by Identity, target string) error
	}{
		{"demote", func(f *fixture, actx context.Context, by Identity, target string) error {
			_, err := f.acc.UpdateUser(actx, by, target, UserUpdate{Role: role(state.RoleViewer)})
			return err
		}},
		{"disable", func(f *fixture, actx context.Context, by Identity, target string) error {
			_, err := f.acc.UpdateUser(actx, by, target, UserUpdate{Disabled: flag(true)})
			return err
		}},
		{"delete", func(f *fixture, actx context.Context, by Identity, target string) error {
			_, err := f.acc.DeleteUser(actx, by, target)
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			alice, actx := f.setupAdmin(t)
			f.addUser(t, "bob", state.RoleAdmin)
			bob, bctx := f.loginAs(t, "bob")
			errs := make([]error, 2)
			start := make(chan struct{})
			var wg sync.WaitGroup
			wg.Go(func() { <-start; errs[0] = tc.change(f, actx, alice, bob.User.ID) })
			wg.Go(func() { <-start; errs[1] = tc.change(f, bctx, bob, alice.User.ID) })
			close(start)
			wg.Wait()
			ok := 0
			for _, err := range errs {
				switch {
				case err == nil:
					ok++
				case errors.Is(err, ErrLastAdmin), errors.Is(err, ErrNotAdmin):
				default:
					t.Errorf("unexpected error %v", err)
				}
			}
			var all []state.User
			f.db.View(func(tx *state.Tx) error { var err error; all, err = tx.Users(); return err })
			if ok != 1 || enabledAdmins(all, "") != 1 {
				t.Errorf("%d changes made, %d enabled admins left (%v)", ok, enabledAdmins(all, ""), errs)
			}
		})
	}
}

func TestDeletingAUserArchivesTheirHome(t *testing.T) {
	f := newFixture(t)
	id, actx := f.setupAdmin(t)
	inv := f.invite(t, actx, id, InviteRequest{Role: state.RoleContributor})
	bob, bctx := f.join(t, inv.Token, "bob")
	f.write(t, "users/bob/notes.txt", "bob's notes")
	os.Mkdir(filepath.Join(f.root, "shared"), 0o755)
	if _, err := f.acc.CreateBinding(actx, id, bob.User.ID, "shared", state.RoleViewer); err != nil {
		t.Fatal(err)
	}
	other := f.login(t, "bob", Client{Addr: "192.0.2.100:1"})
	if _, err := f.files.Mkdir(bctx, "users/bob", "photos"); err != nil {
		t.Fatal(err)
	}

	archived, err := f.acc.DeleteUser(actx, id, bob.User.ID)
	want := "users/.deleted/bob-20261014-" + bob.User.ID
	if err != nil || archived != want {
		t.Fatalf("delete = %q, %v; want %q", archived, err, want)
	}
	if f.exists("users/bob") || !f.exists(want+"/notes.txt") || !f.exists(want+"/photos") {
		t.Error("the home wasn't moved to the archive")
	}
	if _, ok, _ := f.acc.userByName("bob"); ok {
		t.Error("the user is left")
	}
	for _, g := range []string{other.Token} {
		if _, ok := f.acc.Authenticate(g); ok {
			t.Error("a session of the deleted user works")
		}
	}
	if _, st := f.acc.Identify(other.Token); st != NoSession {
		t.Error("a session of the deleted user is left")
	}
	for _, s := range f.storedSessions(t) {
		if s.User == bob.User.ID {
			t.Error("a stored session of the deleted user is left")
		}
	}
	for _, b := range f.bindings(t) {
		if b.Subject == bob.User.ID {
			t.Errorf("binding %+v is left", b)
		}
	}
	var uploaders []string
	f.db.View(func(tx *state.Tx) error {
		up, _, err := tx.Uploader(want + "/photos")
		uploaders = append(uploaders, up.User)
		return err
	})
	if !slices.Equal(uploaders, []string{bob.User.ID}) {
		t.Errorf("uploader records in the archive %q", uploaders)
	}
	moved := f.rec.ofType(events.FileMoved)
	if len(moved) != 1 || moved[0].Path != "users/bob" || moved[0].Target != want || moved[0].Detail != "home of deleted user bob" || moved[0].Actor.ID != id.User.ID {
		t.Errorf("file.moved %+v", moved)
	}
	deleted := f.rec.ofType(events.UserDeleted)
	if len(deleted) != 1 || deleted[0].Path != "bob" || deleted[0].Resolved != bob.User.ID || deleted[0].Detail != "id="+bob.User.ID+" home="+want {
		t.Errorf("user.deleted %+v", deleted)
	}

	inv = f.invite(t, actx, id, InviteRequest{Role: state.RoleContributor})
	bob2, b2ctx := f.join(t, inv.Token, "bob")
	if entries, err := f.files.List(b2ctx, "users/bob"); err != nil || len(entries) != 0 {
		t.Errorf("the new bob's home: %+v, %v", entries, err)
	}
	if _, err := f.files.List(b2ctx, want); err == nil {
		t.Error("the new bob can read the old bob's archive")
	}
	if entries, err := f.files.List(actx, want); err != nil || len(entries) != 2 {
		t.Errorf("an admin reads the archive: %+v, %v", entries, err)
	}
	second, err := f.acc.DeleteUser(actx, id, bob2.User.ID)
	if err != nil || second == want || !f.exists(want) || !f.exists(second) {
		t.Errorf("a second bob deleted the same day: %q, %v", second, err)
	}
}

func TestDeletingAUserWithoutAHomeFolder(t *testing.T) {
	f := newFixture(t)
	id, actx := f.setupAdmin(t)
	vic := f.addUser(t, "vic", state.RoleViewer)
	inv := f.invite(t, actx, id, InviteRequest{Role: state.RoleContributor})
	carol, _ := f.join(t, inv.Token, "carol")
	os.Remove(filepath.Join(f.root, "users", "carol"))
	for _, u := range []state.User{vic, carol.User} {
		if archived, err := f.acc.DeleteUser(actx, id, u.ID); err != nil || archived != "" {
			t.Errorf("delete %s = %q, %v", u.Username, archived, err)
		}
	}
	if f.exists("users/.deleted/carol") || len(f.rec.ofType(events.UserDeleted)) != 2 {
		t.Error("deleting without a home folder")
	}
	if _, err := f.acc.DeleteUser(actx, id, vic.ID); !errors.Is(err, ErrNoSuchUser) {
		t.Errorf("deleting twice: %v", err)
	}
}

// failingFolders moves homes through fsops, then runs hook once.
type failingFolders struct {
	Folders
	hook func()
}

func (h *failingFolders) MoveHome(ctx context.Context, from, to, detail string) error {
	err := h.Folders.MoveHome(ctx, from, to, detail)
	if h.hook != nil {
		h.hook()
		h.hook = nil
	}
	return err
}

func TestAFailedDeleteMovesTheHomeBack(t *testing.T) {
	f := newFixture(t)
	id, actx := f.setupAdmin(t)
	inv := f.invite(t, actx, id, InviteRequest{Role: state.RoleContributor})
	bob, _ := f.join(t, inv.Token, "bob")
	f.write(t, "users/bob/notes.txt", "bob's notes")
	f.acc.folders = &failingFolders{Folders: f.files, hook: func() {
		f.changeUser(t, id.User.ID, func(u *state.User) { u.Disabled = true })
	}}

	if _, err := f.acc.DeleteUser(actx, id, bob.User.ID); !errors.Is(err, ErrNotAdmin) {
		t.Fatalf("delete = %v", err)
	}
	if !f.exists("users/bob/notes.txt") {
		t.Error("the home wasn't moved back")
	}
	if entries, _ := os.ReadDir(filepath.Join(f.root, "users", ".deleted")); len(entries) != 0 {
		t.Errorf("the archive holds %v", entries)
	}
	if _, ok, _ := f.acc.userByName("bob"); !ok {
		t.Error("the user was deleted")
	}
	if _, ok := f.acc.Authenticate(f.login(t, "bob", Client{Addr: "192.0.2.101:1"}).Token); !ok {
		t.Error("bob can't log in")
	}
	moved := f.rec.ofType(events.FileMoved)
	if len(moved) != 2 || moved[1].Target != "users/bob" || moved[1].Detail != "home restored: deleting the user failed" {
		t.Errorf("file.moved %+v", moved)
	}
	if len(f.rec.ofType(events.UserDeleted)) != 0 {
		t.Error("user.deleted was recorded as made")
	}
	if denied := f.rec.ofType(events.UserDeleted, events.OutcomeDenied); len(denied) != 1 || denied[0].Path != "bob" ||
		denied[0].Detail != "id="+bob.User.ID+": "+ErrNotAdmin.Error() {
		t.Errorf("the refused delete's record %+v", denied)
	}
}

func TestPromotingAViewerCreatesTheirHome(t *testing.T) {
	f := newFixture(t)
	id, actx := f.setupAdmin(t)
	vic := f.addUser(t, "vic", state.RoleViewer)
	homes := func() int {
		n := 0
		for _, b := range f.bindings(t) {
			if b.Kind == state.KindHome && b.Subject == vic.ID {
				n++
			}
		}
		return n
	}
	info, err := f.acc.UpdateUser(actx, id, vic.ID, UserUpdate{Role: role(state.RoleContributor)})
	if err != nil || info.Role != state.RoleContributor || info.Home != "users/vic" || !f.exists("users/vic") || homes() != 1 {
		t.Fatalf("promote = %+v, %v; home %t, %d bindings", info, err, f.exists("users/vic"), homes())
	}
	updated := f.rec.ofType(events.UserUpdated)
	if len(updated) != 1 || updated[0].Detail != "id="+vic.ID+" role=viewer->contributor" || updated[0].Resolved != vic.ID {
		t.Errorf("user.updated %+v", updated)
	}
	if created := f.rec.ofType(events.FolderCreated); created[len(created)-1].Path != "users/vic" || created[len(created)-1].Detail != "home" {
		t.Errorf("folder.created %+v", created[len(created)-1])
	}

	f.write(t, "users/vic/notes.txt", "kept")
	if info, err := f.acc.UpdateUser(actx, id, vic.ID, UserUpdate{Role: role(state.RoleViewer)}); err != nil || info.Home != "users/vic" {
		t.Errorf("demote = %+v, %v", info, err)
	}
	if !f.exists("users/vic/notes.txt") || homes() != 1 {
		t.Error("demoting to viewer dropped the home")
	}
	before := len(f.rec.ofType(events.FolderCreated))
	if _, err := f.acc.UpdateUser(actx, id, vic.ID, UserUpdate{Role: role(state.RoleAdmin)}); err != nil {
		t.Errorf("promote again: %v", err)
	}
	if !f.exists("users/vic/notes.txt") || homes() != 1 || len(f.rec.ofType(events.FolderCreated)) != before {
		t.Error("promoting again didn't reuse the home")
	}

	wes := f.addUser(t, "wes", state.RoleViewer)
	f.write(t, "users/wes/old.txt", "someone else's")
	if _, err := f.acc.UpdateUser(actx, id, wes.ID, UserUpdate{Role: role(state.RoleContributor)}); !errors.Is(err, ErrHomeExists) {
		t.Errorf("promote onto an existing folder: %v", err)
	}
	if u := f.user(t, "wes"); u.Role != state.RoleViewer || slices.ContainsFunc(f.bindings(t), func(b state.Binding) bool { return b.Subject == wes.ID }) {
		t.Errorf("a refused promotion changed %+v", u)
	}
	xen := f.addUser(t, "xen", state.RoleViewer)
	os.MkdirAll(filepath.Join(f.root, "users", "xen"), 0o755)
	if info, err := f.acc.UpdateUser(actx, id, xen.ID, UserUpdate{Role: role(state.RoleContributor)}); err != nil || info.Home != "users/xen" {
		t.Errorf("promote onto an empty folder: %+v, %v", info, err)
	}
}

func TestDisablingEndsTheSessions(t *testing.T) {
	f := newFixture(t)
	id, actx := f.setupAdmin(t)
	bob := f.addUser(t, "bob", state.RoleContributor)
	g := f.login(t, "bob", Client{Addr: "192.0.2.102:1"})
	info, err := f.acc.UpdateUser(actx, id, bob.ID, UserUpdate{Disabled: flag(true)})
	if err != nil || !info.Disabled {
		t.Fatalf("disable = %+v, %v", info, err)
	}
	if _, ok := f.acc.Authenticate(g.Token); ok {
		t.Error("a session of a disabled user works")
	}
	if _, err := f.acc.Login(ctx, "bob", goodPassword, Client{Addr: "192.0.2.102:1"}); !errors.Is(err, ErrAccountDisabled) {
		t.Errorf("login while disabled: %v", err)
	}
	if u := f.user(t, "bob"); u.Epoch != bob.Epoch+1 {
		t.Errorf("epoch %d, want %d", u.Epoch, bob.Epoch+1)
	}
	if _, err := f.acc.UpdateUser(actx, id, bob.ID, UserUpdate{Disabled: flag(false)}); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.acc.Authenticate(g.Token); ok {
		t.Error("enabling brought an old session back")
	}
	f.login(t, "bob", Client{Addr: "192.0.2.102:1"})
	var details []string
	for _, ev := range f.rec.ofType(events.UserUpdated) {
		details = append(details, ev.Detail)
	}
	if want := []string{"id=" + bob.ID + " disabled=true", "id=" + bob.ID + " disabled=false"}; !slices.Equal(details, want) {
		t.Errorf("user.updated %q, want %q", details, want)
	}
}

func TestUpdateUserChecks(t *testing.T) {
	f := newFixture(t)
	id, actx := f.setupAdmin(t)
	bob := f.addUser(t, "bob", state.RoleContributor)
	if _, err := f.acc.UpdateUser(actx, id, bob.ID, UserUpdate{Role: role("owner")}); !errors.Is(err, ErrInvalidRole) {
		t.Errorf("invalid role: %v", err)
	}
	if _, err := f.acc.UpdateUser(actx, id, "u-0000000000000000", UserUpdate{Disabled: flag(true)}); !errors.Is(err, ErrNoSuchUser) {
		t.Errorf("unknown user: %v", err)
	}
	info, err := f.acc.UpdateUser(actx, id, bob.ID, UserUpdate{Role: role(state.RoleContributor), Disabled: flag(false)})
	if err != nil || info.Username != "bob" || info.Role != state.RoleContributor {
		t.Errorf("no change = %+v, %v", info, err)
	}
	if len(f.rec.ofType(events.UserUpdated)) != 0 {
		t.Error("an update that changes nothing was recorded")
	}
	users, err := f.acc.Users(id)
	if err != nil || len(users) != 2 || users[0].Username != "alice" || users[0].Home != "users/alice" || users[1].CreatedByName != "console" {
		t.Errorf("users %+v, %v", users, err)
	}
}

// Disabling a user and revoking a link or a session only take access away,
// so they go on while changes are paused; every other admin change waits.
func TestOnlyChangesThatTakeAccessAwayGoOnWhilePaused(t *testing.T) {
	f := newFixture(t)
	id, actx := f.setupAdmin(t)
	bob := f.addUser(t, "bob", state.RoleContributor)
	carol := f.addUser(t, "carol", state.RoleContributor)
	f.addUser(t, "dave", state.RoleViewer)
	dave, _ := f.loginAs(t, "dave")
	inv := f.invite(t, actx, id, InviteRequest{Role: state.RoleViewer})
	os.Mkdir(filepath.Join(f.root, "shared"), 0o755)
	shared, err := f.acc.CreateBinding(actx, id, state.Everyone, "shared", state.RoleViewer)
	if err != nil {
		t.Fatal(err)
	}
	a := audited(f)
	a.paused = true

	if _, err := f.acc.UpdateUser(actx, id, bob.ID, UserUpdate{Disabled: flag(true)}); err != nil {
		t.Errorf("disable: %v", err)
	}
	if _, err := f.acc.UpdateUser(actx, id, carol.ID, UserUpdate{Role: role(state.RoleContributor), Disabled: flag(true)}); err != nil {
		t.Errorf("disable, naming the same role: %v", err)
	}
	if err := f.acc.RevokeLink(actx, id, inv.ID); err != nil {
		t.Errorf("revoke link: %v", err)
	}
	if err := f.acc.EndSession(actx, id, dave.Session.ID); err != nil {
		t.Errorf("end session: %v", err)
	}
	for name, change := range map[string]func() error{
		"enable": func() error {
			_, err := f.acc.UpdateUser(actx, id, bob.ID, UserUpdate{Disabled: flag(false)})
			return err
		},
		"demote and disable": func() error {
			_, err := f.acc.UpdateUser(actx, id, bob.ID, UserUpdate{Role: role(state.RoleViewer), Disabled: flag(true)})
			return err
		},
		"invite": func() error {
			_, err := f.acc.CreateInvite(actx, id, InviteRequest{Role: state.RoleViewer})
			return err
		},
		"reset link": func() error { _, err := f.acc.CreateResetLink(actx, id, carol.ID); return err },
		"delete":     func() error { _, err := f.acc.DeleteUser(actx, id, bob.ID); return err },
		"bind": func() error {
			_, err := f.acc.CreateBinding(actx, id, bob.ID, "shared", state.RoleViewer)
			return err
		},
		"unbind": func() error { return f.acc.DeleteBinding(actx, id, shared.ID) },
	} {
		if err := change(); !errors.Is(err, events.ErrChangesPaused) {
			t.Errorf("%s while paused: %v", name, err)
		}
	}
	plain, protective := a.types()
	if len(plain) != 0 || len(protective) != 4 {
		t.Errorf("records: plain %q, protective %q", plain, protective)
	}
	denied := map[events.Type]int{}
	for _, ev := range f.rec.evs {
		if ev.Outcome == events.OutcomeDenied && strings.Contains(ev.Detail, "disk full") {
			denied[ev.Type]++
		}
	}
	want := map[events.Type]int{events.UserUpdated: 2, events.InviteCreated: 1, events.ResetCreated: 1, events.UserDeleted: 1,
		events.BindingCreated: 1, events.BindingDeleted: 1}
	if !maps.Equal(denied, want) {
		t.Errorf("refused changes recorded as denied: %v, want %v", denied, want)
	}
}

func TestBindings(t *testing.T) {
	f := newFixture(t)
	id, actx := f.setupAdmin(t)
	inv := f.invite(t, actx, id, InviteRequest{Role: state.RoleContributor})
	bob, bctx := f.join(t, inv.Token, "bob")
	os.MkdirAll(filepath.Join(f.root, "Shared", "deep"), 0o755)
	os.MkdirAll(filepath.Join(f.root, "users", ".deleted"), 0o755)
	f.write(t, "file.txt", "x")
	f.write(t, "Shared/a.txt", "a")
	readable := func() bool {
		file, err := f.files.Open(bctx, "Shared/a.txt")
		if err == nil {
			file.Close()
		}
		return err == nil
	}
	if err := os.Symlink(filepath.Join(f.root, "users", "bob"), filepath.Join(f.root, "into-home")); err != nil {
		t.Logf("no symlink: %v", err)
	}

	b, err := f.acc.CreateBinding(actx, id, bob.User.ID, "Shared/", state.RoleViewer)
	if err != nil {
		t.Fatal(err)
	}
	if b.Folder != "Shared" || b.Subject != bob.User.ID || b.SubjectName != "bob" || b.Role != state.RoleViewer ||
		b.Kind != state.KindCustom || b.CreatedBy != id.User.ID || b.CreatedByName != "alice" {
		t.Errorf("binding %+v", b)
	}
	if !readable() {
		t.Error("bob can't read in the bound folder")
	}
	created := f.rec.ofType(events.BindingCreated)
	if len(created) != 1 || created[0].Path != "Shared" || created[0].Detail != "id="+b.ID+" subject="+bob.User.ID+" role=viewer" {
		t.Errorf("binding.created %+v", created)
	}
	if _, err := f.acc.CreateBinding(actx, id, bob.User.ID, "Shared", state.RoleContributor); !errors.Is(err, ErrBindingExists) {
		t.Errorf("a second binding of bob's on the folder: %v", err)
	}
	all, err := f.acc.CreateBinding(actx, id, state.Everyone, "Shared/deep", state.RoleContributor)
	if err != nil || all.SubjectName != "" {
		t.Errorf("a binding for everyone: %+v, %v", all, err)
	}

	for _, tc := range []struct {
		subject, folder string
		role            state.Role
		want            error
	}{
		{bob.User.ID, "users", state.RoleViewer, ErrCoversHomes},
		{bob.User.ID, "users/alice", state.RoleViewer, ErrCoversHomes},
		{bob.User.ID, "users/.deleted", state.RoleViewer, ErrCoversHomes},
		{bob.User.ID, "/", state.RoleViewer, ErrCoversHomes},
		{bob.User.ID, "./users/../users/alice", state.RoleViewer, ErrCoversHomes},
		{bob.User.ID, "missing", state.RoleViewer, fsops.ErrNotFound},
		{bob.User.ID, "file.txt", state.RoleViewer, fsops.ErrNotDir},
		{bob.User.ID, "../outside", state.RoleViewer, sandbox.ErrTraversal},
		{bob.User.ID, ".gocalbox", state.RoleViewer, sandbox.ErrReserved},
		{bob.User.ID, "Shared", state.RoleAdmin, ErrInvalidRole},
		{bob.User.ID, "Shared", "owner", ErrInvalidRole},
		{"u-0000000000000000", "Shared", state.RoleViewer, ErrNoSuchUser},
	} {
		if _, err := f.acc.CreateBinding(actx, id, tc.subject, tc.folder, tc.role); !errors.Is(err, tc.want) {
			t.Errorf("bind %q as %s: %v, want %v", tc.folder, tc.role, err, tc.want)
		}
	}
	if f.exists("into-home") {
		if _, err := f.acc.CreateBinding(actx, id, state.Everyone, "into-home", state.RoleViewer); !errors.Is(err, ErrCoversHomes) {
			t.Errorf("a symlink to a home: %v", err)
		}
	}

	list, err := f.acc.Bindings(id)
	if err != nil {
		t.Fatal(err)
	}
	var folders []string
	for _, b := range list {
		folders = append(folders, b.Folder+" "+string(b.Kind))
	}
	if want := []string{"Shared custom", "Shared/deep custom", "public public", "users/alice home", "users/bob home"}; !slices.Equal(folders, want) {
		t.Errorf("bindings %q, want %q", folders, want)
	}

	var home, public BindingInfo
	for _, b := range list {
		switch b.Kind {
		case state.KindHome:
			home = b
		case state.KindPublic:
			public = b
		}
	}
	if err := f.acc.DeleteBinding(actx, id, home.ID); !errors.Is(err, ErrHomeBinding) {
		t.Errorf("delete a home binding: %v", err)
	}
	if err := f.acc.DeleteBinding(actx, id, "missing"); !errors.Is(err, ErrNoSuchBinding) {
		t.Errorf("delete a missing binding: %v", err)
	}
	for _, id2 := range []string{b.ID, public.ID} {
		if err := f.acc.DeleteBinding(actx, id, id2); err != nil {
			t.Errorf("delete %s: %v", id2, err)
		}
	}
	if readable() {
		t.Error("bob reads in the folder after the binding was deleted")
	}
	if deleted := f.rec.ofType(events.BindingDeleted); len(deleted) != 2 || deleted[0].Path != "Shared" {
		t.Errorf("binding.deleted %+v", deleted)
	}
}

func TestAdminSessions(t *testing.T) {
	f := newFixture(t)
	id, actx := f.setupAdmin(t)
	bob := f.addUser(t, "bob", state.RoleContributor)
	f.clock.advance(time.Second)
	g := f.login(t, "bob", Client{Addr: "192.0.2.104:1", UserAgent: "Bob/1"})
	bobID, bctx := f.identity(t, g)

	all, err := f.acc.AllSessions(id, "")
	if err != nil || len(all) != 2 || all[0].Username != "bob" || all[0].User != bob.ID || all[0].UserAgent != "Bob/1" ||
		all[0].Current || all[1].Username != "alice" || !all[1].Current {
		t.Errorf("all sessions %+v, %v", all, err)
	}
	if mine, _ := f.acc.AllSessions(id, bob.ID); len(mine) != 1 || mine[0].ID != bobID.Session.ID {
		t.Errorf("bob's sessions %+v", mine)
	}
	if _, err := f.acc.AllSessions(bobID, ""); !errors.Is(err, ErrNotAdmin) {
		t.Errorf("a contributor lists sessions: %v", err)
	}
	if err := f.acc.EndSession(bctx, bobID, id.Session.ID); !errors.Is(err, ErrNotAdmin) {
		t.Errorf("a contributor ends a session: %v", err)
	}
	if err := f.acc.EndSession(actx, id, bobID.Session.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.acc.Authenticate(g.Token); ok {
		t.Error("the ended session works")
	}
	if err := f.acc.EndSession(actx, id, bobID.Session.ID); !errors.Is(err, ErrNoSuchSession) {
		t.Errorf("ending it twice: %v", err)
	}
	ended := f.rec.ofType(events.SessionRevoked)
	if len(ended) != 1 || ended[0].Path != "bob" || ended[0].Detail != "id="+bobID.Session.ID+" reason=admin" || ended[0].Actor.ID != id.User.ID {
		t.Errorf("session.revoked %+v", ended)
	}

	f.login(t, "bob", Client{Addr: "192.0.2.105:1"})
	f.clock.advance(DefaultSessions.Idle)
	if all, err := f.acc.AllSessions(id, ""); err != nil || len(all) != 0 {
		t.Errorf("sessions idle too long are listed: %+v, %v", all, err)
	}
}

// Every admin call checks the account as it is now; every change also needs
// a password entered within the reauth window.
func TestAdminCallsNeedAnAdminAndChangesTheReauthWindow(t *testing.T) {
	f := newFixture(t)
	id, actx := f.setupAdmin(t)
	bob := f.addUser(t, "bob", state.RoleContributor)
	os.Mkdir(filepath.Join(f.root, "shared"), 0o755)
	bobID, bctx := f.loginAs(t, "bob")

	calls := func(id Identity, actx context.Context) map[string]error {
		out := map[string]error{}
		_, out["users"] = f.acc.Users(id)
		_, out["links"] = f.acc.Links(id)
		_, out["bindings"] = f.acc.Bindings(id)
		_, out["sessions"] = f.acc.AllSessions(id, "")
		_, out["update"] = f.acc.UpdateUser(actx, id, bob.ID, UserUpdate{Disabled: flag(false), Role: role(state.RoleViewer)})
		_, out["delete"] = f.acc.DeleteUser(actx, id, "u-0000000000000000")
		_, out["invite"] = f.acc.CreateInvite(actx, id, InviteRequest{Role: state.RoleViewer})
		_, out["reset"] = f.acc.CreateResetLink(actx, id, bob.ID)
		out["revoke"] = f.acc.RevokeLink(actx, id, "missing")
		_, out["bind"] = f.acc.CreateBinding(actx, id, bob.ID, "shared", state.RoleViewer)
		out["unbind"] = f.acc.DeleteBinding(actx, id, "missing")
		out["end"] = f.acc.EndSession(actx, id, "missing")
		return out
	}
	for name, err := range calls(bobID, bctx) {
		if !errors.Is(err, ErrNotAdmin) {
			t.Errorf("a contributor's %s: %v", name, err)
		}
	}
	denied := 0
	for _, ev := range f.rec.evs {
		if ev.Outcome == events.OutcomeDenied && ev.Actor.ID == bob.ID && strings.HasSuffix(ev.Detail, ErrNotAdmin.Error()) {
			denied++
		}
	}
	if denied != 8 {
		t.Errorf("%d of a contributor's 8 admin changes were recorded as denied", denied)
	}
	f.acc.CreateInvite(bctx, bobID, InviteRequest{Role: state.RoleAdmin, Username: "eve"})
	if got := f.rec.ofType(events.InviteCreated, events.OutcomeDenied); len(got) != 2 || got[1].Path != "eve" ||
		got[1].Detail != "role=admin: "+ErrNotAdmin.Error() || got[1].Actor.ID != bob.ID {
		t.Errorf("the record of a refused admin invite %+v", got)
	}
	f.clock.advance(15 * time.Minute)
	for name, err := range calls(id, actx) {
		reads := name == "users" || name == "links" || name == "bindings" || name == "sessions"
		if reads != !errors.Is(err, ErrReauthRequired) || reads && err != nil {
			t.Errorf("%s outside the reauth window: %v", name, err)
		}
	}
	refused := 0
	for _, ev := range f.rec.evs {
		if ev.Outcome == events.OutcomeDenied && ev.Actor.ID == id.User.ID && strings.HasSuffix(ev.Detail, ErrReauthRequired.Error()) {
			refused++
		}
	}
	if refused != 8 {
		t.Errorf("%d of 8 changes outside the reauth window were recorded as denied", refused)
	}
	if u := f.user(t, "bob"); u.Role != state.RoleContributor {
		t.Error("a refused update was made")
	}

	f.addUser(t, "carol", state.RoleAdmin)
	carol, cctx := f.loginAs(t, "carol")
	if _, err := f.acc.UpdateUser(cctx, carol, id.User.ID, UserUpdate{Disabled: flag(true)}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.acc.Users(id); !errors.Is(err, ErrNotAdmin) {
		t.Errorf("a disabled admin's identity lists users: %v", err)
	}
}

// countingFolders counts the folder changes asked of fsops.
type countingFolders struct {
	Folders
	provisions, moves int
}

func (c *countingFolders) Provision(ctx context.Context, folders []fsops.Folder, commit func() error) error {
	c.provisions++
	return c.Folders.Provision(ctx, folders, commit)
}

func (c *countingFolders) MoveHome(ctx context.Context, from, to, detail string) error {
	c.moves++
	return c.Folders.MoveHome(ctx, from, to, detail)
}

// hookedFolders runs a hook before a folder operation, once.
type hookedFolders struct {
	Folders
	beforeProvision, beforeBind func()
}

func (h *hookedFolders) Provision(ctx context.Context, folders []fsops.Folder, commit func() error) error {
	if h.beforeProvision != nil {
		h.beforeProvision()
		h.beforeProvision = nil
	}
	return h.Folders.Provision(ctx, folders, commit)
}

func (h *hookedFolders) BindFolder(ctx context.Context, folder string, commit func(stored string) error) error {
	if h.beforeBind != nil {
		h.beforeBind()
		h.beforeBind = nil
	}
	return h.Folders.BindFolder(ctx, folder, commit)
}

// A request a stolen session had under way when the owner secured the
// account doesn't commit afterwards.
func TestAnAdminChangeFromASessionEndedMeanwhileIsRefused(t *testing.T) {
	for _, secure := range []string{"password change", "sign out everywhere else"} {
		t.Run(secure, func(t *testing.T) {
			f := newFixture(t)
			owner, octx := f.setupAdmin(t)
			bob, _ := f.join(t, f.invite(t, octx, owner, InviteRequest{Role: state.RoleContributor}).Token, "bob")
			vic := f.addUser(t, "vic", state.RoleViewer)
			os.Mkdir(filepath.Join(f.root, "shared"), 0o755)
			public := f.bindings(t)[0].ID
			intruder, ictx := f.loginAs(t, "alice")
			folders := &countingFolders{Folders: f.files}
			f.acc.folders = folders
			if secure == "password change" {
				if _, _, err := f.acc.ChangePassword(octx, owner, goodPassword, goodPassword+" changed", adminBrowser); err != nil {
					t.Fatal(err)
				}
			} else if _, err := f.acc.RevokeOtherSessions(octx, owner); err != nil {
				t.Fatal(err)
			}
			link := f.invite(t, octx, owner, InviteRequest{Role: state.RoleViewer})

			for name, change := range map[string]func() error{
				"invite": func() error {
					_, err := f.acc.CreateInvite(ictx, intruder, InviteRequest{Role: state.RoleAdmin})
					return err
				},
				"reset link": func() error { _, err := f.acc.CreateResetLink(ictx, intruder, bob.User.ID); return err },
				"promote": func() error {
					_, err := f.acc.UpdateUser(ictx, intruder, vic.ID, UserUpdate{Role: role(state.RoleAdmin)})
					return err
				},
				"delete": func() error { _, err := f.acc.DeleteUser(ictx, intruder, bob.User.ID); return err },
				"bind": func() error {
					_, err := f.acc.CreateBinding(ictx, intruder, bob.User.ID, "shared", state.RoleContributor)
					return err
				},
				"unbind": func() error { return f.acc.DeleteBinding(ictx, intruder, public) },
				"revoke": func() error { return f.acc.RevokeLink(ictx, intruder, link.ID) },
				"end":    func() error { return f.acc.EndSession(ictx, intruder, owner.Session.ID) },
			} {
				if err := change(); !errors.Is(err, ErrSessionEnded) {
					t.Errorf("%s from the ended session: %v", name, err)
				}
			}
			if !slices.ContainsFunc(slices.Collect(maps.Values(f.storedSessions(t))), func(s state.Session) bool { return s.ID == owner.Session.ID }) {
				t.Error("the ended session ended the owner's")
			}
			unused, _ := f.acc.Links(owner)
			if u := f.user(t, "vic"); u.Role != state.RoleViewer || f.exists("users/vic") || !f.exists("users/bob") || len(unused) != 1 || len(f.bindings(t)) != 3 {
				t.Errorf("a change from the ended session was made: vic %+v, %d links, %d bindings", u, len(unused), len(f.bindings(t)))
			}
			if folders.provisions != 0 || folders.moves != 0 {
				t.Errorf("folders were changed and changed back: %d provisions, %d moves", folders.provisions, folders.moves)
			}
			if denied := f.rec.ofType(events.UserUpdated, events.OutcomeDenied); len(denied) != 1 || denied[0].Actor.Session != intruder.Session.ID {
				t.Errorf("the refused promotion's record %+v", denied)
			}
		})
	}
}

// The snapshot a request checks first may be older than the transaction;
// the transaction checks the account again.
func TestAdminChangesCheckTheAccountInTheTransaction(t *testing.T) {
	f := newFixture(t)
	id, actx := f.setupAdmin(t)
	bob := f.addUser(t, "bob", state.RoleViewer)
	os.Mkdir(filepath.Join(f.root, "shared"), 0o755)
	inv := f.invite(t, actx, id, InviteRequest{Role: state.RoleViewer})
	public := f.bindings(t)[0].ID
	f.addUser(t, "carol", state.RoleAdmin)
	if err := f.db.Update(func(tx *state.Tx) error {
		u, err := tx.User(id.User.ID)
		if err != nil {
			return err
		}
		u.Role = state.RoleContributor
		return tx.UpdateUser(u)
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.acc.asAdmin(id, true); err != nil {
		t.Fatalf("the snapshot already knows: %v", err)
	}
	for name, change := range map[string]func() error{
		"invite":     func() error { _, err := f.acc.CreateInvite(actx, id, InviteRequest{Role: state.RoleAdmin}); return err },
		"reset link": func() error { _, err := f.acc.CreateResetLink(actx, id, bob.ID); return err },
		"promote": func() error {
			_, err := f.acc.UpdateUser(actx, id, bob.ID, UserUpdate{Role: role(state.RoleAdmin)})
			return err
		},
		"delete": func() error { _, err := f.acc.DeleteUser(actx, id, bob.ID); return err },
		"bind": func() error {
			_, err := f.acc.CreateBinding(actx, id, bob.ID, "shared", state.RoleViewer)
			return err
		},
		"unbind": func() error { return f.acc.DeleteBinding(actx, id, public) },
		"revoke": func() error { return f.acc.RevokeLink(actx, id, inv.ID) },
	} {
		if err := change(); !errors.Is(err, ErrNotAdmin) {
			t.Errorf("%s by an admin demoted meanwhile: %v", name, err)
		}
	}
}

// A change that waited for a lock across a pause asks the guard again.
func TestAdminChangesAskTheGuardAgainUnderTheLock(t *testing.T) {
	for _, name := range []string{"update", "delete", "bind", "accept"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			id, actx := f.setupAdmin(t)
			bob := f.addUser(t, "bob", state.RoleViewer)
			os.Mkdir(filepath.Join(f.root, "shared"), 0o755)
			inv := f.invite(t, actx, id, InviteRequest{Role: state.RoleContributor})
			a := audited(f)
			pause := func() { a.mu.Lock(); a.paused = true; a.mu.Unlock() }
			hooked := &hookedFolders{Folders: f.files}
			f.acc.folders = hooked
			var err error
			switch name {
			case "update":
				hooked.beforeProvision = pause
				_, err = f.acc.UpdateUser(actx, id, bob.ID, UserUpdate{Role: role(state.RoleContributor)})
			case "delete":
				f.acc.mu.Lock()
				done := make(chan error, 1)
				go func() { _, err := f.acc.DeleteUser(actx, id, bob.ID); done <- err }()
				time.Sleep(50 * time.Millisecond)
				pause()
				f.acc.mu.Unlock()
				err = <-done
			case "bind":
				hooked.beforeBind = pause
				_, err = f.acc.CreateBinding(actx, id, bob.ID, "shared", state.RoleViewer)
			case "accept":
				hooked.beforeProvision = pause
				_, err = f.acc.AcceptInvite(ctx, inv.Token, "carol", goodPassword, Client{Addr: "192.0.2.110:1"})
			}
			if !errors.Is(err, events.ErrChangesPaused) {
				t.Fatalf("%s paused while it waited: %v", name, err)
			}
			if u, ok := f.acc.users()[bob.ID]; !ok || u.Role != state.RoleViewer || len(f.bindings(t)) != 2 || f.exists("users/bob") || f.exists("users/carol") {
				t.Errorf("the %s was made", name)
			}
			if plain, _ := a.types(); len(plain) != 0 {
				t.Errorf("records %q", plain)
			}
			denied := 0
			for _, ev := range f.rec.evs {
				if ev.Outcome == events.OutcomeDenied && strings.Contains(ev.Detail, "disk full") {
					denied++
				}
			}
			if want := map[bool]int{true: 0, false: 1}[name == "accept"]; denied != want {
				t.Errorf("%d denied records, want %d", denied, want)
			}
		})
	}
}

// A name fixed by an invite made while an accept was hashing its password
// is checked again in the transaction.
func TestAnAcceptChecksTheNameAgainInTheTransaction(t *testing.T) {
	f := newFixture(t)
	id, actx := f.setupAdmin(t)
	open := f.invite(t, actx, id, InviteRequest{Role: state.RoleContributor})
	var fixed NewLink
	f.acc.folders = &hookedFolders{Folders: f.files, beforeProvision: func() {
		fixed = f.invite(t, actx, id, InviteRequest{Role: state.RoleViewer, Username: "bob"})
	}}
	if _, err := f.acc.AcceptInvite(ctx, open.Token, "bob", goodPassword, Client{Addr: "192.0.2.111:1"}); !errors.Is(err, ErrUsernameTaken) {
		t.Fatalf("accept = %v", err)
	}
	if f.exists("users/bob") {
		t.Error("the home made for the refused accept is left")
	}
	if bob, _ := f.join(t, fixed.Token, ""); bob.User.Username != "bob" {
		t.Errorf("the fixed invite: %+v", bob.User)
	}
}

// A reset link restores a password that 100 failures disabled.
func TestAResetLinkRestoresADisabledPassword(t *testing.T) {
	f := newFixture(t)
	id, actx := f.setupAdmin(t)
	bob := f.addUser(t, "bob", state.RoleViewer)
	device := f.login(t, "bob", Client{Addr: "192.0.2.70:1"}).Device
	for i := range disableAt {
		c := addr(i)
		if i >= untrustedLimit {
			c.Device = device
		}
		if _, err := f.acc.Login(ctx, "bob", wrong, c); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d: %v", i+1, err)
		}
	}
	if _, err := f.acc.Login(ctx, "bob", goodPassword, Client{Addr: "192.0.2.71:1", Device: device}); err == nil {
		t.Fatal("the password still works after 100 failures")
	}
	l := f.resetLink(t, actx, id, bob.ID)
	if _, _, err := f.acc.AcceptReset(ctx, l.Token, "a brand new passphrase", Client{Addr: "192.0.2.80:1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.acc.Login(ctx, "bob", "a brand new passphrase", Client{Addr: "192.0.2.81:1"}); err != nil {
		t.Errorf("login after the reset: %v", err)
	}
}

func TestAnAdminDeletesTheirOwnAccount(t *testing.T) {
	f := newFixture(t)
	id, actx := f.setupAdmin(t)
	f.addUser(t, "bob", state.RoleAdmin)
	archived, err := f.acc.DeleteUser(actx, id, id.User.ID)
	if err != nil || archived != "users/.deleted/alice-20261014-"+id.User.ID || !f.exists(archived) || f.exists("users/alice") {
		t.Fatalf("delete = %q, %v", archived, err)
	}
	if _, ok, _ := f.acc.userByName("alice"); ok {
		t.Error("alice is left")
	}
	if len(f.storedSessions(t)) != 0 {
		t.Error("her session is left")
	}
	if len(f.rec.ofType(events.FileMoved)) != 1 || len(f.rec.ofType(events.UserDeleted)) != 1 {
		t.Errorf("events %v", f.rec.types())
	}
}

// A reset accept that waited for a hashing slot across a pause asks the
// guard again.
func TestAResetAsksTheGuardAgainAfterHashing(t *testing.T) {
	f := newFixture(t)
	id, actx := f.setupAdmin(t)
	bob := f.addUser(t, "bob", state.RoleViewer)
	l := f.resetLink(t, actx, id, bob.ID)
	a := audited(f)
	for range cap(f.acc.hasher.slots) {
		f.acc.hasher.slots <- struct{}{}
	}
	done := make(chan error, 1)
	go func() {
		_, _, err := f.acc.AcceptReset(ctx, l.Token, goodPassword+" new", Client{Addr: "192.0.2.90:1"})
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	a.mu.Lock()
	a.paused = true
	a.mu.Unlock()
	for range cap(f.acc.hasher.slots) {
		<-f.acc.hasher.slots
	}
	if err := <-done; !errors.Is(err, events.ErrChangesPaused) {
		t.Errorf("a reset that waited across the pause: %v", err)
	}
	if u := f.user(t, "bob"); u.Epoch != bob.Epoch || u.Hash != bob.Hash {
		t.Error("the password was changed")
	}
	if _, err := f.acc.InspectReset(l.Token, Client{Addr: "192.0.2.91:1"}); err != nil {
		t.Errorf("the link: %v", err)
	}
}
