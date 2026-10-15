package auth

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nobletk/gocalbox/internal/authz"
	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/fsops"
	"github.com/nobletk/gocalbox/internal/state"
)

func TestTheAccountsNameTheSubjectOfARequest(t *testing.T) {
	f := newFixture(t)
	grant, err := f.acc.CompleteSetup(ctx, SetupRequest{Code: f.startSetup(t), Username: "root", Password: goodPassword}, Client{Addr: "192.0.2.9:4000"})
	if err != nil {
		t.Fatal(err)
	}
	cctx := events.WithActor(ctx, events.Actor{ID: events.ConsoleID})
	alice, err := f.acc.CreateUser(cctx, "alice", state.RoleContributor, goodPassword)
	if err != nil {
		t.Fatal(err)
	}
	vera, err := f.acc.CreateUser(cctx, "vera", state.RoleViewer, goodPassword)
	if err != nil {
		t.Fatal(err)
	}
	if failed := f.acc.EnsureLayout(ctx); len(failed) > 0 {
		t.Fatalf("EnsureLayout: %v", failed)
	}
	subject := func(id string) (fsops.Subject, bool) {
		return f.acc.Subject(events.WithActor(ctx, events.Actor{ID: id}))
	}

	if s, ok := subject(grant.Me.ID); !ok || s.ID != grant.Me.ID || s.Role != authz.Admin {
		t.Errorf("admin: %+v, %v", s, ok)
	}
	s, ok := subject(alice.ID)
	if !ok || s.Role != authz.Contributor || s.Bindings.Home(alice.ID) != "users/alice" ||
		s.Bindings.Granted(alice.ID, "users/alice/x") != authz.GrantContributor ||
		s.Bindings.Granted(alice.ID, "public") != authz.GrantContributor ||
		s.Bindings.Granted(alice.ID, "users/root") != authz.GrantNone {
		t.Errorf("contributor: %+v, %v", s, ok)
	}
	s, ok = subject(vera.ID)
	if !ok || s.Role != authz.Viewer || s.Bindings.Home(vera.ID) != "" || s.Bindings.Granted(vera.ID, "users") != authz.GrantNone {
		t.Errorf("viewer: %+v, %v", s, ok)
	}
	for _, id := range []string{"u-nobody", events.AnonymousID, events.ConsoleID, ""} {
		if s, ok := subject(id); ok {
			t.Errorf("a request by %q acts for %+v", id, s)
		}
	}

	err = f.acc.update(func(tx *state.Tx) error {
		u, err := tx.User(alice.ID)
		if err != nil {
			return err
		}
		u.Disabled = true
		return tx.UpdateUser(u)
	})
	if err != nil {
		t.Fatal(err)
	}
	if s, ok := subject(alice.ID); ok {
		t.Errorf("a disabled account acts as %+v", s)
	}
	if name, ok := f.acc.UserName(alice.ID); !ok || name != "alice" {
		t.Errorf("UserName = %q, %v", name, ok)
	}
	if name, ok := f.acc.UserName("u-deleted"); ok {
		t.Errorf("a deleted user is named %q", name)
	}
}

func TestBindingsSnapshotFollowsTheStore(t *testing.T) {
	b := authzBindings([]state.Binding{
		{Subject: "u-1", Folder: "users/one", Role: state.RoleContributor, Kind: state.KindHome},
		{Subject: state.Everyone, Folder: "public", Role: state.RoleContributor, Kind: state.KindPublic},
		{Subject: "u-2", Folder: "media", Role: state.RoleViewer, Kind: state.KindCustom},
	})
	for _, tc := range []struct {
		user, path string
		want       authz.Grant
	}{
		{"u-1", "users/one/a", authz.GrantContributor},
		{"u-1", "users", authz.GrantTraverse},
		{"u-2", "public/x", authz.GrantContributor},
		{"u-2", "media/x", authz.GrantViewer},
		{"u-1", "media", authz.GrantNone},
	} {
		if got := b.Granted(tc.user, tc.path); got != tc.want {
			t.Errorf("Granted(%s, %s) = %d, want %d", tc.user, tc.path, got, tc.want)
		}
	}
	if b.Home("u-1") != "users/one" || b.Home("u-2") != "" {
		t.Error("homes")
	}
	for r, want := range map[state.Role]authz.Role{
		state.RoleAdmin: authz.Admin, state.RoleContributor: authz.Contributor, state.RoleViewer: authz.Viewer, "owner": 0,
	} {
		if got := authzRole(r); got != want {
			t.Errorf("authzRole(%s) = %d", r, got)
		}
	}
}

// Each change here swaps alice's role and her binding on media, and both
// states give her viewer there. Contributor would come from mixing them.
func TestARequestSeesUsersAndBindingsOfOneState(t *testing.T) {
	f := newFixture(t)
	u, err := f.acc.CreateUser(events.WithActor(ctx, events.Actor{ID: events.ConsoleID}), "alice", state.RoleContributor, goodPassword)
	if err != nil {
		t.Fatal(err)
	}
	swap := func(userRole, bindingRole state.Role) {
		err := f.acc.update(func(tx *state.Tx) error {
			cur, err := tx.User(u.ID)
			if err != nil {
				return err
			}
			cur.Role = userRole
			if err := tx.UpdateUser(cur); err != nil {
				return err
			}
			return tx.PutBinding(state.Binding{ID: "b-media", Subject: u.ID, Folder: "media", Role: bindingRole,
				Kind: state.KindCustom, CreatedBy: events.SystemID, CreatedAt: time.Now()})
		})
		if err != nil {
			t.Error(err)
		}
	}
	swap(state.RoleContributor, state.RoleViewer)

	var stop atomic.Bool
	var mixed atomic.Int64
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for !stop.Load() {
				s, ok := f.acc.Subject(events.WithActor(ctx, events.Actor{ID: u.ID}))
				if ok && authz.Effective(s.Role, s.Bindings.Granted(u.ID, "media/x")) == authz.GrantContributor {
					mixed.Add(1)
				}
			}
		})
	}
	for i := range 300 {
		if i%2 == 0 {
			swap(state.RoleViewer, state.RoleContributor)
		} else {
			swap(state.RoleContributor, state.RoleViewer)
		}
	}
	stop.Store(true)
	wg.Wait()
	if mixed.Load() > 0 {
		t.Errorf("%d requests saw contributor on media, which no state grants", mixed.Load())
	}
}
