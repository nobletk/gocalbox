package auth

import (
	"context"

	"github.com/nobletk/gocalbox/internal/authz"
	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/fsops"
	"github.com/nobletk/gocalbox/internal/state"
)

var _ fsops.Policy = (*Accounts)(nil)

// Subject returns the account the request acts for, as the snapshot holds
// it now: a role changed or an account disabled while the request runs
// counts from the next decision on.
func (a *Accounts) Subject(ctx context.Context) (fsops.Subject, bool) {
	snap := a.snap.Load()
	u, ok := snap.users[events.ActorFrom(ctx).ID]
	if !ok || u.Disabled {
		return fsops.Subject{}, false
	}
	return fsops.Subject{ID: u.ID, Role: authzRole(u.Role), Bindings: snap.bindings}, true
}

func (a *Accounts) UserName(id string) (string, bool) {
	u, ok := a.users()[id]
	return u.Username, ok
}

func authzRole(r state.Role) authz.Role {
	switch r {
	case state.RoleAdmin:
		return authz.Admin
	case state.RoleContributor:
		return authz.Contributor
	case state.RoleViewer:
		return authz.Viewer
	}
	return 0
}

func authzBindings(list []state.Binding) *authz.Bindings {
	out := make([]authz.Binding, 0, len(list))
	for _, b := range list {
		grant := authz.GrantNone
		switch b.Role {
		case state.RoleContributor:
			grant = authz.GrantContributor
		case state.RoleViewer:
			grant = authz.GrantViewer
		}
		subject := b.Subject
		if subject == state.Everyone {
			subject = authz.Everyone
		}
		out = append(out, authz.Binding{Subject: subject, Folder: b.Folder, Grant: grant, Home: b.Kind == state.KindHome})
	}
	return authz.NewBindings(out)
}
