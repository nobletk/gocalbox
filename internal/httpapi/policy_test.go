package httpapi

import (
	"context"

	"github.com/nobletk/gocalbox/internal/authz"
	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/fsops"
	"github.com/nobletk/gocalbox/internal/sandbox"
)

// adminPolicy lets every logged-in actor act as an admin, as tester is.
type adminPolicy struct{}

func (adminPolicy) Subject(ctx context.Context) (fsops.Subject, bool) {
	a := events.ActorFrom(ctx)
	return fsops.Subject{ID: a.ID, Role: authz.Admin}, a.ID != events.AnonymousID
}

func (adminPolicy) UserName(id string) (string, bool) { return id, true }

func adminFiles(sb *sandbox.Sandbox, pub fsops.Publisher, opts ...fsops.Option) *fsops.Service {
	s := fsops.New(sb, pub, opts...)
	s.SetPolicy(adminPolicy{})
	return s
}
