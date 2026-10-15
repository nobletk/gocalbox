package fsops

import (
	"context"

	"github.com/nobletk/gocalbox/internal/authz"
	"github.com/nobletk/gocalbox/internal/events"
)

// fixedPolicy acts for one subject whatever the request.
type fixedPolicy Subject

func (p fixedPolicy) Subject(context.Context) (Subject, bool) { return Subject(p), true }

func (p fixedPolicy) UserName(id string) (string, bool) { return id, id == p.ID }

func asAdmin(s *Service) *Service {
	s.SetPolicy(fixedPolicy{ID: "u-admin", Role: authz.Admin})
	return s
}

// usersPolicy acts for the user the request's actor names, with one set of
// bindings for all of them.
type usersPolicy struct {
	roles    map[string]authz.Role
	bindings *authz.Bindings
}

func (p *usersPolicy) Subject(ctx context.Context) (Subject, bool) {
	id := events.ActorFrom(ctx).ID
	role, ok := p.roles[id]
	return Subject{ID: id, Role: role, Bindings: p.bindings}, ok
}

func (p *usersPolicy) UserName(id string) (string, bool) {
	_, ok := p.roles[id]
	return "name-of-" + id, ok
}

func errOf3[A, B any](_ A, _ B, err error) error { return err }
