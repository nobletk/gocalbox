// Package authz decides what a user may do with a path
package authz

import (
	"slices"
	"strings"
)

// Role is an account's role, the most its holder can ever do.
type Role uint8

const (
	Viewer Role = iota + 1
	Contributor
	Admin
)

// Grant is what the bindings give a user on a folder.
type Grant uint8

const (
	GrantNone     Grant = iota
	GrantTraverse       // the folder leads to one of the user's bound folders
	GrantViewer
	GrantContributor
)

// Relation is how a user stands to an object.
type Relation uint8

const (
	Unowned   Relation = iota // no record, or one that doesn't match the file
	Uploader                  // the record names the user
	HomeOwner                 // the object is inside the user's home
	Other                     // the record names someone else
)

// Action is what a request does. A move checks its source and its target
// folder separately; a rename is a move within one folder.
type Action uint8

const (
	List Action = iota
	Read
	Upload
	Mkdir
	MoveSource
	MoveTarget
	Delete
)

type Decision uint8

const (
	Hidden    Decision = iota // answered as if the path didn't exist
	Forbidden                 // the user can see the path but may not do this
	Filtered                  // a listing of only the entries on the way to bound folders
	Allow
)

// ceiling is the most a role lets bindings grant. An unknown role gets
// nothing.
func ceiling(r Role) Grant {
	switch r {
	case Contributor:
		return GrantContributor
	case Viewer:
		return GrantViewer
	}
	return GrantNone
}

// Effective caps a granted role by the account's role.
func Effective(r Role, g Grant) Grant { return min(g, ceiling(r)) }

// Decide applies the decision table to the granted role on the folder that
// counts for the action.
func Decide(r Role, g Grant, rel Relation, a Action) Decision {
	if r == Admin {
		return Allow
	}
	e := Effective(r, g)
	switch a {
	case List:
		switch {
		case e >= GrantViewer:
			return Allow
		case e == GrantTraverse:
			return Filtered
		}
	case Read:
		if e >= GrantViewer {
			return Allow
		}
	case Upload, Mkdir, MoveTarget:
		switch {
		case e == GrantContributor:
			return Allow
		case e >= GrantTraverse:
			return Forbidden
		}
	case MoveSource:
		switch {
		case e == GrantContributor && rel == Uploader:
			return Allow
		case e >= GrantViewer:
			return Forbidden
		}
	case Delete:
		switch {
		case e == GrantContributor && (rel == Uploader || rel == HomeOwner):
			return Allow
		case e >= GrantViewer:
			return Forbidden
		}
	}
	return Hidden
}

// Everyone is the binding subject that stands for every logged-in user.
const Everyone = "*"

// Binding gives a subject a role on a folder and everything below it.
type Binding struct {
	Subject string // a user ID, or Everyone
	Folder  string // in the spelling the directory stores
	Grant   Grant  // GrantViewer or GrantContributor
	Home    bool
}

// Bindings is an immutable set, shared by every request that reads it.
type Bindings struct {
	list []Binding
}

func NewBindings(list []Binding) *Bindings {
	return &Bindings{list: append([]Binding(nil), list...)}
}

// Within reports whether p is folder or lies below it.
func Within(p, folder string) bool {
	return folder == "." || p == folder || strings.HasPrefix(p, folder+"/")
}

// Granted is the most any of the user's bindings give on p; GrantTraverse
// if none covers p but p leads to one of them.
func (b *Bindings) Granted(user, p string) Grant {
	g := GrantNone
	for _, x := range b.list {
		if x.Subject != user && x.Subject != Everyone {
			continue
		}
		switch {
		case Within(p, x.Folder):
			g = max(g, x.Grant)
		case Within(x.Folder, p):
			g = max(g, GrantTraverse)
		}
	}
	return g
}

// Next returns the names in p, a folder the user can traverse, that lead
// towards the folders of the user's bindings.
func (b *Bindings) Next(user, p string) []string {
	var out []string
	for _, x := range b.list {
		if x.Subject != user && x.Subject != Everyone || x.Folder == p || !Within(x.Folder, p) {
			continue
		}
		rest := x.Folder
		if p != "." {
			rest = strings.TrimPrefix(x.Folder, p+"/")
		}
		name, _, _ := strings.Cut(rest, "/")
		if !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	return out
}

// Bound reports whether p is any binding's folder or leads to one. Such a
// folder can't be moved or deleted, by admins either.
func (b *Bindings) Bound(p string) bool {
	for _, x := range b.list {
		if Within(x.Folder, p) {
			return true
		}
	}
	return false
}

// Home is the folder of the user's home binding, or "".
func (b *Bindings) Home(user string) string {
	for _, x := range b.list {
		if x.Home && x.Subject == user {
			return x.Folder
		}
	}
	return ""
}

// RelationOf derives the relation of a user to the object at p from its
// uploader record, if it has one that matches the file, and the user's home.
func RelationOf(user, home, p, recordUser string, matching bool) Relation {
	switch {
	case matching && recordUser == user:
		return Uploader
	case home != "" && p != home && Within(p, home):
		return HomeOwner
	case matching:
		return Other
	}
	return Unowned
}
