package authz

import (
	"fmt"
	"math/rand/v2"
	"path"
	"slices"
	"strings"
	"testing"
)

var (
	roles     = []Role{Viewer, Contributor, Admin}
	grants    = []Grant{GrantNone, GrantTraverse, GrantViewer, GrantContributor}
	relations = []Relation{Uploader, HomeOwner, Other, Unowned}
	actions   = []Action{List, Read, Upload, Mkdir, MoveSource, MoveTarget, Delete}
)

// The decision table for non-admins, by the effective
// role on the folder that counts: none, traverse, viewer, contributor. An
// Allow there also needs one of rels, when given; otherwise it is Forbidden.
// Admins are allowed everything.
var table = []struct {
	action Action
	byRole [4]Decision
	rels   []Relation
}{
	{List, [4]Decision{Hidden, Filtered, Allow, Allow}, nil},
	{Read, [4]Decision{Hidden, Hidden, Allow, Allow}, nil},
	{Upload, [4]Decision{Hidden, Forbidden, Forbidden, Allow}, nil},
	{Mkdir, [4]Decision{Hidden, Forbidden, Forbidden, Allow}, nil},
	{MoveSource, [4]Decision{Hidden, Hidden, Forbidden, Allow}, []Relation{Uploader}},
	{MoveTarget, [4]Decision{Hidden, Forbidden, Forbidden, Allow}, nil},
	{Delete, [4]Decision{Hidden, Hidden, Forbidden, Allow}, []Relation{Uploader, HomeOwner}},
}

func TestDecisionTable(t *testing.T) {
	cases := 0
	for _, row := range table {
		for _, r := range roles {
			for _, g := range grants {
				for _, rel := range relations {
					cases++
					want := Allow
					if r != Admin {
						effective := g
						if r == Viewer && g == GrantContributor {
							effective = GrantViewer
						}
						want = row.byRole[effective]
						if want == Allow && row.rels != nil && !slices.Contains(row.rels, rel) {
							want = Forbidden
						}
					}
					if got := Decide(r, g, rel, row.action); got != want {
						t.Errorf("Decide(role %d, granted %d, relation %d, action %d) = %d, want %d", r, g, rel, row.action, got, want)
					}
				}
			}
		}
	}
	if cases != 336 || len(table) != len(actions) {
		t.Errorf("%d cases over %d actions", cases, len(table))
	}
}

func TestAnUnknownRoleMayDoNothing(t *testing.T) {
	for _, a := range actions {
		if d := Decide(0, GrantContributor, Uploader, a); d != Hidden {
			t.Errorf("action %d: %d", a, d)
		}
	}
}

func TestGrantedRoles(t *testing.T) {
	b := NewBindings([]Binding{
		{Subject: "alice", Folder: "users/alice", Grant: GrantContributor, Home: true},
		{Subject: "bob", Folder: "users/bob", Grant: GrantContributor, Home: true},
		{Subject: Everyone, Folder: "public", Grant: GrantContributor},
		{Subject: "carol", Folder: "media", Grant: GrantViewer},
		{Subject: "carol", Folder: "media/inbox", Grant: GrantContributor},
	})
	for _, tc := range []struct {
		user, path string
		want       Grant
	}{
		{"alice", "users/alice", GrantContributor},
		{"alice", "users/alice/deep/file.txt", GrantContributor},
		{"alice", "users", GrantTraverse},
		{"alice", ".", GrantTraverse},
		{"alice", "users/bob", GrantNone},
		{"alice", "users/alicex", GrantNone},
		{"alice", "public/x", GrantContributor},
		{"alice", "media", GrantNone},
		{"carol", "media", GrantViewer},
		{"carol", "media/inbox/a", GrantContributor},
		{"carol", "media/inboxes", GrantViewer},
		{"carol", "users", GrantNone},
		{"dave", "public", GrantContributor},
		{"dave", ".", GrantTraverse},
		{"dave", "elsewhere", GrantNone},
	} {
		if got := b.Granted(tc.user, tc.path); got != tc.want {
			t.Errorf("Granted(%s, %s) = %d, want %d", tc.user, tc.path, got, tc.want)
		}
	}
	for p, want := range map[string]bool{
		".": true, "users": true, "users/alice": true, "users/alice/x": false, "users/al": false,
		"public": true, "media": true, "media/inbox": true, "media/other": false, "other": false,
	} {
		if got := b.Bound(p); got != want {
			t.Errorf("Bound(%s) = %v", p, got)
		}
	}
	if b.Home("alice") != "users/alice" || b.Home("carol") != "" {
		t.Error("homes")
	}
	for _, tc := range []struct {
		user, path string
		want       []string
	}{
		{"alice", ".", []string{"users", "public"}},
		{"alice", "users", []string{"alice"}},
		{"carol", ".", []string{"public", "media"}},
		{"carol", "media", []string{"inbox"}},
		{"dave", ".", []string{"public"}},
		{"dave", "users", nil},
		{"alice", "users/alice", nil},
	} {
		if got := b.Next(tc.user, tc.path); !slices.Equal(got, tc.want) {
			t.Errorf("Next(%s, %s) = %q, want %q", tc.user, tc.path, got, tc.want)
		}
	}
}

func TestRelation(t *testing.T) {
	for _, tc := range []struct {
		path, recordUser string
		matching         bool
		want             Relation
	}{
		{"public/a.txt", "alice", true, Uploader},
		{"users/alice/a.txt", "alice", true, Uploader},
		{"users/alice/a.txt", "admin", true, HomeOwner},
		{"users/alice/a.txt", "", false, HomeOwner},
		{"users/alice/a.txt", "alice", false, HomeOwner},
		{"users/alice", "", false, Unowned},
		{"users/alicex/a.txt", "", false, Unowned},
		{"public/a.txt", "bob", true, Other},
		{"public/a.txt", "u-deleted", true, Other},
		{"public/a.txt", "alice", false, Unowned},
		{"public/a.txt", "", false, Unowned},
	} {
		if got := RelationOf("alice", "users/alice", tc.path, tc.recordUser, tc.matching); got != tc.want {
			t.Errorf("RelationOf(%s, record %q %v) = %d, want %d", tc.path, tc.recordUser, tc.matching, got, tc.want)
		}
	}
	if got := RelationOf("alice", "", "users/alice/a.txt", "", false); got != Unowned {
		t.Errorf("without a home: %d", got)
	}
}

var (
	folders = []string{".", "a", "a/b", "a/b/c", "a/bc", "d", "d/e", "users", "users/u1", "users/u2", "public"}
	users   = []string{"u1", "u2", "u3"}
)

func randomBindings(r *rand.Rand) []Binding {
	var out []Binding
	for range r.IntN(5) {
		subject := Everyone
		if r.IntN(3) > 0 {
			subject = users[r.IntN(len(users))]
		}
		out = append(out, Binding{Subject: subject, Folder: folders[1+r.IntN(len(folders)-1)], Grant: GrantViewer + Grant(r.IntN(2))})
	}
	return out
}

func randomPath(r *rand.Rand) string {
	p := folders[r.IntN(len(folders))]
	for range r.IntN(3) {
		p = path.Join(p, fmt.Sprintf("x%d", r.IntN(3)))
	}
	return p
}

// covers reports, without Granted, whether a binding of user or of everyone
// lies on p or above it.
func covers(list []Binding, user, p string) bool {
	return slices.ContainsFunc(list, func(b Binding) bool {
		return (b.Subject == user || b.Subject == Everyone) &&
			(b.Folder == p || strings.HasPrefix(p, b.Folder+"/"))
	})
}

// order ranks decisions by how much they let the user do.
var order = map[Decision]int{Hidden: 0, Forbidden: 1, Filtered: 2, Allow: 3}

func checkProperties(t *testing.T, r *rand.Rand) {
	list := randomBindings(r)
	b := NewBindings(list)
	user := users[r.IntN(len(users))]
	role := []Role{Viewer, Contributor}[r.IntN(2)]
	p := randomPath(r)
	rel := relations[r.IntN(len(relations))]

	if !covers(list, user, p) {
		if d := Decide(role, b.Granted(user, p), rel, Read); d != Hidden {
			t.Fatalf("no binding covers %s for %s in %v, yet Read = %d", p, user, list, d)
		}
	}

	below := path.Join(p, fmt.Sprintf("y%d", r.IntN(3)))
	for _, a := range []Action{List, Read, Upload, Mkdir, MoveTarget} {
		if Decide(role, b.Granted(user, p), rel, a) == Allow && Decide(role, b.Granted(user, below), rel, a) != Allow {
			t.Fatalf("%v: action %d allowed on %s but not on %s below it", list, a, p, below)
		}
	}

	added := Binding{Subject: user, Folder: folders[1+r.IntN(len(folders)-1)], Grant: GrantViewer + Grant(r.IntN(2))}
	if r.IntN(2) == 0 {
		added.Subject = Everyone
	}
	more := NewBindings(append(slices.Clone(list), added))
	q := randomPath(r)
	for _, a := range actions {
		before, after := Decide(role, b.Granted(user, q), rel, a), Decide(role, more.Granted(user, q), rel, a)
		if order[after] < order[before] {
			t.Fatalf("%v plus %v: action %d on %s went from %d to %d", list, added, a, q, before, after)
		}
	}
}

func TestDecisionProperties(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for range 20000 {
		checkProperties(t, r)
	}
}

func FuzzDecisionProperties(f *testing.F) {
	for i := range uint64(8) {
		f.Add(i, i*7919)
	}
	f.Fuzz(func(t *testing.T, a, b uint64) {
		checkProperties(t, rand.New(rand.NewPCG(a, b)))
	})
}
