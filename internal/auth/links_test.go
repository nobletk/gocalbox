package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/state"
)

var adminBrowser = Client{Addr: "192.0.2.20:5000", UserAgent: "AdminBrowser/1.0"}

// setupAdmin makes alice the first admin through setup, which creates the
// layout and her home, and returns her identity and a context acting for
// her.
func (f *fixture) setupAdmin(t *testing.T) (Identity, context.Context) {
	t.Helper()
	code := f.startSetup(t)
	g, err := f.acc.CompleteSetup(ctx, SetupRequest{Code: code, Username: "alice", Password: goodPassword}, adminBrowser)
	if err != nil {
		t.Fatal(err)
	}
	return f.identity(t, g)
}

func (f *fixture) identity(t *testing.T, g Grant) (Identity, context.Context) {
	t.Helper()
	id, ok := f.acc.Authenticate(g.Token)
	if !ok {
		t.Fatal("the grant's session isn't valid")
	}
	return id, events.WithActor(ctx, events.Actor{ID: id.User.ID, Name: id.User.Username, Session: id.Session.ID})
}

// loginAs logs a user in from a browser of its own and returns the identity.
func (f *fixture) loginAs(t *testing.T, name string) (Identity, context.Context) {
	t.Helper()
	return f.identity(t, f.login(t, name, Client{Addr: "192.0.2.21:5000"}))
}

func (f *fixture) invite(t *testing.T, actx context.Context, id Identity, req InviteRequest) NewLink {
	t.Helper()
	l, err := f.acc.CreateInvite(actx, id, req)
	if err != nil {
		t.Fatalf("invite %+v: %v", req, err)
	}
	return l
}

func (f *fixture) resetLink(t *testing.T, actx context.Context, id Identity, userID string) NewLink {
	t.Helper()
	l, err := f.acc.CreateResetLink(actx, id, userID)
	if err != nil {
		t.Fatalf("reset link: %v", err)
	}
	return l
}

var joinAddr = 0

// join accepts an invite as name, each time from another address, and
// returns the new account's identity.
func (f *fixture) join(t *testing.T, token, name string) (Identity, context.Context) {
	t.Helper()
	joinAddr++
	g, err := f.acc.AcceptInvite(ctx, token, name, goodPassword, Client{Addr: fmt.Sprintf("198.18.0.%d:1", joinAddr%250+1)})
	if err != nil {
		t.Fatalf("accept as %s: %v", name, err)
	}
	return f.identity(t, g)
}

// storedLinks returns the stored links by key.
func (f *fixture) storedLinks(t *testing.T) map[string]state.Link {
	t.Helper()
	out := map[string]state.Link{}
	f.db.View(func(tx *state.Tx) error {
		return tx.Links(func(k []byte, l state.Link) error { out[string(k)] = l; return nil })
	})
	return out
}

func (f *fixture) storedLink(t *testing.T, id string) (state.Link, bool) {
	t.Helper()
	for _, l := range f.storedLinks(t) {
		if l.ID == id {
			return l, true
		}
	}
	return state.Link{}, false
}

// changeUser writes a user record directly, as no API call would, and
// reloads the snapshot.
func (f *fixture) changeUser(t *testing.T, id string, change func(*state.User)) {
	t.Helper()
	err := f.db.Update(func(tx *state.Tx) error {
		u, err := tx.User(id)
		if err != nil {
			return err
		}
		change(&u)
		return tx.UpdateUser(u)
	})
	if err == nil {
		err = f.acc.reload()
	}
	if err != nil {
		t.Fatal(err)
	}
}

// ofType returns the events of a type, of changes made unless outcome says
// otherwise.
func (r *recorder) ofType(typ events.Type, outcome ...events.Outcome) []events.Event {
	want := events.OutcomeOK
	if len(outcome) > 0 {
		want = outcome[0]
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []events.Event
	for _, ev := range r.evs {
		if ev.Type == typ && ev.Outcome == want {
			out = append(out, ev)
		}
	}
	return out
}

// revokedFor returns the link.revoked events, as "<link ID> <reason>".
func (r *recorder) revokedFor() []string {
	var out []string
	for _, ev := range r.ofType(events.LinkRevoked) {
		var id, reason string
		for _, field := range strings.Fields(ev.Detail) {
			if v, ok := strings.CutPrefix(field, "id="); ok {
				id = v
			}
			if v, ok := strings.CutPrefix(field, "reason="); ok {
				reason = v
			}
		}
		out = append(out, id+" "+reason)
	}
	return out
}

func linkIDs(ls []RevokedLink) []string {
	var out []string
	for _, l := range ls {
		out = append(out, l.ID)
	}
	slices.Sort(out)
	return out
}

func sorted(s ...string) []string {
	s = slices.Clone(s)
	slices.Sort(s)
	return s
}

func TestALinkIsStoredOnlyAsTheHashOfItsToken(t *testing.T) {
	f := newFixture(t)
	id, actx := f.setupAdmin(t)
	bob := f.addUser(t, "bob", state.RoleViewer)
	inv := f.invite(t, actx, id, InviteRequest{Role: state.RoleContributor, Note: "Anna's phone"})
	reset := f.resetLink(t, actx, id, bob.ID)
	console, err := f.acc.ConsoleResetLink(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}

	stored := f.storedLinks(t)
	if len(stored) != 3 {
		t.Fatalf("stored links: %+v", stored)
	}
	for _, nl := range []NewLink{inv, reset, console} {
		if len(nl.Token) != 26 || nl.ID == "" {
			t.Errorf("new link %+v", nl)
		}
		sum := sha256.Sum256([]byte(nl.Token))
		if l, ok := stored[string(sum[:])]; !ok || l.ID != nl.ID || l.Kind != nl.Kind {
			t.Errorf("link %s isn't stored under its token's hash", nl.ID)
		}
	}
	f.acc.Close()
	data, err := os.ReadFile(f.db.Path())
	if err != nil {
		t.Fatal(err)
	}
	for _, nl := range []NewLink{inv, reset, console} {
		if strings.Contains(string(data), nl.Token) {
			t.Errorf("the state file holds the token of %s", nl.ID)
		}
	}
	for _, ev := range f.rec.evs {
		for _, nl := range []NewLink{inv, reset, console} {
			if strings.Contains(fmt.Sprintf("%+v", ev), nl.Token) {
				t.Errorf("event %s holds a token", ev.Type)
			}
		}
	}
	list, err := f.acc.Links(id)
	if err != nil {
		t.Fatal(err)
	}
	js, _ := json.Marshal(list)
	for _, nl := range []NewLink{inv, reset, console} {
		if strings.Contains(string(js), nl.Token) {
			t.Errorf("the list holds the token of %s", nl.ID)
		}
	}
}

func TestAnInviteCreatesTheAccountWithItsHomeAndLogsItIn(t *testing.T) {
	f := newFixture(t)
	id, actx := f.setupAdmin(t)
	now := f.clock.now()
	inv := f.invite(t, actx, id, InviteRequest{Role: state.RoleContributor, Note: "Bob's laptop"})
	if inv.Kind != state.KindInvite || inv.Role != state.RoleContributor || inv.Username != "" || !inv.Expires.Equal(now.Add(7*24*time.Hour)) {
		t.Errorf("invite %+v", inv)
	}
	created := f.rec.ofType(events.InviteCreated)
	if len(created) != 1 || created[0].Detail != "id="+inv.ID+" role=contributor" || created[0].Actor.ID != id.User.ID {
		t.Errorf("invite.created %+v", created)
	}

	info, err := f.acc.InspectInvite(inv.Token, Client{Addr: "192.0.2.31:1"})
	if err != nil || info != (InviteInfo{Role: state.RoleContributor, Expires: inv.Expires}) {
		t.Errorf("inspect = %+v, %v", info, err)
	}
	g, err := f.acc.AcceptInvite(ctx, inv.Token, "Bob", goodPassword, Client{Addr: "192.0.2.31:1", UserAgent: "Phone/1"})
	if err != nil {
		t.Fatal(err)
	}
	if g.Me.Username != "bob" || g.Me.Role != state.RoleContributor || g.Me.Home != "users/bob" || g.Device == "" {
		t.Errorf("grant %+v", g)
	}
	bob, ok := f.acc.Authenticate(g.Token)
	if !ok || bob.Session.UserAgent != "Phone/1" {
		t.Fatalf("the new session: %+v, %v", bob, ok)
	}
	u := f.user(t, "bob")
	if u.CreatedBy != id.User.ID || u.Invite != inv.ID || !u.CreatedAt.Equal(now) {
		t.Errorf("user %+v", u)
	}
	if !f.exists("users/bob") {
		t.Error("no home")
	}
	if !slices.ContainsFunc(f.bindings(t), func(b state.Binding) bool {
		return b.Kind == state.KindHome && b.Subject == u.ID && b.Folder == "users/bob"
	}) {
		t.Errorf("no home binding: %+v", f.bindings(t))
	}
	if l, ok := f.storedLink(t, inv.ID); !ok || !l.Used.Equal(now) {
		t.Errorf("the link wasn't marked used: %+v", l)
	}
	used := f.rec.ofType(events.InviteUsed)
	if len(used) != 1 || used[0].Path != "bob" || used[0].Resolved != u.ID || used[0].Detail != "id="+inv.ID+" role=contributor" ||
		used[0].Actor.ID != u.ID || used[0].Actor.Session != bob.Session.ID {
		t.Errorf("invite.used %+v", used)
	}
	if home := f.rec.ofType(events.FolderCreated); len(home) == 0 || home[len(home)-1].Path != "users/bob" || home[len(home)-1].Detail != "home" {
		t.Errorf("folder.created %+v", home)
	}

	if _, err := f.acc.AcceptInvite(ctx, inv.Token, "bob2", goodPassword, Client{Addr: "192.0.2.32:1"}); !errors.Is(err, ErrLinkInvalid) {
		t.Errorf("second accept: %v", err)
	}
	if _, err := f.acc.InspectInvite(inv.Token, Client{Addr: "192.0.2.32:1"}); !errors.Is(err, ErrLinkInvalid) {
		t.Errorf("inspect after use: %v", err)
	}

	view := f.invite(t, actx, id, InviteRequest{Role: state.RoleViewer, Username: "Vic"})
	if info, err := f.acc.InspectInvite(view.Token, Client{Addr: "192.0.2.33:1"}); err != nil || info.Username != "vic" || info.Role != state.RoleViewer {
		t.Errorf("inspect = %+v, %v", info, err)
	}
	vic, _ := f.join(t, view.Token, "")
	if vic.User.Username != "vic" || vic.User.Role != state.RoleViewer || f.exists("users/vic") {
		t.Errorf("a viewer's invite: %+v, home %t", vic.User, f.exists("users/vic"))
	}
}

func TestAnAdminInviteLastsADayAtMost(t *testing.T) {
	f := newFixture(t)
	id, actx := f.setupAdmin(t)
	now := f.clock.now()
	for _, tc := range []struct {
		ttl  time.Duration
		role state.Role
		want time.Duration
	}{
		{7 * 24 * time.Hour, state.RoleAdmin, 24 * time.Hour},
		{7 * 24 * time.Hour, state.RoleViewer, 7 * 24 * time.Hour},
		{time.Hour, state.RoleAdmin, time.Hour},
		{time.Hour, state.RoleContributor, time.Hour},
	} {
		f.acc.linkCfg.InviteTTL = tc.ttl
		if l := f.invite(t, actx, id, InviteRequest{Role: tc.role}); !l.Expires.Equal(now.Add(tc.want)) {
			t.Errorf("-invite-ttl %v, %s: expires after %v, want %v", tc.ttl, tc.role, l.Expires.Sub(now), tc.want)
		}
	}

	f.acc.linkCfg = DefaultLinks
	l := f.invite(t, actx, id, InviteRequest{Role: state.RoleAdmin})
	f.clock.advance(24*time.Hour - time.Second)
	if _, err := f.acc.InspectInvite(l.Token, Client{Addr: "192.0.2.40:1"}); err != nil {
		t.Errorf("before expiry: %v", err)
	}
	f.clock.advance(time.Second)
	if _, err := f.acc.InspectInvite(l.Token, Client{Addr: "192.0.2.41:1"}); !errors.Is(err, ErrLinkInvalid) {
		t.Errorf("at expiry: %v", err)
	}
	if _, err := f.acc.AcceptInvite(ctx, l.Token, "eve", goodPassword, Client{Addr: "192.0.2.42:1"}); !errors.Is(err, ErrLinkInvalid) {
		t.Errorf("accept at expiry: %v", err)
	}
}

func TestInviteRequestsAreChecked(t *testing.T) {
	f := newFixture(t)
	id, actx := f.setupAdmin(t)
	f.addUser(t, "bob", state.RoleViewer)
	for _, tc := range []struct {
		req  InviteRequest
		want error
	}{
		{InviteRequest{Role: "owner"}, ErrInvalidRole},
		{InviteRequest{Role: ""}, ErrInvalidRole},
		{InviteRequest{Role: state.RoleViewer, Username: "B"}, ErrInvalidUsername},
		{InviteRequest{Role: state.RoleViewer, Username: "console"}, ErrUsernameTaken},
		{InviteRequest{Role: state.RoleViewer, Username: "Bob"}, ErrUsernameTaken},
		{InviteRequest{Role: state.RoleViewer, Note: strings.Repeat("é", 101)}, ErrInvalidNote},
		{InviteRequest{Role: state.RoleViewer, Note: "line\nbreak"}, ErrInvalidNote},
		{InviteRequest{Role: state.RoleViewer, Note: "evil‮gnp.exe"}, ErrInvalidNote},
		{InviteRequest{Role: state.RoleViewer, Note: "bad \xff"}, ErrInvalidNote},
	} {
		if _, err := f.acc.CreateInvite(actx, id, tc.req); !errors.Is(err, tc.want) {
			t.Errorf("%+v: %v, want %v", tc.req, err, tc.want)
		}
	}
	if len(f.storedLinks(t)) != 0 {
		t.Error("a refused invite was stored")
	}
	if _, err := f.acc.CreateInvite(actx, id, InviteRequest{Role: state.RoleViewer, Note: strings.Repeat("é", 100)}); err != nil {
		t.Errorf("a 100-character note: %v", err)
	}
}

// Every bad token gets one answer, at inspect and at accept, so a guess
// tells nothing about the tokens that exist.
func TestEveryBadTokenGetsTheSameAnswer(t *testing.T) {
	f := newFixture(t)
	id, actx := f.setupAdmin(t)
	bob := f.addUser(t, "bob", state.RoleViewer)
	used := f.invite(t, actx, id, InviteRequest{Role: state.RoleViewer})
	f.join(t, used.Token, "carol")
	revoked := f.invite(t, actx, id, InviteRequest{Role: state.RoleViewer})
	if err := f.acc.RevokeLink(actx, id, revoked.ID); err != nil {
		t.Fatal(err)
	}
	expired := f.invite(t, actx, id, InviteRequest{Role: state.RoleViewer})
	expiredReset := f.resetLink(t, actx, id, bob.ID)
	f.clock.advance(7*24*time.Hour + time.Second)
	id, actx = f.loginAs(t, "alice")
	invite := f.invite(t, actx, id, InviteRequest{Role: state.RoleViewer})
	reset := f.resetLink(t, actx, id, bob.ID)

	n := 0
	client := func() Client { n++; return Client{Addr: fmt.Sprintf("203.0.113.%d:1", n)} }
	for _, tc := range []struct {
		name, token string
		kind        state.LinkKind
	}{
		{"unknown", rand.Text(), state.KindInvite},
		{"unknown", rand.Text(), state.KindReset},
		{"empty", "", state.KindInvite},
		{"used", used.Token, state.KindInvite},
		{"revoked", revoked.Token, state.KindInvite},
		{"expired", expired.Token, state.KindInvite},
		{"expired", expiredReset.Token, state.KindReset},
		{"a reset token", reset.Token, state.KindInvite},
		{"an invite token", invite.Token, state.KindReset},
	} {
		var errs []error
		if tc.kind == state.KindInvite {
			_, err := f.acc.InspectInvite(tc.token, client())
			errs = append(errs, err)
			_, err = f.acc.AcceptInvite(ctx, tc.token, "dave", goodPassword, client())
			errs = append(errs, err)
		} else {
			_, err := f.acc.InspectReset(tc.token, client())
			errs = append(errs, err)
			_, _, err = f.acc.AcceptReset(ctx, tc.token, goodPassword+" new", client())
			errs = append(errs, err)
		}
		for _, err := range errs {
			if err != ErrLinkInvalid {
				t.Errorf("%s as %s: %v", tc.name, tc.kind, err)
			}
		}
	}
	if _, err := f.acc.InspectInvite(invite.Token, client()); err != nil {
		t.Errorf("the invite stopped working: %v", err)
	}
	if _, err := f.acc.InspectReset(reset.Token, client()); err != nil {
		t.Errorf("the reset link stopped working: %v", err)
	}
	if _, ok := f.acc.users()[bob.ID]; !ok || f.user(t, "bob").Epoch != bob.Epoch {
		t.Error("a bad token changed the account")
	}
}

func TestBadTokensCountAgainstTheAddress(t *testing.T) {
	f := newFixture(t)
	id, actx := f.setupAdmin(t)
	inv := f.invite(t, actx, id, InviteRequest{Role: state.RoleViewer})
	c := Client{Addr: "203.0.113.7:1"}
	for i := range 4 {
		if _, err := f.acc.InspectInvite(rand.Text(), c); !errors.Is(err, ErrLinkInvalid) {
			t.Fatalf("bad token %d: %v", i, err)
		}
	}
	if _, err := f.acc.InspectInvite(inv.Token, c); err != nil {
		t.Fatalf("a good token after four bad ones: %v", err)
	}
	if _, _, err := f.acc.AcceptReset(ctx, rand.Text(), goodPassword, c); !errors.Is(err, ErrLinkInvalid) {
		t.Fatalf("fifth bad token: %v", err)
	}
	var tm *TooManyAttemptsError
	if _, err := f.acc.InspectInvite(inv.Token, c); !errors.As(err, &tm) || tm.RetryAfter <= 0 {
		t.Fatalf("after five bad tokens, with an inspect between: %v", err)
	}
	if _, err := f.acc.AcceptInvite(ctx, inv.Token, "bob", goodPassword, c); !errors.As(err, &tm) {
		t.Fatalf("accept after five bad tokens: %v", err)
	}
	if _, err := f.acc.Login(ctx, "alice", goodPassword, c); err != nil {
		t.Errorf("logins from that address were blocked by bad tokens: %v", err)
	}
	if _, err := f.acc.InspectInvite(inv.Token, Client{Addr: "203.0.113.8:1"}); err != nil {
		t.Errorf("another address: %v", err)
	}

	f.clock.advance(time.Second)
	if _, err := f.acc.AcceptInvite(ctx, inv.Token, "bob", goodPassword, c); err != nil {
		t.Fatalf("after waiting: %v", err)
	}
	for i := range 5 {
		if _, err := f.acc.InspectInvite(rand.Text(), c); !errors.Is(err, ErrLinkInvalid) {
			t.Fatalf("an accept didn't clear the count: bad token %d: %v", i, err)
		}
	}
}

func TestAFailedAcceptLeavesTheInviteUsable(t *testing.T) {
	f := newFixture(t)
	id, actx := f.setupAdmin(t)
	f.addUser(t, "taken", state.RoleViewer)
	inv := f.invite(t, actx, id, InviteRequest{Role: state.RoleContributor})
	os.MkdirAll(filepath.Join(f.root, "users", "dan", "old"), 0o755)
	var weak *WeakPasswordError
	for _, tc := range []struct {
		name, password string
		want           func(error) bool
	}{
		{"x", goodPassword, func(err error) bool { return errors.Is(err, ErrInvalidUsername) }},
		{"system", goodPassword, func(err error) bool { return errors.Is(err, ErrUsernameTaken) }},
		{"Taken", goodPassword, func(err error) bool { return errors.Is(err, ErrUsernameTaken) }},
		{"alice", goodPassword, func(err error) bool { return errors.Is(err, ErrUsernameTaken) }},
		{"bob", "short", func(err error) bool { return errors.As(err, &weak) }},
		{"bob", "bob's long enough passphrase", func(err error) bool { return errors.As(err, &weak) }},
		{"dan", goodPassword, func(err error) bool { return errors.Is(err, ErrHomeExists) }},
	} {
		if _, err := f.acc.AcceptInvite(ctx, inv.Token, tc.name, tc.password, Client{Addr: "192.0.2.50:1"}); !tc.want(err) {
			t.Errorf("accept as %q: %v", tc.name, err)
		}
	}
	if !f.exists("users/dan/old") {
		t.Error("an existing home folder was changed")
	}
	if _, ok, _ := f.acc.userByName("dan"); ok {
		t.Error("an account was created for an existing home folder")
	}
	if l, _ := f.storedLink(t, inv.ID); !l.Used.IsZero() {
		t.Error("a failed accept used the invite")
	}
	bob, _ := f.join(t, inv.Token, "bob")
	if bob.User.Role != state.RoleContributor {
		t.Errorf("bob %+v", bob.User)
	}
}

func TestAFixedUsernameCannotBeChanged(t *testing.T) {
	f := newFixture(t)
	id, actx := f.setupAdmin(t)
	inv := f.invite(t, actx, id, InviteRequest{Role: state.RoleViewer, Username: "carol"})
	for _, name := range []string{"dave", "carol2"} {
		if _, err := f.acc.AcceptInvite(ctx, inv.Token, name, goodPassword, Client{Addr: "192.0.2.51:1"}); !errors.Is(err, ErrInvalidUsername) {
			t.Errorf("accept as %s: %v", name, err)
		}
	}
	carol, _ := f.join(t, inv.Token, "Carol")
	if carol.User.Username != "carol" {
		t.Errorf("accepted as %q", carol.User.Username)
	}
}

func TestAFixedUsernameIsReservedWhileItsInviteIsUnused(t *testing.T) {
	f := newFixture(t)
	id, actx := f.setupAdmin(t)
	cctx := events.WithActor(ctx, events.Actor{ID: events.ConsoleID})
	open := f.invite(t, actx, id, InviteRequest{Role: state.RoleViewer})

	for _, step := range []struct {
		name string
		free func(l NewLink)
	}{
		{"used", func(l NewLink) { f.join(t, l.Token, "") }},
		{"revoked", func(l NewLink) {
			if err := f.acc.RevokeLink(actx, id, l.ID); err != nil {
				t.Fatal(err)
			}
		}},
		{"expired", func(NewLink) { f.clock.advance(7*24*time.Hour + time.Second) }},
	} {
		name := "name-" + step.name
		fixed := f.invite(t, actx, id, InviteRequest{Role: state.RoleViewer, Username: name})
		if _, err := f.acc.CreateInvite(actx, id, InviteRequest{Role: state.RoleAdmin, Username: name}); !errors.Is(err, ErrUsernameTaken) {
			t.Errorf("%s: another invite fixing it: %v", step.name, err)
		}
		if _, err := f.acc.AcceptInvite(ctx, open.Token, name, goodPassword, Client{Addr: "192.0.2.52:1"}); !errors.Is(err, ErrUsernameTaken) {
			t.Errorf("%s: an accept choosing it: %v", step.name, err)
		}
		if _, err := f.acc.CreateUser(cctx, name, state.RoleViewer, goodPassword); !errors.Is(err, ErrUsernameTaken) {
			t.Errorf("%s: users add: %v", step.name, err)
		}
		step.free(fixed)
		if step.name == "expired" {
			id, actx = f.loginAs(t, "alice")
			open = f.invite(t, actx, id, InviteRequest{Role: state.RoleViewer})
		}
		if step.name != "used" {
			if _, err := f.acc.CreateUser(cctx, name, state.RoleViewer, goodPassword); err != nil {
				t.Errorf("%s: the name is still reserved: %v", step.name, err)
			}
		}
	}
}

// Two accepts of one invite racing: one account is created, and the losers'
// homes are removed.
func TestRacingAcceptsUseAnInviteOnce(t *testing.T) {
	f := newFixture(t)
	id, actx := f.setupAdmin(t)
	inv := f.invite(t, actx, id, InviteRequest{Role: state.RoleContributor})
	const n = 6
	errs := make([]error, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range n {
		wg.Go(func() {
			<-start
			_, errs[i] = f.acc.AcceptInvite(ctx, inv.Token, fmt.Sprintf("racer%d", i), goodPassword, Client{Addr: fmt.Sprintf("192.0.2.%d:1", 60+i)})
		})
	}
	close(start)
	wg.Wait()
	won := 0
	for i, err := range errs {
		switch {
		case err == nil:
			won++
			if !f.exists(fmt.Sprintf("users/racer%d", i)) {
				t.Errorf("the winner racer%d has no home", i)
			}
		case errors.Is(err, ErrLinkInvalid):
			if f.exists(fmt.Sprintf("users/racer%d", i)) {
				t.Errorf("the home of racer%d, who lost, is left", i)
			}
		default:
			t.Errorf("racer%d: %v", i, err)
		}
	}
	var invited int
	for _, u := range f.acc.users() {
		if u.Invite == inv.ID {
			invited++
		}
	}
	if won != 1 || invited != 1 {
		t.Errorf("%d accepts succeeded and %d accounts were created; want one", won, invited)
	}
}

func TestAnEmptyFolderAtTheHomesPlaceIsTakenOver(t *testing.T) {
	f := newFixture(t)
	id, actx := f.setupAdmin(t)
	os.MkdirAll(filepath.Join(f.root, "users", "bob"), 0o755)
	inv := f.invite(t, actx, id, InviteRequest{Role: state.RoleContributor})
	bob, _ := f.join(t, inv.Token, "bob")
	if !slices.ContainsFunc(f.bindings(t), func(b state.Binding) bool { return b.Subject == bob.User.ID && b.Folder == "users/bob" }) {
		t.Error("the empty folder wasn't bound as the home")
	}
}

// The transaction refuses a home folder a binding already names; the folder
// the accept made is removed.
func TestAFailedTransactionRemovesTheHomeItMade(t *testing.T) {
	f := newFixture(t)
	id, actx := f.setupAdmin(t)
	inv := f.invite(t, actx, id, InviteRequest{Role: state.RoleContributor})
	if err := f.db.Update(func(tx *state.Tx) error {
		return tx.PutBinding(state.Binding{ID: state.NewID(), Subject: state.Everyone, Folder: "users/erin", Role: state.RoleViewer, Kind: state.KindCustom})
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.acc.AcceptInvite(ctx, inv.Token, "erin", goodPassword, Client{Addr: "192.0.2.70:1"}); !errors.Is(err, ErrHomeExists) {
		t.Fatalf("accept = %v", err)
	}
	if f.exists("users/erin") {
		t.Error("the home made for the failed accept is left")
	}
	if _, ok, _ := f.acc.userByName("erin"); ok {
		t.Error("the account was created")
	}
	f.join(t, inv.Token, "frank")
}

func TestAcceptsAreRefusedWhileChangesArePaused(t *testing.T) {
	f := newFixture(t)
	id, actx := f.setupAdmin(t)
	bob := f.addUser(t, "bob", state.RoleViewer)
	inv := f.invite(t, actx, id, InviteRequest{Role: state.RoleContributor})
	reset := f.resetLink(t, actx, id, bob.ID)
	a := audited(f)
	a.paused = true

	c := Client{Addr: "192.0.2.71:1"}
	if _, err := f.acc.AcceptInvite(ctx, inv.Token, "carol", goodPassword, c); !errors.Is(err, events.ErrChangesPaused) {
		t.Errorf("accept invite: %v", err)
	}
	if _, _, err := f.acc.AcceptReset(ctx, reset.Token, goodPassword+" new", c); !errors.Is(err, events.ErrChangesPaused) {
		t.Errorf("accept reset: %v", err)
	}
	for range 6 {
		if _, err := f.acc.AcceptInvite(ctx, rand.Text(), "carol", goodPassword, c); !errors.Is(err, events.ErrChangesPaused) {
			t.Fatalf("a bad token while paused: %v", err)
		}
	}
	if _, err := f.acc.CreateInvite(actx, id, InviteRequest{Role: state.RoleViewer}); !errors.Is(err, events.ErrChangesPaused) {
		t.Errorf("create invite: %v", err)
	}
	if _, err := f.acc.CreateResetLink(actx, id, bob.ID); !errors.Is(err, events.ErrChangesPaused) {
		t.Errorf("create reset link: %v", err)
	}
	if _, err := f.acc.InspectInvite(inv.Token, c); err != nil {
		t.Errorf("inspect while paused: %v", err)
	}
	if f.exists("users/carol") || len(f.storedLinks(t)) != 2 {
		t.Error("a refused change changed something")
	}

	a.paused = false
	if _, err := f.acc.AcceptInvite(ctx, inv.Token, "carol", goodPassword, c); err != nil {
		t.Errorf("after the pause, with the bad tokens refused uncounted: %v", err)
	}
	if plain, _ := a.types(); !slices.Contains(plain, string(events.InviteUsed)) {
		t.Errorf("records %v", plain)
	}
}

func TestAResetLinkSetsANewPasswordAndEndsEverySession(t *testing.T) {
	f := newFixture(t)
	id, actx := f.setupAdmin(t)
	bob := f.addUser(t, "bob", state.RoleContributor)
	first := f.login(t, "bob", Client{Addr: "192.0.2.80:1"})
	second := f.login(t, "bob", Client{Addr: "192.0.2.81:1"})
	f.changeUser(t, bob.ID, func(u *state.User) { u.Failures, u.PasswordDisabled = 100, true })
	now := f.clock.now()

	reset := f.resetLink(t, actx, id, bob.ID)
	if reset.Kind != state.KindReset || reset.Username != "bob" || !reset.Expires.Equal(now.Add(24*time.Hour)) {
		t.Errorf("reset link %+v", reset)
	}
	created := f.rec.ofType(events.ResetCreated)
	if len(created) != 1 || created[0].Path != "bob" || created[0].Detail != "id="+reset.ID+" user="+bob.ID || created[0].Actor.ID != id.User.ID {
		t.Errorf("reset.created %+v", created)
	}
	if f.user(t, "bob").Hash != bob.Hash {
		t.Error("creating a reset link changed the password")
	}
	info, err := f.acc.InspectReset(reset.Token, Client{Addr: "192.0.2.82:1"})
	if err != nil || info != (ResetInfo{Username: "bob", Expires: reset.Expires}) {
		t.Errorf("inspect = %+v, %v", info, err)
	}

	next := goodPassword + " renewed"
	g, revoked, err := f.acc.AcceptReset(ctx, reset.Token, next, Client{Addr: "192.0.2.82:1"})
	if err != nil {
		t.Fatal(err)
	}
	if revoked == nil || len(revoked) != 0 {
		t.Errorf("revoked links %#v, want an empty list", revoked)
	}
	if n := len(f.storedSessions(t)); n != 2 {
		t.Errorf("%d stored sessions, want alice's and the new one", n)
	}
	session, ok := f.acc.Authenticate(g.Token)
	if !ok || g.Me.Username != "bob" {
		t.Fatalf("the grant %+v", g)
	}
	for _, old := range []Grant{first, second} {
		if _, ok := f.acc.Authenticate(old.Token); ok {
			t.Error("a session from before the reset still works")
		}
	}
	u := f.user(t, "bob")
	if u.Epoch != bob.Epoch+1 || u.Failures != 0 || u.PasswordDisabled || !u.PasswordChangedAt.Equal(now) {
		t.Errorf("user after reset %+v", u)
	}
	if _, err := f.acc.Login(ctx, "bob", goodPassword, Client{Addr: "192.0.2.83:1"}); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("the old password: %v", err)
	}
	if _, err := f.acc.Login(ctx, "bob", next, Client{Addr: "192.0.2.83:1"}); err != nil {
		t.Errorf("the new password: %v", err)
	}
	usedEv := f.rec.ofType(events.ResetUsed)
	if len(usedEv) != 1 || usedEv[0].Detail != "id="+reset.ID || usedEv[0].Resolved != bob.ID || usedEv[0].Actor.ID != bob.ID || usedEv[0].Actor.Session != session.Session.ID {
		t.Errorf("reset.used %+v", usedEv)
	}
	if _, _, err := f.acc.AcceptReset(ctx, reset.Token, next+" again", Client{Addr: "192.0.2.84:1"}); !errors.Is(err, ErrLinkInvalid) {
		t.Errorf("second accept: %v", err)
	}
	if _, err := f.acc.InspectReset(reset.Token, Client{Addr: "192.0.2.84:1"}); !errors.Is(err, ErrLinkInvalid) {
		t.Errorf("inspect after use: %v", err)
	}

	var weak *WeakPasswordError
	other := f.resetLink(t, actx, id, bob.ID)
	if _, _, err := f.acc.AcceptReset(ctx, other.Token, "bob is my password ok", Client{Addr: "192.0.2.85:1"}); !errors.As(err, &weak) {
		t.Errorf("a weak password: %v", err)
	}
	if _, err := f.acc.InspectReset(other.Token, Client{Addr: "192.0.2.85:1"}); err != nil {
		t.Errorf("a refused password used the link: %v", err)
	}
}

// Accepting a link in a browser that is signed in ends the session it had.
func TestAcceptingEndsTheBrowsersPreviousSession(t *testing.T) {
	f := newFixture(t)
	id, actx := f.setupAdmin(t)
	bob := f.addUser(t, "bob", state.RoleViewer)
	inv := f.invite(t, actx, id, InviteRequest{Role: state.RoleViewer})
	reset := f.resetLink(t, actx, id, bob.ID)

	old := f.login(t, "alice", Client{Addr: "192.0.2.90:1"})
	oldID, _ := f.acc.Authenticate(old.Token)
	g, err := f.acc.AcceptInvite(ctx, inv.Token, "carol", goodPassword, Client{Addr: "192.0.2.90:1", Token: old.Token})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.acc.Authenticate(old.Token); ok {
		t.Error("the browser's previous session survived the invite")
	}
	g2, _, err := f.acc.AcceptReset(ctx, reset.Token, goodPassword+" new", Client{Addr: "192.0.2.90:1", Token: g.Token})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.acc.Authenticate(g.Token); ok {
		t.Error("the browser's previous session survived the reset")
	}
	if _, ok := f.acc.Authenticate(g2.Token); !ok {
		t.Error("the new session doesn't work")
	}
	if _, ok := f.acc.Authenticate(f.login(t, "alice", browser).Token); !ok {
		t.Error("alice can't log in")
	}
	carol := f.user(t, "carol")
	var ended []string
	for _, ev := range f.rec.ofType(events.SessionRevoked) {
		ended = append(ended, ev.Path+" "+ev.Detail)
	}
	want := []string{"alice id=" + oldID.Session.ID + " reason=replaced", "carol id=" + sessionIDOf(t, f, carol.ID) + " reason=replaced"}
	if !slices.Equal(ended, want) {
		t.Errorf("session.revoked %q, want %q", ended, want)
	}
}

// sessionIDOf returns the ID of the only session a user had, from the event
// that started it.
func sessionIDOf(t *testing.T, f *fixture, userID string) string {
	t.Helper()
	for _, ev := range f.rec.ofType(events.InviteUsed) {
		if ev.Resolved == userID {
			return ev.Actor.Session
		}
	}
	t.Fatalf("no invite.used for %s", userID)
	return ""
}

func TestANewResetLinkRevokesTheOlderOne(t *testing.T) {
	f := newFixture(t)
	id, actx := f.setupAdmin(t)
	bob := f.addUser(t, "bob", state.RoleAdmin)
	bobID, bctx := f.loginAs(t, "bob")
	first := f.resetLink(t, actx, id, bob.ID)
	second := f.resetLink(t, bctx, bobID, bob.ID)
	console, err := f.acc.ConsoleResetLink(ctx, "bob")
	if err != nil {
		t.Fatal(err)
	}
	third := f.resetLink(t, actx, id, bob.ID)
	for _, l := range []NewLink{first, second, console} {
		if _, err := f.acc.InspectReset(l.Token, Client{Addr: "192.0.2.91:1"}); !errors.Is(err, ErrLinkInvalid) {
			t.Errorf("an older reset link %s: %v", l.ID, err)
		}
		f.clock.advance(time.Second)
	}
	want := []string{first.ID + " new_reset_link", second.ID + " new_reset_link", console.ID + " new_reset_link"}
	if got := f.rec.revokedFor(); !slices.Equal(got, want) {
		t.Errorf("link.revoked %q, want %q", got, want)
	}
	list, _ := f.acc.Links(id)
	if len(list) != 1 || list[0].ID != third.ID {
		t.Errorf("links %+v", list)
	}
}

func TestResetLinksForDisabledOrDeletedAccountsAreInvalid(t *testing.T) {
	f := newFixture(t)
	id, actx := f.setupAdmin(t)
	bob := f.addUser(t, "bob", state.RoleViewer)
	carol := f.addUser(t, "carol", state.RoleViewer)
	f.addUser(t, "dave", state.RoleAdmin)
	forBob := f.resetLink(t, actx, id, bob.ID)
	forCarol := f.resetLink(t, actx, id, carol.ID)
	forDave, err := f.acc.ConsoleResetLink(ctx, "dave")
	if err != nil {
		t.Fatal(err)
	}

	f.changeUser(t, bob.ID, func(u *state.User) { u.Disabled = true })
	if err := f.db.Update(func(tx *state.Tx) error { return tx.DeleteUser(carol.ID) }); err != nil {
		t.Fatal(err)
	}
	f.acc.reload()
	f.changeUser(t, f.user(t, "dave").ID, func(u *state.User) { u.Role = state.RoleContributor })
	for _, l := range []NewLink{forBob, forCarol, forDave} {
		if _, err := f.acc.InspectReset(l.Token, Client{Addr: "192.0.2.92:1"}); !errors.Is(err, ErrLinkInvalid) {
			t.Errorf("inspect for %s: %v", l.Username, err)
		}
		if _, _, err := f.acc.AcceptReset(ctx, l.Token, goodPassword+" new", Client{Addr: "192.0.2.93:1"}); !errors.Is(err, ErrLinkInvalid) {
			t.Errorf("accept for %s: %v", l.Username, err)
		}
		f.clock.advance(time.Second)
	}

	if _, err := f.acc.CreateResetLink(actx, id, bob.ID); !errors.Is(err, ErrUserDisabled) {
		t.Errorf("a reset link for a disabled account: %v", err)
	}
	if _, err := f.acc.CreateResetLink(actx, id, carol.ID); !errors.Is(err, ErrNoSuchUser) {
		t.Errorf("a reset link for a deleted account: %v", err)
	}
}

func TestTheConsoleLink(t *testing.T) {
	f := newFixture(t)
	id, actx := f.setupAdmin(t)
	f.addUser(t, "bob", state.RoleContributor)
	f.addUser(t, "dis", state.RoleAdmin)
	f.changeUser(t, f.user(t, "dis").ID, func(u *state.User) { u.Disabled = true })
	for _, tc := range []struct {
		name string
		want func(error) bool
	}{
		{"nobody", func(err error) bool { return errors.Is(err, ErrNoSuchUser) }},
		{"Not A Name", func(err error) bool { return errors.Is(err, ErrNoSuchUser) }},
		{"bob", func(err error) bool { return err != nil && strings.Contains(err.Error(), "not an admin") }},
		{"dis", func(err error) bool { return errors.Is(err, ErrUserDisabled) }},
	} {
		if _, err := f.acc.ConsoleResetLink(ctx, tc.name); !tc.want(err) {
			t.Errorf("console link for %q: %v", tc.name, err)
		}
	}

	now := f.clock.now()
	l, err := f.acc.ConsoleResetLink(ctx, "Alice")
	if err != nil {
		t.Fatal(err)
	}
	if l.Username != "alice" || !l.Expires.Equal(now.Add(time.Hour)) {
		t.Errorf("console link %+v", l)
	}
	created := f.rec.ofType(events.ResetCreated)
	if len(created) != 1 || created[0].Actor.ID != events.ConsoleID || created[0].Path != "alice" {
		t.Errorf("reset.created %+v", created)
	}
	list, err := f.acc.Links(id)
	if err != nil || len(list) != 1 || list[0].ID != l.ID || list[0].CreatedBy != events.ConsoleID ||
		list[0].CreatedByName != "console" || list[0].Username != "alice" || list[0].User != id.User.ID {
		t.Errorf("links %+v, %v", list, err)
	}
	f.clock.advance(time.Hour)
	if _, err := f.acc.InspectReset(l.Token, Client{Addr: "192.0.2.94:1"}); !errors.Is(err, ErrLinkInvalid) {
		t.Errorf("after an hour: %v", err)
	}

	f.acc.linkCfg.ResetTTL = 30 * time.Minute
	now = f.clock.now()
	if l, _ := f.acc.ConsoleResetLink(ctx, "alice"); !l.Expires.Equal(now.Add(30 * time.Minute)) {
		t.Errorf("with -reset-ttl 30m it expires after %v", l.Expires.Sub(now))
	}
	id, actx = f.loginAs(t, "alice")
	revocable, _ := f.acc.ConsoleResetLink(ctx, "alice")
	if err := f.acc.RevokeLink(actx, id, revocable.ID); err != nil {
		t.Errorf("revoke: %v", err)
	}
	if _, err := f.acc.InspectReset(revocable.Token, Client{Addr: "192.0.2.95:1"}); !errors.Is(err, ErrLinkInvalid) {
		t.Errorf("after revoking: %v", err)
	}

	once, _ := f.acc.ConsoleResetLink(ctx, "alice")
	if _, _, err := f.acc.AcceptReset(ctx, once.Token, goodPassword+" new", Client{Addr: "192.0.2.96:1"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.acc.AcceptReset(ctx, once.Token, goodPassword+" newer", Client{Addr: "192.0.2.96:1"}); !errors.Is(err, ErrLinkInvalid) {
		t.Errorf("used twice: %v", err)
	}

	g, err := f.acc.Login(ctx, "alice", goodPassword+" new", Client{Addr: "192.0.2.96:2"})
	if err != nil {
		t.Fatal(err)
	}
	id, actx = f.identity(t, g)
	invite := f.invite(t, actx, id, InviteRequest{Role: state.RoleViewer})
	kept, _ := f.acc.ConsoleResetLink(ctx, "alice")
	f.acc.Close()
	restarted := New(Config{DB: f.db, Hasher: f.acc.hasher, Policy: f.acc.policy, Folders: f.files, Events: f.rec, Now: f.clock.now})
	if err := restarted.Start(); err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if _, ok := f.storedLink(t, kept.ID); ok {
		t.Error("the console link survived a restart")
	}
	if _, ok := f.storedLink(t, invite.ID); !ok {
		t.Error("an admin's invite didn't survive a restart")
	}
	revoked := f.rec.ofType(events.LinkRevoked)
	if last := revoked[len(revoked)-1]; last.Actor.ID != events.SystemID || !strings.Contains(last.Detail, "id="+kept.ID) ||
		!strings.Contains(last.Detail, "reason=server_start") || last.Path != "alice" {
		t.Errorf("link.revoked at start %+v", last)
	}
}

func TestTheConsoleLinkDiesWhenTheAccountIsDisabledOrDemoted(t *testing.T) {
	f := newFixture(t)
	id, actx := f.setupAdmin(t)
	carol := f.addUser(t, "carol", state.RoleAdmin)
	dave := f.addUser(t, "dave", state.RoleAdmin)
	forCarol, _ := f.acc.ConsoleResetLink(ctx, "carol")
	forDave, _ := f.acc.ConsoleResetLink(ctx, "dave")

	yes, contributor := true, state.RoleContributor
	if _, err := f.acc.UpdateUser(actx, id, carol.ID, UserUpdate{Disabled: &yes}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.acc.UpdateUser(actx, id, dave.ID, UserUpdate{Role: &contributor}); err != nil {
		t.Fatal(err)
	}
	for _, l := range []NewLink{forCarol, forDave} {
		if _, ok := f.storedLink(t, l.ID); ok {
			t.Errorf("the console link for %s is left", l.Username)
		}
	}
	got := f.rec.revokedFor()
	if !slices.Contains(got, forCarol.ID+" user_disabled") || !slices.Contains(got, forDave.ID+" creator_demoted") {
		t.Errorf("link.revoked %q", got)
	}
	dl := f.resetLink(t, actx, id, dave.ID)
	if _, err := f.acc.InspectReset(dl.Token, Client{Addr: "192.0.2.97:1"}); err != nil {
		t.Errorf("an admin's reset link for a contributor: %v", err)
	}
}

func TestAtMostOneHundredUnusedLinks(t *testing.T) {
	f := newFixture(t)
	id, actx := f.setupAdmin(t)
	bob := f.addUser(t, "bob", state.RoleViewer)
	var first NewLink
	for i := range maxUnusedLinks {
		l := f.invite(t, actx, id, InviteRequest{Role: state.RoleViewer})
		if i == 0 {
			first = l
		}
	}
	if _, err := f.acc.CreateInvite(actx, id, InviteRequest{Role: state.RoleViewer}); !errors.Is(err, ErrTooManyLinks) {
		t.Errorf("invite 101: %v", err)
	}
	if _, err := f.acc.CreateResetLink(actx, id, bob.ID); !errors.Is(err, ErrTooManyLinks) {
		t.Errorf("reset link 101: %v", err)
	}
	if _, err := f.acc.ConsoleResetLink(ctx, "alice"); err != nil {
		t.Errorf("the console link counts: %v", err)
	}
	f.join(t, first.Token, "carol")
	reset := f.resetLink(t, actx, id, bob.ID)
	if _, err := f.acc.CreateResetLink(actx, id, bob.ID); err != nil {
		t.Errorf("a reset link replacing one: %v", err)
	}
	if err := f.acc.RevokeLink(actx, id, reset.ID); !errors.Is(err, ErrNoSuchLink) {
		t.Errorf("revoke a replaced link: %v", err)
	}
	f.clock.advance(7*24*time.Hour + time.Second)
	id, actx = f.loginAs(t, "alice")
	if _, err := f.acc.CreateInvite(actx, id, InviteRequest{Role: state.RoleViewer}); err != nil {
		t.Errorf("after the invites expired: %v", err)
	}
	if err := f.acc.dropOldLinks(ctx, false); err != nil {
		t.Fatal(err)
	}
	if n := len(f.storedLinks(t)); n != 1 {
		t.Errorf("%d links stored after removing used and expired ones", n)
	}
}

func TestLinksListsTheUnusedLinks(t *testing.T) {
	f := newFixture(t)
	id, actx := f.setupAdmin(t)
	bob := f.addUser(t, "bob", state.RoleViewer)
	used := f.invite(t, actx, id, InviteRequest{Role: state.RoleViewer})
	f.clock.advance(time.Second)
	inv := f.invite(t, actx, id, InviteRequest{Role: state.RoleContributor, Username: "carol", Note: "Carol's phone"})
	f.clock.advance(time.Second)
	reset := f.resetLink(t, actx, id, bob.ID)
	f.join(t, used.Token, "dan")

	list, err := f.acc.Links(id)
	if err != nil {
		t.Fatal(err)
	}
	want := []LinkInfo{
		{ID: inv.ID, Kind: state.KindInvite, Role: state.RoleContributor, Username: "carol", Note: "Carol's phone",
			CreatedBy: id.User.ID, CreatedByName: "alice", Created: inv.Expires.Add(-7 * 24 * time.Hour), Expires: inv.Expires},
		{ID: reset.ID, Kind: state.KindReset, Username: "bob", User: bob.ID,
			CreatedBy: id.User.ID, CreatedByName: "alice", Created: reset.Expires.Add(-24 * time.Hour), Expires: reset.Expires},
	}
	got, _ := json.Marshal(list)
	if js, _ := json.Marshal(want); string(got) != string(js) {
		t.Errorf("links\n%s\nwant\n%s", got, js)
	}

	if err := f.acc.RevokeLink(actx, id, inv.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.acc.RevokeLink(actx, id, inv.ID); !errors.Is(err, ErrNoSuchLink) {
		t.Errorf("revoke twice: %v", err)
	}
	if err := f.acc.RevokeLink(actx, id, used.ID); !errors.Is(err, ErrNoSuchLink) {
		t.Errorf("revoke a used link: %v", err)
	}
	if got := f.rec.revokedFor(); !slices.Equal(got, []string{inv.ID + " admin"}) {
		t.Errorf("link.revoked %q", got)
	}
	if revoked := f.rec.ofType(events.LinkRevoked); revoked[0].Path != "carol" || revoked[0].Actor.ID != id.User.ID {
		t.Errorf("link.revoked %+v", revoked[0])
	}
}

// links made for the revocation tests: X and Y by bob, R for bob, and Z and
// W by alice for others.
type linkSet struct {
	x, y, r, z, w NewLink
}

// revocationFixture has alice and bob as admins, and the links of linkSet.
func revocationFixture(t *testing.T) (*fixture, Identity, context.Context, Identity, context.Context, linkSet) {
	f := newFixture(t)
	id, actx := f.setupAdmin(t)
	f.addUser(t, "bob", state.RoleAdmin)
	carol := f.addUser(t, "carol", state.RoleViewer)
	dave := f.addUser(t, "dave", state.RoleViewer)
	bob, bctx := f.loginAs(t, "bob")
	var s linkSet
	s.x = f.invite(t, bctx, bob, InviteRequest{Role: state.RoleAdmin, Username: "xavier", Note: "X"})
	s.y = f.resetLink(t, bctx, bob, carol.ID)
	s.r = f.resetLink(t, actx, id, bob.User.ID)
	s.z = f.invite(t, actx, id, InviteRequest{Role: state.RoleViewer})
	s.w = f.resetLink(t, actx, id, dave.ID)
	return f, id, actx, bob, bctx, s
}

// Recovering a compromised account revokes the links it made and every
// reset link for it, and the response lists them.
func TestSecuringAnAccountRevokesItsLinks(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
		secure       func(f *fixture, bob Identity, bctx context.Context, s linkSet) ([]RevokedLink, error)
		usesR        bool
	}{
		{"password change", "password_changed", func(f *fixture, bob Identity, bctx context.Context, _ linkSet) ([]RevokedLink, error) {
			_, l, err := f.acc.ChangePassword(bctx, bob, goodPassword, goodPassword+" new", browser)
			return l, err
		}, false},
		{"users passwd", "password_changed", func(f *fixture, _ Identity, _ context.Context, _ linkSet) ([]RevokedLink, error) {
			_, l, err := f.acc.SetPassword(events.WithActor(ctx, events.Actor{ID: events.ConsoleID}), "bob", goodPassword+" new")
			return l, err
		}, false},
		{"reset link used", "reset_used", func(f *fixture, _ Identity, _ context.Context, s linkSet) ([]RevokedLink, error) {
			_, l, err := f.acc.AcceptReset(ctx, s.r.Token, goodPassword+" new", browser)
			return l, err
		}, true},
		{"sign out everywhere else", "signed_out_elsewhere", func(f *fixture, bob Identity, bctx context.Context, _ linkSet) ([]RevokedLink, error) {
			return f.acc.RevokeOtherSessions(bctx, bob)
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, _, _, bob, bctx, s := revocationFixture(t)
			got, err := tc.secure(f, bob, bctx, s)
			if err != nil {
				t.Fatal(err)
			}
			want := []string{s.x.ID, s.y.ID, s.r.ID}
			if tc.usesR {
				want = want[:2]
			}
			if !slices.Equal(linkIDs(got), sorted(want...)) {
				t.Errorf("revoked %+v, want %q", got, want)
			}
			for _, l := range got {
				switch l.ID {
				case s.x.ID:
					if l != (RevokedLink{ID: s.x.ID, Kind: "invite", Role: "admin", Username: "xavier", Note: "X"}) {
						t.Errorf("revoked invite %+v", l)
					}
				case s.y.ID:
					if l != (RevokedLink{ID: s.y.ID, Kind: "reset", Username: "carol"}) {
						t.Errorf("revoked reset link %+v", l)
					}
				}
			}
			var wantEvents []string
			for _, id := range want {
				wantEvents = append(wantEvents, id+" "+tc.reason)
			}
			if got := f.rec.revokedFor(); !slices.Equal(sorted(got...), sorted(wantEvents...)) {
				t.Errorf("link.revoked %q, want %q", got, wantEvents)
			}
			for _, l := range []NewLink{s.z, s.w} {
				if _, ok := f.storedLink(t, l.ID); !ok {
					t.Errorf("link %s of another admin was revoked", l.ID)
				}
			}
		})
	}
}

// Links die with their creator's admin rights.
func TestLosingAdminRightsRevokesTheLinksMade(t *testing.T) {
	yes, contributor := true, state.RoleContributor
	for _, tc := range []struct {
		name, reason string
		change       func(f *fixture, id Identity, actx context.Context, bobID string) error
		keepsR       bool
	}{
		{"disable", "user_disabled", func(f *fixture, id Identity, actx context.Context, bobID string) error {
			_, err := f.acc.UpdateUser(actx, id, bobID, UserUpdate{Disabled: &yes})
			return err
		}, false},
		{"demote", "creator_demoted", func(f *fixture, id Identity, actx context.Context, bobID string) error {
			_, err := f.acc.UpdateUser(actx, id, bobID, UserUpdate{Role: &contributor})
			return err
		}, true},
		{"delete", "user_deleted", func(f *fixture, id Identity, actx context.Context, bobID string) error {
			_, err := f.acc.DeleteUser(actx, id, bobID)
			return err
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, id, actx, bob, _, s := revocationFixture(t)
			if err := tc.change(f, id, actx, bob.User.ID); err != nil {
				t.Fatal(err)
			}
			want := []string{s.x.ID + " " + tc.reason, s.y.ID + " " + tc.reason}
			if !tc.keepsR {
				want = append(want, s.r.ID+" "+tc.reason)
			}
			if got := f.rec.revokedFor(); !slices.Equal(sorted(got...), sorted(want...)) {
				t.Errorf("link.revoked %q, want %q", got, want)
			}
			kept := []NewLink{s.z, s.w}
			if tc.keepsR {
				kept = append(kept, s.r)
			}
			for _, l := range kept {
				if _, ok := f.storedLink(t, l.ID); !ok {
					t.Errorf("link %s was revoked", l.ID)
				}
			}
			if _, err := f.acc.InspectInvite(s.x.Token, Client{Addr: "192.0.2.98:1"}); !errors.Is(err, ErrLinkInvalid) {
				t.Errorf("bob's invite: %v", err)
			}
			names := map[string]string{s.x.ID: "xavier", s.y.ID: "carol", s.r.ID: "bob"}
			for _, ev := range f.rec.ofType(events.LinkRevoked) {
				for id, name := range names {
					if strings.Contains(ev.Detail, "id="+id+" ") && ev.Path != name {
						t.Errorf("link.revoked names %q, want %q: %+v", ev.Path, name, ev)
					}
				}
			}
		})
	}
}

// Only an enabled admin may make a link, checked again in the transaction.
func TestOnlyAdminsMakeLinks(t *testing.T) {
	f := newFixture(t)
	id, actx := f.setupAdmin(t)
	bob := f.addUser(t, "bob", state.RoleContributor)
	f.addUser(t, "carol", state.RoleAdmin)
	bobID, bctx := f.loginAs(t, "bob")
	if _, err := f.acc.CreateInvite(bctx, bobID, InviteRequest{Role: state.RoleViewer}); !errors.Is(err, ErrNotAdmin) {
		t.Errorf("a contributor's invite: %v", err)
	}
	if _, err := f.acc.CreateResetLink(bctx, bobID, bob.ID); !errors.Is(err, ErrNotAdmin) {
		t.Errorf("a contributor's reset link: %v", err)
	}
	if _, err := f.acc.Links(bobID); !errors.Is(err, ErrNotAdmin) {
		t.Errorf("a contributor's list: %v", err)
	}

	f.clock.advance(15 * time.Minute)
	if _, err := f.acc.CreateInvite(actx, id, InviteRequest{Role: state.RoleViewer}); !errors.Is(err, ErrReauthRequired) {
		t.Errorf("outside the reauth window: %v", err)
	}
	if _, err := f.acc.Links(id); err != nil {
		t.Errorf("listing outside the reauth window: %v", err)
	}
	g, err := f.acc.Confirm(actx, id, goodPassword, adminBrowser)
	if err != nil {
		t.Fatal(err)
	}
	id, actx = f.identity(t, g)
	l := f.invite(t, actx, id, InviteRequest{Role: state.RoleViewer})

	carol, cctx := f.loginAs(t, "carol")
	contributor := state.RoleContributor
	if _, err := f.acc.UpdateUser(cctx, carol, id.User.ID, UserUpdate{Role: &contributor}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.acc.CreateInvite(actx, id, InviteRequest{Role: state.RoleViewer}); !errors.Is(err, ErrNotAdmin) {
		t.Errorf("after being demoted: %v", err)
	}
	if err := f.acc.RevokeLink(actx, id, l.ID); !errors.Is(err, ErrNotAdmin) {
		t.Errorf("revoke after being demoted: %v", err)
	}
}
