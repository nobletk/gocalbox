package auth

import (
	"context"
	"errors"
	"net/netip"
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

type recorder struct {
	mu  sync.Mutex
	evs []events.Event
}

func (r *recorder) Publish(ev events.Event) {
	r.mu.Lock()
	r.evs = append(r.evs, ev)
	r.mu.Unlock()
}

func (r *recorder) withDetail(substr string) []events.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []events.Event
	for _, ev := range r.evs {
		if strings.Contains(ev.Detail, substr) {
			out = append(out, ev)
		}
	}
	return out
}

func (r *recorder) types() []events.Type {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []events.Type
	for _, ev := range r.evs {
		out = append(out, ev.Type)
	}
	return out
}

type fixture struct {
	acc   *Accounts
	db    *state.DB
	root  string
	rec   *recorder
	clock *clock
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

const goodPassword = "a long enough passphrase"

func newFixture(t *testing.T) *fixture {
	t.Helper()
	return newFixtureWith(t, testParams, func(int) time.Duration { return 0 })
}

// newFixtureWith hashes with p, so that checks can be made to overlap, and
// waits delay(n) after the nth failure.
func newFixtureWith(t *testing.T, p Params, delay func(int) time.Duration) *fixture {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "root")
	os.Mkdir(root, 0o755)
	sb, err := sandbox.New(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sb.Close() })
	db, err := state.Open(filepath.Join(base, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	rec := &recorder{}
	clk := &clock{t: time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)}
	acc := New(Config{
		DB: db, Hasher: NewHasher(p, 2, 5*time.Second), Policy: Policy{MinLength: 15},
		Folders: fsops.New(sb, rec), Events: rec, Now: clk.now,
		FailureDelay: delay,
		OwnNetworks:  func() []netip.Prefix { return []netip.Prefix{netip.MustParsePrefix("2001:db8:1:2::/64")} },
	})
	if err := acc.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { acc.Close() })
	return &fixture{acc: acc, db: db, root: sb.Root(), rec: rec, clock: clk}
}

func (f *fixture) exists(rel string) bool {
	_, err := os.Lstat(filepath.Join(f.root, filepath.FromSlash(rel)))
	return err == nil
}

func (f *fixture) bindings(t *testing.T) []state.Binding {
	t.Helper()
	var bs []state.Binding
	f.db.View(func(tx *state.Tx) error { var err error; bs, err = tx.Bindings(); return err })
	return bs
}

func (f *fixture) startSetup(t *testing.T) string {
	t.Helper()
	code, err := f.acc.StartSetup()
	if err != nil || code == "" || !f.acc.SetupRequired() {
		t.Fatalf("StartSetup = %q, %v", code, err)
	}
	return code
}

func TestSetupCreatesAdminLayoutAndBindings(t *testing.T) {
	f := newFixture(t)
	code := f.startSetup(t)
	actx := events.WithActor(ctx, events.Actor{ID: events.AnonymousID, RemoteAddr: "192.0.2.7:5000"})
	grant, err := f.acc.CompleteSetup(actx, SetupRequest{Code: FormatCode(code), Username: "Alice", Password: goodPassword}, Client{Addr: "192.0.2.9:4000"})
	me := grant.Me
	if err != nil {
		t.Fatal(err)
	}
	if me.Username != "alice" || me.Role != state.RoleAdmin || me.Home != "users/alice" || !strings.HasPrefix(me.ID, "u-") {
		t.Errorf("me = %+v", me)
	}
	id, ok := f.acc.Authenticate(grant.Token)
	if !ok || id.User.ID != me.ID || grant.Device == "" || me.ReauthUntil == nil {
		t.Errorf("setup did not log the new admin in: %+v", grant)
	}
	if !slices.Equal(me.Bindings, []MeBinding{{"public", state.RoleContributor}, {"users/alice", state.RoleContributor}}) {
		t.Errorf("me.Bindings = %+v", me.Bindings)
	}
	if f.acc.SetupRequired() {
		t.Error("still in setup mode")
	}
	for _, p := range []string{"users", "users/alice", "public"} {
		if !f.exists(p) {
			t.Errorf("%s missing", p)
		}
	}
	bs := f.bindings(t)
	if len(bs) != 2 {
		t.Fatalf("bindings: %+v", bs)
	}
	for _, b := range bs {
		switch b.Kind {
		case state.KindHome:
			if b.Subject != me.ID || b.Folder != "users/alice" || b.Role != state.RoleContributor {
				t.Errorf("home binding %+v", b)
			}
		case state.KindPublic:
			if b.Subject != state.Everyone || b.Folder != "public" || b.Role != state.RoleContributor {
				t.Errorf("public binding %+v", b)
			}
		}
	}
	if got := f.rec.types(); !slices.Equal(got, []events.Type{events.FolderCreated, events.FolderCreated, events.FolderCreated, events.AuthSetupCompleted, events.AuthLogin}) {
		t.Errorf("events %v", got)
	}
	if login := f.rec.evs[len(f.rec.evs)-1]; login.Actor.Session != id.Session.ID || login.Detail != "setup" || login.Outcome != events.OutcomeOK {
		t.Errorf("setup's login event %+v", login)
	}
	for _, ev := range f.rec.evs {
		if ev.Actor.ID != me.ID || ev.Actor.Name != "alice" || ev.Actor.RemoteAddr != "192.0.2.7:5000" {
			t.Errorf("%s by %+v", ev.Type, ev.Actor)
		}
	}

	if _, err := f.acc.CompleteSetup(ctx, SetupRequest{Code: code, Username: "mallory", Password: goodPassword}, Client{Addr: "192.0.2.9:4000"}); !errors.Is(err, ErrSetupDone) {
		t.Errorf("second setup: %v", err)
	}
	if again, _ := f.acc.StartSetup(); again != "" {
		t.Error("setup mode again with an admin present")
	}
}

func TestSetupRefusals(t *testing.T) {
	f := newFixture(t)
	code := f.startSetup(t)
	for _, tc := range []struct {
		req  SetupRequest
		want error
	}{
		{SetupRequest{Code: "WRONG", Username: "alice", Password: goodPassword}, ErrSetupCodeInvalid},
		{SetupRequest{Code: code, Username: "a", Password: goodPassword}, ErrInvalidUsername},
		{SetupRequest{Code: code, Username: "console", Password: goodPassword}, ErrUsernameTaken},
		{SetupRequest{Code: code, Username: "alice", Password: "too short"}, &WeakPasswordError{}},
	} {
		_, err := f.acc.CompleteSetup(ctx, tc.req, Client{Addr: "192.0.2.9:4000"})
		var we *WeakPasswordError
		if _, weak := tc.want.(*WeakPasswordError); weak && !errors.As(err, &we) || !weak && !errors.Is(err, tc.want) {
			t.Errorf("%+v: %v", tc.req, err)
		}
	}
	if !f.acc.SetupRequired() || f.exists("users") || len(f.rec.types()) != 0 {
		t.Error("a refused setup changed something")
	}
	if _, err := f.acc.CompleteSetup(ctx, SetupRequest{Code: code, Username: "alice", Password: goodPassword}, Client{Addr: "192.0.2.9:4000"}); err != nil {
		t.Errorf("the code stopped working after refusals: %v", err)
	}
}

func TestSetupWithAnExistingLayout(t *testing.T) {
	f := newFixture(t)
	code := f.startSetup(t)
	os.MkdirAll(filepath.Join(f.root, "public", "old"), 0o755)
	os.MkdirAll(filepath.Join(f.root, "users"), 0o755)

	_, err := f.acc.CompleteSetup(ctx, SetupRequest{Code: code, Username: "alice", Password: goodPassword}, Client{Addr: "192.0.2.9:4000"})
	var le *LayoutExistsError
	if !errors.As(err, &le) || !slices.Equal(le.Paths, []string{"users", "public"}) {
		t.Fatalf("err = %v", err)
	}
	if f.exists("users/alice") || len(f.bindings(t)) != 0 {
		t.Error("layout_exists changed something")
	}

	os.MkdirAll(filepath.Join(f.root, "users", "alice", "stuff"), 0o755)
	_, err = f.acc.CompleteSetup(ctx, SetupRequest{Code: code, Username: "alice", Password: goodPassword, UseExisting: true}, Client{Addr: "192.0.2.9:4000"})
	if !errors.Is(err, ErrHomeExists) {
		t.Fatalf("non-empty home: %v", err)
	}
	if _, err := f.acc.CompleteSetup(ctx, SetupRequest{Code: code, Username: "bob", Password: goodPassword, UseExisting: true}, Client{Addr: "192.0.2.9:4000"}); err != nil {
		t.Fatal(err)
	}
	if !f.exists("public/old") || !f.exists("users/bob") {
		t.Error("existing folders not kept, or the home not created")
	}
}

func TestConcurrentSetupsCreateOneAdmin(t *testing.T) {
	f := newFixture(t)
	code := f.startSetup(t)
	var wg sync.WaitGroup
	results := make([]error, 8)
	for i := range results {
		wg.Go(func() {
			_, results[i] = f.acc.CompleteSetup(ctx, SetupRequest{Code: code, Username: "admin" + string(rune('a'+i)), Password: goodPassword}, Client{Addr: "192.0.2.9:4000"})
		})
	}
	wg.Wait()
	ok := 0
	for _, err := range results {
		switch {
		case err == nil:
			ok++
		case !errors.Is(err, ErrSetupDone):
			t.Errorf("unexpected: %v", err)
		}
	}
	var users []state.User
	f.db.View(func(tx *state.Tx) error { users, _ = tx.Users(); return nil })
	if ok != 1 || len(users) != 1 {
		t.Errorf("%d setups succeeded, %d users", ok, len(users))
	}
}

func TestEnsureLayoutCreatesHomesOfConsoleUsers(t *testing.T) {
	f := newFixture(t)
	cctx := events.WithActor(ctx, events.Actor{ID: events.ConsoleID})
	for _, u := range []struct {
		name string
		role state.Role
	}{{"root", state.RoleAdmin}, {"carol", state.RoleContributor}, {"vic", state.RoleViewer}, {"dave", state.RoleContributor}} {
		if _, err := f.acc.CreateUser(cctx, u.name, u.role, goodPassword); err != nil {
			t.Fatal(err)
		}
	}
	os.MkdirAll(filepath.Join(f.root, "users", "dave", "old"), 0o755)

	warnings := f.acc.EnsureLayout(ctx)
	if len(warnings) != 1 || !strings.Contains(warnings[0], "dave") || !strings.Contains(warnings[0], "users/dave") {
		t.Errorf("warnings %q", warnings)
	}
	for _, p := range []string{"users/root", "users/carol", "public"} {
		if !f.exists(p) {
			t.Errorf("%s missing", p)
		}
	}
	if f.exists("users/vic") {
		t.Error("a viewer got a home")
	}
	kinds := map[state.BindingKind]int{}
	for _, b := range f.bindings(t) {
		kinds[b.Kind]++
	}
	if kinds[state.KindHome] != 2 || kinds[state.KindPublic] != 1 {
		t.Errorf("bindings %v", kinds)
	}
	for _, ev := range f.rec.evs {
		if ev.Type == events.FolderCreated && ev.Actor.ID != events.SystemID {
			t.Errorf("%s %s by %+v, want the actor system", ev.Type, ev.Path, ev.Actor)
		}
	}

	os.RemoveAll(filepath.Join(f.root, "users", "carol"))
	before := len(f.bindings(t))
	if w := f.acc.EnsureLayout(ctx); len(w) != 1 {
		t.Errorf("second run warnings %q", w)
	}
	if !f.exists("users/carol") || len(f.bindings(t)) != before {
		t.Error("a deleted home was not recreated, or bindings were duplicated")
	}
}

func TestSetupRecordsHomesOfConsoleUsersAsTheServer(t *testing.T) {
	f := newFixture(t)
	if _, err := f.acc.CreateUser(events.WithActor(ctx, events.Actor{ID: events.ConsoleID}), "carol", state.RoleContributor, goodPassword); err != nil {
		t.Fatal(err)
	}
	code := f.startSetup(t)
	actx := events.WithRequestID(events.WithActor(ctx, events.Actor{ID: events.AnonymousID, RemoteAddr: "192.0.2.7:5000"}), "req-1")
	grant, err := f.acc.CompleteSetup(actx, SetupRequest{Code: code, Username: "alice", Password: goodPassword}, Client{Addr: "192.0.2.9:4000"})
	me := grant.Me
	if err != nil {
		t.Fatal(err)
	}
	if !f.exists("users/carol") {
		t.Fatal("the console user's home was not created")
	}
	f.rec.mu.Lock()
	defer f.rec.mu.Unlock()
	carol := false
	for _, ev := range f.rec.evs {
		if ev.Type != events.FolderCreated {
			continue
		}
		want := events.Actor{ID: me.ID, Name: "alice", Role: string(state.RoleAdmin), RemoteAddr: "192.0.2.7:5000"}
		if ev.Path == "users/carol" {
			want, carol = events.Actor{ID: events.SystemID}, true
		}
		if ev.Actor != want || ev.RequestID != "req-1" {
			t.Errorf("%s %s by %+v in request %q", ev.Type, ev.Path, ev.Actor, ev.RequestID)
		}
	}
	if !carol {
		t.Error("no folder.created for users/carol")
	}
}

func TestEnsureLayoutNeverSharesAnExistingPublicFolder(t *testing.T) {
	f := newFixture(t)
	os.MkdirAll(filepath.Join(f.root, "public", "private-photos"), 0o755)
	f.acc.CreateUser(events.WithActor(ctx, events.Actor{ID: events.ConsoleID}), "root", state.RoleAdmin, goodPassword)
	warnings := f.acc.EnsureLayout(ctx)
	if len(warnings) != 1 || !strings.Contains(warnings[0], "/public") {
		t.Errorf("warnings %q", warnings)
	}
	for _, b := range f.bindings(t) {
		if b.Kind == state.KindPublic {
			t.Error("an existing /public was shared")
		}
	}
}

func TestCreateUserAndSetPassword(t *testing.T) {
	f := newFixture(t)
	cctx := events.WithActor(ctx, events.Actor{ID: events.ConsoleID})
	u, err := f.acc.CreateUser(cctx, "Bench", state.RoleContributor, goodPassword)
	if err != nil {
		t.Fatal(err)
	}
	if u.Username != "bench" || u.CreatedBy != events.ConsoleID || u.Epoch != 0 {
		t.Errorf("user %+v", u)
	}
	if _, err := f.acc.CreateUser(cctx, "bench", state.RoleViewer, goodPassword); !errors.Is(err, ErrUsernameTaken) {
		t.Errorf("duplicate: %v", err)
	}
	if _, err := f.acc.CreateUser(cctx, "other", state.Role("owner"), goodPassword); err == nil {
		t.Error("an unknown role was accepted")
	}

	f.db.Update(func(tx *state.Tx) error {
		v, _ := tx.User(u.ID)
		v.Failures, v.PasswordDisabled = 100, true
		return tx.UpdateUser(v)
	})
	changed, err := f.acc.SetPassword(cctx, "bench", "another long passphrase")
	if err != nil {
		t.Fatal(err)
	}
	if changed.Epoch != 1 || changed.Failures != 0 || changed.PasswordDisabled || changed.Hash == u.Hash {
		t.Errorf("after SetPassword: %+v", changed)
	}
	ok, _, _ := f.acc.hasher.Verify(ctx, changed.Hash, "another long passphrase")
	if !ok {
		t.Error("the new password does not verify")
	}
	if _, err := f.acc.SetPassword(cctx, "nobody", goodPassword); !errors.Is(err, state.ErrNotFound) {
		t.Errorf("unknown user: %v", err)
	}
	if got := f.rec.types(); !slices.Equal(got, []events.Type{events.UserCreated, events.AuthPasswordChanged}) {
		t.Errorf("events %v", got)
	}
	for _, ev := range f.rec.evs {
		if ev.Actor.ID != events.ConsoleID || ev.Path != "bench" {
			t.Errorf("event %+v", ev)
		}
	}
}

func TestSetupHonoursAContextDeadlineWhileHashing(t *testing.T) {
	f := newFixture(t)
	code := f.startSetup(t)
	f.acc.hasher.slots <- struct{}{}
	f.acc.hasher.slots <- struct{}{}
	dctx, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	if _, err := f.acc.CompleteSetup(dctx, SetupRequest{Code: code, Username: "alice", Password: goodPassword}, Client{Addr: "192.0.2.9:4000"}); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v", err)
	}
}

func TestSetupChecksForAnAdminAgainWhenCommitting(t *testing.T) {
	f := newFixture(t)
	code := f.startSetup(t)
	if _, err := f.acc.CreateUser(events.WithActor(ctx, events.Actor{ID: events.ConsoleID}), "early", state.RoleAdmin, goodPassword); err != nil {
		t.Fatal(err)
	}
	if _, err := f.acc.CompleteSetup(ctx, SetupRequest{Code: code, Username: "alice", Password: goodPassword}, Client{Addr: "192.0.2.9:4000"}); !errors.Is(err, ErrSetupDone) {
		t.Fatalf("err = %v", err)
	}
	if f.exists("users") || f.exists("public") {
		t.Error("folders left after the commit refused")
	}
}

func TestEnsureLayoutRecreatesADeletedPublicFolder(t *testing.T) {
	f := newFixture(t)
	code := f.startSetup(t)
	if _, err := f.acc.CompleteSetup(ctx, SetupRequest{Code: code, Username: "alice", Password: goodPassword}, Client{Addr: "192.0.2.9:4000"}); err != nil {
		t.Fatal(err)
	}
	os.Remove(filepath.Join(f.root, "public"))
	if w := f.acc.EnsureLayout(ctx); len(w) != 0 {
		t.Errorf("warnings %q", w)
	}
	if !f.exists("public") {
		t.Error("/public not recreated")
	}
}
