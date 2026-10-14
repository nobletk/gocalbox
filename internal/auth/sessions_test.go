package auth

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/state"
)

func (f *fixture) addUser(t *testing.T, name string, role state.Role) state.User {
	t.Helper()
	u, err := f.acc.CreateUser(events.WithActor(ctx, events.Actor{ID: events.ConsoleID}), name, role, goodPassword)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func (f *fixture) login(t *testing.T, name string, c Client) Grant {
	t.Helper()
	g, err := f.acc.Login(ctx, name, goodPassword, c)
	if err != nil {
		t.Fatalf("login %s: %v", name, err)
	}
	return g
}

func (f *fixture) storedSessions(t *testing.T) map[string]state.Session {
	t.Helper()
	out := map[string]state.Session{}
	f.db.View(func(tx *state.Tx) error {
		return tx.Sessions(func(k []byte, s state.Session) error { out[string(k)] = s; return nil })
	})
	return out
}

func (f *fixture) user(t *testing.T, name string) state.User {
	t.Helper()
	u, _, err := f.acc.userByName(name)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

var browser = Client{Addr: "192.0.2.10:5000", UserAgent: "TestBrowser/1.0"}

func TestLoginStartsASession(t *testing.T) {
	f := newFixture(t)
	alice := f.addUser(t, "alice", state.RoleAdmin)
	g := f.login(t, "Alice", browser)
	if len(g.Token) != 43 || strings.ContainsAny(g.Token, "+/=") {
		t.Errorf("token %q", g.Token)
	}
	if !g.Expires.Equal(f.clock.now().Add(30*24*time.Hour)) || g.Me.Username != "alice" || g.Me.ReauthUntil == nil ||
		!g.Me.ReauthUntil.Equal(f.clock.now().Add(15*time.Minute)) {
		t.Errorf("grant %+v", g)
	}
	if !f.acc.trustedDevice(g.Device, alice) {
		t.Error("the new device cookie is not trusted")
	}
	id, ok := f.acc.Authenticate(g.Token)
	if !ok || id.User.ID != alice.ID || id.Session.UserAgent != "TestBrowser/1.0" || id.Session.IP != "192.0.2.10" {
		t.Fatalf("Authenticate = %+v, %v", id, ok)
	}
	stored := f.storedSessions(t)
	sum := sha256.Sum256([]byte(g.Token))
	if s, ok := stored[string(sum[:])]; len(stored) != 1 || !ok || s.ID != id.Session.ID {
		t.Errorf("stored sessions %+v", stored)
	}
	for k := range stored {
		if strings.Contains(k, g.Token) {
			t.Error("the token itself is stored")
		}
	}
	last := f.rec.evs[len(f.rec.evs)-1]
	if last.Type != events.AuthLogin || last.Outcome != events.OutcomeOK || last.Actor.ID != alice.ID || last.Actor.Session != id.Session.ID {
		t.Errorf("event %+v", last)
	}
	if _, ok := f.acc.Authenticate(g.Token + "x"); ok {
		t.Error("a changed token was accepted")
	}
}

func TestLoginRefusals(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "alice", state.RoleAdmin)
	bob := f.addUser(t, "bob", state.RoleViewer)
	for _, tc := range []struct {
		name, password string
		want           error
	}{
		{"alice", "wrong password entirely", ErrInvalidCredentials},
		{"nobody", goodPassword, ErrInvalidCredentials},
		{"not a valid name!", goodPassword, ErrInvalidCredentials},
		{"alice", strings.Repeat("x", MaxPasswordBytes+1), ErrInvalidCredentials},
	} {
		c := Client{Addr: fmt.Sprintf("192.0.2.%d:1", len(tc.name))}
		if _, err := f.acc.Login(ctx, tc.name, tc.password, c); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	f.db.Update(func(tx *state.Tx) error { bob.Disabled = true; return tx.UpdateUser(bob) })
	if _, err := f.acc.Login(ctx, "bob", goodPassword, browser); !errors.Is(err, ErrAccountDisabled) {
		t.Errorf("disabled, right password: %v", err)
	}
	if _, err := f.acc.Login(ctx, "bob", "wrong password entirely", browser); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("disabled, wrong password: %v", err)
	}
	denied := 0
	for _, ev := range f.rec.evs {
		if ev.Type == events.AuthLogin && ev.Outcome == events.OutcomeDenied {
			denied++
			if ev.Path == "" || ev.Actor.ID != events.AnonymousID {
				t.Errorf("denied login event %+v", ev)
			}
		}
	}
	if denied != 6 {
		t.Errorf("%d denied login events, want 6", denied)
	}
}

func TestSessionsExpire(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "alice", state.RoleAdmin)
	idle := f.login(t, "alice", browser)
	f.clock.advance(14*24*time.Hour - time.Second)
	if _, ok := f.acc.Authenticate(idle.Token); !ok {
		t.Fatal("expired a second early")
	}
	f.clock.advance(14*24*time.Hour - time.Second)
	if _, ok := f.acc.Authenticate(idle.Token); !ok {
		t.Fatal("use did not extend the idle limit")
	}
	f.clock.advance(14 * 24 * time.Hour)
	if _, ok := f.acc.Authenticate(idle.Token); ok {
		t.Fatal("valid after 14 idle days")
	}
	if len(f.storedSessions(t)) != 0 {
		t.Error("the expired session was not deleted")
	}

	busy := f.login(t, "alice", browser)
	for range 29 {
		f.clock.advance(24 * time.Hour)
		if _, ok := f.acc.Authenticate(busy.Token); !ok {
			t.Fatal("expired before 30 days")
		}
	}
	f.clock.advance(24 * time.Hour)
	if _, ok := f.acc.Authenticate(busy.Token); ok {
		t.Fatal("valid after 30 days of daily use")
	}
}

func TestSessionsEndWithTheAccountsEpochOrDisabling(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "alice", state.RoleAdmin)
	g := f.login(t, "alice", browser)
	if _, err := f.acc.SetPassword(events.WithActor(ctx, events.Actor{ID: events.ConsoleID}), "alice", "another long passphrase"); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.acc.Authenticate(g.Token); ok {
		t.Error("valid after the password changed")
	}
	if f.acc.trustedDevice(g.Device, f.user(t, "alice")) {
		t.Error("the device cookie survived the password change")
	}
	g, err := f.acc.Login(ctx, "alice", "another long passphrase", browser)
	if err != nil {
		t.Fatal(err)
	}
	cur := f.user(t, "alice")
	cur.Disabled = true
	f.acc.update(func(tx *state.Tx) error { return tx.UpdateUser(cur) })
	if _, ok := f.acc.Authenticate(g.Token); ok {
		t.Error("valid after the account was disabled")
	}
}

func TestSessionsSurviveARestart(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "alice", state.RoleAdmin)
	g := f.login(t, "alice", browser)
	f.clock.advance(time.Hour)
	f.acc.Authenticate(g.Token)
	if err := f.acc.Close(); err != nil {
		t.Fatal(err)
	}
	for _, s := range f.storedSessions(t) {
		if !s.LastSeen.Equal(f.clock.now()) {
			t.Errorf("lastSeen %v not written at close", s.LastSeen)
		}
	}
	again := New(Config{DB: f.db, Hasher: NewHasher(testParams, 1, time.Second), Policy: Policy{MinLength: 15}, Now: f.clock.now})
	if err := again.Start(); err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if id, ok := again.Authenticate(g.Token); !ok || id.User.Username != "alice" {
		t.Error("the session did not survive a restart")
	}
}

func TestExpiredSessionsAreRemoved(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "alice", state.RoleAdmin)
	old := f.login(t, "alice", browser)
	f.clock.advance(13 * 24 * time.Hour)
	recent := f.login(t, "alice", browser)
	f.clock.advance(2 * 24 * time.Hour)
	if err := f.acc.dropExpired(); err != nil {
		t.Fatal(err)
	}
	if n := len(f.storedSessions(t)); n != 1 {
		t.Errorf("%d sessions after the hourly cleanup", n)
	}

	f.clock.advance(13 * 24 * time.Hour)
	f.acc.Close()
	f.db.Update(func(tx *state.Tx) error {
		return tx.PutSession([]byte("not a hash"), state.Session{ID: "0011223344556677", User: "u-x"})
	})
	again := New(Config{DB: f.db, Hasher: NewHasher(testParams, 1, time.Second), Policy: Policy{MinLength: 15}, Now: f.clock.now})
	if err := again.Start(); err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if n := len(f.storedSessions(t)); n != 0 {
		t.Errorf("%d sessions after a start", n)
	}
	for _, g := range []Grant{old, recent} {
		if _, ok := again.Authenticate(g.Token); ok {
			t.Error("an expired session works")
		}
	}
}

func TestLastSeenIsWrittenInBatches(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "alice", state.RoleAdmin)
	g := f.login(t, "alice", browser)
	before := f.storedSessions(t)
	f.clock.advance(10 * time.Second)
	f.acc.Authenticate(g.Token)
	if after := f.storedSessions(t); fmt.Sprint(after) != fmt.Sprint(before) {
		t.Error("a request wrote to the state file")
	}
	if err := f.acc.writeLastSeen(); err != nil {
		t.Fatal(err)
	}
	for _, s := range f.storedSessions(t) {
		if !s.LastSeen.Equal(f.clock.now()) {
			t.Errorf("lastSeen %v", s.LastSeen)
		}
	}
}

func TestAtMostTwentySessionsPerUser(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "alice", state.RoleAdmin)
	var grants []Grant
	for range 21 {
		f.clock.advance(time.Minute)
		grants = append(grants, f.login(t, "alice", browser))
	}
	if n := len(f.storedSessions(t)); n != 20 {
		t.Errorf("%d sessions", n)
	}
	if _, ok := f.acc.Authenticate(grants[0].Token); ok {
		t.Error("the session seen least recently survived")
	}
	if _, ok := f.acc.Authenticate(grants[20].Token); !ok {
		t.Error("the newest session is missing")
	}
	if evs := f.rec.withDetail("reason=session_limit"); len(evs) != 1 || evs[0].Type != events.SessionRevoked || evs[0].Path != "alice" {
		t.Errorf("records of the session the limit ended: %+v", evs)
	}
}

func TestTheSessionLimitCountsValidSessionsOnly(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "alice", state.RoleAdmin)
	var grants []Grant
	for range maxSessionsPerUser {
		grants = append(grants, f.login(t, "alice", browser))
	}
	f.clock.advance(13 * 24 * time.Hour)
	for _, g := range grants[1:] {
		f.acc.Authenticate(g.Token)
	}
	f.clock.advance(2 * 24 * time.Hour)
	f.login(t, "alice", browser)
	if evs := f.rec.withDetail("reason=session_limit"); len(evs) != 0 {
		t.Errorf("the limit ended %+v", evs)
	}
	for i, g := range grants[1:] {
		if _, ok := f.acc.Authenticate(g.Token); !ok {
			t.Errorf("session %d ended", i+1)
		}
	}
}

func TestLoginReplacesTheBrowsersSession(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "alice", state.RoleAdmin)
	f.addUser(t, "bob", state.RoleViewer)
	first := f.login(t, "alice", browser)
	c := browser
	c.Token = first.Token
	second := f.login(t, "bob", c)
	if _, ok := f.acc.Authenticate(first.Token); ok {
		t.Error("the browser's previous session survived a new login")
	}
	if second.Token == first.Token {
		t.Error("the token was reused")
	}
	evs := f.rec.withDetail("reason=replaced")
	if len(evs) != 1 || evs[0].Type != events.SessionRevoked || evs[0].Path != "alice" || evs[0].Actor.Name != "bob" {
		t.Errorf("records of the replaced session: %+v", evs)
	}
}

func TestLogoutAndRevocation(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "alice", state.RoleAdmin)
	f.addUser(t, "bob", state.RoleViewer)
	a1, a2, a3 := f.login(t, "alice", browser), f.login(t, "alice", browser), f.login(t, "alice", browser)
	b1 := f.login(t, "bob", browser)
	id1, _ := f.acc.Authenticate(a1.Token)
	idBob, _ := f.acc.Authenticate(b1.Token)

	list := f.acc.Sessions(id1)
	if len(list) != 3 || !slices.ContainsFunc(list, func(s SessionInfo) bool { return s.Current && s.ID == id1.Session.ID }) {
		t.Errorf("sessions %+v", list)
	}
	if err := f.acc.RevokeSession(ctx, id1, idBob.Session.ID); !errors.Is(err, ErrNoSuchSession) {
		t.Errorf("revoking another user's session: %v", err)
	}
	id2, _ := f.acc.Authenticate(a2.Token)
	if err := f.acc.RevokeSession(ctx, id1, id2.Session.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.acc.Authenticate(a2.Token); ok {
		t.Error("a revoked session works")
	}
	links, err := f.acc.RevokeOtherSessions(ctx, id1)
	if err != nil || links == nil || len(links) != 0 {
		t.Fatalf("RevokeOtherSessions = %v, %v", links, err)
	}
	if _, ok := f.acc.Authenticate(a3.Token); ok {
		t.Error("another session survived sign-out everywhere else")
	}
	if _, ok := f.acc.Authenticate(a1.Token); !ok {
		t.Error("the current session ended")
	}
	if _, ok := f.acc.Authenticate(b1.Token); !ok {
		t.Error("another user's session ended")
	}
	if err := f.acc.Logout(ctx, id1); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.acc.Authenticate(a1.Token); ok {
		t.Error("valid after logout")
	}
	revoked := 0
	for _, ev := range f.rec.evs {
		if ev.Type == events.SessionRevoked {
			revoked++
		}
	}
	if revoked != 2 || f.rec.evs[len(f.rec.evs)-1].Type != events.AuthLogout {
		t.Errorf("events %v", f.rec.types())
	}
}

func TestConfirmRenewsTheToken(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "alice", state.RoleAdmin)
	g := f.login(t, "alice", browser)
	id, _ := f.acc.Authenticate(g.Token)
	f.clock.advance(time.Hour)
	if _, err := f.acc.Confirm(ctx, id, "wrong password entirely", browser); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password: %v", err)
	}
	renewed, err := f.acc.Confirm(ctx, id, goodPassword, browser)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.acc.Authenticate(g.Token); ok {
		t.Error("the old token works after renewal")
	}
	nid, ok := f.acc.Authenticate(renewed.Token)
	if !ok || nid.Session.ID != id.Session.ID || !nid.Session.Created.Equal(id.Session.Created) || !nid.Session.AuthTime.Equal(f.clock.now()) {
		t.Errorf("renewed session %+v", nid.Session)
	}
	if !renewed.Expires.Equal(g.Expires) || !renewed.Me.ReauthUntil.Equal(f.clock.now().Add(15*time.Minute)) {
		t.Errorf("renewal moved the limits: %+v", renewed)
	}
}

func TestFiveWrongPasswordsEndASession(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "alice", state.RoleAdmin)
	g := f.login(t, "alice", browser)
	id, _ := f.acc.Authenticate(g.Token)
	for i := 1; i <= 5; i++ {
		f.clock.advance(time.Hour)
		_, err := f.acc.Confirm(ctx, id, "wrong password entirely", Client{Addr: fmt.Sprintf("192.0.2.%d:1", 100+i)})
		want := ErrInvalidCredentials
		if i == 5 {
			want = ErrTooManyWrongPasswords
		}
		if !errors.Is(err, want) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if _, ok := f.acc.Authenticate(g.Token); ok {
		t.Error("the session survived five wrong passwords")
	}
}

func TestFiveWrongCurrentPasswordsEndASession(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "alice", state.RoleAdmin)
	g := f.login(t, "alice", browser)
	id, _ := f.acc.Authenticate(g.Token)
	for i := 1; i <= 5; i++ {
		_, _, err := f.acc.ChangePassword(ctx, id, wrong, "a brand new passphrase", Client{Addr: fmt.Sprintf("192.0.2.%d:1", 110+i)})
		if want := map[bool]error{false: ErrInvalidCredentials, true: ErrTooManyWrongPasswords}[i == 5]; !errors.Is(err, want) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if _, ok := f.acc.Authenticate(g.Token); ok {
		t.Error("the session survived five wrong current passwords")
	}
}

func TestLogoutEndsARenewedSession(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "alice", state.RoleAdmin)
	g := f.login(t, "alice", browser)
	stale, _ := f.acc.Authenticate(g.Token)
	renewed, err := f.acc.Confirm(ctx, stale, goodPassword, browser)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.acc.Logout(ctx, stale); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.acc.Authenticate(renewed.Token); ok {
		t.Error("the renewed token survived the logout")
	}
	if list := f.acc.Sessions(stale); len(list) != 0 {
		t.Errorf("sessions after logout: %+v", list)
	}
}

func TestChangePassword(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "alice", state.RoleAdmin)
	other := f.login(t, "alice", Client{Addr: "192.0.2.20:1"})
	g := f.login(t, "alice", browser)
	id, _ := f.acc.Authenticate(g.Token)

	if _, _, err := f.acc.ChangePassword(ctx, id, "wrong password entirely", "a brand new passphrase", browser); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("wrong current password: %v", err)
	}
	var we *WeakPasswordError
	if _, _, err := f.acc.ChangePassword(ctx, id, goodPassword, "short", browser); !errors.As(err, &we) {
		t.Errorf("weak new password: %v", err)
	}
	renewed, links, err := f.acc.ChangePassword(ctx, id, goodPassword, "a brand new passphrase", browser)
	if err != nil || links == nil || len(links) != 0 {
		t.Fatalf("ChangePassword = %v, %v", links, err)
	}
	if n := len(f.storedSessions(t)); n != 1 {
		t.Errorf("%d sessions stored after the change", n)
	}
	if _, ok := f.acc.Authenticate(other.Token); ok {
		t.Error("another session survived the password change")
	}
	if _, ok := f.acc.Authenticate(g.Token); ok {
		t.Error("the old token works")
	}
	f.acc.throttle.mu.Lock()
	failures := f.acc.throttle.accounts[id.User.ID].failures
	f.acc.throttle.mu.Unlock()
	if failures != 0 {
		t.Errorf("the account's count after the change: %d", failures)
	}
	nid, ok := f.acc.Authenticate(renewed.Token)
	if !ok || nid.Session.ID != id.Session.ID || nid.Session.Epoch != 1 {
		t.Errorf("renewed session %+v, %v", nid.Session, ok)
	}
	u := f.user(t, "alice")
	if u.Epoch != 1 || !f.acc.trustedDevice(renewed.Device, u) || f.acc.trustedDevice(other.Device, u) {
		t.Error("device cookies after the change are wrong")
	}
	if _, err := f.acc.Login(ctx, "alice", goodPassword, Client{Addr: "192.0.2.21:1"}); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("the old password still works: %v", err)
	}
	if _, err := f.acc.Login(ctx, "alice", "a brand new passphrase", Client{Addr: "192.0.2.22:1"}); err != nil {
		t.Errorf("the new password fails: %v", err)
	}
	if !slices.Contains(f.rec.types(), events.AuthPasswordChanged) {
		t.Error("no auth.password_changed event")
	}
}

func TestDeviceCookie(t *testing.T) {
	f := newFixture(t)
	alice, bob := f.addUser(t, "alice", state.RoleAdmin), f.addUser(t, "bob", state.RoleViewer)
	good := f.acc.deviceCookie(alice)
	if !f.acc.trustedDevice(good, alice) {
		t.Fatal("a fresh cookie is not trusted")
	}
	parts := strings.Split(good, ".")
	for name, c := range map[string]string{
		"another account's": f.acc.deviceCookie(bob),
		"forged MAC":        parts[0] + "." + parts[1] + ".AAAA",
		"changed time":      parts[0] + ".1." + parts[2],
		"empty":             "",
		"no dots":           "garbage",
	} {
		if f.acc.trustedDevice(c, alice) {
			t.Errorf("%s cookie trusted", name)
		}
	}
	f.clock.advance(DeviceCookieLifetime + time.Second)
	if f.acc.trustedDevice(good, alice) {
		t.Error("a cookie older than 400 days is trusted")
	}
}

func TestLoginRehashesWeakerHashes(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "alice", state.RoleAdmin)
	strong := NewHasher(Params{Memory: 128, Time: 2, Threads: 1}, 1, time.Second)
	f.acc.hasher, f.acc.dummyHash = strong, strong.dummy()
	f.login(t, "alice", browser)
	if h := f.user(t, "alice").Hash; !strings.HasPrefix(h, "$argon2id$v=19$m=128,t=2,p=1$") {
		t.Errorf("hash after login %s", h)
	}
}

func TestChecksArrivingTogetherShareASessionsFiveTries(t *testing.T) {
	f := newFixtureWith(t, Params{Memory: 4 * 1024, Time: 2, Threads: 1}, func(int) time.Duration { return 0 })
	f.addUser(t, "alice", state.RoleAdmin)
	g := f.login(t, "alice", browser)
	id, _ := f.acc.Authenticate(g.Token)
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Go(func() {
			f.acc.Confirm(ctx, id, wrong, Client{Addr: fmt.Sprintf("192.0.2.%d:1", 100+i)})
		})
	}
	wg.Wait()
	if checked := len(f.rec.withDetail("wrong_password_in_session")); checked != freeFailures {
		t.Errorf("%d wrong passwords checked in one session", checked)
	}
	if ended := f.rec.withDetail("reason=wrong_passwords"); len(ended) != 1 {
		t.Errorf("%d records of the session ending", len(ended))
	}
	if _, ok := f.acc.Authenticate(g.Token); ok {
		t.Error("the session survived")
	}
}

func TestAStolenCookieCannotDisableThePassword(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "alice", state.RoleAdmin)
	owner := f.login(t, "alice", browser)
	stolen := f.login(t, "alice", Client{Addr: "192.0.2.50:1"})
	id, _ := f.acc.Authenticate(stolen.Token)
	long := strings.Repeat("x", MaxPasswordBytes+1)
	var wg sync.WaitGroup
	for i := range 120 {
		wg.Go(func() {
			f.acc.Confirm(ctx, id, long, Client{Addr: fmt.Sprintf("192.0.2.%d:1", 100+i%24)})
		})
	}
	wg.Wait()
	if u := f.user(t, "alice"); u.PasswordDisabled {
		t.Error("the password was disabled")
	}
	if _, err := f.acc.Login(ctx, "alice", goodPassword, Client{Addr: "192.0.2.51:1", Device: owner.Device}); err != nil {
		t.Errorf("the owner's login: %v", err)
	}
}

func TestARightPasswordInASessionEndedMeanwhileTellsNothing(t *testing.T) {
	p := Params{Memory: 16 * 1024, Time: 8, Threads: 1}
	begin := time.Now()
	NewHasher(p, 1, time.Second).Hash(ctx, goodPassword)
	delay := max(500*time.Millisecond, 4*time.Since(begin))
	f := newFixtureWith(t, p, func(int) time.Duration { return delay })
	f.addUser(t, "alice", state.RoleAdmin)
	g := f.login(t, "alice", browser)
	id, _ := f.acc.Authenticate(g.Token)
	type result struct {
		err  error
		took time.Duration
	}
	done := make(chan result, 1)
	go func() {
		start := time.Now()
		_, err := f.acc.Confirm(ctx, id, goodPassword, browser)
		done <- result{err, time.Since(start)}
	}()
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(time.Millisecond) {
		f.acc.sessions.mu.Lock()
		e := f.acc.sessions.byKey[id.key]
		checking := e != nil && e.checking > 0
		f.acc.sessions.mu.Unlock()
		if checking {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the check never started")
		}
	}
	if err := f.acc.Logout(ctx, id); err != nil {
		t.Fatal(err)
	}
	r := <-done
	if !errors.Is(r.err, ErrSessionEnded) || r.took < delay {
		t.Errorf("Confirm = %v after %v; want the session ended, after the failure delay of %v", r.err, r.took, delay)
	}
	f.acc.throttle.mu.Lock()
	c := f.acc.throttle.accounts[id.User.ID]
	counted := c != nil && c.failures != 0
	f.acc.throttle.mu.Unlock()
	if counted {
		t.Error("the right password stayed counted as a failure")
	}
}

func TestTheFifthWrongPasswordEndsTheSessionBeforeTheDelay(t *testing.T) {
	const delay = time.Second
	f := newFixtureWith(t, testParams, func(n int) time.Duration {
		if n < freeFailures {
			return 0
		}
		return delay
	})
	f.addUser(t, "alice", state.RoleAdmin)
	g := f.login(t, "alice", browser)
	id, _ := f.acc.Authenticate(g.Token)
	for i := range freeFailures - 1 {
		f.acc.Confirm(ctx, id, wrong, Client{Addr: fmt.Sprintf("192.0.2.%d:1", 120+i)})
	}
	done := make(chan error, 1)
	go func() {
		_, err := f.acc.Confirm(ctx, id, wrong, Client{Addr: "192.0.2.130:1"})
		done <- err
	}()
	for deadline := time.Now().Add(delay / 2); ; time.Sleep(time.Millisecond) {
		if _, ok := f.acc.Authenticate(g.Token); !ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the session was not ended before the failure delay")
		}
	}
	if err := <-done; !errors.Is(err, ErrTooManyWrongPasswords) {
		t.Errorf("fifth wrong password: %v", err)
	}
}

func TestFiveWrongPasswordsEndASessionRenewedMeanwhile(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "alice", state.RoleAdmin)
	g := f.login(t, "alice", browser)
	id, _ := f.acc.Authenticate(g.Token)

	f.acc.usersMu.Lock()
	renewed := make(chan Grant, 1)
	go func() {
		g, _ := f.acc.Confirm(ctx, id, goodPassword, browser)
		renewed <- g
	}()
	for deadline := time.Now().Add(5 * time.Second); f.acc.sessions.write.TryLock(); time.Sleep(time.Millisecond) {
		f.acc.sessions.write.Unlock()
		if time.Now().After(deadline) {
			f.acc.usersMu.Unlock()
			t.Fatal("the renewal never started")
		}
	}
	errs := make(chan error, freeFailures)
	for i := range freeFailures {
		go func() {
			_, err := f.acc.Confirm(ctx, id, wrong, Client{Addr: fmt.Sprintf("192.0.2.%d:1", 140+i)})
			errs <- err
		}()
	}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(time.Millisecond) {
		f.acc.sessions.mu.Lock()
		e := f.acc.sessions.byKey[id.key]
		counted := e != nil && e.failures == freeFailures
		f.acc.sessions.mu.Unlock()
		if counted {
			break
		}
		if time.Now().After(deadline) {
			f.acc.usersMu.Unlock()
			t.Fatal("the wrong passwords were never counted")
		}
	}
	f.acc.usersMu.Unlock()
	r := <-renewed
	ended := 0
	for range freeFailures {
		if errors.Is(<-errs, ErrTooManyWrongPasswords) {
			ended++
		}
	}
	if ended != 1 {
		t.Errorf("%d answers ended the session", ended)
	}
	if _, ok := f.acc.Authenticate(r.Token); ok {
		t.Error("the session renewed while five wrong passwords ended it is still valid")
	}
}

func TestASessionThatFiveWrongPasswordsEndIsNotRenewed(t *testing.T) {
	f := newFixture(t)
	u := f.addUser(t, "alice", state.RoleAdmin)
	g := f.login(t, "alice", browser)
	id, _ := f.acc.Authenticate(g.Token)
	f.acc.sessions.mu.Lock()
	f.acc.sessions.byKey[id.key].failures = freeFailures
	f.acc.sessions.mu.Unlock()
	if _, err := f.acc.renew(id, u, false); !errors.Is(err, ErrSessionEnded) {
		t.Errorf("renew = %v", err)
	}
}

func TestTheOldTokenDuringAPasswordChangeIsNotReportedEnded(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "alice", state.RoleAdmin)
	passwords := []string{goodPassword, "another long passphrase"}
	for i := range 40 {
		g, err := f.acc.Login(ctx, "alice", passwords[i%2], Client{Addr: "192.0.2.60:1"})
		if err != nil {
			t.Fatal(err)
		}
		id, _ := f.acc.Authenticate(g.Token)
		done := make(chan error, 1)
		go func() {
			_, _, err := f.acc.ChangePassword(ctx, id, passwords[i%2], passwords[(i+1)%2], Client{Addr: "192.0.2.60:1"})
			done <- err
		}()
		for running := true; running; {
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
				running = false
			default:
				if _, s := f.acc.Identify(g.Token); s == EndedSession {
					t.Fatalf("try %d: the token a password change was replacing was reported ended", i)
				}
			}
		}
	}
}

func TestLogoutAndRevocationRacingARenewalEndTheRenewedSession(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "alice", state.RoleAdmin)
	for i := range 400 {
		id, _ := f.acc.Authenticate(f.login(t, "alice", browser).Token)
		var renewed Grant
		var cerr, lerr error
		var wg sync.WaitGroup
		wg.Go(func() { renewed, cerr = f.acc.Confirm(ctx, id, goodPassword, browser) })
		wg.Go(func() {
			time.Sleep(time.Duration(i%8) * 25 * time.Microsecond)
			if i%2 == 0 {
				lerr = f.acc.Logout(ctx, id)
			} else {
				lerr = f.acc.RevokeSession(ctx, id, id.Session.ID)
			}
		})
		wg.Wait()
		if cerr == nil && lerr == nil {
			if _, ok := f.acc.Authenticate(renewed.Token); ok {
				t.Fatalf("try %d: the session renewed during a successful logout or revocation is still valid", i)
			}
		}
	}
}

func TestLoginsWhileRequestsArrive(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "alice", state.RoleAdmin)
	tokens := []string{f.login(t, "alice", browser).Token, f.login(t, "alice", browser).Token}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			f.clock.advance(time.Millisecond)
			for _, tk := range tokens {
				f.acc.Authenticate(tk)
			}
		}
	})
	for range 30 {
		f.login(t, "alice", browser)
	}
	close(stop)
	wg.Wait()
	if n := len(f.storedSessions(t)); n != maxSessionsPerUser {
		t.Errorf("%d sessions", n)
	}
}

func TestSessionsNoLongerValidAreNeitherListedNorRecorded(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "alice", state.RoleAdmin)
	f.login(t, "alice", browser)
	g := f.login(t, "alice", Client{Addr: "192.0.2.30:1"})
	other := f.login(t, "alice", Client{Addr: "192.0.2.31:1"})
	f.clock.advance(13 * 24 * time.Hour)
	id, _ := f.acc.Authenticate(g.Token)
	f.acc.Authenticate(other.Token)
	f.clock.advance(2 * 24 * time.Hour)
	if list := f.acc.Sessions(id); len(list) != 2 {
		t.Errorf("listed %+v", list)
	}
	var expired string
	for _, s := range f.storedSessions(t) {
		if s.ID != id.Session.ID && !slices.ContainsFunc(f.acc.Sessions(id), func(i SessionInfo) bool { return i.ID == s.ID }) {
			expired = s.ID
		}
	}
	if err := f.acc.RevokeSession(ctx, id, expired); !errors.Is(err, ErrNoSuchSession) {
		t.Errorf("revoking the expired session: %v", err)
	}
	before := len(f.rec.withDetail("id="))
	if _, err := f.acc.RevokeOtherSessions(ctx, id); err != nil {
		t.Fatal(err)
	}
	if recorded := len(f.rec.withDetail("id=")) - before; recorded != 1 {
		t.Errorf("%d session.revoked records for one valid session", recorded)
	}
	if n := len(f.storedSessions(t)); n != 1 {
		t.Errorf("%d sessions left", n)
	}
}
