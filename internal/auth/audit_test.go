package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/state"
)

type fakeAuditor struct {
	mu         sync.Mutex
	paused     bool
	fail       error
	plain      []events.Event
	protective []events.Event
}

func (f *fakeAuditor) Allow() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.paused {
		return fmt.Errorf("%w: disk full", events.ErrChangesPaused)
	}
	return nil
}

func (f *fakeAuditor) Record(_ context.Context, evs ...events.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.plain = append(f.plain, evs...)
	return f.fail
}

func (f *fakeAuditor) RecordProtective(ctx context.Context, evs ...events.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.protective = append(f.protective, evs...)
	return f.fail
}

func (f *fakeAuditor) types() (plain, protective []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, ev := range f.plain {
		plain = append(plain, string(ev.Type))
	}
	for _, ev := range f.protective {
		protective = append(protective, string(ev.Type)+" "+ev.Detail)
	}
	return plain, protective
}

func audited(f *fixture) *fakeAuditor {
	a := &fakeAuditor{}
	f.acc.audit = a
	return a
}

var notRecorded = fmt.Errorf("%w: disk full", events.ErrNotRecorded)

func TestSetupIsRefusedWhileChangesArePaused(t *testing.T) {
	f := newFixture(t)
	code := f.startSetup(t)
	a := audited(f)
	a.paused = true

	_, err := f.acc.CompleteSetup(ctx, SetupRequest{Code: "wrong", Username: "alice", Password: goodPassword}, browser)
	if !errors.Is(err, events.ErrChangesPaused) {
		t.Fatalf("setup while paused = %v", err)
	}
	if !f.acc.SetupRequired() || f.exists("users") || f.exists("public") {
		t.Error("setup changed something while changes are paused")
	}
	a.paused = false
	for range freeFailures {
		if _, err := f.acc.CompleteSetup(ctx, SetupRequest{Code: "wrong"}, browser); !errors.Is(err, ErrSetupCodeInvalid) {
			t.Fatalf("wrong code = %v; the refused setup was counted as a wrong code", err)
		}
	}
	f.acc.throttle.reset(codeKey(f.acc.throttle.group(browser.Addr)))
	if _, err := f.acc.CompleteSetup(ctx, SetupRequest{Code: FormatCode(code), Username: "alice", Password: goodPassword}, browser); err != nil {
		t.Errorf("setup after changes resumed = %v", err)
	}
}

func TestASetupWhoseRecordFailedStillLogsTheAdminIn(t *testing.T) {
	f := newFixture(t)
	code := f.startSetup(t)
	a := audited(f)
	a.fail = notRecorded

	g, err := f.acc.CompleteSetup(ctx, SetupRequest{Code: FormatCode(code), Username: "alice", Password: goodPassword}, browser)
	if !events.IsUnrecorded(err) {
		t.Fatalf("setup = %v", err)
	}
	if _, ok := f.acc.Authenticate(g.Token); !ok || g.Me.Username != "alice" || f.acc.SetupRequired() {
		t.Errorf("the grant of a setup that was made but not recorded = %+v", g)
	}
	if plain, _ := a.types(); len(plain) != 1 || plain[0] != string(events.AuthSetupCompleted) {
		t.Errorf("waited for %v", plain)
	}
}

func TestChangesThatOnlyTakeAccessAwayGoOnWhileChangesArePaused(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "alice", state.RoleAdmin)
	a := audited(f)
	a.paused = true

	first := f.login(t, "alice", browser)
	second := f.login(t, "alice", Client{Addr: browser.Addr, Token: first.Token}) // replaces the first
	third := f.login(t, "alice", browser)
	fourth := f.login(t, "alice", browser)
	id, _ := f.acc.Authenticate(second.Token)
	idThird, _ := f.acc.Authenticate(third.Token)

	if err := f.acc.RevokeSession(ctx, id, idThird.Session.ID); err != nil {
		t.Errorf("revoke while paused = %v", err)
	}
	if _, err := f.acc.RevokeOtherSessions(ctx, id); err != nil {
		t.Errorf("revoke others while paused = %v", err)
	}
	if _, ok := f.acc.Authenticate(fourth.Token); ok {
		t.Error("a session survived revoke-others")
	}
	g, _, err := f.acc.ChangePassword(ctx, id, goodPassword, goodPassword+" too", browser)
	if err != nil {
		t.Fatalf("password change while paused = %v", err)
	}
	id, _ = f.acc.Authenticate(g.Token)
	for range freeFailures {
		f.acc.Confirm(ctx, id, wrong, browser)
	}
	if _, ok := f.acc.Authenticate(g.Token); ok {
		t.Error("five wrong passwords didn't end the session")
	}

	plain, protective := a.types()
	if len(plain) != 0 {
		t.Errorf("waited as for ordinary changes: %v", plain)
	}
	want := []string{"session.revoked replaced", "session.revoked", "session.revoked", "auth.password_changed", "session.revoked wrong_passwords"}
	if len(protective) != len(want) {
		t.Fatalf("protective records = %q", protective)
	}
	for i, w := range want {
		typ, reason, _ := strings.Cut(w, " ")
		if !strings.HasPrefix(protective[i], typ) || !strings.Contains(protective[i], reason) {
			t.Errorf("protective record %d = %q, want %q", i, protective[i], w)
		}
	}
}

func TestAProtectiveChangeWhoseRecordFailedIsStillMade(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "alice", state.RoleAdmin)
	a := audited(f)
	a.fail = notRecorded

	first := f.login(t, "alice", browser)
	g, err := f.acc.Login(ctx, "alice", goodPassword, Client{Addr: browser.Addr, Token: first.Token})
	if !events.IsUnrecorded(err) || g.Token == "" {
		t.Fatalf("login that ended a session = %+v, %v", g, err)
	}
	if _, ok := f.acc.Authenticate(g.Token); !ok {
		t.Error("the new session doesn't work")
	}
	id, _ := f.acc.Authenticate(g.Token)
	other := f.login(t, "alice", browser)
	idOther, _ := f.acc.Authenticate(other.Token)
	if err := f.acc.RevokeSession(ctx, id, idOther.Session.ID); !events.IsUnrecorded(err) {
		t.Errorf("revoke = %v", err)
	}
	if _, ok := f.acc.Authenticate(other.Token); ok {
		t.Error("the revoked session works")
	}

	renewed, links, err := f.acc.ChangePassword(ctx, id, goodPassword, goodPassword+" too", browser)
	if !events.IsUnrecorded(err) || links == nil {
		t.Fatalf("password change = %v", err)
	}
	if _, ok := f.acc.Authenticate(renewed.Token); !ok {
		t.Error("the renewed session doesn't work")
	}
	if _, err := f.acc.Login(ctx, "alice", goodPassword+" too", Client{Addr: "192.0.2.99:1"}); err != nil && !events.IsUnrecorded(err) {
		t.Errorf("the new password: %v", err)
	}
}

func TestAttemptsRefusedBeforeTheCheckAreRecorded(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "alice", state.RoleAdmin)
	c := Client{Addr: "192.0.2.50:1"}
	for range freeFailures {
		f.acc.Login(ctx, "alice", wrong, c)
	}
	var tm *TooManyAttemptsError
	if _, err := f.acc.Login(ctx, "alice", goodPassword, c); !errors.As(err, &tm) {
		t.Fatalf("sixth attempt = %v", err)
	}
	if evs := f.rec.withDetail("too_many_attempts"); len(evs) != 1 || evs[0].Type != events.AuthLogin || evs[0].Outcome != events.OutcomeDenied || evs[0].Path != "alice" {
		t.Errorf("refused attempt recorded as %+v", evs)
	}

	f.acc.hasher = NewHasher(testParams, 1, 20*time.Millisecond)
	f.acc.hasher.slots <- struct{}{}
	if _, err := f.acc.Login(ctx, "bob", wrong, Client{Addr: "192.0.2.60:1"}); !errors.Is(err, ErrBusy) {
		t.Fatalf("login without a hashing slot = %v", err)
	}
	if evs := f.rec.withDetail("busy"); len(evs) != 1 || evs[0].Path != "bob" {
		t.Errorf("busy recorded as %+v", evs)
	}
	f.acc.hasher.release()

	g := f.login(t, "alice", browser)
	id, _ := f.acc.Authenticate(g.Token)
	f.acc.sessions.mu.Lock()
	f.acc.sessions.byKey[id.key].checking = freeFailures
	f.acc.sessions.mu.Unlock()
	if _, err := f.acc.Confirm(ctx, id, goodPassword, browser); !errors.As(err, &tm) {
		t.Fatalf("a sixth check in a session = %v", err)
	}
	if evs := f.rec.withDetail("too_many_attempts_in_session id=" + id.Session.ID); len(evs) != 1 {
		t.Errorf("refused check in a session recorded as %+v", evs)
	}
}

func TestEveryRefusalBeforeTheCheckIsRecorded(t *testing.T) {
	f := newFixture(t)
	alice := f.addUser(t, "alice", state.RoleAdmin)
	g := f.login(t, "alice", browser)
	id, _ := f.acc.Authenticate(g.Token)
	inSession := "_in_session id=" + id.Session.ID

	far := Client{Addr: "192.0.2.80:1"}
	for range freeFailures {
		f.acc.Login(ctx, "nobody", wrong, far)
	}
	if _, err := f.acc.Confirm(ctx, id, goodPassword, far); !errors.As(err, new(*TooManyAttemptsError)) {
		t.Fatalf("a check in a session from an address under back-off = %v", err)
	}
	if evs := f.rec.withDetail("too_many_attempts" + inSession); len(evs) != 1 || evs[0].Resolved != alice.ID {
		t.Errorf("refused check recorded as %+v", evs)
	}

	f.acc.hasher = NewHasher(testParams, 1, 20*time.Millisecond)
	f.acc.hasher.slots <- struct{}{}
	if _, err := f.acc.Confirm(ctx, id, goodPassword, browser); !errors.Is(err, ErrBusy) {
		t.Fatalf("a check without a hashing slot = %v", err)
	}
	if evs := f.rec.withDetail("busy" + inSession); len(evs) != 1 {
		t.Errorf("busy check recorded as %+v", evs)
	}
	f.acc.hasher.release()

	err := f.db.Update(func(tx *state.Tx) error {
		u, err := tx.User(alice.ID)
		if err != nil {
			return err
		}
		u.PasswordDisabled = true
		return tx.UpdateUser(u)
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.acc.Login(ctx, "alice", goodPassword, Client{Addr: "192.0.2.81:1"}); !errors.Is(err, ErrPasswordDisabled) {
		t.Fatalf("login with a disabled password = %v", err)
	}
	if evs := f.rec.withDetail("password_disabled"); len(evs) != 1 || evs[0].Path != "alice" || evs[0].Resolved != alice.ID {
		t.Errorf("refusal recorded as %+v", evs)
	}
}

func TestLoginEventsNameTheAccountTheyAreFor(t *testing.T) {
	f := newFixture(t)
	alice := f.addUser(t, "alice", state.RoleAdmin)
	f.login(t, "alice", browser)
	f.acc.Login(ctx, "alice", wrong, browser)
	f.acc.Login(ctx, "nobody", wrong, browser)

	var got []string
	for _, ev := range f.rec.evs {
		if ev.Type == events.AuthLogin {
			got = append(got, fmt.Sprintf("%s/%s/%s", ev.Path, ev.Outcome, ev.Resolved))
		}
	}
	want := []string{"alice/ok/" + alice.ID, "alice/denied/" + alice.ID, "nobody/denied/"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("login events = %v, want %v", got, want)
	}
}
