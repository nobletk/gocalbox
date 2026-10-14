package auth

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/state"
)

const wrong = "wrong password entirely"

func addr(i int) Client { return Client{Addr: fmt.Sprintf("198.51.%d.%d:4000", i/250, i%250+1)} }

func TestBackOffPerAddress(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "alice", state.RoleAdmin)
	c := Client{Addr: "192.0.2.50:1"}
	for i := 1; i <= 5; i++ {
		if _, err := f.acc.Login(ctx, "alice", wrong, c); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	var tm *TooManyAttemptsError
	if _, err := f.acc.Login(ctx, "alice", goodPassword, c); !errors.As(err, &tm) || tm.RetryAfter != time.Second {
		t.Fatalf("sixth attempt: %v", err)
	}
	if _, err := f.acc.Login(ctx, "nobody", goodPassword, c); !errors.As(err, &tm) {
		t.Errorf("another name from the same address: %v", err)
	}
	if _, err := f.acc.Login(ctx, "alice", goodPassword, Client{Addr: "192.0.2.51:1"}); err != nil {
		t.Errorf("another address: %v", err)
	}
	// A success from another address leaves this address's count as it was.
	f.clock.advance(time.Second)
	if _, err := f.acc.Login(ctx, "bob", wrong, c); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("after waiting: %v", err)
	}
	if _, err := f.acc.Login(ctx, "bob", wrong, c); !errors.As(err, &tm) || tm.RetryAfter != 2*time.Second {
		t.Errorf("the wait did not double: %v", err)
	}
	for range 20 {
		f.clock.advance(maxBackoff)
		f.acc.Login(ctx, "bob", wrong, c)
	}
	if _, err := f.acc.Login(ctx, "bob", wrong, c); !errors.As(err, &tm) || tm.RetryAfter != maxBackoff {
		t.Errorf("the wait exceeds 15 minutes: %v", err)
	}
}

func TestStrangersAreRefusedAfterFiftyFailures(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "alice", state.RoleAdmin)
	known := f.login(t, "alice", Client{Addr: "192.0.2.60:1"})
	for i := range untrustedLimit {
		if _, err := f.acc.Login(ctx, "alice", wrong, addr(i)); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d: %v", i+1, err)
		}
	}
	var tm *TooManyAttemptsError
	if _, err := f.acc.Login(ctx, "alice", goodPassword, addr(untrustedLimit)); !errors.As(err, &tm) || tm.RetryAfter != 0 {
		t.Fatalf("a stranger after 50 failures: %v", err)
	}
	if got := f.user(t, "alice").Failures; got != 50 {
		t.Errorf("stored failures %d", got)
	}
	trusted := Client{Addr: "192.0.2.61:1", Device: known.Device}
	if _, err := f.acc.Login(ctx, "alice", goodPassword, trusted); err != nil {
		t.Fatalf("the user's own browser was refused: %v", err)
	}
	if got := f.user(t, "alice").Failures; got != 0 {
		t.Errorf("stored failures after a success %d", got)
	}
	if _, err := f.acc.Login(ctx, "alice", goodPassword, addr(untrustedLimit+1)); err != nil {
		t.Errorf("a stranger after the user's success: %v", err)
	}
}

func TestUnknownNamesAreThrottledAlike(t *testing.T) {
	f := newFixture(t)
	for i := range untrustedLimit {
		f.acc.Login(ctx, "ghost", wrong, addr(i))
	}
	var tm *TooManyAttemptsError
	if _, err := f.acc.Login(ctx, "ghost", wrong, addr(untrustedLimit)); !errors.As(err, &tm) || tm.RetryAfter != 0 {
		t.Errorf("unknown name after 50 failures: %v", err)
	}
}

func TestPasswordIsDisabledAtOneHundredFailures(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "alice", state.RoleAdmin)
	device := f.login(t, "alice", Client{Addr: "192.0.2.70:1"}).Device
	for i := range disableAt {
		c := addr(i)
		if i >= untrustedLimit {
			c.Device = device
		}
		if _, err := f.acc.Login(ctx, "alice", wrong, c); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d: %v", i+1, err)
		}
	}
	u := f.user(t, "alice")
	if !u.PasswordDisabled || u.Failures != disableAt {
		t.Fatalf("after 100 failures: %+v", u)
	}
	if _, err := f.acc.Login(ctx, "alice", goodPassword, Client{Addr: "192.0.2.71:1", Device: device}); !errors.Is(err, ErrPasswordDisabled) {
		t.Errorf("right password after disabling: %v", err)
	}
	if n := slices.Index(f.rec.types(), events.AuthPasswordDisabled); n < 0 {
		t.Error("no auth.password_disabled event")
	}
	if _, err := f.acc.SetPassword(events.WithActor(ctx, events.Actor{ID: events.ConsoleID}), "alice", "a brand new passphrase"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.acc.Login(ctx, "alice", "a brand new passphrase", Client{Addr: "192.0.2.72:1"}); err != nil {
		t.Errorf("after a new password: %v", err)
	}
}

func TestFailureCountSurvivesARestart(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "alice", state.RoleAdmin)
	for i := range 13 {
		f.acc.Login(ctx, "alice", wrong, addr(i))
	}
	if got := f.user(t, "alice").Failures; got != 10 {
		t.Fatalf("stored after 13 failures: %d", got)
	}
	again := New(Config{DB: f.db, Hasher: NewHasher(testParams, 1, time.Second), Policy: Policy{MinLength: 15}, Now: f.clock.now,
		FailureDelay: func(int) time.Duration { return 0 }})
	if err := again.Start(); err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	for i := range 40 {
		if _, err := again.Login(ctx, "alice", wrong, addr(100+i)); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d after restart: %v", 11+i, err)
		}
	}
	var tm *TooManyAttemptsError
	if _, err := again.Login(ctx, "alice", wrong, addr(200)); !errors.As(err, &tm) {
		t.Errorf("the count started from 0 after the restart: %v", err)
	}
}

func TestSetupCodesHaveTheirOwnCounter(t *testing.T) {
	f := newFixture(t)
	code := f.startSetup(t)
	c := Client{Addr: "192.0.2.80:1"}
	for range 5 {
		if _, err := f.acc.CompleteSetup(ctx, SetupRequest{Code: "WRONG", Username: "alice", Password: goodPassword}, c); !errors.Is(err, ErrSetupCodeInvalid) {
			t.Fatal(err)
		}
	}
	var tm *TooManyAttemptsError
	if _, err := f.acc.CompleteSetup(ctx, SetupRequest{Code: code, Username: "alice", Password: goodPassword}, c); !errors.As(err, &tm) {
		t.Fatalf("sixth code: %v", err)
	}
	if _, err := f.acc.Login(ctx, "alice", goodPassword, c); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("logins from that address were blocked by wrong codes: %v", err)
	}
	f.clock.advance(time.Second)
	if _, err := f.acc.CompleteSetup(ctx, SetupRequest{Code: code, Username: "alice", Password: goodPassword}, c); err != nil {
		t.Errorf("after waiting: %v", err)
	}
}

func TestClientAddressGrouping(t *testing.T) {
	th := newThrottle(time.Now, func() []netip.Prefix { return []netip.Prefix{netip.MustParsePrefix("2001:db8:1:2::/64")} })
	for in, want := range map[string]string{
		"192.0.2.1:5000":           "192.0.2.1",
		"[::ffff:192.0.2.1]:5000":  "192.0.2.1",
		"[2001:db8:1:2::5]:1":      "2001:db8:1:2::5",
		"[2001:db8:9:9:1:2:3:4]:1": "2001:db8:9:9::/64",
		"[2001:db8:9:9:ffff::1]:1": "2001:db8:9:9::/64",
		"[fe80::1%eth0]:1":         "fe80::1",
		"[fd00:1:2:3::9]:1":        "fd00:1:2:3::9",
		"[::1]:1":                  "::1",
		"not an address":           "not an address",
	} {
		if got := th.group(in); got != want {
			t.Errorf("group(%s) = %s, want %s", in, got, want)
		}
	}
}

func TestDefaultFailureDelay(t *testing.T) {
	for n, want := range map[int]time.Duration{1: 100 * time.Millisecond, 10: time.Second, 50: 5 * time.Second, 100: 5 * time.Second} {
		if got := defaultFailureDelay(n); got != want {
			t.Errorf("delay(%d) = %v", n, got)
		}
	}
}

func TestThrottleKeepsTheMostRecentEntries(t *testing.T) {
	th := newThrottle(time.Now, nil)
	th.fail("first")
	for i := range throttleEntries {
		th.fail(fmt.Sprint(i))
	}
	if th.order.Len() != throttleEntries || th.peek("first") != nil || th.peek("0") == nil {
		t.Errorf("%d entries", th.order.Len())
	}
	th.wait("unseen")
	if _, _, err := th.admit("a", "p", account{key: "u-1", known: true, disabled: true}, false); err == nil || th.peek("a") != nil {
		t.Error("a refused attempt was counted")
	}
	if th.order.Len() != throttleEntries || len(th.accounts) != 0 {
		t.Error("checking a key added it")
	}
}

func TestAnAccountsCountCannotBePushedOut(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "alice", state.RoleAdmin)
	for i := range 45 {
		f.acc.Login(ctx, "alice", wrong, addr(i))
	}
	for i := range throttleEntries {
		f.acc.Login(ctx, fmt.Sprintf("ghost%d", i), wrong, addr(1000+i/5))
	}
	if f.acc.throttle.peek(addressKey("198.51.0.1")) != nil {
		t.Fatal("the flood did not fill the shared counters")
	}
	for i := range 5 {
		f.acc.Login(ctx, "alice", wrong, addr(100+i))
	}
	var tm *TooManyAttemptsError
	if _, err := f.acc.Login(ctx, "alice", goodPassword, addr(200)); !errors.As(err, &tm) {
		t.Errorf("a stranger after 50 failures and a flood: %v", err)
	}
}

func TestAttemptsArrivingTogetherShareOneLimit(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "alice", state.RoleAdmin)
	burst := func(clients func(int) Client) (checked, refused int) {
		var mu sync.Mutex
		var wg sync.WaitGroup
		for i := range 30 {
			wg.Go(func() {
				_, err := f.acc.Login(ctx, "alice", wrong, clients(i))
				mu.Lock()
				defer mu.Unlock()
				var tm *TooManyAttemptsError
				switch {
				case errors.Is(err, ErrInvalidCredentials):
					checked++
				case errors.As(err, &tm):
					refused++
				default:
					t.Errorf("attempt: %v", err)
				}
			})
		}
		wg.Wait()
		return checked, refused
	}
	if checked, refused := burst(func(int) Client { return Client{Addr: "192.0.2.90:1"} }); checked != freeFailures || refused != 30-freeFailures {
		t.Errorf("one address: %d checked, %d refused", checked, refused)
	}
	for i := range untrustedLimit - 1 - freeFailures {
		f.acc.Login(ctx, "alice", wrong, addr(i))
	}
	if checked, refused := burst(func(i int) Client { return addr(500 + i) }); checked != 1 || refused != 29 {
		t.Errorf("strangers at 49 failures: %d checked, %d refused", checked, refused)
	}
}

func TestIPv6ClientsOutsideOwnNetworksShareTheirSlash64(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "alice", state.RoleAdmin)
	for i := range freeFailures {
		f.acc.Login(ctx, "alice", wrong, Client{Addr: fmt.Sprintf("[2001:db8:9:9::%x]:1", i+1)})
		f.acc.Login(ctx, "alice", wrong, Client{Addr: fmt.Sprintf("[2001:db8:1:2::%x]:1", i+1)})
	}
	var tm *TooManyAttemptsError
	if _, err := f.acc.Login(ctx, "alice", goodPassword, Client{Addr: "[2001:db8:9:9:abcd::1]:1"}); !errors.As(err, &tm) {
		t.Errorf("another address of the same outside /64: %v", err)
	}
	if _, err := f.acc.Login(ctx, "alice", goodPassword, Client{Addr: "[2001:db8:1:2::99]:1"}); err != nil {
		t.Errorf("another device of the server's own network: %v", err)
	}
}

func TestLoginNamesAreNotFoldedByUnicode(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "kate", state.RoleViewer)
	if _, err := f.acc.Login(ctx, "\u212Aate", goodPassword, browser); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("Kelvin sign for k: %v", err)
	}
	if _, err := f.acc.Login(ctx, "KATE", goodPassword, browser); err != nil {
		t.Errorf("ASCII capitals: %v", err)
	}
}

func TestTheHundredthAttemptDecides(t *testing.T) {
	th := newThrottle(time.Now, nil)
	alice := account{key: "u-1", known: true, stored: disableAt - 1}
	n, got, err := th.admit("a1", "p1", alice, false)
	if err != nil || n != disableAt {
		t.Fatalf("hundredth attempt: %d, %v", n, err)
	}
	var tm *TooManyAttemptsError
	if _, _, err := th.admit("a2", "p2", alice, false); !errors.As(err, &tm) || tm.RetryAfter != firstBackoff {
		t.Errorf("while the hundredth is checked: %v", err)
	}
	th.giveBack("a1", "p1", alice, got)
	if n, _, err := th.admit("a2", "p2", alice, false); err != nil || n != disableAt {
		t.Errorf("after the hundredth was given back: %d, %v", n, err)
	}
	alice.disabled = true
	if _, _, err := th.admit("a3", "p3", alice, false); !errors.Is(err, ErrPasswordDisabled) {
		t.Errorf("stored as disabled: %v", err)
	}
}

func TestASuccessResetsTheStoredCountWrittenMeanwhile(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "alice", state.RoleAdmin)
	u := f.user(t, "alice")
	f.db.Update(func(tx *state.Tx) error {
		cur, _ := tx.User(u.ID)
		cur.Failures = 10
		return tx.UpdateUser(cur)
	})
	update, err := f.acc.afterRightPassword(ctx, u, goodPassword, false, attempt{acct: accountOf(u)})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.db.Update(update); err != nil {
		t.Fatal(err)
	}
	if got := f.user(t, "alice").Failures; got != 0 {
		t.Errorf("stored failures after the success: %d", got)
	}
}

func TestAFailureRecordedAfterASuccessWritesNothing(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "alice", state.RoleAdmin)
	for i := range 9 {
		f.acc.Login(ctx, "alice", wrong, addr(i))
	}
	u := f.user(t, "alice")
	at, err := f.acc.admit("alice", "192.0.2.80:1", accountOf(u), true)
	if err != nil || at.n != 10 {
		t.Fatalf("tenth attempt: %d, %v", at.n, err)
	}
	f.login(t, "alice", Client{Addr: "192.0.2.81:1"})
	f.acc.recordFailure(ctx, "alice", u, at, "invalid_credentials")
	if got := f.user(t, "alice").Failures; got != 0 {
		t.Errorf("stored failures: %d", got)
	}
	if _, err := f.acc.Login(ctx, "alice", wrong, Client{Addr: "192.0.2.82:1"}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatal(err)
	}
	f.acc.throttle.mu.Lock()
	n := f.acc.throttle.accounts[u.ID].failures
	f.acc.throttle.mu.Unlock()
	if n != 1 {
		t.Errorf("the next failure counted as %d", n)
	}
}

func TestASuccessLeavesTheAccountACountOfZero(t *testing.T) {
	th := newThrottle(time.Now, nil)
	alice := account{key: "u-1", known: true, stored: 10}
	if n, _, err := th.admit("a1", "p1", alice, false); err != nil || n != 11 {
		t.Fatalf("first attempt: %d, %v", n, err)
	}
	th.succeed("a1", "p1", alice)
	if n, _, err := th.admit("a2", "p2", alice, false); err != nil || n != 1 {
		t.Errorf("after a success, with the stored count not yet reset: %d, %v", n, err)
	}
	th.resetAccount("u-1")
	if n, _, err := th.admit("a3", "p3", alice, false); err != nil || n != 1 {
		t.Errorf("after a new password: %d, %v", n, err)
	}
}

func TestGivingBackSparesACounterThatReplacedTheAttempts(t *testing.T) {
	th := newThrottle(time.Now, nil)
	alice := account{key: "u-1", known: true}
	_, got, _ := th.admit("a1", "p1", alice, false)
	th.succeed("a1", "p1", alice)
	th.admit("a1", "p1", alice, false)
	th.giveBack("a1", "p1", alice, got)
	for _, c := range []*counter{th.peek("a1"), th.peek("p1"), th.accounts["u-1"]} {
		if c.failures != 1 {
			t.Errorf("counter %q: %d", c.key, c.failures)
		}
	}
}
