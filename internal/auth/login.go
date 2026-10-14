package auth

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/state"
)

var (
	ErrInvalidCredentials = errors.New("wrong username or password")
	ErrAccountDisabled    = errors.New("the account is disabled")
	ErrPasswordDisabled   = errors.New("the password was disabled after too many failed attempts; a reset link restores it")

	// ErrTooManyWrongPasswords is the answer that ends a session: the
	// browser's cookie can be cleared, unlike for ErrSessionEnded alone.
	ErrTooManyWrongPasswords = fmt.Errorf("five wrong passwords in a row: %w", ErrSessionEnded)
)

// TooManyAttemptsError refuses an attempt without checking it. RetryAfter is
// zero when only the account's next successful login lifts the refusal.
type TooManyAttemptsError struct {
	RetryAfter time.Duration
}

func (e *TooManyAttemptsError) Error() string {
	if e.RetryAfter == 0 {
		return "too many failed attempts for this account from browsers it has not logged in from"
	}
	return fmt.Sprintf("too many failed attempts; try again in %s", e.RetryAfter.Round(time.Second))
}

const maxLoginName = 64

// loginName is the form of a typed username the throttle counts under, and
// whether it can name an account. An invalid name is counted too, so
// guessing at names that cannot exist is throttled alike.
func loginName(s string) (string, bool) {
	if name, err := NormalizeUsername(s); err == nil {
		return name, true
	}
	return truncateUTF8(asciiLower(s), maxLoginName), false
}

// Login checks a username and password and starts a session. The throttle
// is checked before any hashing; an unknown username is checked against a
// dummy hash, so its answer and timing match a wrong password's.
func (a *Accounts) Login(ctx context.Context, username, password string, c Client) (Grant, error) {
	start := time.Now()
	name, valid := loginName(username)
	var u state.User
	known := false
	if valid {
		var err error
		if u, known, err = a.userByName(name); err != nil {
			return Grant{}, err
		}
	}
	acct := account{key: name}
	if known {
		acct = accountOf(u)
	}
	trusted := known && a.trustedDevice(c.Device, u)
	at, err := a.admit(name, c.Addr, acct, !trusted)
	if errors.Is(err, ErrPasswordDisabled) {
		a.publishLogin(ctx, name, events.OutcomeDenied, "password_disabled")
	}
	if err != nil {
		return Grant{}, err
	}

	ok, rehash := false, false
	if len(password) <= MaxPasswordBytes {
		hash := a.dummyHash
		if known {
			hash = u.Hash
		}
		if ok, rehash, err = a.hasher.Verify(ctx, hash, password); err != nil {
			a.giveBack(at)
			return Grant{}, err
		}
	}
	if !ok || !known {
		a.recordFailure(ctx, name, u, at, "invalid_credentials")
		a.waitFailure(ctx, start, at.n)
		return Grant{}, ErrInvalidCredentials
	}
	if u.Disabled {
		a.giveBack(at)
		a.publishLogin(ctx, name, events.OutcomeDenied, "account_disabled")
		return Grant{}, ErrAccountDisabled
	}
	update, err := a.afterRightPassword(ctx, u, password, rehash, at)
	if err != nil {
		a.giveBack(at)
		return Grant{}, err
	}
	grant, e, ended, err := a.startSession(u, c, update)
	if err != nil {
		a.giveBack(at)
		return Grant{}, err
	}
	actor := events.ActorFrom(asUser(ctx, u))
	actor.Session = e.rec.ID
	ctx = events.WithActor(ctx, actor)
	a.publish(ctx, events.Event{Type: events.AuthLogin, Path: name})
	a.publishEnded(ctx, ended)
	return grant, nil
}

func accountOf(u state.User) account {
	return account{key: u.ID, known: true, stored: u.Failures, disabled: u.PasswordDisabled}
}

func (a *Accounts) userByName(name string) (state.User, bool, error) {
	var u state.User
	err := a.db.View(func(tx *state.Tx) error {
		var err error
		u, err = tx.UserByName(name)
		return err
	})
	if errors.Is(err, state.ErrNotFound) {
		return state.User{}, false, nil
	}
	return u, err == nil, err
}

// attempt is a password check that the throttle has counted.
type attempt struct {
	addr, pair string
	acct       account
	got        admitted
	n          int // the account's count with this attempt
}

func (a *Accounts) admit(name, remoteAddr string, acct account, untrusted bool) (attempt, error) {
	addr := a.throttle.group(remoteAddr)
	at := attempt{addr: addressKey(addr), pair: pairKey(name, addr), acct: acct}
	var err error
	at.n, at.got, err = a.throttle.admit(at.addr, at.pair, acct, untrusted)
	return at, err
}

// giveBack undoes the count of an attempt whose password was never checked,
// or whose right password changed nothing.
func (a *Accounts) giveBack(at attempt) { a.throttle.giveBack(at.addr, at.pair, at.acct, at.got) }

// afterRightPassword returns the change a right password makes, to run in
// the transaction that starts or renews the session: the stored failure
// count goes back to 0, a hash with weaker parameters than the current ones
// is replaced, and the throttle's counters are reset. Resetting them inside
// the transaction keeps a failure recorded at the same moment from writing
// its count back afterwards.
func (a *Accounts) afterRightPassword(ctx context.Context, u state.User, password string, rehash bool, at attempt) (func(*state.Tx) error, error) {
	var newHash string
	if rehash {
		var err error
		if newHash, err = a.hasher.Hash(ctx, password); err != nil {
			return nil, err
		}
	}
	return func(tx *state.Tx) error {
		cur, err := tx.User(u.ID)
		if err != nil {
			return err
		}
		a.throttle.succeed(at.addr, at.pair, at.acct)
		replace := newHash != "" && cur.Hash == u.Hash
		if cur.Failures == 0 && !replace {
			return nil
		}
		cur.Failures = 0
		if replace {
			cur.Hash = newHash
		}
		return tx.UpdateUser(cur)
	}, nil
}

// recordFailure records the nth consecutive failure of an account, which
// admit counted already. The count is written at every tenth failure; at
// disableAt the password is disabled. Nothing is written once a success or a
// new password has reset the count since the attempt was admitted.
func (a *Accounts) recordFailure(ctx context.Context, name string, u state.User, at attempt, detail string) {
	a.publishLogin(ctx, name, events.OutcomeDenied, detail)
	if !at.acct.known || at.n%10 != 0 {
		return
	}
	disable := at.n >= disableAt
	disabledNow := false
	err := a.update(func(tx *state.Tx) error {
		if !a.throttle.current(at.acct, at.got[2]) {
			return nil
		}
		cur, err := tx.User(u.ID)
		if err != nil {
			return err
		}
		if cur.Failures >= at.n && cur.PasswordDisabled == disable {
			return nil
		}
		disabledNow = disable && !cur.PasswordDisabled
		cur.Failures = max(cur.Failures, at.n)
		cur.PasswordDisabled = cur.PasswordDisabled || disable
		return tx.UpdateUser(cur)
	})
	if err != nil {
		log.Printf("accounts: cannot record the failed logins of %s: %v", name, err)
	} else if disabledNow {
		a.publish(ctx, events.Event{Type: events.AuthPasswordDisabled, Path: name, Detail: fmt.Sprintf("failures=%d", at.n)})
	}
}

// waitFailure holds the answer to a failed attempt until start plus a delay
// that grows with n, which also hides the time of recordFailure's write.
func (a *Accounts) waitFailure(ctx context.Context, start time.Time, n int) {
	t := time.NewTimer(time.Until(start.Add(a.failureDelay(n))))
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

func (a *Accounts) publishLogin(ctx context.Context, name string, outcome events.Outcome, detail string) {
	a.publish(ctx, events.Event{Type: events.AuthLogin, Outcome: outcome, Path: name, Detail: detail})
}

type checkOutcome int

const (
	checkSkipped checkOutcome = iota
	checkRight
	checkWrong
)

// startCheck counts a password check of a session before it runs, so that
// checks arriving together cannot get past freeFailures between them.
func (a *Accounts) startCheck(id Identity) (*sessionEntry, error) {
	a.sessions.mu.Lock()
	defer a.sessions.mu.Unlock()
	e, ok := a.sessions.byKey[id.key]
	if !ok {
		return nil, ErrSessionEnded
	}
	if e.failures+e.checking >= freeFailures {
		return nil, &TooManyAttemptsError{RetryAfter: firstBackoff}
	}
	e.checking++
	return e, nil
}

// finishCheck records how a check that startCheck counted ended. It reports
// whether the session is still the one checked, and whether this wrong
// password is the one that ends it.
func (a *Accounts) finishCheck(id Identity, e *sessionEntry, outcome checkOutcome) (alive, ends bool) {
	a.sessions.mu.Lock()
	defer a.sessions.mu.Unlock()
	e.checking--
	alive = a.sessions.byKey[id.key] == e
	switch {
	case !alive:
	case outcome == checkRight:
		e.failures = 0
	case outcome == checkWrong:
		e.failures++
		ends = e.failures == freeFailures
	}
	return alive, ends
}

// checkSessionPassword checks the password of a logged-in user under the
// same counters as a login. A session is always heard, under the address's
// back-off, but the fifth wrong password in a row ends it. It returns the
// counted attempt, which the caller resets with afterRightPassword or gives
// back, and whether the stored hash should be replaced.
func (a *Accounts) checkSessionPassword(ctx context.Context, id Identity, password string, c Client) (state.User, attempt, bool, error) {
	start := time.Now()
	name := id.User.Username
	u, known, err := a.userByName(name)
	if err != nil {
		return state.User{}, attempt{}, false, err
	}
	if !known || u.ID != id.User.ID {
		return state.User{}, attempt{}, false, ErrSessionEnded
	}
	e, err := a.startCheck(id)
	if err != nil {
		return state.User{}, attempt{}, false, err
	}
	at, err := a.admit(name, c.Addr, accountOf(u), false)
	if err != nil {
		a.finishCheck(id, e, checkSkipped)
		return state.User{}, attempt{}, false, err
	}
	ok, rehash := false, false
	if len(password) <= MaxPasswordBytes {
		if ok, rehash, err = a.hasher.Verify(ctx, u.Hash, password); err != nil {
			a.giveBack(at)
			a.finishCheck(id, e, checkSkipped)
			return state.User{}, attempt{}, false, err
		}
	}
	outcome := checkWrong
	if ok {
		outcome = checkRight
	}
	alive, ends := a.finishCheck(id, e, outcome)
	switch {
	case ok && alive:
		return u, at, rehash, nil
	case ok:
		// The session ended while its password was checked. The answer then
		// comes when a wrong password's would, so it tells nothing.
		a.giveBack(at)
		a.waitFailure(ctx, start, at.n)
		return state.User{}, attempt{}, false, ErrSessionEnded
	}
	a.recordFailure(ctx, name, u, at, "wrong_password_in_session id="+id.Session.ID)
	if ends {
		if _, err := a.endWhere(func(s state.Session) bool { return s.ID == id.Session.ID }); err != nil {
			return state.User{}, attempt{}, false, err
		}
		a.publishEnded(ctx, []endedSession{{id.Session, "wrong_passwords"}})
	}
	a.waitFailure(ctx, start, at.n)
	switch {
	case ends:
		return state.User{}, attempt{}, false, ErrTooManyWrongPasswords
	case !alive:
		return state.User{}, attempt{}, false, ErrSessionEnded
	}
	return state.User{}, attempt{}, false, ErrInvalidCredentials
}

// Confirm checks the password of a logged-in user, which opens the window
// for admin changes, and renews the session's token.
func (a *Accounts) Confirm(ctx context.Context, id Identity, password string, c Client) (Grant, error) {
	u, at, rehash, err := a.checkSessionPassword(ctx, id, password, c)
	if err != nil {
		return Grant{}, err
	}
	update, err := a.afterRightPassword(ctx, u, password, rehash, at)
	if err != nil {
		a.giveBack(at)
		return Grant{}, err
	}
	g, err := a.renew(id, u, false, update)
	if err != nil {
		a.giveBack(at)
	}
	return g, err
}

// ChangePassword replaces the password of a logged-in user after checking
// the current one. The higher epoch ends every other session of the account
// and invalidates the device cookies of other browsers; this session gets a
// new token. The returned list names the links revoked with the sessions;
// it is empty while the server has no links.
func (a *Accounts) ChangePassword(ctx context.Context, id Identity, current, next string, c Client) (Grant, []RevokedLink, error) {
	if err := a.policy.Check(id.User.Username, next); err != nil {
		return Grant{}, nil, err
	}
	u, at, _, err := a.checkSessionPassword(ctx, id, current, c)
	if err != nil {
		return Grant{}, nil, err
	}
	hash, err := a.hasher.Hash(ctx, next)
	if err != nil {
		a.giveBack(at)
		return Grant{}, nil, err
	}
	changed := u
	changed.Hash, changed.Epoch, changed.PasswordChangedAt = hash, u.Epoch+1, a.wallNow()
	changed.Failures, changed.PasswordDisabled = 0, false
	grant, err := a.renew(id, changed, true, func(tx *state.Tx) error {
		cur, err := tx.User(u.ID)
		if err != nil {
			return err
		}
		if cur.Epoch != u.Epoch {
			return ErrSessionEnded
		}
		a.throttle.succeed(at.addr, at.pair, at.acct)
		cur.Hash, cur.Epoch, cur.PasswordChangedAt = changed.Hash, changed.Epoch, changed.PasswordChangedAt
		cur.Failures, cur.PasswordDisabled = 0, false
		return tx.UpdateUser(cur)
	})
	if err != nil {
		a.giveBack(at)
		return Grant{}, nil, err
	}
	a.publish(ctx, events.Event{Type: events.AuthPasswordChanged, Path: u.Username, Detail: "id=" + u.ID})
	return grant, []RevokedLink{}, nil
}
