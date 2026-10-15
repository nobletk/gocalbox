package auth

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/fsops"
	"github.com/nobletk/gocalbox/internal/state"
)

var (
	ErrLinkInvalid  = errors.New("the link is unknown, used, expired or revoked")
	ErrTooManyLinks = errors.New("too many unused links")
	ErrUserDisabled = errors.New("the account is disabled")
	ErrNoSuchLink   = errors.New("no such unused link")
	ErrNoSuchUser   = errors.New("no such user")
	ErrInvalidRole  = errors.New("invalid role")
	ErrInvalidNote  = errors.New("invalid note")
)

type LinkConfig struct {
	InviteTTL time.Duration
	ResetTTL  time.Duration
}

var DefaultLinks = LinkConfig{InviteTTL: 7 * 24 * time.Hour, ResetTTL: 24 * time.Hour}

const (
	// maxUnusedLinks bounds the links the console didn't make; the check for
	// a username an invite fixes reads them all.
	maxUnusedLinks = 100
	maxNoteRunes   = 100
	adminInviteTTL = 24 * time.Hour
	consoleLinkTTL = time.Hour
)

// Why a link was revoked, as its record names it.
const (
	revokedByAdmin   = "admin"
	revokedPassword  = "password_changed"
	revokedResetUsed = "reset_used"
	revokedSignOut   = "signed_out_elsewhere"
	revokedNewReset  = "new_reset_link"
	revokedDisabled  = "user_disabled"
	revokedDeleted   = "user_deleted"
	revokedDemoted   = "creator_demoted"
	revokedRestart   = "server_start"
)

// NewLink is a link just made. Token is its only copy.
type NewLink struct {
	ID       string
	Kind     state.LinkKind
	Token    string
	Role     state.Role // an invite's
	Username string     // the name an invite fixes, or the account of a reset link
	Expires  time.Time
}

// LinkInfo describes an unused link, without its token.
type LinkInfo struct {
	ID            string         `json:"id"`
	Kind          state.LinkKind `json:"kind"`
	Role          state.Role     `json:"role,omitempty"`
	Username      string         `json:"username,omitempty"`
	User          string         `json:"user,omitempty"`
	Note          string         `json:"note,omitempty"`
	CreatedBy     string         `json:"createdBy"`
	CreatedByName string         `json:"createdByName,omitempty"`
	Created       time.Time      `json:"created"`
	Expires       time.Time      `json:"expires"`
}

type InviteRequest struct {
	Role     state.Role
	Username string // optional; the invited person can't change it
	Note     string
}

type InviteInfo struct {
	Role     state.Role `json:"role"`
	Username string     `json:"username"`
	Expires  time.Time  `json:"expires"`
}

type ResetInfo struct {
	Username string    `json:"username"`
	Expires  time.Time `json:"expires"`
}

func linkKey(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// revoked is a revoked link with the reason its record names, and the name
// an invite fixes or the account of a reset link. The account's name is read
// in the transaction, since the change may delete the account.
type revoked struct {
	link   state.Link
	name   string
	reason string
}

func revokedOf(tx *state.Tx, l state.Link, reason string) (revoked, error) {
	r := revoked{link: l, name: l.Username, reason: reason}
	if l.Kind == state.KindReset {
		u, err := tx.User(l.User)
		if err != nil && !errors.Is(err, state.ErrNotFound) {
			return r, err
		}
		r.name = u.Username
	}
	return r, nil
}

func revokeWhere(tx *state.Tx, now time.Time, reason string, match func(state.Link) bool) ([]revoked, error) {
	var keys [][]byte
	var out []revoked
	err := tx.Links(func(key []byte, l state.Link) error {
		if l.ID == "" || !l.Unused(now) || !match(l) {
			return nil
		}
		r, err := revokedOf(tx, l, reason)
		keys, out = append(keys, key), append(out, r)
		return err
	})
	if err != nil {
		return nil, err
	}
	for _, k := range keys {
		if err := tx.DeleteLink(k); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// securing selects what recovering a compromised account revokes: the
// links its owner made, and every reset link for it.
func securing(userID string) func(state.Link) bool {
	return func(l state.Link) bool {
		return l.CreatedBy == userID || l.Kind == state.KindReset && l.User == userID
	}
}

func resetFor(userID string) func(state.Link) bool {
	return func(l state.Link) bool { return l.Kind == state.KindReset && l.User == userID }
}

func revokedLinks(rs []revoked) []RevokedLink {
	out := make([]RevokedLink, 0, len(rs))
	for _, r := range rs {
		out = append(out, RevokedLink{ID: r.link.ID, Kind: string(r.link.Kind), Role: string(r.link.Role), Username: r.name, Note: r.link.Note})
	}
	return out
}

func revokedEvents(rs []revoked) []events.Event {
	out := make([]events.Event, 0, len(rs))
	for _, r := range rs {
		out = append(out, events.Event{
			Type: events.LinkRevoked, Path: r.name,
			Detail: fmt.Sprintf("id=%s kind=%s reason=%s", r.link.ID, r.link.Kind, r.reason),
		})
	}
	return out
}

// fixedByInvite reports whether an unused invite other than skipID fixes
// name, which reserves it.
func fixedByInvite(tx *state.Tx, now time.Time, name, skipID string) (bool, error) {
	fixed := false
	err := tx.Links(func(_ []byte, l state.Link) error {
		if l.Kind == state.KindInvite && l.ID != skipID && l.Username == name && l.Unused(now) {
			fixed = true
		}
		return nil
	})
	return fixed, err
}

func nameFree(tx *state.Tx, now time.Time, name, skipID string) error {
	switch _, err := tx.UserByName(name); {
	case err == nil:
		return ErrUsernameTaken
	case !errors.Is(err, state.ErrNotFound):
		return err
	}
	fixed, err := fixedByInvite(tx, now, name, skipID)
	if err == nil && fixed {
		err = ErrUsernameTaken
	}
	return err
}

func roomForLink(tx *state.Tx, now time.Time) error {
	n := 0
	err := tx.Links(func(_ []byte, l state.Link) error {
		if l.Unused(now) && l.CreatedBy != events.ConsoleID {
			n++
		}
		return nil
	})
	if err == nil && n >= maxUnusedLinks {
		err = ErrTooManyLinks
	}
	return err
}

func checkNote(note string) error {
	if utf8.RuneCountInString(note) > maxNoteRunes || !utf8.ValidString(note) {
		return ErrInvalidNote
	}
	for _, r := range note {
		if unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) {
			return ErrInvalidNote
		}
	}
	return nil
}

// stillAdmin checks in the transaction that the request's account is still
// an enabled admin and that its session hasn't ended meanwhile. Securing an
// account ends its other sessions, so a request one of them still had under
// way must not commit after that.
func stillAdmin(tx *state.Tx, id Identity) error {
	u, err := tx.User(id.User.ID)
	if errors.Is(err, state.ErrNotFound) || err == nil && (u.Disabled || u.Role != state.RoleAdmin) {
		return ErrNotAdmin
	}
	if err != nil {
		return err
	}
	s, err := tx.SessionByID(id.Session.ID)
	if errors.Is(err, state.ErrNotFound) || err == nil && (s.User != u.ID || s.Epoch != u.Epoch) {
		return ErrSessionEnded
	}
	return err
}

// refused records an admin change refused before anything was done, by the
// audit guard, the admin check, the reauth window or an ended session, and
// returns err. Refusals of anonymous requests, setup and the accepts, aren't
// recorded: anyone could fill the log with them while changes are paused.
func (a *Accounts) refused(ctx context.Context, ev events.Event, err error) error {
	if events.IsUnrecorded(err) || !errors.Is(err, events.ErrChangesPaused) && !errors.Is(err, ErrNotAdmin) &&
		!errors.Is(err, ErrReauthRequired) && !errors.Is(err, ErrSessionEnded) {
		return err
	}
	ev.Outcome = events.OutcomeDenied
	ev.Detail = strings.TrimPrefix(ev.Detail+": "+err.Error(), ": ")
	a.publish(ctx, ev)
	return err
}

// CreateInvite makes an invite link. An admin invite lasts at most a day,
// since whoever holds it becomes an admin.
func (a *Accounts) CreateInvite(ctx context.Context, id Identity, req InviteRequest) (NewLink, error) {
	refusal := events.Event{Type: events.InviteCreated, Path: truncateUTF8(req.Username, 64), Detail: "role=" + truncateUTF8(string(req.Role), 32)}
	if err := a.asAdmin(id, true); err != nil {
		return NewLink{}, a.refused(ctx, refusal, err)
	}
	if err := a.allow(); err != nil {
		return NewLink{}, a.refused(ctx, refusal, err)
	}
	if !req.Role.Valid() {
		return NewLink{}, ErrInvalidRole
	}
	var name string
	if req.Username != "" {
		var err error
		if name, err = NormalizeUsername(req.Username); err != nil {
			return NewLink{}, err
		}
	}
	if err := checkNote(req.Note); err != nil {
		return NewLink{}, err
	}
	now := a.wallNow()
	ttl := a.linkCfg.InviteTTL
	if req.Role == state.RoleAdmin {
		ttl = min(ttl, adminInviteTTL)
	}
	token := rand.Text()
	l := state.Link{
		ID: state.NewID(), Kind: state.KindInvite, Role: req.Role, Username: name, Note: req.Note,
		CreatedBy: id.User.ID, Created: now, Expires: now.Add(ttl),
	}
	err := a.update(func(tx *state.Tx) error {
		if err := stillAdmin(tx, id); err != nil {
			return err
		}
		if err := roomForLink(tx, now); err != nil {
			return err
		}
		if name != "" {
			if err := nameFree(tx, now, name, ""); err != nil {
				return err
			}
		}
		return tx.PutLink(linkKey(token), l)
	})
	if err != nil {
		return NewLink{}, a.refused(ctx, refusal, err)
	}
	detail := fmt.Sprintf("id=%s role=%s", l.ID, l.Role)
	if name != "" {
		detail += " username=" + name
	}
	nl := NewLink{ID: l.ID, Kind: l.Kind, Token: token, Role: l.Role, Username: name, Expires: l.Expires}
	return nl, a.record(ctx, false, events.Event{Type: events.InviteCreated, Path: name, Detail: detail})
}

// CreateResetLink makes a reset link for a user, revoking the user's older
// unused ones. The old password keeps working until the link is used.
func (a *Accounts) CreateResetLink(ctx context.Context, id Identity, userID string) (NewLink, error) {
	refusal := events.Event{Type: events.ResetCreated, Path: a.users()[userID].Username, Resolved: a.users()[userID].ID}
	if err := a.asAdmin(id, true); err != nil {
		return NewLink{}, a.refused(ctx, refusal, err)
	}
	if err := a.allow(); err != nil {
		return NewLink{}, a.refused(ctx, refusal, err)
	}
	l, err := a.createReset(ctx, &id, userID, "", a.linkCfg.ResetTTL)
	if err != nil {
		return NewLink{}, a.refused(ctx, refusal, err)
	}
	return l, nil
}

// ConsoleResetLink makes the reset link -recover-admin prints for an
// enabled admin. It lasts an hour at most and the next start deletes it.
func (a *Accounts) ConsoleResetLink(ctx context.Context, username string) (NewLink, error) {
	name, err := NormalizeUsername(username)
	if err != nil {
		return NewLink{}, fmt.Errorf("%w named %q", ErrNoSuchUser, username)
	}
	return a.createReset(events.WithActor(ctx, events.Actor{ID: events.ConsoleID}), nil, "", name,
		min(consoleLinkTTL, a.linkCfg.ResetTTL))
}

// createReset makes a reset link for the user with userID as the admin by,
// or for the admin named name as the console when by is nil.
func (a *Accounts) createReset(ctx context.Context, by *Identity, userID, name string, ttl time.Duration) (NewLink, error) {
	now := a.wallNow()
	token := rand.Text()
	creator := events.ConsoleID
	if by != nil {
		creator = by.User.ID
	}
	var target state.User
	var made state.Link
	var gone []revoked
	err := a.update(func(tx *state.Tx) error {
		var err error
		if by == nil {
			if target, err = tx.UserByName(name); errors.Is(err, state.ErrNotFound) {
				return fmt.Errorf("%w named %q", ErrNoSuchUser, name)
			}
			if err == nil && target.Role != state.RoleAdmin {
				return fmt.Errorf("%s is not an admin", name)
			}
		} else {
			if err := stillAdmin(tx, *by); err != nil {
				return err
			}
			if target, err = tx.User(userID); errors.Is(err, state.ErrNotFound) {
				return ErrNoSuchUser
			}
		}
		if err != nil {
			return err
		}
		if target.Disabled {
			return ErrUserDisabled
		}
		if gone, err = revokeWhere(tx, now, revokedNewReset, resetFor(target.ID)); err != nil {
			return err
		}
		if by != nil {
			if err := roomForLink(tx, now); err != nil {
				return err
			}
		}
		made = state.Link{
			ID: state.NewID(), Kind: state.KindReset, User: target.ID,
			CreatedBy: creator, Created: now, Expires: now.Add(ttl),
		}
		return tx.PutLink(linkKey(token), made)
	})
	if err != nil {
		return NewLink{}, err
	}
	nl := NewLink{ID: made.ID, Kind: state.KindReset, Token: token, Username: target.Username, Expires: made.Expires}
	evs := append([]events.Event{{
		Type: events.ResetCreated, Path: target.Username, Detail: fmt.Sprintf("id=%s user=%s", made.ID, target.ID),
	}}, revokedEvents(gone)...)
	return nl, a.record(ctx, false, evs...)
}

// RevokeLink deletes an unused link. Revoking only takes access away, so
// the audit policy never refuses it.
func (a *Accounts) RevokeLink(ctx context.Context, id Identity, linkID string) error {
	refusal := events.Event{Type: events.LinkRevoked, Detail: "id=" + truncateUTF8(linkID, 32)}
	if err := a.asAdmin(id, true); err != nil {
		return a.refused(ctx, refusal, err)
	}
	now := a.wallNow()
	var r revoked
	err := a.update(func(tx *state.Tx) error {
		if err := stillAdmin(tx, id); err != nil {
			return err
		}
		key, link, err := tx.LinkByID(linkID)
		if errors.Is(err, state.ErrNotFound) || err == nil && !link.Unused(now) {
			return ErrNoSuchLink
		}
		if err != nil {
			return err
		}
		if r, err = revokedOf(tx, link, revokedByAdmin); err != nil {
			return err
		}
		return tx.DeleteLink(key)
	})
	if err != nil {
		return a.refused(ctx, refusal, err)
	}
	return a.record(ctx, true, revokedEvents([]revoked{r})...)
}

// Links lists the unused links, the console's included, oldest first.
func (a *Accounts) Links(id Identity) ([]LinkInfo, error) {
	if err := a.asAdmin(id, false); err != nil {
		return nil, err
	}
	now := a.wallNow()
	users := a.users()
	out := []LinkInfo{}
	err := a.db.View(func(tx *state.Tx) error {
		return tx.Links(func(_ []byte, l state.Link) error {
			if l.ID == "" || !l.Unused(now) {
				return nil
			}
			info := LinkInfo{
				ID: l.ID, Kind: l.Kind, Role: l.Role, Username: l.Username, User: l.User, Note: l.Note,
				CreatedBy: l.CreatedBy, CreatedByName: nameOf(users, l.CreatedBy), Created: l.Created, Expires: l.Expires,
			}
			if l.Kind == state.KindReset {
				info.Username = users[l.User].Username
			}
			out = append(out, info)
			return nil
		})
	})
	slices.SortFunc(out, func(x, y LinkInfo) int { return x.Created.Compare(y.Created) })
	return out, err
}

// nameOf names the account with id, an actor name such as "console", or a
// deleted user.
func nameOf(users map[string]state.User, id string) string {
	if u, ok := users[id]; ok {
		return u.Username
	}
	if id == events.ConsoleID || id == events.SystemID {
		return id
	}
	return fsops.DeletedUser
}

// dropOldLinks deletes used and expired links, and at start-up every link
// the console made, since the console prints its links anew at each start.
func (a *Accounts) dropOldLinks(ctx context.Context, start bool) error {
	now := a.wallNow()
	var gone []revoked
	err := a.update(func(tx *state.Tx) error {
		var keys [][]byte
		err := tx.Links(func(key []byte, l state.Link) error {
			switch {
			case l.ID == "" || !l.Unused(now):
				keys = append(keys, key)
			case start && l.CreatedBy == events.ConsoleID:
				r, err := revokedOf(tx, l, revokedRestart)
				if err != nil {
					return err
				}
				keys, gone = append(keys, key), append(gone, r)
			}
			return nil
		})
		if err != nil {
			return err
		}
		for _, k := range keys {
			if err := tx.DeleteLink(k); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil || len(gone) == 0 {
		return err
	}
	return a.record(events.WithActor(ctx, events.Actor{ID: events.SystemID}), true, revokedEvents(gone)...)
}

// findLink looks a token up for inspect and accept, under the address's
// back-off for codes and tokens. Every bad token gets the same answer.
func (a *Accounts) findLink(token string, kind state.LinkKind, c Client) ([]byte, state.Link, state.User, error) {
	addr := a.throttle.group(c.Addr)
	if wait := a.throttle.wait(codeKey(addr)); wait > 0 {
		return nil, state.Link{}, state.User{}, &TooManyAttemptsError{RetryAfter: wait}
	}
	key := linkKey(token)
	var l state.Link
	var u state.User
	err := a.db.View(func(tx *state.Tx) error {
		var err error
		if l, err = tx.Link(key); err != nil {
			return orNotFound(err, ErrLinkInvalid)
		}
		u, err = validLink(tx, l, kind, a.wallNow())
		return err
	})
	if errors.Is(err, ErrLinkInvalid) {
		a.throttle.fail(codeKey(addr))
	}
	return key, l, u, err
}

// validLink checks a link at accept or inspect, and for a reset link
// returns its account, which must be enabled, and an admin for the
// console's link.
func validLink(tx *state.Tx, l state.Link, kind state.LinkKind, now time.Time) (state.User, error) {
	if l.Kind != kind || !l.Unused(now) {
		return state.User{}, ErrLinkInvalid
	}
	if kind != state.KindReset {
		return state.User{}, nil
	}
	u, err := tx.User(l.User)
	if err != nil {
		return u, orNotFound(err, ErrLinkInvalid)
	}
	if u.Disabled || l.CreatedBy == events.ConsoleID && u.Role != state.RoleAdmin {
		return u, ErrLinkInvalid
	}
	return u, nil
}

func orNotFound(err, notFound error) error {
	if errors.Is(err, state.ErrNotFound) {
		return notFound
	}
	return err
}

// InspectInvite tells the invite page the role and any fixed username.
// Unlike an accept, it doesn't reset the address's counter, so one valid
// link can't clear it between guesses at others.
func (a *Accounts) InspectInvite(token string, c Client) (InviteInfo, error) {
	_, l, _, err := a.findLink(token, state.KindInvite, c)
	if err != nil {
		return InviteInfo{}, err
	}
	return InviteInfo{Role: l.Role, Username: l.Username, Expires: l.Expires}, nil
}

func (a *Accounts) InspectReset(token string, c Client) (ResetInfo, error) {
	_, l, u, err := a.findLink(token, state.KindReset, c)
	if err != nil {
		return ResetInfo{}, err
	}
	return ResetInfo{Username: u.Username, Expires: l.Expires}, nil
}

// AcceptInvite creates the invited account and logs it in. Bad tokens and
// bad input are refused before the password is hashed; the home, the
// account, the link's use and the session then take effect together or not
// at all. With an error for which events.IsUnrecorded holds, the account
// was created and the grant is valid.
func (a *Accounts) AcceptInvite(ctx context.Context, token, username, password string, c Client) (Grant, error) {
	if err := a.allow(); err != nil {
		return Grant{}, err
	}
	key, l, _, err := a.findLink(token, state.KindInvite, c)
	if err != nil {
		return Grant{}, err
	}
	name := l.Username
	if username != "" || name == "" {
		typed, err := NormalizeUsername(username)
		if err != nil {
			return Grant{}, err
		}
		if name != "" && typed != name {
			return Grant{}, ErrInvalidUsername
		}
		name = typed
	}
	now := a.wallNow()
	if err := a.db.View(func(tx *state.Tx) error { return nameFree(tx, now, name, l.ID) }); err != nil {
		return Grant{}, err
	}
	if err := a.policy.Check(name, password); err != nil {
		return Grant{}, err
	}
	hash, err := a.hasher.Hash(ctx, password)
	if err != nil {
		return Grant{}, err
	}

	user := state.User{
		ID: state.NewUserID(), Username: name, Role: l.Role, Hash: hash,
		CreatedAt: now, CreatedBy: l.CreatedBy, Invite: l.ID, PasswordChangedAt: now,
	}
	ctx = asUser(ctx, user)
	home := HomeOf(name)
	var grant Grant
	var e *sessionEntry
	var ended []endedSession
	commit := func() error {
		if err := a.allow(); err != nil {
			return err
		}
		var err error
		grant, e, ended, err = a.startSession(user, c, false, func(tx *state.Tx) error {
			cur, err := tx.Link(key)
			if err != nil {
				return orNotFound(err, ErrLinkInvalid)
			}
			if _, err := validLink(tx, cur, state.KindInvite, now); err != nil {
				return err
			}
			if err := nameFree(tx, now, name, cur.ID); err != nil {
				return err
			}
			if user.Role.HasHome() {
				bindings, err := tx.Bindings()
				if err != nil {
					return err
				}
				if slices.ContainsFunc(bindings, func(b state.Binding) bool { return b.Folder == home }) {
					return ErrHomeExists
				}
				if err := tx.PutBinding(homeBinding(user, now)); err != nil {
					return err
				}
			}
			if err := tx.CreateUser(user); err != nil {
				return err
			}
			cur.Used = now
			return tx.PutLink(key, cur)
		})
		return err
	}
	var unrecorded error
	if user.Role.HasHome() {
		err = a.folders.Provision(ctx, []fsops.Folder{
			{Path: usersFolder, Detail: "layout", IfExists: fsops.Reuse},
			{Path: home, Detail: "home", IfExists: fsops.TakeOverEmpty},
		}, commit)
		if events.IsUnrecorded(err) {
			unrecorded, err = err, nil
		}
		err = folderError(err, home)
	} else {
		err = commit()
	}
	if err != nil {
		return Grant{}, err
	}
	a.throttle.reset(codeKey(a.throttle.group(c.Addr)))
	ctx = withSession(ctx, e)
	evs := append([]events.Event{{
		Type: events.InviteUsed, Path: name, Resolved: user.ID, Detail: fmt.Sprintf("id=%s role=%s", l.ID, l.Role),
	}}, a.endedEvents(ended)...)
	return grant, cmp.Or(unrecorded, a.record(ctx, false, evs...))
}

// AcceptReset sets a new password through a reset link and logs the
// account in. The new epoch ends every other session of the account, and
// the links of the account's recovery are revoked with it. With an error
// for which events.IsUnrecorded holds, the password was changed and the
// grant is valid.
func (a *Accounts) AcceptReset(ctx context.Context, token, password string, c Client) (Grant, []RevokedLink, error) {
	if err := a.allow(); err != nil {
		return Grant{}, nil, err
	}
	key, _, u, err := a.findLink(token, state.KindReset, c)
	if err != nil {
		return Grant{}, nil, err
	}
	if err := a.policy.Check(u.Username, password); err != nil {
		return Grant{}, nil, err
	}
	hash, err := a.hasher.Hash(ctx, password)
	if err != nil {
		return Grant{}, nil, err
	}
	now := a.wallNow()
	changed := u
	changed.Hash, changed.Epoch, changed.PasswordChangedAt = hash, u.Epoch+1, now
	changed.Failures, changed.PasswordDisabled = 0, false
	ctx = asUser(ctx, u)
	var used state.Link
	var gone []revoked
	grant, e, ended, err := a.startSession(changed, c, true, func(tx *state.Tx) error {
		if err := a.allow(); err != nil {
			return err
		}
		cur, err := tx.Link(key)
		if err != nil {
			return orNotFound(err, ErrLinkInvalid)
		}
		acct, err := validLink(tx, cur, state.KindReset, now)
		if err != nil {
			return err
		}
		if acct.ID != u.ID || acct.Epoch != u.Epoch {
			return ErrLinkInvalid
		}
		acct.Hash, acct.Epoch, acct.PasswordChangedAt = changed.Hash, changed.Epoch, changed.PasswordChangedAt
		acct.Failures, acct.PasswordDisabled = 0, false
		if err := tx.UpdateUser(acct); err != nil {
			return err
		}
		a.throttle.resetAccount(u.ID)
		cur.Used = now
		if err := tx.PutLink(key, cur); err != nil {
			return err
		}
		used = cur
		gone, err = revokeWhere(tx, now, revokedResetUsed, securing(u.ID))
		return err
	})
	if err != nil {
		return Grant{}, nil, err
	}
	a.throttle.reset(codeKey(a.throttle.group(c.Addr)))
	ctx = withSession(ctx, e)
	evs := append([]events.Event{{
		Type: events.ResetUsed, Path: u.Username, Resolved: u.ID, Detail: "id=" + used.ID,
	}}, revokedEvents(gone)...)
	evs = append(evs, a.endedEvents(ended)...)
	return grant, revokedLinks(gone), a.record(ctx, false, evs...)
}

func withSession(ctx context.Context, e *sessionEntry) context.Context {
	actor := events.ActorFrom(ctx)
	actor.Session = e.rec.ID
	return events.WithActor(ctx, actor)
}
