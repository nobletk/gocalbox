package auth

import (
	"cmp"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"slices"
	"strings"
	"time"

	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/fsops"
	"github.com/nobletk/gocalbox/internal/state"
)

var (
	ErrNotAdmin       = errors.New("only admins may do this")
	ErrReauthRequired = errors.New("enter the password again to change users and folder access")
	ErrLastAdmin      = errors.New("the last enabled admin can't be deleted, disabled or demoted")
	ErrNoSuchBinding  = errors.New("no such binding")
	ErrHomeBinding    = errors.New("a home's binding goes only with its user")
	ErrCoversHomes    = errors.New("a binding may not cover /users or a home")
	ErrBindingExists  = errors.New("the user already has a binding on this folder")
)

// deletedFolder holds the homes of deleted users. No binding covers it, so
// only admins can reach it.
const deletedFolder = usersFolder + "/.deleted"

// asAdmin checks that the request's account is an enabled admin now and,
// for a change, that its password was entered within the reauth window.
func (a *Accounts) asAdmin(id Identity, change bool) error {
	u, ok := a.users()[id.User.ID]
	if !ok || u.Disabled || u.Role != state.RoleAdmin {
		return ErrNotAdmin
	}
	if change && !a.wallNow().Before(id.Session.AuthTime.Add(a.sessionCfg.Reauth)) {
		return ErrReauthRequired
	}
	return nil
}

type UserInfo struct {
	ID                string     `json:"id"`
	Username          string     `json:"username"`
	Role              state.Role `json:"role"`
	Disabled          bool       `json:"disabled"`
	PasswordDisabled  bool       `json:"passwordDisabled"`
	Home              string     `json:"home,omitempty"`
	CreatedAt         time.Time  `json:"createdAt"`
	CreatedBy         string     `json:"createdBy"`
	CreatedByName     string     `json:"createdByName,omitempty"`
	Invite            string     `json:"invite,omitempty"`
	PasswordChangedAt time.Time  `json:"passwordChangedAt"`
}

func userInfo(u state.User, users map[string]state.User, bindings []state.Binding) UserInfo {
	info := UserInfo{
		ID: u.ID, Username: u.Username, Role: u.Role, Disabled: u.Disabled, PasswordDisabled: u.PasswordDisabled,
		CreatedAt: u.CreatedAt, CreatedBy: u.CreatedBy, CreatedByName: nameOf(users, u.CreatedBy),
		Invite: u.Invite, PasswordChangedAt: u.PasswordChangedAt,
	}
	if b, ok := homeBindingOf(bindings, u.ID); ok {
		info.Home = b.Folder
	}
	return info
}

func homeBindingOf(bindings []state.Binding, userID string) (state.Binding, bool) {
	i := slices.IndexFunc(bindings, func(b state.Binding) bool { return b.Kind == state.KindHome && b.Subject == userID })
	if i < 0 {
		return state.Binding{}, false
	}
	return bindings[i], true
}

// Users lists every account, without password hashes, by username.
func (a *Accounts) Users(id Identity) ([]UserInfo, error) {
	if err := a.asAdmin(id, false); err != nil {
		return nil, err
	}
	var out []UserInfo
	err := a.db.View(func(tx *state.Tx) error {
		list, err := tx.Users()
		if err != nil {
			return err
		}
		bindings, err := tx.Bindings()
		if err != nil {
			return err
		}
		users := make(map[string]state.User, len(list))
		for _, u := range list {
			users[u.ID] = u
		}
		out = make([]UserInfo, 0, len(list))
		for _, u := range list {
			out = append(out, userInfo(u, users, bindings))
		}
		return nil
	})
	return out, err
}

func enabledAdmins(users []state.User, skipID string) int {
	n := 0
	for _, u := range users {
		if u.ID != skipID && u.Role == state.RoleAdmin && !u.Disabled {
			n++
		}
	}
	return n
}

type UserUpdate struct {
	Role     *state.Role
	Disabled *bool
}

// userChange is an update or deletion made, with what it must record.
type userChange struct {
	evs        []events.Event
	protective bool
	unrecorded error // the record of a folder change that failed
}

// UpdateUser changes a user's role or disables or enables the account. A
// change takes effect on the user's next request. An update whose only
// change is disabling only takes access away, so the audit policy doesn't
// refuse it. With an error for which events.IsUnrecorded holds, the update
// was made.
func (a *Accounts) UpdateUser(ctx context.Context, id Identity, userID string, upd UserUpdate) (UserInfo, error) {
	refusal := a.userEvent(events.UserUpdated, userID)
	if upd.Role != nil {
		refusal.Detail += " role=" + truncateUTF8(string(*upd.Role), 32)
	}
	if upd.Disabled != nil {
		refusal.Detail += fmt.Sprintf(" disabled=%t", *upd.Disabled)
	}
	if err := a.asAdmin(id, true); err != nil {
		return UserInfo{}, a.refused(ctx, refusal, err)
	}
	if upd.Role != nil && !upd.Role.Valid() {
		return UserInfo{}, ErrInvalidRole
	}
	a.mu.Lock()
	after, c, err := a.updateUser(ctx, id, userID, upd)
	a.mu.Unlock()
	if err != nil {
		return UserInfo{}, a.refused(ctx, refusal, err)
	}
	if c.evs == nil {
		return a.userInfoOf(after), nil
	}
	return a.userInfoOf(after), cmp.Or(c.unrecorded, a.record(ctx, c.protective, c.evs...))
}

// updateUser makes the update while the caller holds a.mu. With nothing to
// change it returns the user and no events.
func (a *Accounts) updateUser(ctx context.Context, id Identity, userID string, upd UserUpdate) (state.User, userChange, error) {
	before, ok := a.users()[userID]
	if !ok {
		return state.User{}, userChange{}, ErrNoSuchUser
	}
	want := before
	if upd.Role != nil {
		want.Role = *upd.Role
	}
	if upd.Disabled != nil {
		want.Disabled = *upd.Disabled
	}
	if want.Role == before.Role && want.Disabled == before.Disabled {
		return before, userChange{}, nil
	}
	c := userChange{protective: want.Role == before.Role && want.Disabled}
	if !c.protective {
		if err := a.allow(); err != nil {
			return state.User{}, userChange{}, err
		}
	}

	now := a.wallNow()
	var after state.User
	var gone []revoked
	change := func() error {
		if !c.protective {
			if err := a.allow(); err != nil {
				return err
			}
		}
		return a.update(func(tx *state.Tx) error {
			if err := stillAdmin(tx, id); err != nil {
				return err
			}
			u, err := tx.User(userID)
			if err != nil {
				return orNotFound(err, ErrNoSuchUser)
			}
			u.Role, u.Disabled = want.Role, want.Disabled
			if before.Role == state.RoleAdmin && !before.Disabled && (u.Role != state.RoleAdmin || u.Disabled) {
				users, err := tx.Users()
				if err != nil {
					return err
				}
				if enabledAdmins(users, u.ID) == 0 {
					return ErrLastAdmin
				}
			}
			if u.Disabled && !before.Disabled {
				u.Epoch++
				r, err := revokeWhere(tx, now, revokedDisabled, func(l state.Link) bool {
					return l.CreatedBy == u.ID || resetFor(u.ID)(l)
				})
				if err != nil {
					return err
				}
				gone = append(gone, r...)
			}
			if before.Role == state.RoleAdmin && u.Role != state.RoleAdmin {
				r, err := revokeWhere(tx, now, revokedDemoted, func(l state.Link) bool {
					return l.CreatedBy == u.ID || l.CreatedBy == events.ConsoleID && resetFor(u.ID)(l)
				})
				if err != nil {
					return err
				}
				gone = append(gone, r...)
			}
			if u.Role.HasHome() && !before.Role.HasHome() {
				bindings, err := tx.Bindings()
				if err != nil {
					return err
				}
				if _, ok := homeBindingOf(bindings, u.ID); !ok {
					home := HomeOf(u.Username)
					if slices.ContainsFunc(bindings, func(b state.Binding) bool { return b.Folder == home }) {
						return ErrHomeExists
					}
					if err := tx.PutBinding(homeBinding(u, now)); err != nil {
						return err
					}
				}
			}
			after = u
			return tx.UpdateUser(u)
		})
	}

	var err error
	if want.Role.HasHome() && !before.Role.HasHome() {
		folder, ifExists := HomeOf(before.Username), fsops.TakeOverEmpty
		var bindings []state.Binding
		if err := a.db.View(func(tx *state.Tx) error {
			if err := stillAdmin(tx, id); err != nil {
				return err
			}
			var err error
			bindings, err = tx.Bindings()
			return err
		}); err != nil {
			return state.User{}, userChange{}, err
		}
		if b, ok := homeBindingOf(bindings, before.ID); ok {
			folder, ifExists = b.Folder, fsops.Reuse
		}
		err = a.folders.Provision(ctx, []fsops.Folder{
			{Path: usersFolder, Detail: "layout", IfExists: fsops.Reuse},
			{Path: folder, Detail: "home", IfExists: ifExists},
		}, change)
		if events.IsUnrecorded(err) {
			c.unrecorded, err = err, nil
		}
		err = folderError(err, folder)
	} else {
		err = change()
	}
	if err != nil {
		return state.User{}, userChange{}, err
	}
	var changed []string
	if after.Role != before.Role {
		changed = append(changed, fmt.Sprintf("role=%s->%s", before.Role, after.Role))
	}
	if after.Disabled != before.Disabled {
		changed = append(changed, fmt.Sprintf("disabled=%t", after.Disabled))
	}
	c.evs = append([]events.Event{{
		Type: events.UserUpdated, Path: after.Username, Resolved: after.ID,
		Detail: strings.Join(append([]string{"id=" + after.ID}, changed...), " "),
	}}, revokedEvents(gone)...)
	return after, c, nil
}

// userEvent is the event of a change to the user with userID, for its
// record if the change is refused.
func (a *Accounts) userEvent(typ events.Type, userID string) events.Event {
	u, ok := a.users()[userID]
	if !ok {
		return events.Event{Type: typ, Detail: "id=" + truncateUTF8(userID, 32)}
	}
	return events.Event{Type: typ, Path: u.Username, Resolved: u.ID, Detail: "id=" + u.ID}
}

func (a *Accounts) userInfoOf(u state.User) UserInfo {
	var bindings []state.Binding
	a.db.View(func(tx *state.Tx) error { var err error; bindings, err = tx.Bindings(); return err })
	return userInfo(u, a.users(), bindings)
}

// DeleteUser removes an account. Its home moves first to
// /users/.deleted/<username>-<YYYYMMDD>-<id>, where only admins reach it;
// then one transaction removes the user, their sessions, their bindings and
// their unused links, and if it fails the home moves back. Files they
// uploaded elsewhere keep a record naming a deleted user, so only admins
// can change them. It returns where the home went, if anywhere. With an
// error for which events.IsUnrecorded holds, the user was deleted.
func (a *Accounts) DeleteUser(ctx context.Context, id Identity, userID string) (string, error) {
	refusal := a.userEvent(events.UserDeleted, userID)
	if err := a.asAdmin(id, true); err != nil {
		return "", a.refused(ctx, refusal, err)
	}
	if err := a.allow(); err != nil {
		return "", a.refused(ctx, refusal, err)
	}
	a.mu.Lock()
	archived, c, err := a.deleteUser(ctx, id, userID)
	a.mu.Unlock()
	if err != nil {
		return "", a.refused(ctx, refusal, err)
	}
	return archived, cmp.Or(c.unrecorded, a.record(ctx, false, c.evs...))
}

// deleteUser makes the deletion while the caller holds a.mu.
func (a *Accounts) deleteUser(ctx context.Context, id Identity, userID string) (string, userChange, error) {
	var c userChange
	if err := a.allow(); err != nil {
		return "", c, err
	}
	u, ok := a.users()[userID]
	if !ok {
		return "", c, ErrNoSuchUser
	}
	var home state.Binding
	var users []state.User
	err := a.db.View(func(tx *state.Tx) error {
		if err := stillAdmin(tx, id); err != nil {
			return err
		}
		bindings, err := tx.Bindings()
		if err != nil {
			return err
		}
		home, _ = homeBindingOf(bindings, u.ID)
		users, err = tx.Users()
		return err
	})
	if err != nil {
		return "", c, err
	}
	if u.Role == state.RoleAdmin && !u.Disabled && enabledAdmins(users, u.ID) == 0 {
		return "", c, ErrLastAdmin
	}

	now := a.wallNow()
	var archived string
	if home.Folder != "" {
		err := a.folders.Provision(ctx, []fsops.Folder{
			{Path: usersFolder, Detail: "layout", IfExists: fsops.Reuse},
			{Path: deletedFolder, Detail: "layout", IfExists: fsops.Reuse},
		}, nil)
		if events.IsUnrecorded(err) {
			c.unrecorded, err = err, nil
		}
		if err != nil {
			return "", c, err
		}
		dest := fmt.Sprintf("%s/%s-%s-%s", deletedFolder, u.Username, now.Format("20060102"), u.ID)
		switch err := a.folders.MoveHome(ctx, home.Folder, dest, "home of deleted user "+u.Username); {
		case errors.Is(err, fsops.ErrNotFound):
		case events.IsUnrecorded(err):
			c.unrecorded, archived = cmp.Or(c.unrecorded, err), dest
		case err != nil:
			return "", c, fmt.Errorf("archive the home %s: %w", home.Folder, err)
		default:
			archived = dest
		}
	}

	var gone []revoked
	a.sessions.write.Lock()
	var keys [][sha256.Size]byte
	a.sessions.mu.Lock()
	for k, e := range a.sessions.byKey {
		if e.rec.User == u.ID {
			keys = append(keys, k)
		}
	}
	a.sessions.mu.Unlock()
	err = a.changeSessions(keys, nil, func(tx *state.Tx) error {
		if err := stillAdmin(tx, id); err != nil {
			return err
		}
		cur, err := tx.User(u.ID)
		if err != nil {
			return orNotFound(err, ErrNoSuchUser)
		}
		if cur.Role == state.RoleAdmin && !cur.Disabled {
			all, err := tx.Users()
			if err != nil {
				return err
			}
			if enabledAdmins(all, cur.ID) == 0 {
				return ErrLastAdmin
			}
		}
		bindings, err := tx.Bindings()
		if err != nil {
			return err
		}
		for _, b := range bindings {
			if b.Subject == cur.ID {
				if err := tx.DeleteBinding(b.ID); err != nil {
					return err
				}
			}
		}
		if gone, err = revokeWhere(tx, now, revokedDeleted, func(l state.Link) bool {
			return l.CreatedBy == cur.ID || resetFor(cur.ID)(l)
		}); err != nil {
			return err
		}
		return tx.DeleteUser(cur.ID)
	})
	a.sessions.write.Unlock()
	if err != nil {
		if archived != "" {
			if merr := a.folders.MoveHome(ctx, archived, home.Folder, "home restored: deleting the user failed"); merr != nil && !events.IsUnrecorded(merr) {
				log.Printf("accounts: deleting %s failed, and its home stays at %s: %v", u.Username, archived, merr)
			}
		}
		return "", userChange{}, err
	}
	detail := "id=" + u.ID
	if archived != "" {
		detail += " home=" + archived
	}
	c.evs = append([]events.Event{{Type: events.UserDeleted, Path: u.Username, Resolved: u.ID, Detail: detail}}, revokedEvents(gone)...)
	return archived, c, nil
}

type BindingInfo struct {
	ID            string            `json:"id"`
	Subject       string            `json:"subject"`
	SubjectName   string            `json:"subjectName,omitempty"`
	Folder        string            `json:"folder"`
	Role          state.Role        `json:"role"`
	Kind          state.BindingKind `json:"kind"`
	CreatedBy     string            `json:"createdBy,omitempty"`
	CreatedByName string            `json:"createdByName,omitempty"`
	CreatedAt     time.Time         `json:"createdAt"`
}

func bindingInfo(b state.Binding, users map[string]state.User) BindingInfo {
	info := BindingInfo{
		ID: b.ID, Subject: b.Subject, Folder: b.Folder, Role: b.Role, Kind: b.Kind,
		CreatedBy: b.CreatedBy, CreatedAt: b.CreatedAt,
	}
	if b.Subject != state.Everyone {
		info.SubjectName = nameOf(users, b.Subject)
	}
	if b.CreatedBy != "" {
		info.CreatedByName = nameOf(users, b.CreatedBy)
	}
	return info
}

// Bindings lists every binding by folder.
func (a *Accounts) Bindings(id Identity) ([]BindingInfo, error) {
	if err := a.asAdmin(id, false); err != nil {
		return nil, err
	}
	var list []state.Binding
	if err := a.db.View(func(tx *state.Tx) error { var err error; list, err = tx.Bindings(); return err }); err != nil {
		return nil, err
	}
	users := a.users()
	out := make([]BindingInfo, 0, len(list))
	for _, b := range list {
		out = append(out, bindingInfo(b, users))
	}
	slices.SortFunc(out, func(x, y BindingInfo) int {
		return cmp.Or(strings.Compare(x.Folder, y.Folder), strings.Compare(x.Subject, y.Subject))
	})
	return out, nil
}

// coversHomes reports whether a binding on folder would reach /users or a
// home: homes are never shared.
func coversHomes(folder string) bool {
	return folder == "." || folder == usersFolder || strings.HasPrefix(folder, usersFolder+"/")
}

// CreateBinding opens an existing folder to a user, or with subject "*" to
// every user, as viewer or contributor. The folder is named in the spelling
// the directory stores, read while it can't move.
func (a *Accounts) CreateBinding(ctx context.Context, id Identity, subject, folder string, role state.Role) (BindingInfo, error) {
	refusal := events.Event{Type: events.BindingCreated, Path: truncateUTF8(folder, 1024),
		Detail: fmt.Sprintf("subject=%s role=%s", truncateUTF8(subject, 32), truncateUTF8(string(role), 32))}
	if err := a.asAdmin(id, true); err != nil {
		return BindingInfo{}, a.refused(ctx, refusal, err)
	}
	if err := a.allow(); err != nil {
		return BindingInfo{}, a.refused(ctx, refusal, err)
	}
	if role != state.RoleViewer && role != state.RoleContributor {
		return BindingInfo{}, ErrInvalidRole
	}
	if _, ok := a.users()[subject]; !ok && subject != state.Everyone {
		return BindingInfo{}, ErrNoSuchUser
	}
	var b state.Binding
	err := a.folders.BindFolder(ctx, folder, func(stored string) error {
		if coversHomes(stored) {
			return ErrCoversHomes
		}
		if err := a.allow(); err != nil {
			return err
		}
		return a.update(func(tx *state.Tx) error {
			if err := stillAdmin(tx, id); err != nil {
				return err
			}
			if subject != state.Everyone {
				if _, err := tx.User(subject); err != nil {
					return orNotFound(err, ErrNoSuchUser)
				}
			}
			bindings, err := tx.Bindings()
			if err != nil {
				return err
			}
			if slices.ContainsFunc(bindings, func(x state.Binding) bool { return x.Subject == subject && x.Folder == stored }) {
				return ErrBindingExists
			}
			b = state.Binding{
				ID: state.NewID(), Subject: subject, Folder: stored, Role: role,
				Kind: state.KindCustom, CreatedBy: id.User.ID, CreatedAt: a.wallNow(),
			}
			return tx.PutBinding(b)
		})
	})
	if err != nil {
		return BindingInfo{}, a.refused(ctx, refusal, err)
	}
	info := bindingInfo(b, a.users())
	return info, a.record(ctx, false, events.Event{
		Type: events.BindingCreated, Path: b.Folder, Resolved: b.Folder,
		Detail: fmt.Sprintf("id=%s subject=%s role=%s", b.ID, b.Subject, b.Role),
	})
}

// DeleteBinding removes a custom or the public binding. A home's binding
// goes only with its user.
func (a *Accounts) DeleteBinding(ctx context.Context, id Identity, bindingID string) error {
	refusal := events.Event{Type: events.BindingDeleted, Detail: "id=" + truncateUTF8(bindingID, 32)}
	if err := a.asAdmin(id, true); err != nil {
		return a.refused(ctx, refusal, err)
	}
	if err := a.allow(); err != nil {
		return a.refused(ctx, refusal, err)
	}
	var b state.Binding
	err := a.update(func(tx *state.Tx) error {
		if err := stillAdmin(tx, id); err != nil {
			return err
		}
		var err error
		if b, err = tx.Binding(bindingID); err != nil {
			return orNotFound(err, ErrNoSuchBinding)
		}
		if b.Kind == state.KindHome {
			return ErrHomeBinding
		}
		return tx.DeleteBinding(b.ID)
	})
	if err != nil {
		return a.refused(ctx, refusal, err)
	}
	return a.record(ctx, false, events.Event{
		Type: events.BindingDeleted, Path: b.Folder, Resolved: b.Folder,
		Detail: fmt.Sprintf("id=%s subject=%s role=%s", b.ID, b.Subject, b.Role),
	})
}

type AdminSessionInfo struct {
	SessionInfo
	User     string `json:"user"`
	Username string `json:"username"`
}

// AllSessions lists the valid sessions of every user, or of one, the one
// seen most recently first.
func (a *Accounts) AllSessions(id Identity, userID string) ([]AdminSessionInfo, error) {
	if err := a.asAdmin(id, false); err != nil {
		return nil, err
	}
	now := a.wallNow()
	users := a.users()
	a.sessions.mu.Lock()
	out := []AdminSessionInfo{}
	for _, e := range a.sessions.byKey {
		if (userID == "" || e.rec.User == userID) && a.validIn(users, e.rec, now) {
			out = append(out, AdminSessionInfo{
				SessionInfo: SessionInfo{
					ID: e.rec.ID, Created: e.rec.Created, LastSeen: e.rec.LastSeen,
					Address: e.rec.IP, UserAgent: e.rec.UserAgent, Current: e.rec.ID == id.Session.ID,
				},
				User: e.rec.User, Username: users[e.rec.User].Username,
			})
		}
	}
	a.sessions.mu.Unlock()
	slices.SortFunc(out, func(x, y AdminSessionInfo) int { return y.LastSeen.Compare(x.LastSeen) })
	return out, nil
}

// EndSession ends any user's valid session. It only takes access away, so
// the audit policy doesn't refuse it.
func (a *Accounts) EndSession(ctx context.Context, id Identity, sessionID string) error {
	refusal := events.Event{Type: events.SessionRevoked, Detail: "id=" + truncateUTF8(sessionID, 32)}
	if err := a.asAdmin(id, true); err != nil {
		return a.refused(ctx, refusal, err)
	}
	now := a.wallNow()
	ended, err := a.endWhere(func(s state.Session) bool { return s.ID == sessionID && a.valid(s, now) },
		func(tx *state.Tx) error { return stillAdmin(tx, id) })
	if err != nil {
		return a.refused(ctx, refusal, err)
	}
	if len(ended) == 0 {
		return ErrNoSuchSession
	}
	return a.record(ctx, true, events.Event{
		Type: events.SessionRevoked, Path: a.users()[ended[0].User].Username, Detail: "id=" + sessionID + " reason=admin",
	})
}
