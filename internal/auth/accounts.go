package auth

import (
	"context"
	"errors"
	"fmt"
	"log"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/fsops"
	"github.com/nobletk/gocalbox/internal/state"
)

const (
	usersFolder  = "users"
	publicFolder = "public"
)

var (
	ErrSetupDone        = errors.New("setup is already complete")
	ErrSetupCodeInvalid = errors.New("wrong setup code")
	ErrHomeExists       = errors.New("a folder with the home's name already exists")
)

// LayoutExistsError names the folders setup would have shared or used for
// homes that existed before it; setup changes nothing unless asked to use
// them.
type LayoutExistsError struct {
	Paths []string
}

func (e *LayoutExistsError) Error() string {
	return "these folders already exist: " + strings.Join(e.Paths, ", ")
}

type Folders interface {
	Provision(ctx context.Context, folders []fsops.Folder, commit func() error) error
}

type Publisher interface {
	Publish(events.Event)
}

type Config struct {
	DB      *state.DB
	Hasher  *Hasher
	Policy  Policy
	Folders Folders // nil where no folders are created, as in the users command
	Events  Publisher
	Now     func() time.Time
}

type Accounts struct {
	db      *state.DB
	hasher  *Hasher
	policy  Policy
	folders Folders
	events  Publisher
	now     func() time.Time

	mu    sync.Mutex // serializes setup and layout changes
	setup atomic.Pointer[SetupCode]
}

func New(c Config) *Accounts {
	now := c.Now
	if now == nil {
		now = time.Now
	}
	return &Accounts{db: c.DB, hasher: c.Hasher, policy: c.Policy, folders: c.Folders, events: c.Events, now: now}
}

type Me struct {
	ID       string      `json:"id"`
	Username string      `json:"username"`
	Role     state.Role  `json:"role"`
	Home     string      `json:"home,omitempty"`
	Bindings []MeBinding `json:"bindings"`
}

type MeBinding struct {
	Folder string     `json:"folder"`
	Role   state.Role `json:"role"`
}

type SetupRequest struct {
	Code        string
	Username    string
	Password    string
	UseExisting bool
}

// StartSetup enters setup mode when no enabled admin exists and returns the
// new setup code, to be shown once on the console; otherwise it returns "".
func (a *Accounts) StartSetup() (string, error) {
	var hasAdmin bool
	err := a.db.View(func(tx *state.Tx) error {
		var err error
		hasAdmin, err = tx.HasEnabledAdmin()
		return err
	})
	if err != nil || hasAdmin {
		return "", err
	}
	code, check := NewSetupCode()
	a.setup.Store(check)
	return code, nil
}

func (a *Accounts) SetupRequired() bool { return a.setup.Load() != nil }

// CompleteSetup creates the first admin, the folder layout and its bindings.
// The code is checked before anything else, so a wrong one costs no hashing.
// A request that fails leaves the code valid.
func (a *Accounts) CompleteSetup(ctx context.Context, req SetupRequest) (Me, error) {
	code := a.setup.Load()
	if code == nil {
		return Me{}, ErrSetupDone
	}
	if !code.Matches(req.Code) {
		return Me{}, ErrSetupCodeInvalid
	}
	name, err := NormalizeUsername(req.Username)
	if err != nil {
		return Me{}, err
	}
	if err := a.policy.Check(name, req.Password); err != nil {
		return Me{}, err
	}
	hash, err := a.hasher.Hash(ctx, req.Password)
	if err != nil {
		return Me{}, err
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.setup.Load() != code {
		return Me{}, ErrSetupDone
	}
	now := a.now().UTC()
	user := state.User{
		ID: state.NewUserID(), Username: name, Role: state.RoleAdmin, Hash: hash,
		CreatedAt: now, CreatedBy: events.ConsoleID, PasswordChangedAt: now,
	}
	home := HomeOf(name)
	layout := fsops.Refuse
	if req.UseExisting {
		layout = fsops.Reuse
	}
	ctx = asUser(ctx, user)
	err = a.folders.Provision(ctx, []fsops.Folder{
		{Path: usersFolder, Detail: "layout", IfExists: layout},
		{Path: home, Detail: "home", IfExists: fsops.TakeOverEmpty},
		{Path: publicFolder, Detail: "layout", IfExists: layout},
	}, func() error {
		return a.db.Update(func(tx *state.Tx) error {
			if ok, err := tx.HasEnabledAdmin(); err != nil || ok {
				return orElse(err, ErrSetupDone)
			}
			bindings, err := tx.Bindings()
			if err != nil {
				return err
			}
			if slices.ContainsFunc(bindings, func(b state.Binding) bool { return b.Folder == home }) {
				return ErrHomeExists
			}
			if err := tx.CreateUser(user); err != nil {
				return err
			}
			if err := tx.PutBinding(homeBinding(user, now)); err != nil {
				return err
			}
			if slices.ContainsFunc(bindings, func(b state.Binding) bool { return b.Kind == state.KindPublic }) {
				return nil
			}
			return tx.PutBinding(publicBinding(user.ID, now))
		})
	})
	if err != nil {
		return Me{}, folderError(err, home)
	}
	a.setup.Store(nil)
	a.publish(ctx, events.Event{Type: events.AuthSetupCompleted, Path: name, Detail: "id=" + user.ID})

	for _, w := range a.ensureLayout(events.WithActor(ctx, events.Actor{ID: events.SystemID})) {
		log.Printf("WARNING: %s", w)
	}
	return a.Me(user.ID)
}

func orElse(err, otherwise error) error {
	if err != nil {
		return err
	}
	return otherwise
}

func folderError(err error, home string) error {
	var ce *fsops.ConflictError
	if !errors.As(err, &ce) {
		return err
	}
	var layout []string
	for _, p := range ce.Paths {
		if p != home {
			layout = append(layout, p)
		}
	}
	if len(layout) > 0 {
		return &LayoutExistsError{Paths: layout}
	}
	return ErrHomeExists
}

// EnsureLayout creates what users added from the console lack: their homes,
// and the shared /public folder once an admin exists. It never shares a
// folder that existed before; it returns a warning for each one it left.
func (a *Accounts) EnsureLayout(ctx context.Context) []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.ensureLayout(events.WithActor(ctx, events.Actor{ID: events.SystemID}))
}

func (a *Accounts) ensureLayout(ctx context.Context) []string {
	var users []state.User
	var bindings []state.Binding
	err := a.db.View(func(tx *state.Tx) error {
		var err error
		if users, err = tx.Users(); err != nil {
			return err
		}
		bindings, err = tx.Bindings()
		return err
	})
	if err != nil {
		return []string{fmt.Sprintf("cannot read the accounts to create missing homes: %v", err)}
	}
	var warnings []string
	now := a.now().UTC()

	hasAdmin := slices.ContainsFunc(users, func(u state.User) bool { return u.Role == state.RoleAdmin && !u.Disabled })
	if i := slices.IndexFunc(bindings, func(b state.Binding) bool { return b.Kind == state.KindPublic }); i >= 0 {
		if err := a.folders.Provision(ctx, []fsops.Folder{{Path: bindings[i].Folder, Detail: "layout", IfExists: fsops.Reuse}}, nil); err != nil {
			warnings = append(warnings, fmt.Sprintf("cannot recreate /%s: %v", bindings[i].Folder, err))
		}
	} else if hasAdmin {
		err := a.folders.Provision(ctx, []fsops.Folder{{Path: publicFolder, Detail: "layout", IfExists: fsops.Refuse}}, func() error {
			return a.db.Update(func(tx *state.Tx) error { return tx.PutBinding(publicBinding(events.SystemID, now)) })
		})
		var ce *fsops.ConflictError
		switch {
		case errors.As(err, &ce):
			warnings = append(warnings, "the folder /public existed before any account and is not shared; it stays admin-only. "+
				"Move it aside and restart to have an empty /public created and shared with every user")
		case err != nil:
			warnings = append(warnings, fmt.Sprintf("cannot create /public: %v", err))
		}
	}

	for _, u := range users {
		if !u.Role.HasHome() {
			continue
		}
		i := slices.IndexFunc(bindings, func(b state.Binding) bool { return b.Kind == state.KindHome && b.Subject == u.ID })
		var err error
		if i >= 0 {
			err = a.folders.Provision(ctx, []fsops.Folder{
				{Path: usersFolder, Detail: "layout", IfExists: fsops.Reuse},
				{Path: bindings[i].Folder, Detail: "home", IfExists: fsops.Reuse},
			}, nil)
		} else {
			home := HomeOf(u.Username)
			err = a.folders.Provision(ctx, []fsops.Folder{
				{Path: usersFolder, Detail: "layout", IfExists: fsops.Reuse},
				{Path: home, Detail: "home", IfExists: fsops.TakeOverEmpty},
			}, func() error {
				return a.db.Update(func(tx *state.Tx) error {
					current, err := tx.Bindings()
					if err != nil {
						return err
					}
					if slices.ContainsFunc(current, func(b state.Binding) bool { return b.Folder == home }) {
						return ErrHomeExists
					}
					return tx.PutBinding(homeBinding(u, now))
				})
			})
		}
		var ce *fsops.ConflictError
		switch {
		case errors.As(err, &ce):
			warnings = append(warnings, fmt.Sprintf("%s has no home folder: %s is in the way (a file, a link, or a folder that is not empty); "+
				"move it aside and restart", u.Username, strings.Join(ce.Paths, ", ")))
		case err != nil:
			warnings = append(warnings, fmt.Sprintf("%s has no home folder: %v", u.Username, err))
		}
	}
	return warnings
}

// CreateUser adds an account; it is for the users command, which runs while
// the server is stopped. The server creates the home at its next start.
func (a *Accounts) CreateUser(ctx context.Context, username string, role state.Role, password string) (state.User, error) {
	name, err := NormalizeUsername(username)
	if err != nil {
		return state.User{}, err
	}
	if !role.Valid() {
		return state.User{}, fmt.Errorf("invalid role %q: use admin, contributor or viewer", role)
	}
	if err := a.policy.Check(name, password); err != nil {
		return state.User{}, err
	}
	hash, err := a.hasher.Hash(ctx, password)
	if err != nil {
		return state.User{}, err
	}
	now := a.now().UTC()
	u := state.User{
		ID: state.NewUserID(), Username: name, Role: role, Hash: hash,
		CreatedAt: now, CreatedBy: events.ActorFrom(ctx).ID, PasswordChangedAt: now,
	}
	if err := a.db.Update(func(tx *state.Tx) error { return tx.CreateUser(u) }); err != nil {
		return state.User{}, err
	}
	a.publish(ctx, events.Event{Type: events.UserCreated, Path: name, Detail: fmt.Sprintf("id=%s role=%s", u.ID, role)})
	return u, nil
}

// SetPassword replaces a user's password. The higher epoch ends every
// session of the account, and a password disabled by failed attempts works
// again.
func (a *Accounts) SetPassword(ctx context.Context, username, password string) (state.User, error) {
	var u state.User
	err := a.db.View(func(tx *state.Tx) error {
		var err error
		u, err = tx.UserByName(username)
		return err
	})
	if err != nil {
		return u, err
	}
	if err := a.policy.Check(u.Username, password); err != nil {
		return u, err
	}
	hash, err := a.hasher.Hash(ctx, password)
	if err != nil {
		return u, err
	}
	err = a.db.Update(func(tx *state.Tx) error {
		current, err := tx.User(u.ID)
		if err != nil {
			return err
		}
		u = current
		u.Hash, u.Epoch, u.PasswordChangedAt = hash, u.Epoch+1, a.now().UTC()
		u.Failures, u.PasswordDisabled = 0, false
		return tx.UpdateUser(u)
	})
	if err != nil {
		return u, err
	}
	a.publish(ctx, events.Event{Type: events.AuthPasswordChanged, Path: u.Username, Detail: "id=" + u.ID})
	return u, nil
}

func (a *Accounts) Me(id string) (Me, error) {
	var me Me
	err := a.db.View(func(tx *state.Tx) error {
		u, err := tx.User(id)
		if err != nil {
			return err
		}
		bindings, err := tx.Bindings()
		if err != nil {
			return err
		}
		me = Me{ID: u.ID, Username: u.Username, Role: u.Role, Bindings: []MeBinding{}}
		for _, b := range bindings {
			if b.Subject != u.ID && b.Subject != state.Everyone {
				continue
			}
			me.Bindings = append(me.Bindings, MeBinding{Folder: b.Folder, Role: b.Role})
			if b.Kind == state.KindHome {
				me.Home = b.Folder
			}
		}
		slices.SortFunc(me.Bindings, func(x, y MeBinding) int { return strings.Compare(x.Folder, y.Folder) })
		return nil
	})
	return me, err
}

func homeBinding(u state.User, now time.Time) state.Binding {
	return state.Binding{
		ID: state.NewID(), Subject: u.ID, Folder: HomeOf(u.Username), Role: state.RoleContributor,
		Kind: state.KindHome, CreatedBy: events.SystemID, CreatedAt: now,
	}
}

func publicBinding(createdBy string, now time.Time) state.Binding {
	return state.Binding{
		ID: state.NewID(), Subject: state.Everyone, Folder: publicFolder, Role: state.RoleContributor,
		Kind: state.KindPublic, CreatedBy: createdBy, CreatedAt: now,
	}
}

func asUser(ctx context.Context, u state.User) context.Context {
	actor := events.ActorFrom(ctx)
	actor.ID, actor.Name, actor.Role = u.ID, u.Username, string(u.Role)
	return events.WithActor(ctx, actor)
}

func (a *Accounts) publish(ctx context.Context, ev events.Event) {
	if a.events == nil {
		return
	}
	ev.Actor = events.ActorFrom(ctx)
	ev.RequestID = events.RequestIDFrom(ctx)
	ev.Outcome = events.OutcomeOK
	a.events.Publish(ev)
}
