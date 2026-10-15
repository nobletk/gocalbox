package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log"
	"net"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/state"
)

const (
	SessionCookie = "__Host-gocalbox-session"
	DeviceCookie  = "__Host-gocalbox-device"

	maxSessionsPerUser = 20
	lastSeenEvery      = time.Minute
	cleanupEvery       = time.Hour
	userAgentBytes     = 200
)

type SessionConfig struct {
	Idle   time.Duration
	Max    time.Duration
	Reauth time.Duration // how long a password entry allows admin changes
}

var DefaultSessions = SessionConfig{Idle: 14 * 24 * time.Hour, Max: 30 * 24 * time.Hour, Reauth: 15 * time.Minute}

var (
	ErrSessionEnded  = errors.New("the session has ended")
	ErrNoSuchSession = errors.New("no such session")
)

// Client is what a request tells about who is asking.
type Client struct {
	Addr      string // the connection's remote address
	UserAgent string
	Device    string // the device cookie the browser sent, if any
	Token     string // the session cookie the browser sent, if any
}

// Identity is a valid session and its account, as read for one request.
type Identity struct {
	User    state.User
	Session state.Session
	key     [sha256.Size]byte
}

// Grant is a new or renewed session for the browser to keep. Token is the
// cookie's only copy; the server keeps its SHA-256.
type Grant struct {
	Me      Me
	Token   string
	Expires time.Time // the session's absolute limit
	Device  string    // a new device cookie
}

type SessionInfo struct {
	ID        string    `json:"id"`
	Created   time.Time `json:"created"`
	LastSeen  time.Time `json:"lastSeen"`
	Address   string    `json:"address"`
	UserAgent string    `json:"userAgent"`
	Current   bool      `json:"current"`
}

type sessionEntry struct {
	key      [sha256.Size]byte
	rec      state.Session
	written  time.Time // the lastSeen the state file holds
	failures int       // consecutive wrong passwords entered in this session
	checking int       // password checks of this session still running
}

// SessionState is what a session cookie names.
type SessionState int

const (
	NoSession    SessionState = iota // no session has this token
	EndedSession                     // a session that is no longer valid, deleted now
	ValidSession
)

// endedSession is a session ended as a side effect, for its audit record.
type endedSession struct {
	rec    state.Session
	reason string
}

type sessionStore struct {
	// write serializes every change and is held across its transaction, so
	// the maps and the state file never disagree; mu guards the maps alone.
	write sync.Mutex
	mu    sync.Mutex
	byKey map[[sha256.Size]byte]*sessionEntry
}

func newSessionStore() *sessionStore {
	return &sessionStore{byKey: map[[sha256.Size]byte]*sessionEntry{}}
}

func newToken() (string, [sha256.Size]byte) {
	var b [32]byte
	rand.Read(b[:])
	token := base64.RawURLEncoding.EncodeToString(b[:])
	return token, sha256.Sum256([]byte(token))
}

func (a *Accounts) wallNow() time.Time { return a.now().Round(0).UTC() }

// Start loads the sessions, dropping the ones no longer valid, and begins
// writing lastSeen once a minute and removing expired sessions once an hour.
func (a *Accounts) Start() error {
	err := a.db.View(func(tx *state.Tx) error {
		a.deviceKey = tx.DeviceKey()
		return nil
	})
	if err != nil {
		return err
	}
	if err := a.reload(); err != nil {
		return err
	}
	var stale [][]byte
	now := a.wallNow()
	a.sessions.mu.Lock()
	err = a.db.View(func(tx *state.Tx) error {
		return tx.Sessions(func(key []byte, s state.Session) error {
			if len(key) != sha256.Size || s.ID == "" || !a.valid(s, now) {
				stale = append(stale, key)
				return nil
			}
			e := &sessionEntry{key: [sha256.Size]byte(key), rec: s, written: s.LastSeen}
			a.sessions.byKey[e.key] = e
			return nil
		})
	})
	a.sessions.mu.Unlock()
	if err != nil {
		return err
	}
	if len(stale) > 0 {
		if err := a.db.Update(func(tx *state.Tx) error {
			for _, k := range stale {
				if err := tx.DeleteSession(k); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return err
		}
	}
	a.stop, a.stopped = make(chan struct{}), make(chan struct{})
	go a.maintain()
	return nil
}

// Close stops the background work and writes the last lastSeen times.
func (a *Accounts) Close() error {
	if a.stop == nil {
		return nil
	}
	close(a.stop)
	<-a.stopped
	a.stop = nil
	return a.writeLastSeen()
}

func (a *Accounts) maintain() {
	defer close(a.stopped)
	seen, cleanup := time.NewTicker(lastSeenEvery), time.NewTicker(cleanupEvery)
	defer seen.Stop()
	defer cleanup.Stop()
	for {
		select {
		case <-seen.C:
			if err := a.writeLastSeen(); err != nil {
				log.Printf("sessions: cannot record when sessions were last used: %v", err)
			}
		case <-cleanup.C:
			if err := a.dropExpired(); err != nil {
				log.Printf("sessions: cannot remove expired sessions: %v", err)
			}
		case <-a.stop:
			return
		}
	}
}

func (a *Accounts) valid(s state.Session, now time.Time) bool {
	return a.validIn(a.users(), s, now)
}

func (a *Accounts) validIn(users map[string]state.User, s state.Session, now time.Time) bool {
	u, ok := users[s.User]
	return ok && !u.Disabled && u.Epoch == s.Epoch &&
		now.Before(s.Created.Add(a.sessionCfg.Max)) && now.Before(s.LastSeen.Add(a.sessionCfg.Idle))
}

// Identify returns the session a cookie names. A session that is no longer
// valid is deleted and reported as EndedSession.
func (a *Accounts) Identify(token string) (Identity, SessionState) {
	if token == "" {
		return Identity{}, NoSession
	}
	key := sha256.Sum256([]byte(token))
	now := a.wallNow()
	a.sessions.mu.Lock()
	e, ok := a.sessions.byKey[key]
	if !ok {
		a.sessions.mu.Unlock()
		return Identity{}, NoSession
	}
	users := a.users()
	if !a.validIn(users, e.rec, now) {
		a.sessions.mu.Unlock()
		return Identity{}, a.endInvalid(key, e)
	}
	if now.After(e.rec.LastSeen) {
		e.rec.LastSeen = now
	}
	id := Identity{User: users[e.rec.User], Session: e.rec, key: key}
	a.sessions.mu.Unlock()
	return id, ValidSession
}

// endInvalid deletes a session that Identify found no longer valid. A
// password change makes the session it renews look invalid until the new
// token replaces the old one; holding sessions.write waits for that, and the
// old token then names no session rather than an ended one.
func (a *Accounts) endInvalid(key [sha256.Size]byte, e *sessionEntry) SessionState {
	a.sessions.write.Lock()
	defer a.sessions.write.Unlock()
	a.sessions.mu.Lock()
	still := a.sessions.byKey[key] == e
	a.sessions.mu.Unlock()
	if !still {
		return NoSession
	}
	if err := a.changeSessions([][sha256.Size]byte{key}, nil); err != nil {
		log.Printf("sessions: cannot delete an expired session: %v", err)
	}
	return EndedSession
}

// Authenticate reports whether a cookie names a valid session.
func (a *Accounts) Authenticate(token string) (Identity, bool) {
	id, s := a.Identify(token)
	return id, s == ValidSession
}

func (a *Accounts) writeLastSeen() error {
	a.sessions.write.Lock()
	defer a.sessions.write.Unlock()
	type pending struct {
		e   *sessionEntry
		rec state.Session
	}
	var due []pending
	a.sessions.mu.Lock()
	for _, e := range a.sessions.byKey {
		if e.rec.LastSeen.After(e.written) {
			due = append(due, pending{e, e.rec})
		}
	}
	a.sessions.mu.Unlock()
	if len(due) == 0 {
		return nil
	}
	err := a.db.Update(func(tx *state.Tx) error {
		for _, p := range due {
			if err := tx.PutSession(p.e.key[:], p.rec); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	a.sessions.mu.Lock()
	for _, p := range due {
		p.e.written = p.rec.LastSeen
	}
	a.sessions.mu.Unlock()
	return nil
}

func (a *Accounts) dropExpired() error {
	now := a.wallNow()
	var keys [][sha256.Size]byte
	a.sessions.mu.Lock()
	for k, e := range a.sessions.byKey {
		if !a.valid(e.rec, now) {
			keys = append(keys, k)
		}
	}
	a.sessions.mu.Unlock()
	return a.endSessions(keys...)
}

// endSessions deletes sessions from the state file, then from memory.
func (a *Accounts) endSessions(keys ...[sha256.Size]byte) error {
	if len(keys) == 0 {
		return nil
	}
	a.sessions.write.Lock()
	defer a.sessions.write.Unlock()
	return a.changeSessions(keys, nil)
}

// changeSessions deletes and adds sessions in one transaction, with also run
// in it, then applies the same to memory. The caller holds sessions.write.
func (a *Accounts) changeSessions(drop [][sha256.Size]byte, add []*sessionEntry, also ...func(*state.Tx) error) error {
	run := a.db.Update
	if len(also) > 0 {
		run = a.update
	}
	err := run(func(tx *state.Tx) error {
		for _, k := range drop {
			if err := tx.DeleteSession(k[:]); err != nil {
				return err
			}
		}
		for _, e := range add {
			if err := tx.PutSession(e.key[:], e.rec); err != nil {
				return err
			}
		}
		for _, f := range also {
			if err := f(tx); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	a.sessions.mu.Lock()
	defer a.sessions.mu.Unlock()
	for _, k := range drop {
		delete(a.sessions.byKey, k)
	}
	for _, e := range add {
		e.written = e.rec.LastSeen
		a.sessions.byKey[e.key] = e
	}
	return nil
}

// startSession creates a session for u. It replaces the session the browser
// had, and beyond maxSessionsPerUser the valid one seen least recently;
// sessions of u that are no longer valid are dropped without a record. It
// returns the valid sessions it ended, for their audit records.
func (a *Accounts) startSession(u state.User, c Client, also ...func(*state.Tx) error) (Grant, *sessionEntry, []endedSession, error) {
	token, key := newToken()
	now := a.wallNow()
	e := &sessionEntry{key: key, rec: state.Session{
		ID: state.NewID(), User: u.ID, Created: now, LastSeen: now, AuthTime: now, Epoch: u.Epoch,
		UserAgent: truncateUTF8(c.UserAgent, userAgentBytes), IP: hostOf(c.Addr),
	}}

	a.sessions.write.Lock()
	defer a.sessions.write.Unlock()
	var drop [][sha256.Size]byte
	var ended []endedSession
	var own []endedSession
	a.sessions.mu.Lock()
	if c.Token != "" {
		if old, ok := a.sessions.byKey[sha256.Sum256([]byte(c.Token))]; ok {
			drop = append(drop, old.key)
			if a.valid(old.rec, now) {
				ended = append(ended, endedSession{old.rec, "replaced"})
			}
		}
	}
	keys := map[string][sha256.Size]byte{}
	for k, s := range a.sessions.byKey {
		switch {
		case s.rec.User != u.ID || slices.Contains(drop, k):
		case !a.valid(s.rec, now):
			drop = append(drop, k)
		default:
			own, keys[s.rec.ID] = append(own, endedSession{s.rec, "session_limit"}), k
		}
	}
	a.sessions.mu.Unlock()
	slices.SortFunc(own, func(x, y endedSession) int { return x.rec.LastSeen.Compare(y.rec.LastSeen) })
	for len(own) >= maxSessionsPerUser {
		drop, ended, own = append(drop, keys[own[0].rec.ID]), append(ended, own[0]), own[1:]
	}
	if err := a.changeSessions(drop, []*sessionEntry{e}, also...); err != nil {
		return Grant{}, nil, nil, err
	}
	return a.grant(u, e, token), e, ended, nil
}

// renew gives a session a new token and records a new password entry, and
// with endOthers ends every other session of u. The creation time stays, so
// renewal never extends the absolute limit. A session that five wrong
// passwords are ending is not renewed, even for a right one checked before
// them.
func (a *Accounts) renew(id Identity, u state.User, endOthers bool, also ...func(*state.Tx) error) (Grant, error) {
	token, key := newToken()
	now := a.wallNow()
	a.sessions.write.Lock()
	defer a.sessions.write.Unlock()
	a.sessions.mu.Lock()
	old, ok := a.sessions.byKey[id.key]
	ok = ok && old.failures < freeFailures
	var rec state.Session
	drop := [][sha256.Size]byte{id.key}
	if ok {
		rec = old.rec
		for k, e := range a.sessions.byKey {
			if endOthers && e.rec.User == u.ID && k != id.key {
				drop = append(drop, k)
			}
		}
	}
	a.sessions.mu.Unlock()
	if !ok {
		return Grant{}, ErrSessionEnded
	}
	rec.LastSeen, rec.AuthTime, rec.Epoch = now, now, u.Epoch
	e := &sessionEntry{key: key, rec: rec}
	if err := a.changeSessions(drop, []*sessionEntry{e}, also...); err != nil {
		return Grant{}, err
	}
	return a.grant(u, e, token), nil
}

func (a *Accounts) grant(u state.User, e *sessionEntry, token string) Grant {
	return Grant{
		Me:      a.meFor(u, e.rec),
		Token:   token,
		Expires: e.rec.Created.Add(a.sessionCfg.Max),
		Device:  a.deviceCookie(u),
	}
}

// endWhere ends the sessions match selects and returns their records. It
// chooses them while holding sessions.write, so a renewal cannot replace a
// chosen token before it is deleted.
func (a *Accounts) endWhere(match func(state.Session) bool) ([]state.Session, error) {
	a.sessions.write.Lock()
	defer a.sessions.write.Unlock()
	var keys [][sha256.Size]byte
	var recs []state.Session
	a.sessions.mu.Lock()
	for k, e := range a.sessions.byKey {
		if match(e.rec) {
			keys, recs = append(keys, k), append(recs, e.rec)
		}
	}
	a.sessions.mu.Unlock()
	if len(keys) == 0 {
		return nil, nil
	}
	return recs, a.changeSessions(keys, nil)
}

func (a *Accounts) publishEnded(ctx context.Context, ended []endedSession) {
	users := a.users()
	for _, s := range ended {
		detail := "id=" + s.rec.ID
		if s.reason != "" {
			detail += " reason=" + s.reason
		}
		a.publish(ctx, events.Event{Type: events.SessionRevoked, Path: users[s.rec.User].Username, Detail: detail})
	}
}

// Logout ends the session by its ID, so a renewal of its token racing the
// logout cannot leave it alive.
func (a *Accounts) Logout(ctx context.Context, id Identity) error {
	if _, err := a.endWhere(func(s state.Session) bool { return s.ID == id.Session.ID }); err != nil {
		return err
	}
	a.publish(ctx, events.Event{Type: events.AuthLogout, Path: id.User.Username})
	return nil
}

// Sessions lists the user's valid sessions, the one seen most recently first.
func (a *Accounts) Sessions(id Identity) []SessionInfo {
	now := a.wallNow()
	a.sessions.mu.Lock()
	defer a.sessions.mu.Unlock()
	out := []SessionInfo{}
	for _, e := range a.sessions.byKey {
		if e.rec.User == id.User.ID && a.valid(e.rec, now) {
			out = append(out, SessionInfo{
				ID: e.rec.ID, Created: e.rec.Created, LastSeen: e.rec.LastSeen,
				Address: e.rec.IP, UserAgent: e.rec.UserAgent, Current: e.rec.ID == id.Session.ID,
			})
		}
	}
	slices.SortFunc(out, func(x, y SessionInfo) int { return y.LastSeen.Compare(x.LastSeen) })
	return out
}

// RevokeSession ends one of the user's own valid sessions, the current one
// included.
func (a *Accounts) RevokeSession(ctx context.Context, id Identity, sessionID string) error {
	now := a.wallNow()
	ended, err := a.endWhere(func(s state.Session) bool {
		return s.ID == sessionID && s.User == id.User.ID && a.valid(s, now)
	})
	if err != nil {
		return err
	}
	if len(ended) == 0 {
		return ErrNoSuchSession
	}
	a.publish(ctx, events.Event{Type: events.SessionRevoked, Path: id.User.Username, Detail: "id=" + sessionID})
	return nil
}

// RevokeOtherSessions ends every session of the user but the current one;
// only the ones still valid get an audit record. The returned list names the
// links revoked with them; it is empty while the server has no links.
func (a *Accounts) RevokeOtherSessions(ctx context.Context, id Identity) ([]RevokedLink, error) {
	now := a.wallNow()
	ended, err := a.endWhere(func(s state.Session) bool { return s.User == id.User.ID && s.ID != id.Session.ID })
	if err != nil {
		return nil, err
	}
	for _, s := range ended {
		if a.valid(s, now) {
			a.publish(ctx, events.Event{Type: events.SessionRevoked, Path: id.User.Username, Detail: "id=" + s.ID})
		}
	}
	return []RevokedLink{}, nil
}

// RevokedLink names a link revoked as a side effect (auth design §5.6).
type RevokedLink struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Role     string `json:"role,omitempty"`
	Username string `json:"username,omitempty"`
	Note     string `json:"note,omitempty"`
}

func hostOf(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

func truncateUTF8(s string, n int) string {
	if len(s) <= n {
		return strings.ToValidUTF8(s, "")
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return strings.ToValidUTF8(s[:n], "")
}
