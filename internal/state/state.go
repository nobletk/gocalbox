// Package state keeps the server's own records in one bbolt file: accounts,
// folder bindings, sessions, invite and reset links, uploader records, and
// the registry of upload sessions.
package state

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"slices"
	"strconv"
	"time"

	bolt "go.etcd.io/bbolt"
	berrors "go.etcd.io/bbolt/errors"
)

const Schema = 1

const lockTimeout = time.Second

var (
	bucketMeta       = []byte("meta")
	bucketUsers      = []byte("users")
	bucketUsernames  = []byte("usernames")
	bucketBindings   = []byte("bindings")
	bucketSessions   = []byte("sessions")
	bucketSessionIDs = []byte("sessionids")
	bucketLinks      = []byte("links")
	bucketLinkIDs    = []byte("linkids")
	bucketUploaders  = []byte("uploaders")
	bucketUploads    = []byte("uploads")

	buckets = [][]byte{
		bucketMeta, bucketUsers, bucketUsernames, bucketBindings, bucketSessions,
		bucketSessionIDs, bucketLinks, bucketLinkIDs, bucketUploaders, bucketUploads,
	}

	keySchema    = []byte("schema")
	keyDeviceKey = []byte("devicekey")
)

var (
	ErrLocked        = errors.New("the state file is in use by another process")
	ErrNotFound      = errors.New("not found")
	ErrUsernameTaken = errors.New("username already taken")
	ErrNotStateFile  = errors.New("not a gocalbox state file")
	ErrOpenToOthers  = errors.New("other users can read or write the state file; allow only its owner (chmod 600)")
)

type SchemaError struct {
	Found int
}

func (e *SchemaError) Error() string {
	if e.Found > Schema {
		return fmt.Sprintf("the state file has schema %d, newer than the %d this server knows; use a newer gocalbox", e.Found, Schema)
	}
	return fmt.Sprintf("the state file has schema %d, and no migration to schema %d exists", e.Found, Schema)
}

type Role string

const (
	RoleAdmin       Role = "admin"
	RoleContributor Role = "contributor"
	RoleViewer      Role = "viewer"
)

func (r Role) Valid() bool { return r == RoleAdmin || r == RoleContributor || r == RoleViewer }

func (r Role) HasHome() bool { return r == RoleAdmin || r == RoleContributor }

type User struct {
	ID                string    `json:"id"`
	Username          string    `json:"username"`
	Role              Role      `json:"role"`
	Hash              string    `json:"hash"`
	Disabled          bool      `json:"disabled"`
	Epoch             uint64    `json:"epoch"`
	Failures          int       `json:"failures"`
	PasswordDisabled  bool      `json:"passwordDisabled"`
	CreatedAt         time.Time `json:"createdAt"`
	CreatedBy         string    `json:"createdBy"`
	Invite            string    `json:"invite,omitempty"`
	PasswordChangedAt time.Time `json:"passwordChangedAt"`
}

type BindingKind string

const (
	KindHome   BindingKind = "home"
	KindPublic BindingKind = "public"
	KindCustom BindingKind = "custom"
)

// Everyone is the binding subject that stands for every logged-in user.
const Everyone = "*"

type Binding struct {
	ID        string      `json:"id"`
	Subject   string      `json:"subject"`
	Folder    string      `json:"folder"`
	Role      Role        `json:"role"`
	Kind      BindingKind `json:"kind"`
	CreatedBy string      `json:"createdBy"`
	CreatedAt time.Time   `json:"createdAt"`
}

type DB struct {
	bolt *bolt.DB
}

// Open opens or creates the state file. Another process holding it makes
// Open fail with ErrLocked within a second. A file other users may read is
// refused: it holds the password hashes.
func Open(path string) (*DB, error) {
	if fi, err := os.Stat(path); err == nil && runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		return nil, ErrOpenToOthers
	}
	b, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: lockTimeout})
	switch {
	case errors.Is(err, berrors.ErrTimeout):
		return nil, ErrLocked
	case errors.Is(err, berrors.ErrInvalid), errors.Is(err, berrors.ErrVersionMismatch), errors.Is(err, berrors.ErrChecksum):
		return nil, fmt.Errorf("%w: %v", ErrNotStateFile, err)
	case err != nil:
		return nil, err
	}
	if err := b.Update(initialize); err != nil {
		b.Close()
		return nil, err
	}
	return &DB{bolt: b}, nil
}

func initialize(tx *bolt.Tx) error {
	meta := tx.Bucket(bucketMeta)
	if meta == nil {
		empty := true
		tx.ForEach(func([]byte, *bolt.Bucket) error { empty = false; return nil })
		if !empty {
			return ErrNotStateFile
		}
		var err error
		if meta, err = tx.CreateBucket(bucketMeta); err != nil {
			return err
		}
		if err := meta.Put(keySchema, []byte(strconv.Itoa(Schema))); err != nil {
			return err
		}
	}
	found, err := strconv.Atoi(string(meta.Get(keySchema)))
	if err != nil {
		return fmt.Errorf("%w: unreadable schema version", ErrNotStateFile)
	}
	if found != Schema {
		return &SchemaError{Found: found}
	}
	for _, name := range buckets {
		if _, err := tx.CreateBucketIfNotExists(name); err != nil {
			return err
		}
	}
	if meta.Get(keyDeviceKey) == nil {
		key := make([]byte, 32)
		rand.Read(key)
		if err := meta.Put(keyDeviceKey, key); err != nil {
			return err
		}
	}
	return nil
}

func (d *DB) Close() error { return d.bolt.Close() }

func (d *DB) Path() string { return d.bolt.Path() }

func (d *DB) View(fn func(*Tx) error) error {
	return d.bolt.View(func(tx *bolt.Tx) error { return fn(&Tx{tx: tx}) })
}

// Update runs fn in one write transaction, committed with an fsync; an error
// from fn discards every change it made.
func (d *DB) Update(fn func(*Tx) error) error {
	return d.bolt.Update(func(tx *bolt.Tx) error { return fn(&Tx{tx: tx}) })
}

type Tx struct {
	tx *bolt.Tx
}

func (t *Tx) DeviceKey() []byte {
	return bytes.Clone(t.tx.Bucket(bucketMeta).Get(keyDeviceKey))
}

func (t *Tx) User(id string) (User, error) {
	var u User
	v := t.tx.Bucket(bucketUsers).Get([]byte(id))
	if v == nil {
		return u, ErrNotFound
	}
	return u, json.Unmarshal(v, &u)
}

func (t *Tx) UserByName(name string) (User, error) {
	id := t.tx.Bucket(bucketUsernames).Get([]byte(name))
	if id == nil {
		return User{}, ErrNotFound
	}
	return t.User(string(id))
}

// Users returns every account, sorted by username.
func (t *Tx) Users() ([]User, error) {
	var out []User
	err := t.tx.Bucket(bucketUsernames).ForEach(func(_, id []byte) error {
		u, err := t.User(string(id))
		if err != nil {
			return fmt.Errorf("user %s: %w", id, err)
		}
		out = append(out, u)
		return nil
	})
	return out, err
}

func (t *Tx) HasEnabledAdmin() (bool, error) {
	users, err := t.Users()
	if err != nil {
		return false, err
	}
	return slices.ContainsFunc(users, func(u User) bool { return u.Role == RoleAdmin && !u.Disabled }), nil
}

func (t *Tx) CreateUser(u User) error {
	if u.ID == "" || u.Username == "" || !u.Role.Valid() {
		return fmt.Errorf("incomplete user record %q", u.Username)
	}
	names := t.tx.Bucket(bucketUsernames)
	if names.Get([]byte(u.Username)) != nil {
		return ErrUsernameTaken
	}
	users := t.tx.Bucket(bucketUsers)
	if users.Get([]byte(u.ID)) != nil {
		return fmt.Errorf("user ID %s already exists", u.ID)
	}
	if err := putJSON(users, u.ID, u); err != nil {
		return err
	}
	return names.Put([]byte(u.Username), []byte(u.ID))
}

// UpdateUser replaces the record of an existing user. The username is fixed
// at creation.
func (t *Tx) UpdateUser(u User) error {
	old, err := t.User(u.ID)
	if err != nil {
		return err
	}
	if old.Username != u.Username {
		return fmt.Errorf("the username of %s cannot change", u.ID)
	}
	if !u.Role.Valid() {
		return fmt.Errorf("invalid role %q", u.Role)
	}
	return putJSON(t.tx.Bucket(bucketUsers), u.ID, u)
}

// DeleteUser removes the user's record and username. Their sessions,
// bindings and links are the caller's to remove in the same transaction.
func (t *Tx) DeleteUser(id string) error {
	u, err := t.User(id)
	if err != nil {
		return err
	}
	if err := t.tx.Bucket(bucketUsernames).Delete([]byte(u.Username)); err != nil {
		return err
	}
	return t.tx.Bucket(bucketUsers).Delete([]byte(id))
}

func (t *Tx) Binding(id string) (Binding, error) {
	var b Binding
	v := t.tx.Bucket(bucketBindings).Get([]byte(id))
	if v == nil {
		return b, ErrNotFound
	}
	return b, json.Unmarshal(v, &b)
}

func (t *Tx) DeleteBinding(id string) error {
	if t.tx.Bucket(bucketBindings).Get([]byte(id)) == nil {
		return ErrNotFound
	}
	return t.tx.Bucket(bucketBindings).Delete([]byte(id))
}

func (t *Tx) Bindings() ([]Binding, error) {
	var out []Binding
	err := t.tx.Bucket(bucketBindings).ForEach(func(k, v []byte) error {
		var b Binding
		if err := json.Unmarshal(v, &b); err != nil {
			return fmt.Errorf("binding %s: %w", k, err)
		}
		out = append(out, b)
		return nil
	})
	return out, err
}

func (t *Tx) PutBinding(b Binding) error {
	if b.ID == "" || b.Subject == "" || b.Folder == "" || !b.Role.Valid() || b.Role == RoleAdmin {
		return fmt.Errorf("incomplete binding for %q", b.Folder)
	}
	return putJSON(t.tx.Bucket(bucketBindings), b.ID, b)
}

func putJSON(b *bolt.Bucket, key string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return b.Put([]byte(key), data)
}

// NewUserID returns "u-" and 64 random bits in hex.
func NewUserID() string { return "u-" + NewID() }

// NewID returns 64 random bits in hex, for bindings, sessions and links.
func NewID() string {
	var b [8]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
