package state

import (
	"encoding/json"
	"fmt"
	"time"
)

// Session is stored under the SHA-256 of its token, so the file holds
// nothing that can be presented as a cookie.
type Session struct {
	ID        string    `json:"id"`
	User      string    `json:"user"`
	Created   time.Time `json:"created"`
	LastSeen  time.Time `json:"lastSeen"`
	AuthTime  time.Time `json:"authTime"`
	Epoch     uint64    `json:"epoch"`
	UserAgent string    `json:"userAgent"`
	IP        string    `json:"ip"`
}

// PutSession stores s under key and indexes it by its ID, replacing a record
// with the same key.
func (t *Tx) PutSession(key []byte, s Session) error {
	if len(key) == 0 || s.ID == "" || s.User == "" {
		return fmt.Errorf("incomplete session record %q", s.ID)
	}
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if err := t.tx.Bucket(bucketSessions).Put(key, data); err != nil {
		return err
	}
	return t.tx.Bucket(bucketSessionIDs).Put([]byte(s.ID), key)
}

// DeleteSession removes the session stored under key and its ID index; a
// missing session is not an error.
func (t *Tx) DeleteSession(key []byte) error {
	b := t.tx.Bucket(bucketSessions)
	v := b.Get(key)
	if v == nil {
		return nil
	}
	var s Session
	if err := json.Unmarshal(v, &s); err == nil {
		ids := t.tx.Bucket(bucketSessionIDs)
		if k := ids.Get([]byte(s.ID)); k != nil && string(k) == string(key) {
			if err := ids.Delete([]byte(s.ID)); err != nil {
				return err
			}
		}
	}
	return b.Delete(key)
}

func (t *Tx) SessionByID(id string) (Session, error) {
	var s Session
	key := t.tx.Bucket(bucketSessionIDs).Get([]byte(id))
	if key == nil {
		return s, ErrNotFound
	}
	v := t.tx.Bucket(bucketSessions).Get(key)
	if v == nil {
		return s, ErrNotFound
	}
	return s, json.Unmarshal(v, &s)
}

// Sessions calls fn for every stored session. A record that cannot be read
// is passed with an empty ID, so the caller can delete it.
func (t *Tx) Sessions(fn func(key []byte, s Session) error) error {
	return t.tx.Bucket(bucketSessions).ForEach(func(k, v []byte) error {
		var s Session
		if err := json.Unmarshal(v, &s); err != nil {
			s = Session{}
		}
		return fn(append([]byte(nil), k...), s)
	})
}
