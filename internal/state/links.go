package state

import (
	"encoding/json"
	"fmt"
	"time"
)

type LinkKind string

const (
	KindInvite LinkKind = "invite"
	KindReset  LinkKind = "reset"
)

// Link is an invite or reset link, stored under the SHA-256 of its token so
// the file holds nothing that can be presented as one.
type Link struct {
	ID        string    `json:"id"`
	Kind      LinkKind  `json:"kind"`
	Role      Role      `json:"role,omitempty"`     // an invite's
	Username  string    `json:"username,omitempty"` // the name an invite fixes
	User      string    `json:"user,omitempty"`     // the account of a reset link
	Note      string    `json:"note,omitempty"`
	CreatedBy string    `json:"createdBy"`
	Created   time.Time `json:"created"`
	Expires   time.Time `json:"expires"`
	Used      time.Time `json:"used,omitzero"`
}

// Unused reports whether l can still be accepted at now.
func (l Link) Unused(now time.Time) bool { return l.Used.IsZero() && now.Before(l.Expires) }

func (t *Tx) PutLink(key []byte, l Link) error {
	if len(key) == 0 || l.ID == "" || (l.Kind != KindInvite && l.Kind != KindReset) {
		return fmt.Errorf("incomplete link record %q", l.ID)
	}
	if l.Kind == KindInvite && !l.Role.Valid() {
		return fmt.Errorf("invite %s has no valid role", l.ID)
	}
	data, err := json.Marshal(l)
	if err != nil {
		return err
	}
	if err := t.tx.Bucket(bucketLinks).Put(key, data); err != nil {
		return err
	}
	return t.tx.Bucket(bucketLinkIDs).Put([]byte(l.ID), key)
}

func (t *Tx) Link(key []byte) (Link, error) {
	var l Link
	v := t.tx.Bucket(bucketLinks).Get(key)
	if v == nil {
		return l, ErrNotFound
	}
	return l, json.Unmarshal(v, &l)
}

func (t *Tx) LinkByID(id string) ([]byte, Link, error) {
	key := t.tx.Bucket(bucketLinkIDs).Get([]byte(id))
	if key == nil {
		return nil, Link{}, ErrNotFound
	}
	key = append([]byte(nil), key...)
	l, err := t.Link(key)
	return key, l, err
}

// DeleteLink removes the link stored under key and its ID index; a missing
// link is not an error.
func (t *Tx) DeleteLink(key []byte) error {
	b := t.tx.Bucket(bucketLinks)
	v := b.Get(key)
	if v == nil {
		return nil
	}
	var l Link
	if err := json.Unmarshal(v, &l); err == nil {
		ids := t.tx.Bucket(bucketLinkIDs)
		if k := ids.Get([]byte(l.ID)); k != nil && string(k) == string(key) {
			if err := ids.Delete([]byte(l.ID)); err != nil {
				return err
			}
		}
	}
	return b.Delete(key)
}

// Links calls fn for every stored link. A record that cannot be read is
// passed with an empty ID, so the caller can delete it.
func (t *Tx) Links(fn func(key []byte, l Link) error) error {
	return t.tx.Bucket(bucketLinks).ForEach(func(k, v []byte) error {
		var l Link
		if err := json.Unmarshal(v, &l); err != nil {
			l = Link{}
		}
		return fn(append([]byte(nil), k...), l)
	})
}
