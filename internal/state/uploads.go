package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// UploadVersion is the version of the upload records this server writes.
const UploadVersion = 1

var ErrUploadExists = errors.New("an upload with this ID exists")

// Upload is the registry record of an upload session, written once when the
// session is created and deleted when it is removed. What has happened to
// the session since is kept with its staged data, not here.
type Upload struct {
	V       int    `json:"v"`
	ID      string `json:"id"`
	Owner   string `json:"owner"`
	Session string `json:"session,omitempty"` // the login session that created it

	Dir    string `json:"dir"`    // the target folder as the client gave it, cleaned
	Folder string `json:"folder"` // its key when the session was created
	Name   string `json:"name"`

	Size      int64     `json:"size"`
	PartSize  int64     `json:"partSize"`
	PartCount int       `json:"partCount"`
	ClientKey string    `json:"clientKey,omitempty"`
	Created   time.Time `json:"created"`
}

// PutUpload stores a new record. A record is never replaced: an ID already
// in use gives ErrUploadExists.
func (t *Tx) PutUpload(u Upload) error {
	if u.ID == "" || u.Owner == "" || u.Name == "" || u.Size < 0 || u.PartSize <= 0 || u.PartCount < 0 {
		return fmt.Errorf("incomplete upload record %q", u.ID)
	}
	b := t.tx.Bucket(bucketUploads)
	if b.Get([]byte(u.ID)) != nil {
		return ErrUploadExists
	}
	u.V = UploadVersion
	return putJSON(b, u.ID, u)
}

func (t *Tx) Upload(id string) (Upload, error) {
	v := t.tx.Bucket(bucketUploads).Get([]byte(id))
	if v == nil {
		return Upload{}, ErrNotFound
	}
	return decodeUpload(id, v)
}

// DeleteUpload removes the record of id; a missing record is not an error.
func (t *Tx) DeleteUpload(id string) error {
	return t.tx.Bucket(bucketUploads).Delete([]byte(id))
}

// Uploads calls fn for every record, in the order of their IDs. A record
// that can't be read is passed with its error, so the caller can delete it
// by id.
func (t *Tx) Uploads(fn func(id string, u Upload, err error) error) error {
	return t.tx.Bucket(bucketUploads).ForEach(func(k, v []byte) error {
		u, err := decodeUpload(string(k), v)
		return fn(string(k), u, err)
	})
}

func decodeUpload(id string, v []byte) (Upload, error) {
	var u Upload
	if err := json.Unmarshal(v, &u); err != nil {
		return Upload{}, fmt.Errorf("upload record %q: %w", id, err)
	}
	if u.V != UploadVersion {
		return Upload{}, fmt.Errorf("upload record %q has version %d, not %d", id, u.V, UploadVersion)
	}
	if u.ID != id {
		return Upload{}, fmt.Errorf("upload record %q names upload %q", id, u.ID)
	}
	return u, nil
}
