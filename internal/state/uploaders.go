package state

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

// Uploader records who created a file or folder. Size and MTime identify
// the file the record was made for; a record without them, of a folder or of
// an upload still running, matches whatever of its kind is at its path.
type Uploader struct {
	User    string    `json:"user"`
	Created time.Time `json:"created"`
	Dir     bool      `json:"dir,omitempty"`
	Size    *int64    `json:"size,omitempty"`
	MTime   *int64    `json:"mtime,omitempty"` // nanoseconds, as the file system reports them
}

// Uploaders are keyed by the canonical path in the spelling the directory
// stores; a folder's entries lie under its path and "/", which is not one
// contiguous key range ("a/b!" sorts between "a/b" and "a/b/").
func validRecordPath(p string) bool {
	return p != "" && p != "." && p[0] != '/' && p[len(p)-1] != '/'
}

func (t *Tx) Uploader(p string) (Uploader, bool, error) {
	v := t.tx.Bucket(bucketUploaders).Get([]byte(p))
	if v == nil {
		return Uploader{}, false, nil
	}
	var u Uploader
	if err := json.Unmarshal(v, &u); err != nil {
		return Uploader{}, false, fmt.Errorf("uploader record of %q: %w", p, err)
	}
	return u, true, nil
}

func (t *Tx) PutUploader(p string, u Uploader) error {
	if !validRecordPath(p) || u.User == "" {
		return fmt.Errorf("incomplete uploader record for %q", p)
	}
	return putJSON(t.tx.Bucket(bucketUploaders), p, u)
}

// DeleteUploader removes the record of p alone.
func (t *Tx) DeleteUploader(p string) error {
	if !validRecordPath(p) {
		return fmt.Errorf("invalid uploader path %q", p)
	}
	return t.tx.Bucket(bucketUploaders).Delete([]byte(p))
}

// DeleteUploaders removes the records of p and of everything below it.
func (t *Tx) DeleteUploaders(p string) error {
	if !validRecordPath(p) {
		return fmt.Errorf("invalid uploader path %q", p)
	}
	b := t.tx.Bucket(bucketUploaders)
	if err := b.Delete([]byte(p)); err != nil {
		return err
	}
	prefix := []byte(p + "/")
	c := b.Cursor()
	for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Seek(prefix) {
		if err := c.Delete(); err != nil {
			return err
		}
	}
	return nil
}

// MoveUploaders gives the records of from and everything below it the same
// places under to, after deleting any records left at to and below it.
func (t *Tx) MoveUploaders(from, to string) error {
	if !validRecordPath(from) || !validRecordPath(to) || to == from || bytes.HasPrefix([]byte(to), []byte(from+"/")) {
		return fmt.Errorf("invalid uploader move %q to %q", from, to)
	}
	if err := t.DeleteUploaders(to); err != nil {
		return err
	}
	b := t.tx.Bucket(bucketUploaders)
	type record struct{ key, value []byte }
	var moved []record
	if v := b.Get([]byte(from)); v != nil {
		moved = append(moved, record{[]byte(to), bytes.Clone(v)})
	}
	prefix := []byte(from + "/")
	c := b.Cursor()
	for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
		moved = append(moved, record{append([]byte(to), k[len(from):]...), bytes.Clone(v)})
	}
	if err := t.DeleteUploaders(from); err != nil {
		return err
	}
	for _, r := range moved {
		if err := b.Put(r.key, r.value); err != nil {
			return err
		}
	}
	return nil
}
