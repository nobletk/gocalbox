package state

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func newUpload(id string) Upload {
	return Upload{
		ID: id, Owner: "u-0123456789abcdef", Session: "9c1e0b7a44d2f3e1",
		Dir: "users/alice/videos", Folder: "users/alice/videos", Name: "holiday.mp4",
		Size: 4294967297, PartSize: 8 << 20, PartCount: 513, ClientKey: "9f2c",
		Created: time.Date(2026, 10, 16, 17, 0, 0, 0, time.UTC),
	}
}

func TestUploads(t *testing.T) {
	d, _ := openTemp(t)
	a, b := newUpload("3f9a00000000000000000000000000aa"), newUpload("3f9a00000000000000000000000000bb")
	b.Owner = "u-fedcba9876543210"
	err := d.Update(func(tx *Tx) error {
		if err := tx.PutUpload(b); err != nil {
			return err
		}
		return tx.PutUpload(a)
	})
	if err != nil {
		t.Fatal(err)
	}

	d.View(func(tx *Tx) error {
		got, err := tx.Upload(a.ID)
		a.V = UploadVersion
		if err != nil || got != a {
			t.Errorf("read back %+v, %v; want %+v", got, err, a)
		}
		if _, err := tx.Upload("3f9a00000000000000000000000000cc"); !errors.Is(err, ErrNotFound) {
			t.Errorf("a missing record: %v", err)
		}
		var ids []string
		tx.Uploads(func(id string, u Upload, err error) error {
			if err != nil || u.ID != id {
				t.Errorf("%s: %+v, %v", id, u, err)
			}
			ids = append(ids, id)
			return nil
		})
		if strings.Join(ids, ",") != a.ID+","+b.ID {
			t.Errorf("listed %v, want them in ID order", ids)
		}
		return nil
	})

	if err := d.Update(func(tx *Tx) error { return tx.PutUpload(newUpload(a.ID)) }); !errors.Is(err, ErrUploadExists) {
		t.Errorf("a second record under one ID: %v", err)
	}
	if err := d.Update(func(tx *Tx) error { return tx.DeleteUpload(a.ID) }); err != nil {
		t.Fatal(err)
	}
	if err := d.Update(func(tx *Tx) error { return tx.DeleteUpload(a.ID) }); err != nil {
		t.Errorf("deleting a missing record: %v", err)
	}
	d.View(func(tx *Tx) error {
		if _, err := tx.Upload(a.ID); !errors.Is(err, ErrNotFound) {
			t.Errorf("after delete: %v", err)
		}
		return nil
	})
}

func TestPutUploadRefusesIncompleteRecords(t *testing.T) {
	d, _ := openTemp(t)
	for name, change := range map[string]func(*Upload){
		"no ID":          func(u *Upload) { u.ID = "" },
		"no owner":       func(u *Upload) { u.Owner = "" },
		"no name":        func(u *Upload) { u.Name = "" },
		"negative size":  func(u *Upload) { u.Size = -1 },
		"no part size":   func(u *Upload) { u.PartSize = 0 },
		"negative parts": func(u *Upload) { u.PartCount = -1 },
	} {
		u := newUpload("3f9a00000000000000000000000000aa")
		change(&u)
		if err := d.Update(func(tx *Tx) error { return tx.PutUpload(u) }); err == nil {
			t.Errorf("%s: stored", name)
		}
	}
}

// A record that can't be read reaches the caller with its error and its
// key, so recovery can delete it.
func TestUnreadableUploadRecords(t *testing.T) {
	d, _ := openTemp(t)
	good := newUpload("3f9a00000000000000000000000000aa")
	d.Update(func(tx *Tx) error { return tx.PutUpload(good) })
	bad := map[string]string{
		"3f9a00000000000000000000000000b1": `{not json`,
		"3f9a00000000000000000000000000b2": `{"v":2,"id":"3f9a00000000000000000000000000b2"}`,
		"3f9a00000000000000000000000000b3": `{"v":1,"id":"3f9a00000000000000000000000000aa"}`,
	}
	d.bolt.Update(func(tx *bolt.Tx) error {
		for k, v := range bad {
			tx.Bucket(bucketUploads).Put([]byte(k), []byte(v))
		}
		return nil
	})
	var failed []string
	d.View(func(tx *Tx) error {
		return tx.Uploads(func(id string, u Upload, err error) error {
			if err != nil {
				failed = append(failed, id)
			} else if id != good.ID {
				t.Errorf("%s read as %+v", id, u)
			}
			return nil
		})
	})
	if len(failed) != len(bad) {
		t.Errorf("failed records %v, want the %d bad ones", failed, len(bad))
	}
}

// A state file made before the registry existed gains its bucket when it is
// opened, without a new schema version.
func TestOpenAddsTheUploadsBucket(t *testing.T) {
	d, path := openTemp(t)
	d.bolt.Update(func(tx *bolt.Tx) error { return tx.DeleteBucket(bucketUploads) })
	d.Close()

	again, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if err := again.Update(func(tx *Tx) error { return tx.PutUpload(newUpload("3f9a00000000000000000000000000aa")) }); err != nil {
		t.Errorf("after reopening: %v", err)
	}
	var buf bytes.Buffer
	again.Dump(&buf)
	if !strings.Contains(buf.String(), "uploads (1)") || !strings.Contains(buf.String(), "holiday.mp4") {
		t.Errorf("the dump doesn't show the registry:\n%s", buf.String())
	}
}
