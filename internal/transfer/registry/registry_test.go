package registry

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/nobletk/gocalbox/internal/state"
	"github.com/nobletk/gocalbox/internal/transfer"
)

func TestRecordsGoToTheStateFile(t *testing.T) {
	db, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	r := New(db)
	rec := transfer.Record{ID: "0123456789abcdef0123456789abcdef", Owner: "u-alice", Session: "s1", Dir: "users/Alice",
		Folder: "users/alice", Name: "a.bin", Size: 10, PartSize: 8 << 20, PartCount: 1, ClientKey: "k",
		Created: time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)}
	if err := r.PutUpload(rec); err != nil {
		t.Fatal(err)
	}
	if err := r.PutUpload(rec); !errors.Is(err, state.ErrUploadExists) {
		t.Errorf("a second record under one ID: %v", err)
	}
	var got state.Upload
	db.View(func(tx *state.Tx) error { got, err = tx.Upload(rec.ID); return err })
	want := state.Upload{V: state.UploadVersion, ID: rec.ID, Owner: rec.Owner, Session: rec.Session, Dir: rec.Dir, Folder: rec.Folder,
		Name: rec.Name, Size: rec.Size, PartSize: rec.PartSize, PartCount: rec.PartCount, ClientKey: rec.ClientKey, Created: rec.Created}
	if err != nil || got != want {
		t.Errorf("stored %+v, %v; want %+v", got, err, want)
	}
	recs, bad, err := r.Uploads()
	if err != nil || len(bad) != 0 || len(recs) != 1 || recs[0] != rec {
		t.Errorf("listed %+v, %v, %v", recs, bad, err)
	}
	if err := r.DeleteUpload(rec.ID); err != nil {
		t.Fatal(err)
	}
	db.View(func(tx *state.Tx) error { _, err = tx.Upload(rec.ID); return nil })
	if !errors.Is(err, state.ErrNotFound) {
		t.Errorf("after delete: %v", err)
	}
	if err := r.DeleteUpload(rec.ID); err != nil {
		t.Errorf("deleting a missing record: %v", err)
	}
}

func TestARecordThatCantBeReadIsListedApart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := state.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	raw, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("uploads")).Put([]byte("bad"), []byte("{")) })
	raw.Close()
	db, err = state.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	recs, bad, err := New(db).Uploads()
	if err != nil || len(recs) != 0 || len(bad) != 1 || bad["bad"] == nil {
		t.Errorf("listed %+v, bad %v, %v", recs, bad, err)
	}
}
