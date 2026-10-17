package registry

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

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
