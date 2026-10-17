// Package registry keeps the records of the upload engine's sessions in the
// state file, outside the served folder.
package registry

import (
	"github.com/nobletk/gocalbox/internal/state"
	"github.com/nobletk/gocalbox/internal/transfer"
)

type Registry struct{ db *state.DB }

func New(db *state.DB) *Registry { return &Registry{db: db} }

func (r *Registry) PutUpload(rec transfer.Record) error {
	return r.db.Update(func(tx *state.Tx) error { return tx.PutUpload(toState(rec)) })
}

func (r *Registry) DeleteUpload(id string) error {
	return r.db.Update(func(tx *state.Tx) error { return tx.DeleteUpload(id) })
}

func (r *Registry) Uploads() ([]transfer.Record, map[string]error, error) {
	var recs []transfer.Record
	bad := map[string]error{}
	err := r.db.View(func(tx *state.Tx) error {
		return tx.Uploads(func(id string, u state.Upload, err error) error {
			if err != nil {
				bad[id] = err
			} else {
				recs = append(recs, fromState(u))
			}
			return nil
		})
	})
	return recs, bad, err
}

func fromState(u state.Upload) transfer.Record {
	return transfer.Record{
		ID:        u.ID,
		Owner:     u.Owner,
		Session:   u.Session,
		Dir:       u.Dir,
		Folder:    u.Folder,
		Name:      u.Name,
		Size:      u.Size,
		PartSize:  u.PartSize,
		PartCount: u.PartCount,
		ClientKey: u.ClientKey,
		Created:   u.Created,
	}
}

func toState(rec transfer.Record) state.Upload {
	return state.Upload{
		ID:        rec.ID,
		Owner:     rec.Owner,
		Session:   rec.Session,
		Dir:       rec.Dir,
		Folder:    rec.Folder,
		Name:      rec.Name,
		Size:      rec.Size,
		PartSize:  rec.PartSize,
		PartCount: rec.PartCount,
		ClientKey: rec.ClientKey,
		Created:   rec.Created,
	}
}
