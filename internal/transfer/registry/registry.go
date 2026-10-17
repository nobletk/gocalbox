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
