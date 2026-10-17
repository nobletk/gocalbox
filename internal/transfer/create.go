package transfer

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"time"

	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/sandbox"
	"github.com/nobletk/gocalbox/internal/space"
)

type CreateRequest struct {
	Dir       string `json:"dir"`
	Name      string `json:"name"`
	Size      int64  `json:"size"`
	ClientKey string `json:"clientKey,omitempty"`
}

type Created struct {
	UploadID    string    `json:"uploadId"`
	PartSize    int64     `json:"partSize"`
	PartCount   int       `json:"partCount"`
	MaxParallel int       `json:"maxParallel"`
	ExpiresAt   time.Time `json:"expiresAt"`
	Resumed     bool      `json:"resumed"`
	Received    []Range   `json:"received"`
}

// Create opens a session for an upload of req.Size bytes into req.Dir, or
// returns the user's own session that is still receiving the same file, as
// its client key tells, with Resumed set.
func (e *Engine) Create(ctx context.Context, req CreateRequest) (Created, error) {
	if err := e.enter(); err != nil {
		return Created{}, err
	}
	defer e.leave()
	p := logicalJoin(req.Dir, req.Name)
	refuse := func(err error) (Created, error) {
		ev := e.event(ctx, events.UploadRejected, p, nil, err)
		ev.Size = req.Size
		e.publish(ev)
		return Created{}, err
	}
	dir, err := sandbox.Clean(req.Dir)
	if err != nil {
		return refuse(err)
	}
	switch {
	case req.Size < 0, !validClientKey(req.ClientKey):
		return refuse(ErrInvalidRequest)
	case req.Size > MaxSize, e.lim.MaxSize > 0 && req.Size > e.lim.MaxSize:
		return refuse(ErrTooLarge)
	case e.maxFile > 0 && req.Size > e.maxFile:
		return refuse(ErrTooLargeForVolume)
	}
	uid, _, ok := e.files.Who(ctx)
	if ok && req.ClientKey != "" {
		if c, found, err := e.resume(ctx, uid, dir, req); found {
			return c, err
		}
	}
	clean, folder, err := e.files.PrepareUpload(ctx, req.Dir, req.Name)
	if err != nil {
		return refuse(err)
	}
	if err := e.takeSession(uid); err != nil {
		return Created{}, err
	}
	counted := false
	defer func() {
		if !counted {
			e.giveSession(uid)
		}
	}()
	partSize := e.partSize(req.Size)
	rec := Record{
		ID:        newID(),
		Owner:     uid,
		Session:   events.ActorFrom(ctx).Session,
		Dir:       clean,
		Folder:    folder,
		Name:      req.Name,
		Size:      req.Size,
		PartSize:  partSize,
		PartCount: PartCount(req.Size, partSize),
		ClientKey: req.ClientKey,
		Created:   e.now(),
	}
	s, err := e.start(rec)
	if err != nil {
		return refuse(err)
	}
	s.seen(clientAddr(ctx))
	c := e.created(s, false)
	ev := e.event(ctx, events.UploadCreated, s.path(), s.info(0, ""), nil)
	ev.Resolved, ev.Size = rec.Folder, rec.Size

	e.mu.Lock()
	s.counted, counted = true, true
	e.sessions[rec.ID] = s
	e.mu.Unlock()
	e.publish(ev)
	return c, nil
}

// resume looks for the newest session of uid that is receiving the file req
// describes; found is false if there is none.
func (e *Engine) resume(ctx context.Context, uid, dir string, req CreateRequest) (c Created, found bool, err error) {
	e.mu.Lock()
	var cands []*session
	for _, s := range e.sessions {
		r := s.rec
		if r.Owner == uid && r.ClientKey == req.ClientKey && r.Dir == dir && r.Name == req.Name && r.Size == req.Size {
			cands = append(cands, s)
		}
	}
	e.mu.Unlock()
	slices.SortFunc(cands, func(a, b *session) int { return b.rec.Created.Compare(a.rec.Created) })

	for _, s := range cands {
		s.mu.Lock()
		receiving := s.state == Receiving
		s.mu.Unlock()
		if !receiving {
			continue
		}
		if err := e.files.MayUpload(ctx, s.rec.Folder); err != nil {
			e.publish(e.event(ctx, events.UploadRejected, s.path(), &events.UploadInfo{ID: s.rec.ID, Owner: s.rec.Owner}, err))
			return Created{}, true, err
		}
		s.mu.Lock()
		if s.state != Receiving {
			s.mu.Unlock()
			continue
		}
		s.seen(clientAddr(ctx))
		c := e.created(s, true)
		ev := e.event(ctx, events.UploadCreated, s.path(), s.info(0, ""), nil)
		s.mu.Unlock()
		ev.Resolved, ev.Size, ev.Detail = s.rec.Folder, s.rec.Size, "resumed"
		e.publish(ev)
		return c, true, nil
	}
	return Created{}, false, nil
}

// created is the answer to create. The caller holds s.mu, or is the only one
// who knows s.
func (e *Engine) created(s *session, resumed bool) Created {
	return Created{
		UploadID:    s.rec.ID,
		PartSize:    s.rec.PartSize,
		PartCount:   s.rec.PartCount,
		MaxParallel: e.lim.MaxParallel,
		ExpiresAt:   e.expiresAt(s),
		Resumed:     resumed,
		Received:    s.ranges(false),
	}
}

// start admits a new session against free space, registers it and creates
// its staging folder, in that order, so that whatever a crash leaves can be
// told apart.
func (e *Engine) start(rec Record) (*session, error) {
	var window *space.Reservation
	if e.ledger != nil {
		if err := e.ledger.Admits(rec.Size); err != nil {
			return nil, err
		}
		w, err := e.ledger.Reserve(min(rec.Size, e.windowFor(rec.PartSize)))
		if err != nil {
			return nil, err
		}
		window = w
	}
	s := newSession(rec)
	s.window = window
	if err := e.reg.PutUpload(rec); err != nil {
		s.releaseWindow()
		return nil, fmt.Errorf("register the upload: %w", err)
	}
	e.at("registered")
	if err := e.stage(s); err != nil {
		if derr := e.reg.DeleteUpload(rec.ID); derr != nil {
			logf("cannot delete the record of upload %s, whose staging failed: %v", rec.ID, derr)
		}
		s.releaseWindow()
		if isNoSpace(err) {
			return nil, noSpace(err)
		}
		return nil, fmt.Errorf("stage the upload: %w", err)
	}
	return s, nil
}

// stage creates the session's folder with an empty data and log, and makes
// them durable before the session is answered.
func (e *Engine) stage(s *session) (err error) {
	dir := sessionDir(s.rec.ID)
	if err := e.root.Mkdir(dir, 0o700); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			s.closeFiles()
			if rerr := e.root.RemoveAll(dir); rerr != nil {
				logf("cannot remove the staging of upload %s: %v", s.rec.ID, rerr)
			}
		}
	}()
	if s.log, err = e.root.OpenFile(native(uploadsDir, s.rec.ID, logName), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600); err != nil {
		return err
	}
	if s.data, err = e.root.OpenFile(native(uploadsDir, s.rec.ID, dataName), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o644); err != nil {
		return err
	}
	return errors.Join(e.syncDir(e.root, dir), e.syncDir(e.root, uploadsDir))
}
