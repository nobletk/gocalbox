package transfer

import (
	"context"
	"errors"
	"fmt"
	"path"

	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/space"
)

// Result is the answer to a completion.
type Result struct {
	Path            string `json:"path"`
	Name            string `json:"name"`
	Size            int64  `json:"size"`
	CompositeSHA256 string `json:"compositeSha256"`
}

// Complete places a fully received upload in its folder, once the parts'
// composite hash matches composite. It answers only once the file's records
// are in the audit log; if they aren't, the file is placed all the same and
// the error, which events.IsUnrecorded reports, comes with the result. A
// finished session answers again as it did.
func (e *Engine) Complete(ctx context.Context, id, composite string) (Result, error) {
	if err := e.enter(); err != nil {
		return Result{}, err
	}
	defer e.leave()
	if !ValidID(id) || !isHex(composite, 64) {
		e.publish(e.event(ctx, events.UploadRejected, "", &events.UploadInfo{ID: shownID(id)}, ErrInvalidRequest))
		return Result{}, ErrInvalidRequest
	}
	s, _, err := e.owned(ctx, id, false)
	if err != nil {
		return Result{}, err
	}
	s.mu.Lock()
	if s.state != Receiving {
		defer s.mu.Unlock()
		if s.state == Completed {
			return *s.result, s.resultErr
		}
		return Result{}, s.stateErr()
	}
	s.mu.Unlock()
	if e.audit != nil {
		if err := e.audit.Allow(); err != nil {
			return Result{}, e.refuseComplete(ctx, s, err)
		}
	}

	s.mu.Lock()
	if err := e.ready(s, composite); err != nil {
		s.mu.Unlock()
		if errors.Is(err, ErrCompleting) || errors.Is(err, ErrClosed) {
			return Result{}, err
		}
		return Result{}, e.refuseComplete(ctx, s, err)
	}
	s.state = Completing
	// Windows can't link, rename or remove a file that is open.
	if s.data != nil {
		s.data.Close()
		s.data = nil
	}
	s.mu.Unlock()
	return e.finish(ctx, s, composite)
}

// stateErr is the refusal of a session that isn't receiving. The caller
// holds s.mu.
func (s *session) stateErr() error {
	if s.state == Completing {
		return ErrCompleting
	}
	return closed(s.state, s.reason)
}

// ready checks that a session may be completed. The caller holds s.mu.
func (e *Engine) ready(s *session, composite string) error {
	if s.state != Receiving {
		return s.stateErr()
	}
	// A part in flight is missing too, so it comes first: the client is to
	// wait for it, not send it again.
	if len(s.inflight) > 0 {
		return ErrPartsInFlight
	}
	if missing := s.ranges(true); len(missing) > 0 {
		return &MissingError{Missing: missing}
	}
	if s.composite() != composite {
		return ErrChecksumMismatch
	}
	return nil
}

func (e *Engine) refuseComplete(ctx context.Context, s *session, err error) error {
	s.mu.Lock()
	s.rejected++
	if s.state == Receiving {
		if lerr := e.appendLine(s, line{Op: opReject, Reason: reasonOf(err), IP: clientAddr(ctx)}, false); lerr != nil {
			logf("cannot log a refused completion of upload %s: %v", s.rec.ID, lerr)
		}
	}
	up := s.info(0, "")
	s.mu.Unlock()
	e.publish(e.event(ctx, events.UploadRejected, s.path(), up, err))
	return err
}

// finish places the staged file of a completing session through Files and
// records it.
func (e *Engine) finish(ctx context.Context, s *session, composite string) (Result, error) {
	failed := func(reason string) (Result, error) {
		s.mu.Lock()
		ev, err := e.fail(ctx, s, reason)
		s.mu.Unlock()
		e.failed(s, ev)
		return Result{}, err
	}
	info, err := e.root.Lstat(native(uploadsDir, s.rec.ID, dataName))
	switch {
	case err != nil:
		return failed(fmt.Sprintf("the staged data is gone: %v", err))
	case !info.Mode().IsRegular() || info.Size() != s.rec.Size:
		return failed(fmt.Sprintf("the staged data holds %d bytes, not %d", info.Size(), s.rec.Size))
	}
	size, mtime := info.Size(), info.ModTime().UnixNano()
	actor, request := events.ActorFrom(ctx), events.RequestIDFrom(ctx)

	var logErr error
	final, placed, err := e.files.Adopt(ctx, stagedPath(s.rec.ID), s.rec.Dir, s.rec.Name, func(p string) error {
		s.mu.Lock()
		defer s.mu.Unlock()
		logErr = e.appendLine(s, line{Op: opFinishing, Path: p, Size: &size, MTime: &mtime, Actor: &actor, Request: request}, true)
		return logErr
	})
	if err != nil && logErr != nil && !errors.Is(logErr, space.ErrInsufficient) {
		return failed(fmt.Sprintf("cannot log the completion: %v", logErr))
	}
	if err != nil {
		s.mu.Lock()
		s.state = Receiving
		s.mu.Unlock()
		return Result{}, e.refuseComplete(ctx, s, err)
	}

	// The file is placed: from here on the upload is done, whatever fails.
	res := Result{Path: final, Name: path.Base(final), Size: s.rec.Size, CompositeSHA256: composite}
	e.counters.completed.Add(1)
	s.mu.Lock()
	// A line with no room is written later, before recorded; one lost
	// otherwise leaves the next start to tell from finishing.
	logged := e.logOrKeep(s, line{Op: opCompleted, Path: final, Actor: &actor, Request: request})
	e.at("completed")
	s.releaseWindow()
	e.dropData(s)
	ev := e.event(ctx, events.UploadCompleted, s.path(), s.totals(e.now(), composite), nil)
	s.mu.Unlock()
	ev.Resolved, ev.Size = final, s.rec.Size
	placed.Upload = &events.UploadInfo{ID: s.rec.ID, Owner: s.rec.Owner}

	var rerr error
	if e.audit != nil {
		rerr = e.audit.Record(ctx, e.named(placed), e.named(ev))
	} else {
		e.publish(placed, ev)
	}

	e.at("recorded")
	s.mu.Lock()
	if rerr == nil && logged {
		e.logOrKeep(s, line{Op: opRecorded})
	}
	s.state, s.result, s.resultErr, s.over = Completed, &res, rerr, e.now()
	s.closeFiles()
	s.mu.Unlock()
	e.closeSlot(s)
	e.wakeJanitor()
	return res, rerr
}
