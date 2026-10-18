package transfer

import (
	"cmp"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"time"

	"github.com/nobletk/gocalbox/internal/events"
)

func (e *Engine) janitor(every time.Duration) {
	defer close(e.janitorDone)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-e.stop:
			return
		case <-t.C:
		case <-e.wake:
		}
		e.at("janitor")
		if !e.startSweep() {
			return
		}
		e.sweep()
		e.endSweep()
	}
}

// startSweep marks a run of the janitor as under way, unless the engine is
// closing; Close waits only for a run under way, not for the goroutine.
func (e *Engine) startSweep() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return false
	}
	e.sweeping = true
	return true
}

func (e *Engine) endSweep() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.sweeping = false
	if e.swept != nil {
		close(e.swept)
		e.swept = nil
	}
}

type tombstone struct {
	s         *session
	completed bool
	over      time.Time
}

// sweep runs every timer once: it expires sessions, gives back the windows
// of idle ones, removes the data of finished ones, and removes tombstones
// that are too old or over their owner's cap.
func (e *Engine) sweep() {
	now := e.now()
	e.mu.Lock()
	list := e.list()
	e.mu.Unlock()

	known := map[string]bool{}
	deleted := func(user string) bool {
		ok, seen := known[user]
		if !seen {
			_, ok = e.files.UserName(user)
			known[user] = ok
		}
		return !ok
	}
	tombs := map[string][]tombstone{}
	var remove []*session
	for _, s := range list {
		gone := deleted(s.rec.Owner)
		var ev *events.Event
		s.mu.Lock()
		switch {
		case s.state == Receiving && len(s.inflight) == 0:
			if reason := e.expiry(s, now, gone); reason != "" {
				e.end(s, Expired, line{Op: opExpired, Reason: reason})
				ev = &events.Event{
					Type:    events.UploadExpired,
					Actor:   events.Actor{ID: events.SystemID},
					Outcome: events.OutcomeOK,
					Path:    truncate(s.path()),
					Size:    s.recvBytes,
					Detail:  reason,
					Upload:  s.totals(now, ""),
				}
			} else if e.idle(s, now) {
				s.releaseWindow()
				s.closeFiles()
			}
		case s.state.Over():
			e.dropData(s)
			e.logPending(s)
		}
		if s.state.Over() {
			if now.Before(s.over.Add(e.lim.TombstoneTTL)) {
				tombs[s.rec.Owner] = append(tombs[s.rec.Owner], tombstone{s, s.state == Completed, s.over})
			} else {
				remove = append(remove, s)
			}
		}
		s.mu.Unlock()
		if ev != nil {
			e.closeSlot(s)
			e.publish(*ev)
		}
	}
	for _, ts := range tombs {
		if extra := len(ts) - e.lim.MaxTombstones; extra > 0 {
			// Completed ones go last: they hold an answer a client may
			// still need.
			slices.SortFunc(ts, func(a, b tombstone) int {
				if a.completed != b.completed {
					if a.completed {
						return 1
					}
					return -1
				}
				return cmp.Compare(a.over.UnixNano(), b.over.UnixNano())
			})
			for _, t := range ts[:extra] {
				remove = append(remove, t.s)
			}
		}
	}
	for _, s := range remove {
		e.remove(s)
	}
}

// expiry returns why a receiving session with no part in flight expires
// now, or "". The caller holds s.mu.
func (e *Engine) expiry(s *session, now time.Time, ownerGone bool) string {
	switch {
	case ownerGone:
		return "owner_deleted"
	case now.Sub(s.rec.Created) >= e.lim.MaxAge:
		return "max_age"
	case s.nReceived == 0 && now.Sub(s.rec.Created) >= e.lim.FirstPartTTL:
		return "no_parts"
	case s.nReceived > 0 && now.Sub(s.lastPart) >= e.lim.IdleTTL:
		return "idle"
	}
	return ""
}

// idle reports whether a receiving session has accepted no part for long
// enough to give back its window and close its files. The caller holds s.mu.
func (e *Engine) idle(s *session, now time.Time) bool {
	last := s.lastPart
	if s.nReceived == 0 {
		last = s.rec.Created
	}
	held := (s.window != nil && s.window.Left() > 0) || s.data != nil || s.log != nil
	return held && now.Sub(last) >= e.lim.IdleRelease
}

// remove deletes a finished session: its staging folder goes into the trash,
// then its record is deleted. A step that fails is tried again at the next
// run.
func (e *Engine) remove(s *session) {
	s.mu.Lock()
	if s.removing || len(s.inflight) > 0 {
		s.mu.Unlock()
		return
	}
	s.removing = true
	s.closeFiles()
	s.mu.Unlock()
	retry := func() {
		s.mu.Lock()
		s.removing = false
		s.mu.Unlock()
	}

	id := s.rec.ID
	if err := e.removeStaging(id); err != nil {
		logf("cannot remove upload %s, trying again later: %v", id, err)
		retry()
		return
	}
	e.mu.Lock()
	if e.sessions[id] == s {
		delete(e.sessions, id)
	}
	e.mu.Unlock()
}

// removeStaging moves a session's folder into the trash, then deletes its
// record, then empties the trash of it. After an error the record stays, so
// that the removal can be tried again.
func (e *Engine) removeStaging(id string) error {
	trashed := native(trashDir, trashName())
	err := e.root.Rename(sessionDir(id), trashed)
	moved := err == nil
	if err != nil {
		// A missing trash folder is reported like a missing session folder,
		// so only the session folder's absence counts as already moved.
		if _, serr := e.root.Lstat(sessionDir(id)); !errors.Is(serr, fs.ErrNotExist) {
			return err
		}
	}
	e.at("moved")
	if err := e.reg.DeleteUpload(id); err != nil {
		return fmt.Errorf("delete its record: %w", err)
	}
	if moved {
		if err := e.root.RemoveAll(trashed); err != nil {
			logf("cannot empty %s; the next start removes it: %v", trashed, err)
		}
	}
	return nil
}
