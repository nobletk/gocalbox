package transfer

import (
	"context"
	"encoding/hex"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nobletk/gocalbox/internal/events"
)

// MaxHashes is the most part hashes one status call may ask for.
const MaxHashes = 16

type Status struct {
	UploadID  string             `json:"uploadId"`
	State     State              `json:"state"`
	Reason    string             `json:"reason,omitempty"`
	Dir       string             `json:"dir"`
	Name      string             `json:"name"`
	Size      int64              `json:"size"`
	PartSize  int64              `json:"partSize"`
	PartCount int                `json:"partCount"`
	Received  []Range            `json:"received"`
	InFlight  []int              `json:"inFlight"`
	Hashes    map[string]*string `json:"hashes,omitempty"`
	Created   time.Time          `json:"created"`
	ExpiresAt time.Time          `json:"expiresAt"`
	Result    *Result            `json:"result,omitempty"`
	Owner     *Owner             `json:"owner,omitempty"`
}

type Owner struct {
	ID       string `json:"id"`
	Username string `json:"username,omitempty"`
}

// Status describes an upload to its owner or an admin, with the stored
// hashes of the parts numbered in hashes.
func (e *Engine) Status(ctx context.Context, id string, hashes []int) (Status, error) {
	if err := e.enter(); err != nil {
		return Status{}, err
	}
	defer e.leave()
	if !ValidID(id) || len(hashes) > MaxHashes {
		e.publish(e.event(ctx, events.UploadRejected, "", &events.UploadInfo{ID: shownID(id)}, ErrInvalidRequest))
		return Status{}, ErrInvalidRequest
	}
	s, who, err := e.owned(ctx, id, true)
	if err != nil {
		return Status{}, err
	}
	st := e.status(s, hashes)
	if who.admin {
		st.Owner = e.owner(s.rec.Owner)
	}
	return st, nil
}

func (e *Engine) status(s *session, hashes []int) Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Status{
		UploadID:  s.rec.ID,
		State:     s.state,
		Reason:    shownReason(s.state, s.reason),
		Dir:       s.rec.Dir,
		Name:      s.rec.Name,
		Size:      s.rec.Size,
		PartSize:  s.rec.PartSize,
		PartCount: s.rec.PartCount,
		Received:  s.ranges(false),
		InFlight:  s.inFlight(),
		Created:   s.rec.Created,
		ExpiresAt: e.expiresAt(s),
		Result:    s.result,
	}
	if len(hashes) > 0 {
		st.Hashes = map[string]*string{}
		for _, n := range hashes {
			var v *string
			if n >= 1 && n <= s.rec.PartCount && s.has(n) {
				h := s.hash(n)
				x := hex.EncodeToString(h[:])
				v = &x
			}
			st.Hashes[strconv.Itoa(n)] = v
		}
	}
	return st
}

// shownReason is why a session ended, as status tells it: a failure's
// reason without the detail after its first ": ", which can carry the
// system's error text and names inside the staging folder. The whole reason
// stays in parts.log, the console and the audit log.
func shownReason(st State, reason string) string {
	if st != Failed {
		return reason
	}
	cause, _, _ := strings.Cut(reason, ": ")
	return cause
}

func (e *Engine) owner(id string) *Owner {
	o := &Owner{ID: id}
	o.Username, _ = e.files.UserName(id)
	return o
}

type AbortResult struct {
	UploadID string `json:"uploadId"`
	State    State  `json:"state"`
}

// Abort ends a receiving upload for its owner or an admin and removes its
// data. An upload that is already aborted, expired or failed answers with
// that state.
func (e *Engine) Abort(ctx context.Context, id string) (AbortResult, error) {
	if err := e.enter(); err != nil {
		return AbortResult{}, err
	}
	defer e.leave()
	if !ValidID(id) {
		e.publish(e.event(ctx, events.UploadRejected, "", &events.UploadInfo{ID: shownID(id)}, ErrInvalidRequest))
		return AbortResult{}, ErrInvalidRequest
	}
	s, who, err := e.owned(ctx, id, true)
	if err != nil {
		return AbortResult{}, err
	}
	s.mu.Lock()
	switch s.state {
	case Receiving:
	case Completing, Completed:
		defer s.mu.Unlock()
		return AbortResult{}, s.stateErr()
	default:
		defer s.mu.Unlock()
		return AbortResult{UploadID: id, State: s.state}, nil
	}
	e.end(s, Aborted, line{Op: opAborted, By: who.id})
	ev := e.event(ctx, events.UploadAborted, s.path(), s.totals(e.now(), ""), nil)
	ev.Size = s.recvBytes
	s.mu.Unlock()
	e.closeSlot(s)
	e.publish(ev)
	return AbortResult{UploadID: id, State: Aborted}, nil
}

// List describes the uploads of the user of ctx, newest first; with all
// set, an admin gets everyone's.
func (e *Engine) List(ctx context.Context, all bool) ([]Status, error) {
	if err := e.enter(); err != nil {
		return nil, err
	}
	defer e.leave()
	uid, admin, ok := e.files.Who(ctx)
	if !ok {
		return nil, ErrNoAccount
	}
	all = all && admin
	e.mu.Lock()
	var mine []*session
	for _, s := range e.sessions {
		if all || s.rec.Owner == uid {
			mine = append(mine, s)
		}
	}
	e.mu.Unlock()
	slices.SortFunc(mine, func(a, b *session) int {
		if c := b.rec.Created.Compare(a.rec.Created); c != 0 {
			return c
		}
		return strings.Compare(a.rec.ID, b.rec.ID)
	})
	out := make([]Status, 0, len(mine))
	owners := map[string]*Owner{}
	for _, s := range mine {
		st := e.status(s, nil)
		if admin {
			if owners[s.rec.Owner] == nil {
				owners[s.rec.Owner] = e.owner(s.rec.Owner)
			}
			o := *owners[s.rec.Owner]
			st.Owner = &o
		}
		out = append(out, st)
	}
	return out, nil
}
