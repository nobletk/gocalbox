package transfer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"sync"

	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/space"
)

type PartRequest struct {
	ID     string
	N      int
	SHA256 string // 64 lowercase hex characters
	// Length is the body's length when the client declared it, or -1.
	Length int64
	Body   io.Reader
}

type PartResult struct {
	Part      int    `json:"part"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
	Received  int    `json:"received"`
	PartCount int    `json:"partCount"`
	Duplicate bool   `json:"duplicate,omitempty"`
}

var copyBufs = sync.Pool{New: func() any { b := make([]byte, 1<<20); return &b }}

// Part receives part req.N of an upload. A part already received with the
// same hash is read and discarded, and answered as a duplicate.
func (e *Engine) Part(ctx context.Context, req PartRequest) (PartResult, error) {
	if err := e.enter(); err != nil {
		return PartResult{}, err
	}
	defer e.leave()
	if !ValidID(req.ID) || req.N < 1 {
		e.publish(e.event(ctx, events.UploadRejected, "", &events.UploadInfo{ID: shownID(req.ID), Part: req.N}, ErrInvalidPart))
		return PartResult{}, ErrInvalidPart
	}
	if !isHex(req.SHA256, 2*sha256.Size) {
		e.publish(e.event(ctx, events.UploadRejected, "", &events.UploadInfo{ID: req.ID, Part: req.N}, ErrMissingChecksum))
		return PartResult{}, ErrMissingChecksum
	}
	s, _, err := e.owned(ctx, req.ID, false)
	if err != nil {
		return PartResult{}, err
	}
	if err := e.files.MayUpload(ctx, s.rec.Folder); err != nil {
		return PartResult{}, e.refusePart(ctx, s, req.N, err)
	}

	s.mu.Lock()
	expected, dup, err := s.check(req)
	s.mu.Unlock()
	if err != nil {
		return PartResult{}, e.refusePart(ctx, s, req.N, err)
	}
	release, err := e.admit(s.rec.Owner)
	if err != nil {
		return PartResult{}, err
	}
	defer release()
	if dup {
		return e.duplicate(ctx, s, req, expected)
	}
	if e.admitted != nil {
		e.admitted(req)
	}

	s.mu.Lock()
	expected, dup, err = s.check(req)
	if err == nil && !dup {
		err = e.cover(s, expected)
	}
	if err == nil && !dup {
		if oerr := e.openData(s); errors.Is(oerr, fs.ErrNotExist) {
			ev, ferr := e.fail(ctx, s, fmt.Sprintf("the staged data is gone: %v", oerr))
			s.mu.Unlock()
			e.failed(s, ev)
			return PartResult{}, ferr
		} else if oerr != nil {
			err = fmt.Errorf("open the staged data: %w", oerr)
		}
	}
	if err != nil {
		s.mu.Unlock()
		return PartResult{}, e.refusePart(ctx, s, req.N, err)
	}
	if dup {
		s.mu.Unlock()
		return e.duplicate(ctx, s, req, expected)
	}
	s.inflight[req.N] = expected
	s.inBytes += expected
	data := s.data
	s.mu.Unlock()

	got := e.receive(data, int64(req.N-1)*s.rec.PartSize, expected, req.Body)
	return e.finishPart(ctx, s, req, expected, got)
}

// check decides what a part may be before anything is read: the error that
// refuses it, or whether it is a duplicate. The caller holds s.mu.
func (s *session) check(req PartRequest) (expected int64, dup bool, err error) {
	switch s.state {
	case Receiving:
	case Completing:
		return 0, false, ErrCompleting
	default:
		return 0, false, closed(s.state, s.reason)
	}
	if req.N > s.rec.PartCount {
		return 0, false, ErrInvalidPart
	}
	expected = partLen(s.rec.Size, s.rec.PartSize, req.N)
	if req.Length >= 0 && req.Length != expected {
		return 0, false, ErrPartSizeMismatch
	}
	if s.has(req.N) {
		h := s.hash(req.N)
		if hex.EncodeToString(h[:]) == req.SHA256 {
			return expected, true, nil
		}
		return 0, false, ErrPartConflict
	}
	if _, ok := s.inflight[req.N]; ok {
		return 0, false, ErrPartInProgress
	}
	return expected, false, nil
}

// cover makes sure the session's window holds every part in flight, the
// next one included, growing it as far as the window size. The caller holds
// s.mu.
func (e *Engine) cover(s *session, next int64) error {
	if e.ledger == nil {
		return nil
	}
	if s.window == nil {
		w, err := e.ledger.Reserve(0)
		if err != nil {
			return err
		}
		s.window = w
	}
	need := s.inBytes + next
	if s.window.Left() >= need {
		return nil
	}
	target := max(need, min(s.rec.Size-s.recvBytes, e.windowFor(s.rec.PartSize)))
	return s.window.Grow(target - s.window.Left())
}

// duplicate reads and discards a part received before with the same hash.
func (e *Engine) duplicate(ctx context.Context, s *session, req PartRequest, expected int64) (PartResult, error) {
	if _, err := io.CopyN(io.Discard, req.Body, expected+1); err != nil && !errors.Is(err, io.EOF) {
		return PartResult{}, fmt.Errorf("%w: %v", ErrPartAborted, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != Receiving {
		return PartResult{}, s.stateErr()
	}
	s.retries++
	s.seen(clientAddr(ctx))
	return PartResult{Part: req.N, Size: expected, SHA256: req.SHA256, Received: s.nReceived, PartCount: s.rec.PartCount, Duplicate: true}, nil
}

// received is what became of a part's body: its hash, or the error that
// ends it.
type received struct {
	sum string
	// write is an error of writing the staged data, sync one of flushing
	// it, body one of the request's body, or ErrPartSizeMismatch for a body
	// of another length.
	write, sync, body error
}

// receive writes exactly expected bytes of body at off and makes them
// durable.
func (e *Engine) receive(data *os.File, off, expected int64, body io.Reader) received {
	buf := copyBufs.Get().(*[]byte)
	defer copyBufs.Put(buf)
	h := sha256.New()
	w := &errWriter{w: e.writeAt(data, off)}
	copied, err := io.CopyBuffer(w, io.TeeReader(io.LimitReader(body, expected), h), *buf)
	switch {
	case w.err != nil:
		return received{write: w.err}
	case err != nil:
		return received{body: fmt.Errorf("%w: %v", ErrPartAborted, err)}
	case copied < expected:
		return received{body: ErrPartSizeMismatch}
	}
	if more, err := io.ReadFull(body, (*buf)[:1]); more > 0 {
		return received{body: ErrPartSizeMismatch}
	} else if !errors.Is(err, io.EOF) {
		return received{body: fmt.Errorf("%w: %v", ErrPartAborted, err)}
	}
	if err := e.syncFile(data); err != nil {
		return received{sync: err}
	}
	return received{sum: hexSum(h)}
}

func hexSum(h hash.Hash) string { return hex.EncodeToString(h.Sum(nil)) }

type errWriter struct {
	w   io.Writer
	err error
}

func (w *errWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	if err != nil && w.err == nil {
		w.err = err
	}
	return n, err
}

// finishPart records a part whose body was read: accepted if it is whole
// and matches its hash, refused otherwise. A write the file system refused
// for lack of space or for the file's size only refuses the part. Any
// other error of the staged data fails the session, a failed flush above
// all: the kernel may report a write lost by one part to another part's
// flush of the same file, so no part of it can be trusted afterwards.
func (e *Engine) finishPart(ctx context.Context, s *session, req PartRequest, expected int64, got received) (PartResult, error) {
	refusal, broken := got.body, got.sync
	switch {
	case got.write != nil && isNoSpace(got.write):
		refusal = noSpace(got.write)
	case got.write != nil && isTooBig(got.write):
		refusal = fmt.Errorf("%w: %v", ErrTooLargeForVolume, got.write)
	case got.write != nil:
		broken = got.write
	case refusal == nil && broken == nil && got.sum != req.SHA256:
		refusal = ErrChecksumMismatch
	}

	s.mu.Lock()
	delete(s.inflight, req.N)
	s.inBytes -= expected
	if s.state != Receiving {
		e.dropData(s)
		err := s.stateErr()
		s.mu.Unlock()
		return PartResult{}, err
	}
	if broken != nil {
		ev, err := e.fail(ctx, s, fmt.Sprintf("cannot write part %d: %v", req.N, broken))
		s.mu.Unlock()
		e.failed(s, ev)
		return PartResult{}, err
	}
	if refusal != nil {
		s.mu.Unlock()
		return PartResult{}, e.refusePart(ctx, s, req.N, refusal)
	}
	e.at("written")
	if err := e.appendLine(s, line{Op: opPart, N: req.N, SHA256: got.sum, IP: clientAddr(ctx)}, true); errors.Is(err, space.ErrInsufficient) {
		s.mu.Unlock()
		return PartResult{}, e.refusePart(ctx, s, req.N, err)
	} else if err != nil {
		ev, ferr := e.fail(ctx, s, fmt.Sprintf("cannot log part %d: %v", req.N, err))
		s.mu.Unlock()
		e.failed(s, ev)
		return PartResult{}, ferr
	}
	e.at("logged")
	var raw [sha256.Size]byte
	hex.Decode(raw[:], []byte(got.sum))
	s.keep(req.N, raw)
	s.nReceived++
	s.recvBytes += expected
	s.lastPart = e.now()
	if s.window != nil {
		s.window.Consume(expected)
	}
	s.seen(clientAddr(ctx))
	res := PartResult{Part: req.N, Size: expected, SHA256: got.sum, Received: s.nReceived, PartCount: s.rec.PartCount}
	ev := e.event(ctx, events.UploadPartReceived, s.path(), s.info(req.N, got.sum), nil)
	s.mu.Unlock()

	ev.Size = expected
	if e.auditParts {
		e.publish(ev)
	} else {
		e.pub.TryPublish(e.named(ev))
	}
	return res, nil
}

// refusePart records a refused part and returns err. Refusals that are only
// a matter of timing or of the session's state are not recorded; others are
// counted, and logged in parts.log while it is receiving.
func (e *Engine) refusePart(ctx context.Context, s *session, n int, err error) error {
	switch {
	case errors.Is(err, ErrPartInProgress), errors.Is(err, ErrCompleting), errors.Is(err, ErrClosed),
		errors.Is(err, ErrPartAborted):
		return err
	}
	s.mu.Lock()
	s.rejected++
	if s.state == Receiving {
		// Only a number the session has goes in the log, which recovery
		// reads as untrusted input.
		logged := n
		if n < 1 || n > s.rec.PartCount {
			logged = 0
		}
		if lerr := e.appendLine(s, line{Op: opReject, N: logged, Reason: reasonOf(err), IP: clientAddr(ctx)}, false); lerr != nil {
			logf("cannot log a refused part of upload %s: %v", s.rec.ID, lerr)
		}
	}
	up := s.info(n, "")
	s.mu.Unlock()
	e.publish(e.event(ctx, events.UploadRejected, s.path(), up, err))
	return err
}

// reasonOf is the code of an engine refusal, or the error's text.
func reasonOf(err error) string {
	var te *Error
	if errors.As(err, &te) {
		return te.Code
	}
	if errors.Is(err, space.ErrInsufficient) {
		return "insufficient_storage"
	}
	return truncate(err.Error())
}
