package transfer

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/sandbox"
)

// maxLine is the longest parts.log line recovery reads. The engine's own
// lines stay far below it: reasons are cut short, and no path nears it.
const maxLine = 64 << 10

// found is what recovery made of one session.
type found struct {
	s *session
	// failed is why the session was found failed at this start, so that
	// its event is published.
	failed string
	// gone marks a session whose staging was removed at once.
	gone bool
	// unrecorded marks a completion whose records weren't confirmed, with
	// the actor and request it is recorded for and when it completed;
	// logged tells whether its completed line is, or will be, in the log.
	unrecorded bool
	logged     bool
	actor      events.Actor
	request    string
	done       time.Time
}

// recover rebuilds the sessions a previous run left, from the registry and
// their staging, before any call is answered.
func (e *Engine) recover() error {
	recs, bad, err := e.reg.Uploads()
	if err != nil {
		return err
	}
	for id, why := range bad {
		logf("deleting the record of upload %q, which can't be read: %v", id, why)
		e.deleteRecord(id)
	}
	known := map[string]bool{}
	var all []found
	removed := 0
	for _, rec := range recs {
		if err := e.validRecord(rec); err != nil {
			logf("deleting the record of upload %q: %v", rec.ID, err)
			e.deleteRecord(rec.ID)
			continue
		}
		known[rec.ID] = true
		if f, ok := e.recoverSession(rec); ok {
			all = append(all, f)
		} else {
			removed++
		}
	}

	// One wait budget for every record recovery waits for, so that a
	// stalled audit log delays the start once, not once per upload.
	ctx := events.WithWaitBudget(context.Background())
	counts := map[State]int{}
	again := 0
	for _, f := range all {
		if f.unrecorded {
			again++
			e.republish(ctx, f)
		}
	}
	for _, f := range all {
		s := f.s
		if f.failed != "" {
			e.publish(events.Event{
				Type:    events.UploadFailed,
				Actor:   events.Actor{ID: events.SystemID},
				Outcome: events.OutcomeError,
				Path:    truncate(s.path()),
				Size:    s.recvBytes,
				Detail:  f.failed,
				Upload:  s.totals(e.now(), ""),
			})
		}
		if f.gone {
			removed++
			continue
		}
		counts[s.state]++
		e.mu.Lock()
		if s.state == Receiving {
			s.counted = true
			e.open[s.rec.Owner]++
			e.openTotal++
		}
		e.sessions[s.rec.ID] = s
		e.mu.Unlock()
	}
	e.reportForeign(known)
	if len(all) > 0 || removed > 0 {
		logf("recovered %d uploads: %d receiving, %d completed (%d recorded again), %d aborted, %d expired, %d failed; %d not kept",
			len(all)-countGone(all), counts[Receiving], counts[Completed], again, counts[Aborted], counts[Expired], counts[Failed], removed)
	}
	e.wakeJanitor()
	return nil
}

func countGone(all []found) int {
	n := 0
	for _, f := range all {
		if f.gone {
			n++
		}
	}
	return n
}

func (e *Engine) deleteRecord(id string) {
	if err := e.reg.DeleteUpload(id); err != nil {
		logf("cannot delete the record of upload %q: %v", id, err)
	}
}

// validRecord checks a registry record as untrusted input.
func (e *Engine) validRecord(r Record) error {
	clean, err := sandbox.Clean(r.Dir)
	switch {
	case !ValidID(r.ID):
		return errors.New("malformed ID")
	case r.Owner == "":
		return errors.New("no owner")
	case err != nil || clean != r.Dir:
		return fmt.Errorf("the folder %q isn't a clean path", r.Dir)
	case !validName(r.Name):
		return fmt.Errorf("invalid name %q", r.Name)
	case r.Size < 0 || r.Size > MaxSize:
		return fmt.Errorf("size %d out of range", r.Size)
	case r.PartSize != e.partSize(r.Size) || r.PartCount != PartCount(r.Size, r.PartSize):
		return fmt.Errorf("%d parts of %d bytes don't fit size %d", r.PartCount, r.PartSize, r.Size)
	case r.Created.IsZero():
		return errors.New("no creation time")
	case !validClientKey(r.ClientKey):
		return errors.New("malformed client key")
	}
	return nil
}

func validName(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, "/\\") && !sandbox.IsReserved(name)
}

// validPath reports whether p is a clean path inside the served folder,
// outside its reserved names, that names a file.
func validPath(p string) bool {
	clean, err := sandbox.Clean(p)
	return err == nil && clean == p && p != "."
}

// variantOf reports whether got is name, or a name of the form fsops gives
// its numbered variants when name is taken: "a (2).bin" for "a.bin", the
// stem cut short when the whole would be longer than a name may be. It
// accepts more than fsops picks, never less.
func variantOf(name, got string) bool {
	if got == name {
		return true
	}
	ext := path.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	if stem == "" {
		stem, ext = name, ""
	}
	rest, ok := strings.CutSuffix(got, ext)
	open := strings.LastIndex(rest, " (")
	if !ok || open <= 0 || !strings.HasSuffix(rest, ")") {
		return false
	}
	digits := rest[open+2 : len(rest)-1]
	n, err := strconv.Atoi(digits)
	if err != nil || n < 1 || digits != strconv.Itoa(n) {
		return false
	}
	prefix, suffix := rest[:open], rest[open:]
	return prefix == stem || strings.HasPrefix(stem, prefix) && len(stem)+len(suffix)+len(ext) > 255
}

// fileState is what Lstat found of a staged file.
type fileState struct {
	info    fs.FileInfo
	missing bool
}

// errUntrusted marks staging that isn't plain files: what a link points to
// isn't the session's own.
var errUntrusted = errors.New("not a regular file")

func (e *Engine) stagedFile(id, name string) (fileState, error) {
	info, err := e.lstat(native(uploadsDir, id, name))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fileState{missing: true}, nil
	case err != nil:
		return fileState{}, err
	case !info.Mode().IsRegular():
		return fileState{}, fmt.Errorf("%s: %w", name, errUntrusted)
	}
	return fileState{info: info}, nil
}

// errBadLine marks a log whose content is wrong, as opposed to one that
// can't be read now.
type errBadLine struct {
	n   int
	err error
}

func (e *errBadLine) Error() string { return fmt.Sprintf("line %d: %v", e.n, e.err) }

// recoverSession rebuilds one session from its staging. It returns false
// when nothing is kept in memory: a create that never answered, a removal
// cut short, or staging that can't be read now, which is left for the next
// start with its record.
func (e *Engine) recoverSession(rec Record) (found, bool) {
	s := newSession(rec)
	id := rec.ID
	leave := func(err error) (found, bool) {
		logf("WARNING: upload %s is left for the next start: %v", id, err)
		return found{}, false
	}
	info, err := e.lstat(sessionDir(id))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		logf("deleting the record of upload %s, whose staging is gone", id)
		e.deleteRecord(id)
		return found{}, false
	case err != nil:
		return leave(err)
	case !info.IsDir():
		return e.untrusted(s, "its staging folder is not a folder"), true
	}
	logFile, lerr := e.stagedFile(id, logName)
	data, derr := e.stagedFile(id, dataName)
	switch err := errors.Join(lerr, derr); {
	case errors.Is(err, errUntrusted):
		return e.untrusted(s, fmt.Sprintf("its staged files can't be trusted: %v", err)), true
	case err != nil:
		return leave(err)
	}

	var end int64
	if !logFile.missing {
		if end, err = e.cutTornLine(id); err != nil {
			return leave(err)
		}
	}
	if end == 0 {
		switch {
		case logFile.missing && !data.missing && data.info.Size() > 0:
			return e.foundFailed(s, "its log is gone"), true
		case logFile.missing || data.missing:
			// A create that never answered: its folder goes before its
			// record, as any removal's does.
			if err := e.removeStaging(id); err != nil {
				logf("cannot remove the staging of upload %s, whose create never answered: %v", id, err)
			}
			return found{}, false
		}
	}

	r, err := e.replay(s, end)
	var bad *errBadLine
	switch {
	case errors.As(err, &bad):
		l, ok, lerr := e.loggedFailure(id, end)
		switch {
		case lerr != nil:
			return leave(lerr)
		case ok:
			return e.failedBefore(s, l), true
		}
		return e.foundFailed(s, fmt.Sprintf("its log can't be trusted: %v", err)), true
	case err != nil:
		return leave(err)
	}
	s.over = r.lastAt
	f := found{s: s}
	switch r.last {
	case "", opPart:
		return e.receiving(s, r, data), true
	case opFinishing:
		f, err := e.reconcile(s, r, data)
		if err != nil {
			return leave(err)
		}
		return f, true
	case opCompleted:
		e.completedAt(s, r.completed.Path)
		f.unrecorded, f.logged, f.actor, f.request, f.done = true, true, *r.completed.Actor, r.completed.Request, r.completed.At
	case opRecorded:
		s.over = r.completed.At
		e.completedAt(s, r.completed.Path)
	case opAborted, opExpired, opFailed:
		s.mu.Lock()
		s.state = map[string]State{opAborted: Aborted, opExpired: Expired, opFailed: Failed}[r.last]
		s.reason = r.end.Reason
		e.dropData(s)
		s.closeFiles()
		s.mu.Unlock()
	}
	return f, true
}

// receiving keeps a session that may receive more parts, once its data
// holds every part its log names.
func (e *Engine) receiving(s *session, r replayed, data fileState) found {
	switch {
	case data.missing:
		return e.foundFailed(s, "its staged data is gone")
	case data.info.Size() < r.dataEnd:
		return e.foundFailed(s, fmt.Sprintf("its staged data holds %d bytes, not the %d its logged parts need", data.info.Size(), r.dataEnd))
	}
	s.state = Receiving
	return found{s: s}
}

// reconcile decides what became of a completion the log says was under
// way: whether the file was placed at the path it names. An error reading
// the file, other than its absence, decides nothing and is returned.
func (e *Engine) reconcile(s *session, r replayed, data fileState) (found, error) {
	fin := r.finishing
	target := filepath.FromSlash(fin.Path)
	placed := false
	pinfo, err := e.served.Lstat(target)
	switch {
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, syscall.ENOTDIR):
	case err != nil:
		return found{}, err
	case !pinfo.Mode().IsRegular():
	case data.missing:
		// Renamed: the file must be the one whose size and modification
		// time were logged before.
		placed = pinfo.Size() == *fin.Size && pinfo.ModTime().UnixNano() == *fin.MTime
	default:
		// On Windows too, os.Root's Lstat reads the file's ID through a
		// handle, which os.SameFile compares.
		placed = os.SameFile(pinfo, data.info)
	}
	switch {
	case !placed && data.missing:
		return e.foundFailed(s, fmt.Sprintf("its staged data is gone, and the file at its target isn't the one placed: %s", fin.Path)), nil
	case !placed:
		return e.receiving(s, r, data), nil
	}

	if err := e.files.RecordAdopted(s.rec.Owner, fin.Path, *fin.Size, *fin.MTime); err != nil {
		// Only an answer about the file is final: that it is gone or isn't
		// the one placed any more, or that its path can't hold a record. Any
		// other error may pass, so the next start tries again.
		o := e.files.Outcome(err)
		if o != events.OutcomeNotFound && o != events.OutcomeInvalid && !errors.Is(err, fs.ErrNotExist) {
			return found{}, fmt.Errorf("record the uploader of %s: %w", fin.Path, err)
		}
		logf("upload %s is placed at %s, but its uploader can't be recorded: %v", s.rec.ID, fin.Path, err)
	}
	done := e.now()
	s.mu.Lock()
	logged := e.logOrKeep(s, line{Op: opCompleted, Path: fin.Path, Actor: fin.Actor, Request: fin.Request, At: done})
	s.mu.Unlock()
	s.over = done
	e.completedAt(s, fin.Path)
	return found{s: s, unrecorded: true, logged: logged, actor: *fin.Actor, request: fin.Request, done: done}, nil
}

// completedAt makes s a completed session whose file is at p.
func (e *Engine) completedAt(s *session, p string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = Completed
	s.result = &Result{Path: p, Name: path.Base(p), Size: s.rec.Size, CompositeSHA256: s.composite()}
	e.dropData(s)
	if len(s.unlogged) == 0 {
		s.closeFiles()
	}
}

// foundFailed makes s a session found failed at this start: it logs why,
// so that the next start doesn't report it again, and removes the data.
func (e *Engine) foundFailed(s *session, reason string) found {
	reason = truncate(reason)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state, s.over, s.reason = Failed, e.now(), reason
	logf("upload %s failed: %s", s.rec.ID, reason)
	if s.log == nil {
		// A lost log is made again for the failed line.
		if f, err := e.root.OpenFile(native(uploadsDir, s.rec.ID, logName), os.O_WRONLY|os.O_CREATE, 0o600); err == nil {
			s.log = f
		}
	}
	e.logOrKeep(s, line{Op: opFailed, Reason: reason, At: s.over})
	e.dropData(s)
	if len(s.unlogged) == 0 {
		s.closeFiles()
	}
	return found{s: s, failed: reason}
}

// failedBefore keeps a session whose log ends with the failed line a
// previous start wrote, though lines before it don't validate.
func (e *Engine) failedBefore(s *session, l line) found {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state, s.over, s.reason = Failed, l.At, l.Reason
	e.dropData(s)
	return found{s: s}
}

// untrusted reports a session whose staging isn't plain files, and removes
// it at once, without a tombstone: no log can be written there, and what a
// link points to isn't the session's own. Moving the folder into the trash
// and removing it there follows no link.
func (e *Engine) untrusted(s *session, reason string) found {
	reason = truncate(reason)
	logf("WARNING: upload %s failed: %s", s.rec.ID, reason)
	s.state, s.reason, s.dataGone = Failed, reason, true
	if err := e.removeStaging(s.rec.ID); err != nil {
		logf("cannot remove the staging of upload %s: %v", s.rec.ID, err)
	}
	return found{s: s, failed: reason, gone: true}
}

// cutTornLine cuts off a last line that has no newline, which a power cut
// between an append and its flush can leave, so that the next append doesn't
// join it. It returns where the log's last whole line ends.
func (e *Engine) cutTornLine(id string) (int64, error) {
	f, err := e.root.OpenFile(native(uploadsDir, id, logName), os.O_RDWR, 0)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return 0, err
	}
	size := info.Size()
	end, err := lastNewline(f, size)
	if err != nil || end == size {
		return end, err
	}
	logf("cutting off the torn last line of upload %s's log (%d bytes)", id, size-end)
	if err := f.Truncate(end); err != nil {
		return 0, err
	}
	return end, e.syncFile(f)
}

// lastNewline returns the offset just after the last newline in the first
// size bytes of f, or 0 if there is none.
func lastNewline(f io.ReaderAt, size int64) (int64, error) {
	buf := make([]byte, 4096)
	for off := size; off > 0; {
		n := int64(len(buf))
		if off < n {
			n = off
		}
		off -= n
		if _, err := f.ReadAt(buf[:n], off); err != nil && !errors.Is(err, io.EOF) {
			return 0, err
		}
		if i := bytes.LastIndexByte(buf[:n], '\n'); i >= 0 {
			return off + int64(i) + 1, nil
		}
	}
	return 0, nil
}

// loggedFailure returns the failed line a log ends with: a session found
// failed, and reported, before. Its data is gone already.
func (e *Engine) loggedFailure(id string, end int64) (line, bool, error) {
	f, err := e.openLog(id)
	if err != nil {
		return line{}, false, err
	}
	defer f.Close()
	start, err := lastNewline(f, end-1)
	switch {
	case err != nil:
		return line{}, false, err
	case end-start > maxLine:
		return line{}, false, nil
	}
	b := make([]byte, end-start)
	if _, err := f.ReadAt(b, start); err != nil {
		return line{}, false, err
	}
	l, err := decodeLine(b)
	if err != nil || l.Op != opFailed || l.At.IsZero() {
		return line{}, false, nil
	}
	return l, true, nil
}

// replayed is what a session's log says happened to it.
type replayed struct {
	// last is the op of the last line that changes the state; reject lines
	// don't.
	last      string
	finishing line
	completed line
	end       line
	// dataEnd is where the furthest logged part ends in the data.
	dataEnd int64
	lastAt  time.Time
}

type logReader interface {
	io.Reader
	io.ReaderAt
	io.Closer
}

// replay reads the first end bytes of the session's log and rebuilds the
// session's parts, hashes and counters from them.
func (e *Engine) replay(s *session, end int64) (replayed, error) {
	if end == 0 {
		return replayed{}, nil
	}
	f, err := e.openLog(s.rec.ID)
	if err != nil {
		return replayed{}, err
	}
	defer f.Close()
	return replayFrom(s, io.LimitReader(f, end))
}

// replayFrom replays lines from r, checking each as untrusted input. An
// error of the content is an *errBadLine; any other is one of reading.
func replayFrom(s *session, r io.Reader) (replayed, error) {
	var rp replayed
	br := bufio.NewReaderSize(r, maxLine)
	for n := 1; ; n++ {
		b, err := br.ReadSlice('\n')
		switch {
		case errors.Is(err, io.EOF) && len(b) == 0:
			return rp, nil
		case errors.Is(err, bufio.ErrBufferFull):
			return rp, &errBadLine{n, fmt.Errorf("longer than %d bytes", maxLine)}
		case errors.Is(err, io.EOF):
			return rp, &errBadLine{n, errors.New("no newline")}
		case err != nil:
			return rp, err
		}
		l, err := decodeLine(b)
		if err == nil {
			err = rp.apply(s, l)
		}
		if err != nil {
			return rp, &errBadLine{n, err}
		}
	}
}

func decodeLine(b []byte) (line, error) {
	var l line
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&l); err != nil {
		return line{}, err
	}
	if dec.More() {
		return line{}, errors.New("more than one value")
	}
	return l, nil
}

// next lists the lines that may follow the last line that changed a
// session's state.
var next = map[string][]string{
	"":          {opPart, opReject, opFinishing, opAborted, opExpired, opFailed},
	opPart:      {opPart, opReject, opFinishing, opAborted, opExpired, opFailed},
	opFinishing: {opReject, opFinishing, opCompleted, opAborted, opExpired, opFailed},
	opCompleted: {opRecorded},
}

// apply checks one line against what came before it, and replays it.
func (r *replayed) apply(s *session, l line) error {
	if l.At.IsZero() {
		return errors.New("no time")
	}
	if !slices.Contains(next[r.last], l.Op) {
		return fmt.Errorf("a %q line can't follow a %q line", l.Op, r.last)
	}
	rec := s.rec
	switch l.Op {
	case opPart:
		if l.N < 1 || l.N > rec.PartCount || !isHex(l.SHA256, 64) {
			return fmt.Errorf("part %d with hash %q", l.N, l.SHA256)
		}
		var h [32]byte
		hex.Decode(h[:], []byte(l.SHA256))
		if s.has(l.N) {
			if s.hash(l.N) != h {
				return fmt.Errorf("part %d logged twice with different hashes", l.N)
			}
			break
		}
		s.keep(l.N, h)
		size := partLen(rec.Size, rec.PartSize, l.N)
		s.nReceived++
		s.recvBytes += size
		s.lastPart = l.At
		r.dataEnd = max(r.dataEnd, int64(l.N-1)*rec.PartSize+size)
	case opReject:
		s.rejected++
	case opFinishing:
		switch {
		case !validPath(l.Path) || !variantOf(rec.Name, path.Base(l.Path)):
			return fmt.Errorf("finishing at %q, for %q", l.Path, rec.Name)
		case l.Size == nil || *l.Size != rec.Size || l.MTime == nil || l.Actor == nil:
			return errors.New("finishing without the staged file's size, modification time or actor")
		case s.nReceived != rec.PartCount:
			return fmt.Errorf("finishing with %d of %d parts", s.nReceived, rec.PartCount)
		}
		r.finishing = l
	case opCompleted:
		if l.Path != r.finishing.Path || l.Actor == nil {
			return fmt.Errorf("completed at %q, but finishing at %q", l.Path, r.finishing.Path)
		}
		r.completed = l
	case opAborted:
		if l.By == "" {
			return errors.New("aborted by no one")
		}
		r.end = l
	case opExpired:
		if l.Reason == "" {
			return errors.New("expired for no reason")
		}
		r.end = l
	case opFailed:
		r.end = l
	}
	s.seen(l.IP)
	if l.Op != opReject {
		r.last = l.Op
	}
	r.lastAt = l.At
	return nil
}

// republish records a completion again whose records the previous run
// didn't see confirmed, as its completing request would have, and logs
// that they are once they are.
func (e *Engine) republish(ctx context.Context, f found) {
	s := f.s
	s.mu.Lock()
	res := *s.result
	placed := events.Event{
		Type:      events.FileUploaded,
		Actor:     f.actor,
		RequestID: f.request,
		Outcome:   events.OutcomeOK,
		Path:      truncate(logicalJoin(s.rec.Dir, res.Name)),
		Resolved:  res.Path,
		Size:      res.Size,
		Detail:    "recovered",
		Upload:    &events.UploadInfo{ID: s.rec.ID, Owner: s.rec.Owner},
	}
	ev := events.Event{
		Type:      events.UploadCompleted,
		Actor:     f.actor,
		RequestID: f.request,
		Outcome:   events.OutcomeOK,
		Path:      truncate(s.path()),
		Resolved:  res.Path,
		Size:      res.Size,
		Detail:    "recovered",
		Upload:    s.totals(f.done, res.CompositeSHA256),
	}
	s.mu.Unlock()

	var rerr error
	if e.audit != nil {
		rerr = e.audit.Record(ctx, e.named(placed), e.named(ev))
	} else {
		e.publish(placed, ev)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.resultErr = rerr
	switch {
	case rerr != nil:
		logf("the records of upload %s, completed before the last start, are still not confirmed: %v", s.rec.ID, rerr)
	case f.logged:
		e.logOrKeep(s, line{Op: opRecorded})
	}
	if len(s.unlogged) == 0 {
		s.closeFiles()
	}
}

// reportForeign logs the staging folders that have no record. Recovery
// neither trusts nor removes them: this server didn't make them with this
// state file.
func (e *Engine) reportForeign(known map[string]bool) {
	d, err := e.root.Open(uploadsDir)
	if err != nil {
		logf("cannot list the staging folder: %v", err)
		return
	}
	defer d.Close()
	entries, err := d.ReadDir(-1)
	if err != nil {
		logf("cannot list the staging folder: %v", err)
		return
	}
	for _, ent := range entries {
		if !known[ent.Name()] {
			logf("WARNING: %s has no record in the state file; it is left alone", path.Join(sandbox.UploadsDir, ent.Name()))
		}
	}
}
