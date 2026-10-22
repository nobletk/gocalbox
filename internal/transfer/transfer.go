// Package transfer is the resumable upload engine. A session receives one
// file in parts, in any order and in parallel, from the user who created it,
// keeps them in the staging folder, and finishes by placing the file in the
// served tree through Files.
package transfer

import (
	"cmp"
	"container/list"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/sandbox"
	"github.com/nobletk/gocalbox/internal/space"
)

// Files is how the engine reaches the served tree and asks who may do what.
// fsops.Service implements it.
type Files interface {
	// Who returns the user a request acts for, and whether they are an
	// admin; ok is false for a request without an enabled account.
	Who(ctx context.Context) (id string, admin, ok bool)
	// UserName names a user; false only for one known to have been
	// deleted, whose sessions then expire.
	UserName(id string) (string, bool)
	// PrepareUpload decides an upload into dir before any data is sent and
	// returns dir cleaned and the key of the folder.
	PrepareUpload(ctx context.Context, dir, name string) (clean, folder string, err error)
	// MayUpload decides in memory whether the user may still upload into
	// the folder with this key.
	MayUpload(ctx context.Context, folder string) error
	// Adopt places the staged file in dir and returns its path and the
	// file.uploaded event. It calls intent with the path it chose before
	// placing the file there.
	Adopt(ctx context.Context, staged, dir, name string, intent func(path string) error) (string, events.Event, error)
	// RecordAdopted writes the owner's uploader record of a file Adopt
	// placed at path, with the size and modification time logged before it
	// was placed, when a crash came between the two.
	RecordAdopted(owner, path string, size, mtime int64) error
	// Outcome classifies an error of these calls for the audit log.
	Outcome(err error) events.Outcome
}

// Registry keeps one record per session, outside the served folder.
type Registry interface {
	// PutUpload stores the record of a new session; it never replaces one.
	PutUpload(Record) error
	// DeleteUpload removes a record; a missing one is not an error.
	DeleteUpload(id string) error
	// Uploads lists every record, and in bad, by ID, why each record that
	// can't be read was refused.
	Uploads() (recs []Record, bad map[string]error, err error)
}

// Record is what the registry keeps of a session: who owns it and where it
// goes. It never changes.
type Record struct {
	ID      string
	Owner   string // user ID
	Session string // the login session that created it, for the audit log
	Dir     string // the target folder as the client gave it, cleaned
	Folder  string // the folder's key when the session was created
	Name    string

	Size      int64
	PartSize  int64
	PartCount int
	ClientKey string
	Created   time.Time
}

type Publisher interface {
	Publish(events.Event)
	TryPublish(events.Event) bool
}

// Limits are the engine's bounds. A zero field takes its default.
type Limits struct {
	MaxSize      int64 // largest declared size; 0 for none
	Window       int64 // most space a session holds in the ledger at a time
	MaxParallel  int   // parts a client is advised to send at once
	IdleTTL      time.Duration
	FirstPartTTL time.Duration
	MaxAge       time.Duration
	TombstoneTTL time.Duration
	IdleRelease  time.Duration // a session idle this long gives its window back

	MaxSessions      int // open sessions per user
	MaxSessionsTotal int
	MaxInflight      int // parts being received at once, server-wide
	MaxInflightUser  int
	MaxTombstones    int // finished sessions kept per user
}

var DefaultLimits = Limits{
	Window:           1 << 30,
	MaxParallel:      4,
	IdleTTL:          24 * time.Hour,
	FirstPartTTL:     time.Hour,
	MaxAge:           7 * 24 * time.Hour,
	TombstoneTTL:     24 * time.Hour,
	IdleRelease:      2 * time.Minute,
	MaxSessions:      16,
	MaxSessionsTotal: 256,
	MaxInflight:      32,
	MaxInflightUser:  8,
	MaxTombstones:    256,
}

func (l Limits) withDefaults() Limits {
	d := DefaultLimits
	set := func(v *int, def int) {
		if *v <= 0 {
			*v = def
		}
	}
	setD := func(v *time.Duration, def time.Duration) {
		if *v <= 0 {
			*v = def
		}
	}
	if l.Window <= 0 {
		l.Window = d.Window
	}
	set(&l.MaxParallel, d.MaxParallel)
	set(&l.MaxSessions, d.MaxSessions)
	set(&l.MaxSessionsTotal, d.MaxSessionsTotal)
	set(&l.MaxInflight, d.MaxInflight)
	set(&l.MaxInflightUser, d.MaxInflightUser)
	set(&l.MaxTombstones, d.MaxTombstones)
	setD(&l.IdleTTL, d.IdleTTL)
	setD(&l.FirstPartTTL, d.FirstPartTTL)
	setD(&l.MaxAge, d.MaxAge)
	setD(&l.TombstoneTTL, d.TombstoneTTL)
	setD(&l.IdleRelease, d.IdleRelease)
	l.MaxSize = max(l.MaxSize, 0)
	return l
}

type Config struct {
	// Root is the served folder; the engine opens the staging folder in it.
	Root *os.Root
	// Staging is what start-up found of the staging folder. Without a
	// usable one the engine is off and every call answers ErrUnavailable.
	Staging  *sandbox.Staging
	Files    Files
	Registry Registry
	Events   Publisher
	// Audit applies the audit log's policies to completions; nil records
	// without waiting.
	Audit events.Auditor
	// Ledger holds the space of the parts on their way; nil for none.
	Ledger *space.Ledger
	Limits Limits
	// AuditParts publishes accepted parts so that the audit log keeps them,
	// at the cost of waiting for it.
	AuditParts bool
	// JanitorEvery is the janitor's period: 30 seconds by default, and no
	// janitor at all when negative.
	JanitorEvery time.Duration
	// AdmitWait is how long a part waits for a server-wide slot: 10 seconds
	// when zero.
	AdmitWait time.Duration
	Now       func() time.Time

	// prepare, when set, runs once the engine is made and before it
	// recovers anything, so that tests can set its hooks.
	prepare func(*Engine)
}

const (
	uploadsDir = "uploads"
	trashDir   = "trash"
	dataName   = "data"
	logName    = "parts.log"
)

// Engine runs the upload sessions. Its methods are safe for concurrent use.
type Engine struct {
	files      Files
	reg        Registry
	pub        Publisher
	audit      events.Auditor
	ledger     *space.Ledger
	lim        Limits
	auditParts bool
	now        func() time.Time
	off        error
	maxFile    int64

	// root is the staging folder; the engine reaches staging only through
	// it. served is the served folder, which recovery only reads.
	root   *os.Root
	served *os.Root

	// mu guards the session map and the counters. It is never held
	// together with a session's lock.
	mu        sync.Mutex
	sessions  map[string]*session
	open      map[string]int
	openTotal int
	// userParts counts each user's parts being received or waiting for a
	// slot; slots counts the server-wide slots taken, and queue holds the
	// parts waiting for one, in arrival order. Once stopping is set, no part
	// waits; stopWaiting is closed then.
	userParts   map[string]int
	slots       int
	queue       list.List
	stopping    bool
	stopWaiting chan struct{}
	admitWait   time.Duration
	closed      bool
	finished    bool
	active      int
	drained     chan struct{}

	counters counters

	wake        chan struct{}
	stop        chan struct{}
	janitorDone chan struct{}
	// sweeping, guarded by mu, is whether a run of the janitor is under way;
	// swept, once Close waits for that run, is closed when it ends.
	sweeping bool
	swept    chan struct{}

	syncFile func(*os.File) error
	syncDir  func(root *os.Root, dir string) error
	writeLog func(f *os.File, b []byte, off int64) (int, error)
	writeAt  func(f *os.File, off int64) io.Writer
	partSize func(size int64) int64
	// admitted, when set, runs once a part has its slots, before the
	// session is checked again.
	admitted func(PartRequest)
	// point, when set, runs at the named points where a crash leaves
	// something recovery must tell apart.
	point func(name string)
	// lstat and openLog are how recovery reads the staging folder.
	lstat   func(name string) (fs.FileInfo, error)
	openLog func(id string) (logReader, error)
}

// New starts the engine. With a staging folder that start-up found
// unusable, the engine is off: it is returned all the same, and answers
// every call with ErrUnavailable.
func New(cfg Config) (*Engine, error) {
	if cfg.Files == nil || cfg.Registry == nil || cfg.Events == nil || cfg.Root == nil {
		return nil, errors.New("transfer: Files, Registry, Events and Root are required")
	}
	e := &Engine{
		files:       cfg.Files,
		reg:         cfg.Registry,
		pub:         cfg.Events,
		audit:       cfg.Audit,
		ledger:      cfg.Ledger,
		lim:         cfg.Limits.withDefaults(),
		auditParts:  cfg.AuditParts,
		now:         cfg.Now,
		sessions:    map[string]*session{},
		open:        map[string]int{},
		userParts:   map[string]int{},
		stopWaiting: make(chan struct{}),
		admitWait:   cmp.Or(cfg.AdmitWait, admitWait),
		drained:     make(chan struct{}),
		wake:        make(chan struct{}, 1),
		syncFile:    (*os.File).Sync,
		syncDir:     syncDir,
		writeLog:    (*os.File).WriteAt,
		writeAt:     func(f *os.File, off int64) io.Writer { return io.NewOffsetWriter(f, off) },
		partSize:    PartSize,
		served:      cfg.Root,
	}
	if cfg.prepare != nil {
		cfg.prepare(e)
	}
	if e.now == nil {
		e.now = func() time.Time { return time.Now().Round(0).UTC() }
	}
	switch {
	case cfg.Staging == nil:
		e.off = errors.New("no staging folder")
	case !cfg.Staging.Usable():
		e.off = cfg.Staging.Problem
	}
	if e.off != nil {
		return e, nil
	}
	e.maxFile = cfg.Staging.MaxFileSize
	root, err := cfg.Root.OpenRoot(sandbox.ReservedName)
	if err != nil {
		e.off = fmt.Errorf("open %s: %w", sandbox.ReservedName, err)
		return e, nil
	}
	e.root = root
	if e.lstat == nil {
		e.lstat = root.Lstat
	}
	if e.openLog == nil {
		e.openLog = func(id string) (logReader, error) { return root.Open(native(uploadsDir, id, logName)) }
	}
	if err := e.recover(); err != nil {
		root.Close()
		return nil, fmt.Errorf("transfer: recover the uploads: %w", err)
	}
	every := cfg.JanitorEvery
	if every == 0 {
		every = 30 * time.Second
	}
	if every > 0 {
		e.stop, e.janitorDone = make(chan struct{}), make(chan struct{})
		go e.janitor(every)
	}
	return e, nil
}

// Off returns why the engine is off, or nil.
func (e *Engine) Off() error { return e.off }

// Close stops the janitor and closes every staged file once the calls under
// way and a run of the janitor have returned. If ctx ends first, it returns
// and closes nothing, since what still runs may use the files; calling it
// again finishes the job. Sessions stay on disk.
func (e *Engine) Close(ctx context.Context) error {
	e.BeginShutdown()
	e.mu.Lock()
	if e.finished {
		e.mu.Unlock()
		return nil
	}
	if !e.closed {
		e.closed = true
		if e.active == 0 {
			close(e.drained)
		}
		if e.stop != nil {
			close(e.stop)
		}
	}
	var swept chan struct{}
	if e.sweeping {
		if e.swept == nil {
			e.swept = make(chan struct{})
		}
		swept = e.swept
	}
	e.mu.Unlock()

	if !waitFor(ctx, e.drained) {
		return fmt.Errorf("upload calls still running at shutdown: %w", ctx.Err())
	}
	if swept != nil && !waitFor(ctx, swept) {
		return fmt.Errorf("the upload janitor still running at shutdown: %w", ctx.Err())
	}
	e.mu.Lock()
	if e.finished {
		e.mu.Unlock()
		return nil
	}
	e.finished = true
	list := e.list()
	e.mu.Unlock()
	for _, s := range list {
		s.mu.Lock()
		// Past the deadline, waiting lines are left to the next start, which
		// decides from the log as it is.
		if ctx.Err() == nil {
			e.logPending(s)
		}
		s.releaseWindow()
		s.closeFiles()
		s.mu.Unlock()
	}
	if e.root != nil {
		return e.root.Close()
	}
	return nil
}

// Ready returns the error a call would get now for an engine that is off,
// ErrUnavailable, or one that is closing, ErrShuttingDown; otherwise nil.
// It lets a caller refuse a call before reading its request.
func (e *Engine) Ready() error {
	if e.off != nil {
		return ErrUnavailable
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return ErrShuttingDown
	}
	return nil
}

// waitFor waits until done is closed, or ctx ends first. A done that is
// closed already counts even if ctx has ended too, which select alone would
// decide at random.
func waitFor(ctx context.Context, done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
	}
	select {
	case <-done:
		return true
	case <-ctx.Done():
		return false
	}
}

// enter admits a call, unless the engine is off or closing.
func (e *Engine) enter() error {
	if e.off != nil {
		return ErrUnavailable
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return ErrShuttingDown
	}
	e.active++
	return nil
}

func (e *Engine) leave() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.active--; e.closed && e.active == 0 {
		close(e.drained)
	}
}

// list returns every session. The caller holds e.mu.
func (e *Engine) list() []*session {
	l := make([]*session, 0, len(e.sessions))
	for _, s := range e.sessions {
		l = append(l, s)
	}
	return l
}

func (e *Engine) lookup(id string) *session {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.sessions[id]
}

// caller is the user a call acts for.
type caller struct {
	id    string
	admin bool
}

// owned finds the session id for the user of ctx: its owner, or with admins
// set an admin too. Anyone else, and an unknown ID, get ErrUploadNotFound,
// recorded as refused.
func (e *Engine) owned(ctx context.Context, id string, admins bool) (*session, caller, error) {
	uid, admin, ok := e.files.Who(ctx)
	s := e.lookup(id)
	if s == nil {
		e.publish(e.event(ctx, events.UploadRejected, "", &events.UploadInfo{ID: id}, ErrUploadNotFound))
		return nil, caller{}, ErrUploadNotFound
	}
	if !ok || (s.rec.Owner != uid && !(admins && admin)) {
		ev := e.event(ctx, events.UploadRejected, s.path(), &events.UploadInfo{ID: id, Owner: s.rec.Owner}, ErrUploadNotFound)
		ev.Outcome = events.OutcomeDenied
		e.publish(ev)
		return nil, caller{}, ErrUploadNotFound
	}
	return s, caller{id: uid, admin: admin}, nil
}

// takeSession counts a new open session for user, or refuses it.
func (e *Engine) takeSession(user string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	switch {
	case e.open[user] >= e.lim.MaxSessions:
		e.counters.tooManyUploads.Add(1)
		return ErrTooManyUploads
	case e.openTotal >= e.lim.MaxSessionsTotal:
		e.counters.busy.Add(1)
		return ErrBusy
	}
	e.open[user]++
	e.openTotal++
	return nil
}

func (e *Engine) giveSession(user string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.uncount(user)
}

func (e *Engine) uncount(user string) {
	if e.open[user]--; e.open[user] <= 0 {
		delete(e.open, user)
	}
	e.openTotal--
}

// closeSlot stops counting s as open, once.
func (e *Engine) closeSlot(s *session) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if s.counted {
		s.counted = false
		e.uncount(s.rec.Owner)
	}
}

// windowFor is the most space a session holds at a time.
func (e *Engine) windowFor(partSize int64) int64 {
	return max(e.lim.Window, int64(e.lim.MaxParallel)*partSize)
}

func (e *Engine) at(point string) {
	if e.point != nil {
		e.point(point)
	}
}

func (e *Engine) wakeJanitor() {
	select {
	case e.wake <- struct{}{}:
	default:
	}
}

// event builds an event of the user of ctx about an upload. The engine
// builds a new UploadInfo for every event, since subscribers share it.
func (e *Engine) event(ctx context.Context, t events.Type, p string, up *events.UploadInfo, err error) events.Event {
	ev := events.Event{
		Type:      t,
		Actor:     events.ActorFrom(ctx),
		RequestID: events.RequestIDFrom(ctx),
		Outcome:   e.outcome(err),
		Path:      truncate(p),
		Upload:    up,
	}
	if err != nil {
		ev.Detail = truncate(err.Error())
	}
	return ev
}

// named adds the owner's name to an event another user caused.
func (e *Engine) named(ev events.Event) events.Event {
	if up := ev.Upload; up != nil && up.Owner != "" && up.Owner != ev.Actor.ID {
		up.OwnerName, _ = e.files.UserName(up.Owner)
	}
	return ev
}

// publish publishes evs, naming the owner in those another user caused. The
// caller holds no lock.
func (e *Engine) publish(evs ...events.Event) {
	for _, ev := range evs {
		e.pub.Publish(e.named(ev))
	}
}

func newID() string {
	var b [16]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func trashName() string {
	var b [8]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func native(parts ...string) string { return filepath.FromSlash(path.Join(parts...)) }

func sessionDir(id string) string { return native(uploadsDir, id) }

// stagedPath names a session's data from the served folder, as Adopt takes
// it.
func stagedPath(id string) string { return path.Join(sandbox.UploadsDir, id, dataName) }

// clientAddr is the address of the request's client, without its port.
func clientAddr(ctx context.Context) string {
	a := events.ActorFrom(ctx).RemoteAddr
	if host, _, err := net.SplitHostPort(a); err == nil {
		return host
	}
	return a
}

// shownID is an upload ID as an event names it: one that isn't an ID is cut
// short, since a client chooses it.
func shownID(id string) string {
	if len(id) > 64 {
		return strings.ToValidUTF8(id[:64], "") + "…(truncated)"
	}
	return id
}

func logicalJoin(dir, name string) string {
	if dir == "" || dir == "." {
		return name
	}
	return strings.TrimRight(dir, "/") + "/" + name
}

const maxLogged = 1024

func truncate(s string) string {
	if len(s) <= maxLogged {
		return s
	}
	return strings.ToValidUTF8(s[:maxLogged], "") + "…(truncated)"
}

func logf(format string, args ...any) { log.Printf("uploads: "+format, args...) }
