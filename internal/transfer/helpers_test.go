package transfer

import (
	"bytes"
	"context"
	"crypto/sha256"
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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/sandbox"
	"github.com/nobletk/gocalbox/internal/space"
)

const (
	alice = "u-alice"
	bob   = "u-bob"
	admin = "u-admin"
)

var (
	errForbidden    = errors.New("fake: forbidden")
	errParentAbsent = errors.New("fake: parent folder not found")
	errNotPlaced    = errors.New("fake: no longer the file that was placed")
)

type user struct {
	name    string
	admin   bool
	enabled bool
}

// fakeFiles decides like fsops would for a few users, and places files by
// linking them into the served folder.
type fakeFiles struct {
	root *os.Root

	mu      sync.Mutex
	users   map[string]*user
	deny    map[string]bool // folder → MayUpload refuses
	prepare error           // PrepareUpload's answer, when set
	adopt   func(rel string) error
	may     func()
	adopts  int
	// rename places files by renaming them, as on a volume without links.
	rename bool
	// linked runs once Adopt has placed the file.
	linked    func(rel string)
	recorded  []adoptedRecord
	recordErr error
	// onRecord runs once RecordAdopted has recorded.
	onRecord func()
}

type adoptedRecord struct {
	owner, rel  string
	size, mtime int64
}

func newFakeFiles(root *os.Root) *fakeFiles {
	return &fakeFiles{
		root: root,
		users: map[string]*user{
			alice: {name: "alice", enabled: true},
			bob:   {name: "bob", enabled: true},
			admin: {name: "root", admin: true, enabled: true},
		},
		deny: map[string]bool{},
	}
}

func (f *fakeFiles) Who(ctx context.Context) (string, bool, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := events.ActorFrom(ctx).ID
	u := f.users[id]
	if u == nil {
		return "", false, false
	}
	// As a policy may, a disabled account is named, but not enabled.
	return id, u.admin && u.enabled, u.enabled
}

func (f *fakeFiles) UserName(id string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if u := f.users[id]; u != nil {
		return u.name, true
	}
	return "", false
}

func (f *fakeFiles) PrepareUpload(ctx context.Context, dir, name string) (string, string, error) {
	f.mu.Lock()
	err := f.prepare
	f.mu.Unlock()
	if err != nil {
		return "", "", err
	}
	if _, _, ok := f.Who(ctx); !ok {
		return "", "", errParentAbsent
	}
	clean, err := sandbox.Clean(dir)
	if err != nil {
		return "", "", err
	}
	if info, err := f.root.Stat(filepath.FromSlash(clean)); err != nil || !info.IsDir() {
		return "", "", errParentAbsent
	}
	return clean, "key:" + clean, nil
}

func (f *fakeFiles) MayUpload(ctx context.Context, folder string) error {
	if _, _, ok := f.Who(ctx); !ok {
		return errParentAbsent
	}
	f.mu.Lock()
	hook, denied := f.may, f.deny[folder]
	f.mu.Unlock()
	if hook != nil {
		hook()
	}
	if denied {
		return errForbidden
	}
	return nil
}

func (f *fakeFiles) Adopt(ctx context.Context, staged, dir, name string, intent func(string) error) (string, events.Event, error) {
	f.mu.Lock()
	f.adopts++
	hook, place := f.adopt, f.root.Link
	if f.rename {
		place = f.root.Rename
	}
	f.mu.Unlock()
	clean, _ := sandbox.Clean(dir)
	rel := path.Join(clean, name)
	for i := 1; ; i++ {
		if _, err := f.root.Lstat(filepath.FromSlash(rel)); errors.Is(err, fs.ErrNotExist) {
			break
		}
		ext := path.Ext(name)
		rel = path.Join(clean, fmt.Sprintf("%s (%d)%s", strings.TrimSuffix(name, ext), i, ext))
	}
	if err := intent(rel); err != nil {
		return "", events.Event{}, fmt.Errorf("log the chosen name: %w", err)
	}
	if hook != nil {
		if err := hook(rel); err != nil {
			return "", events.Event{}, err
		}
	}
	if err := place(filepath.FromSlash(staged), filepath.FromSlash(rel)); err != nil {
		return "", events.Event{}, err
	}
	f.mu.Lock()
	linked := f.linked
	f.mu.Unlock()
	if linked != nil {
		linked(rel)
	}
	info, _ := f.root.Lstat(filepath.FromSlash(rel))
	return rel, events.Event{Type: events.FileUploaded, Actor: events.ActorFrom(ctx), Outcome: events.OutcomeOK,
		Path: dir + "/" + name, Resolved: rel, Size: info.Size()}, nil
}

func (f *fakeFiles) RecordAdopted(owner, rel string, size, mtime int64) error {
	f.mu.Lock()
	f.recorded = append(f.recorded, adoptedRecord{owner, rel, size, mtime})
	hook, err := f.onRecord, f.recordErr
	f.mu.Unlock()
	if hook != nil {
		hook()
	}
	return err
}

func (f *fakeFiles) Outcome(err error) events.Outcome {
	switch {
	case errors.Is(err, errForbidden), errors.Is(err, sandbox.ErrTraversal):
		return events.OutcomeDenied
	case errors.Is(err, errParentAbsent), errors.Is(err, errNotPlaced):
		return events.OutcomeNotFound
	}
	return events.OutcomeError
}

func (f *fakeFiles) set(fn func(f *fakeFiles)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

type fakeRegistry struct {
	mu      sync.Mutex
	recs    map[string]Record
	bad     map[string]error // records that can't be read
	putErr  error
	delErr  error
	listErr error
	deletes int
}

func (r *fakeRegistry) PutUpload(rec Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.putErr != nil {
		return r.putErr
	}
	if _, ok := r.recs[rec.ID]; ok {
		return errors.New("exists")
	}
	r.recs[rec.ID] = rec
	return nil
}

func (r *fakeRegistry) DeleteUpload(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.delErr != nil {
		return r.delErr
	}
	r.deletes++
	delete(r.recs, id)
	delete(r.bad, id)
	return nil
}

func (r *fakeRegistry) Uploads() ([]Record, map[string]error, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var recs []Record
	for _, rec := range r.recs {
		recs = append(recs, rec)
	}
	slices.SortFunc(recs, func(a, b Record) int { return strings.Compare(a.ID, b.ID) })
	bad := map[string]error{}
	for id, err := range r.bad {
		bad[id] = err
	}
	return recs, bad, r.listErr
}

func (r *fakeRegistry) has(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.recs[id]
	_, bad := r.bad[id]
	return ok || bad
}

// recBus keeps what is published. With full set, TryPublish gives up.
type recBus struct {
	mu      sync.Mutex
	evs     []events.Event
	tried   int
	full    bool
	publish func(events.Event)
}

func (b *recBus) Publish(ev events.Event) {
	b.mu.Lock()
	hook := b.publish
	b.evs = append(b.evs, ev)
	b.mu.Unlock()
	if hook != nil {
		hook(ev)
	}
}

func (b *recBus) TryPublish(ev events.Event) bool {
	b.mu.Lock()
	b.tried++
	hook, full := b.publish, b.full
	if !full {
		b.evs = append(b.evs, ev)
	}
	b.mu.Unlock()
	if hook != nil {
		hook(ev)
	}
	return !full
}

func (b *recBus) all() []events.Event {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Clone(b.evs)
}

func (b *recBus) of(t events.Type) []events.Event {
	var out []events.Event
	for _, ev := range b.all() {
		if ev.Type == t {
			out = append(out, ev)
		}
	}
	return out
}

func (b *recBus) reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.evs = nil
}

// fakeAudit applies policies C and D with answers set by the test.
type fakeAudit struct {
	mu       sync.Mutex
	paused   error
	recErr   error
	recorded [][]events.Event
	requests []string // the request of each Record
	// spend is how long each Record takes of its request's wait budget,
	// and left how much of a 10-second limit was left before each.
	spend time.Duration
	left  []time.Duration
	pub   *recBus
}

func (a *fakeAudit) Allow() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.paused != nil {
		return fmt.Errorf("%w: %v", events.ErrChangesPaused, a.paused)
	}
	return nil
}

func (a *fakeAudit) Record(ctx context.Context, evs ...events.Event) error {
	a.mu.Lock()
	a.recorded = append(a.recorded, evs)
	a.requests = append(a.requests, events.RequestIDFrom(ctx))
	a.left = append(a.left, events.WaitLeft(ctx, 10*time.Second))
	events.Waited(ctx, a.spend)
	err := a.recErr
	a.mu.Unlock()
	for _, ev := range evs {
		a.pub.Publish(ev)
	}
	return err
}

func (a *fakeAudit) RecordProtective(ctx context.Context, evs ...events.Event) error {
	return a.Record(ctx, evs...)
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type env struct {
	t      *testing.T
	dir    string // the served folder
	root   *os.Root
	e      *Engine
	files  *fakeFiles
	reg    *fakeRegistry
	bus    *recBus
	audit  *fakeAudit
	clock  *clock
	ledger *space.Ledger
	free   *int64
	mu     sync.Mutex
}

type option func(*Config, *env)

func withLimits(l Limits) option { return func(c *Config, _ *env) { c.Limits = l } }

// withEngine sets hooks of the engine before it recovers anything.
func withEngine(f func(*Engine)) option {
	return func(c *Config, _ *env) {
		prev := c.prepare
		c.prepare = func(e *Engine) {
			if prev != nil {
				prev(e)
			}
			f(e)
		}
	}
}

// testPartSize keeps the tests' files small: parts of 4 KiB.
const testPartSize = 4 << 10

// testAdmitWait keeps a wait for a slot that runs out short.
const testAdmitWait = 200 * time.Millisecond

// withFree adds a ledger measuring free bytes of the test's choosing, with
// no reserve.
func withFree(free int64) option {
	return func(c *Config, en *env) {
		en.free = &free
		en.ledger = space.NewLedger(func() (int64, error) {
			en.mu.Lock()
			defer en.mu.Unlock()
			return *en.free, nil
		}, 0)
		c.Ledger = en.ledger
	}
}

func newEnv(t *testing.T, opts ...option) *env {
	t.Helper()
	dir := t.TempDir()
	for _, d := range []string{"users/alice", "users/bob", "public"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	en := &env{t: t, dir: dir, reg: &fakeRegistry{recs: map[string]Record{}},
		clock: &clock{t: time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)}}
	en.start(opts...)
	return en
}

// start opens the served folder and starts an engine on it with the
// registry en holds, as the server's start does. Options run before the
// engine starts, so they can set up what its recovery meets.
func (en *env) start(opts ...option) {
	t := en.t
	t.Helper()
	root, err := os.OpenRoot(en.dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	st, err := sandbox.CheckStaging(root)
	if err != nil || !st.Usable() {
		t.Fatal(err, st.Problem)
	}
	t.Cleanup(func() { st.Close() })
	en.root, en.files, en.bus = root, newFakeFiles(root), &recBus{}
	en.audit = &fakeAudit{pub: en.bus}
	cfg := Config{Root: root, Staging: st, Files: en.files, Registry: en.reg, Events: en.bus, Audit: en.audit,
		JanitorEvery: -1, Now: en.clock.now, prepare: func(e *Engine) {
			e.partSize = func(int64) int64 { return testPartSize }
			e.admitWait = testAdmitWait
		}}
	for _, o := range opts {
		o(&cfg, en)
	}
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeWithin(t, e, context.Background()) })
	en.e = e
}

func (en *env) setFree(n int64) {
	en.mu.Lock()
	defer en.mu.Unlock()
	*en.free = n
}

func as(id string) context.Context {
	return events.WithRequestID(events.WithActor(context.Background(), events.Actor{ID: id, RemoteAddr: "192.0.2.7:4242"}), "req-"+id)
}

// file is a source file cut into parts by the engine's schedule, or by
// partSize when the test sets it.
type file struct {
	data     []byte
	partSize int64
}

func newFile(size int) file {
	b := make([]byte, size)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return file{data: b, partSize: testPartSize}
}

func (f file) parts() int { return PartCount(int64(len(f.data)), f.partSize) }

func (f file) part(n int) []byte {
	off := int64(n-1) * f.partSize
	return f.data[off:min(off+f.partSize, int64(len(f.data)))]
}

func (f file) sum(n int) string {
	h := sha256.Sum256(f.part(n))
	return hex.EncodeToString(h[:])
}

func (f file) composite() string {
	var hs [][sha256.Size]byte
	for n := 1; n <= f.parts(); n++ {
		hs = append(hs, sha256.Sum256(f.part(n)))
	}
	return Composite(hs)
}

func (en *env) create(user, dir, name string, f file) Created {
	en.t.Helper()
	c, err := en.e.Create(as(user), CreateRequest{Dir: dir, Name: name, Size: int64(len(f.data))})
	if err != nil {
		en.t.Fatalf("%s creates %s/%s: %v", user, dir, name, err)
	}
	return c
}

func (en *env) send(user, id string, f file, n int) (PartResult, error) {
	b := f.part(n)
	return en.e.Part(as(user), PartRequest{ID: id, N: n, SHA256: f.sum(n), Length: int64(len(b)), Body: bytes.NewReader(b)})
}

func (en *env) sendAll(user, id string, f file) {
	en.t.Helper()
	for n := 1; n <= f.parts(); n++ {
		if _, err := en.send(user, id, f, n); err != nil {
			en.t.Fatalf("part %d: %v", n, err)
		}
	}
}

func (en *env) session(id string) *session {
	en.t.Helper()
	s := en.e.lookup(id)
	if s == nil {
		en.t.Fatalf("no session %s", id)
	}
	return s
}

func (en *env) state(id string) State {
	s := en.session(id)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

func (en *env) staged(id string, name string) string {
	return filepath.Join(en.dir, sandbox.ReservedName, uploadsDir, id, name)
}

func (en *env) logLines(id string) []line {
	en.t.Helper()
	b, err := os.ReadFile(en.staged(id, logName))
	if err != nil {
		en.t.Fatal(err)
	}
	var out []line
	for _, l := range bytes.Split(bytes.TrimSpace(b), []byte("\n")) {
		if len(l) == 0 {
			continue
		}
		var x line
		if err := json.Unmarshal(l, &x); err != nil {
			en.t.Fatalf("parts.log line %q: %v", l, err)
		}
		out = append(out, x)
	}
	return out
}

func ops(ls []line) []string {
	var out []string
	for _, l := range ls {
		out = append(out, l.Op)
	}
	return out
}

func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

// gate is a body that delivers its first byte and then waits until opened.
type gate struct {
	data    []byte
	off     int
	opened  chan struct{}
	reached chan struct{}
	once    sync.Once
}

func newGate(data []byte) *gate {
	return &gate{data: data, opened: make(chan struct{}), reached: make(chan struct{})}
}

func (g *gate) Read(p []byte) (int, error) {
	if g.off == 1 {
		g.once.Do(func() { close(g.reached) })
		<-g.opened
	}
	if g.off >= len(g.data) {
		return 0, io.EOF
	}
	n := 1
	if g.off > 0 {
		n = copy(p, g.data[g.off:])
	} else {
		p[0] = g.data[0]
	}
	g.off += n
	return n, nil
}

func (g *gate) open() { close(g.opened) }

// within waits for a value from ch, failing the test after ten seconds
// rather than letting a regression hang the whole run.
func within[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(10 * time.Second):
		t.Fatal("waited ten seconds")
	}
	panic("unreachable")
}

// closeWithin closes e with ctx, and fails the test if Close hasn't
// returned within ten seconds.
func closeWithin(t *testing.T, e *Engine, ctx context.Context) error {
	t.Helper()
	closed := make(chan error, 1)
	go func() { closed <- e.Close(ctx) }()
	return within(t, closed)
}

// give sends on ch, and fails the test if nothing receives it within ten
// seconds.
func give(t *testing.T, ch chan<- struct{}) {
	t.Helper()
	select {
	case ch <- struct{}{}:
	case <-time.After(10 * time.Second):
		t.Fatal("waited ten seconds")
	}
}
