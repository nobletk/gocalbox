package transfer

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nobletk/gocalbox/internal/audit"
	"github.com/nobletk/gocalbox/internal/authz"
	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/fsops"
	"github.com/nobletk/gocalbox/internal/sandbox"
	"github.com/nobletk/gocalbox/internal/state"
)

var _ Files = (*fsops.Service)(nil)

// stateRegistry is the registry in the state file, as the package
// registry keeps it; that package imports this one.
type stateRegistry struct{ db *state.DB }

func (r stateRegistry) PutUpload(rec Record) error {
	return r.db.Update(func(tx *state.Tx) error {
		return tx.PutUpload(state.Upload{ID: rec.ID, Owner: rec.Owner, Session: rec.Session, Dir: rec.Dir, Folder: rec.Folder,
			Name: rec.Name, Size: rec.Size, PartSize: rec.PartSize, PartCount: rec.PartCount, ClientKey: rec.ClientKey, Created: rec.Created})
	})
}

func (r stateRegistry) DeleteUpload(id string) error {
	return r.db.Update(func(tx *state.Tx) error { return tx.DeleteUpload(id) })
}

// policy decides like the accounts do, for two contributors with homes and
// a public folder open to every user. With denyAll it knows no one.
type policy struct {
	mu       sync.Mutex
	roles    map[string]authz.Role
	bindings *authz.Bindings
	denyAll  bool
}

func newPolicy() *policy {
	p := &policy{roles: map[string]authz.Role{alice: authz.Contributor, bob: authz.Contributor}}
	p.bind(authz.GrantContributor)
	return p
}

func (p *policy) bind(public authz.Grant) {
	p.bindings = authz.NewBindings([]authz.Binding{
		{Subject: alice, Folder: "users/alice", Grant: authz.GrantContributor, Home: true},
		{Subject: bob, Folder: "users/bob", Grant: authz.GrantContributor, Home: true},
		{Subject: authz.Everyone, Folder: "public", Grant: public},
	})
}

func (p *policy) Subject(ctx context.Context) (fsops.Subject, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	id := events.ActorFrom(ctx).ID
	r, ok := p.roles[id]
	if !ok || p.denyAll {
		return fsops.Subject{}, false
	}
	return fsops.Subject{ID: id, Role: r, Bindings: p.bindings}, true
}

func (p *policy) UserName(id string) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.roles[id]; !ok {
		return "", false
	}
	return id[2:], true
}

type stack struct {
	t      *testing.T
	dir    string
	db     *state.DB
	guard  *audit.Guard
	writer *audit.Writer
	files  *fsops.Service
	policy *policy
	audit  string
	e      *Engine
	close  func()
}

// newStack builds the upload path as start-up wires it; without links set,
// the staging volume is taken to have no hard links.
func newStack(t *testing.T, links ...bool) *stack {
	t.Helper()
	dir := t.TempDir()
	for _, d := range []string{"users/alice", "users/bob", "public"} {
		os.MkdirAll(filepath.Join(dir, d), 0o755)
	}
	sb, err := sandbox.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	st, err := sandbox.CheckStaging(sb.OSRoot())
	if err != nil || !st.Usable() {
		t.Fatal(err, st.Problem)
	}
	if len(links) > 0 {
		st.Links = links[0]
	}
	db, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	w, err := audit.Open(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	co := audit.NewCoalescer(w, 0, audit.LoginWindow)
	guard := audit.NewGuard(w.Err)
	bus := events.New()
	audit.Subscribe(bus, co, guard, audit.Keep{}, 10*time.Second)
	rec := audit.NewRecorder(bus, guard, audit.RecorderOptions{Wait: true, Timeout: 10 * time.Second})
	files := fsops.New(sb, bus, fsops.WithRecords(db), fsops.WithAudit(rec), fsops.WithStaging(st))
	p := newPolicy()
	files.SetPolicy(p)
	e, err := New(Config{Root: sb.OSRoot(), Staging: st, Files: files, Registry: stateRegistry{db}, Events: bus, Audit: rec})
	if err != nil {
		t.Fatal(err)
	}
	s := &stack{t: t, dir: dir, db: db, guard: guard, writer: w, files: files, policy: p, audit: auditPath, e: e}
	s.close = sync.OnceFunc(func() {
		e.Close(context.Background())
		bus.Close(context.Background())
		co.Close()
		w.Close()
		db.Close()
		st.Close()
		sb.Close()
	})
	t.Cleanup(s.close)
	return s
}

// asUser is a request of the user id, with its own wait budget.
func asUser(id string) context.Context {
	return events.WithWaitBudget(events.WithRequestID(events.WithActor(context.Background(),
		events.Actor{ID: id, Name: id[2:], RemoteAddr: "192.0.2.9:1"}), "req-"+id))
}

type upload struct {
	data     []byte
	partSize int64
}

func newUpload(size int, seed byte) upload {
	b := make([]byte, size)
	for i := range b {
		b[i] = byte(i%251) + seed
	}
	ps := PartSize(int64(size))
	return upload{data: b, partSize: ps}
}

func (u upload) part(n int) []byte {
	off := int64(n-1) * u.partSize
	return u.data[off:min(off+u.partSize, int64(len(u.data)))]
}

func (u upload) sum(n int) string {
	h := sha256.Sum256(u.part(n))
	return hex.EncodeToString(h[:])
}

func (u upload) composite() string {
	var hs [][sha256.Size]byte
	for n := 1; n <= PartCount(int64(len(u.data)), u.partSize); n++ {
		hs = append(hs, sha256.Sum256(u.part(n)))
	}
	return Composite(hs)
}

func (s *stack) send(user, id string, u upload, n int) error {
	b := u.part(n)
	_, err := s.e.Part(asUser(user), PartRequest{ID: id, N: n, SHA256: u.sum(n), Length: int64(len(b)), Body: bytes.NewReader(b)})
	return err
}

func (s *stack) upload(user, dir, name string, u upload) (Result, error) {
	s.t.Helper()
	c, err := s.e.Create(asUser(user), CreateRequest{Dir: dir, Name: name, Size: int64(len(u.data))})
	if err != nil {
		return Result{}, err
	}
	for n := 1; n <= c.PartCount; n++ {
		if err := s.send(user, c.UploadID, u, n); err != nil {
			return Result{}, err
		}
	}
	return s.e.Complete(asUser(user), c.UploadID, u.composite())
}

func (s *stack) records() []events.Event {
	s.t.Helper()
	f, err := os.Open(s.audit)
	if err != nil {
		s.t.Fatal(err)
	}
	defer f.Close()
	var out []events.Event
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		var r struct{ Event events.Event }
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			s.t.Fatal(err)
		}
		out = append(out, r.Event)
	}
	return out
}

func types(evs []events.Event) []events.Type {
	var out []events.Type
	for _, ev := range evs {
		out = append(out, ev.Type)
	}
	return out
}

func TestAnUploadThroughTheRealStack(t *testing.T) {
	s := newStack(t)
	u := newUpload(8<<20+1000, 0)
	res, err := s.upload(alice, "users/alice", "a.bin", u)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(s.dir, "users", "alice", "a.bin"))
	if err != nil || !bytes.Equal(got, u.data) || res.Path != "users/alice/a.bin" {
		t.Fatalf("placed %+v: %v", res, err)
	}
	info, _ := os.Stat(filepath.Join(s.dir, "users", "alice", "a.bin"))
	var up state.Uploader
	var ok bool
	if err := s.db.View(func(tx *state.Tx) error {
		up, ok, err = tx.Uploader("users/alice/a.bin")
		return err
	}); err != nil || !ok {
		t.Fatalf("uploader record: %v, %v", ok, err)
	}
	if up.User != alice || up.Size == nil || *up.Size != info.Size() || up.MTime == nil || *up.MTime != info.ModTime().UnixNano() {
		t.Errorf("uploader record %+v", up)
	}
	var recs []state.Upload
	s.db.View(func(tx *state.Tx) error {
		return tx.Uploads(func(id string, r state.Upload, err error) error { recs = append(recs, r); return err })
	})
	if len(recs) != 1 || recs[0].Owner != alice || recs[0].Dir != "users/alice" || recs[0].Folder != "users/alice" || recs[0].PartCount != 2 {
		t.Errorf("registry %+v", recs)
	}
	// Policy D: the records are on disk once complete has answered.
	if got := types(s.records()); !slices.Equal(got, []events.Type{events.UploadCreated, events.FileUploaded, events.UploadCompleted}) {
		t.Errorf("audit log %v", got)
	}
	done := s.records()[2]
	if done.Upload == nil || done.Upload.SHA256 != u.composite() || done.Upload.Received != 2 || done.Resolved != "users/alice/a.bin" {
		t.Errorf("upload.completed %+v", done)
	}
}

func TestPolicyCPausesNewSessionsAndCompletionOnly(t *testing.T) {
	s := newStack(t)
	u := newUpload(8<<20+1, 1)
	c, err := s.e.Create(asUser(alice), CreateRequest{Dir: "public", Name: "a.bin", Size: int64(len(u.data)), ClientKey: "k"})
	if err != nil {
		t.Fatal(err)
	}
	s.guard.Trip(errors.New("disk full"))
	if _, err := s.e.Create(asUser(alice), CreateRequest{Dir: "public", Name: "b", Size: 1}); !errors.Is(err, events.ErrChangesPaused) {
		t.Errorf("a new session: %v", err)
	}
	if r, err := s.e.Create(asUser(alice), CreateRequest{Dir: "public", Name: "a.bin", Size: int64(len(u.data)), ClientKey: "k"}); err != nil || !r.Resumed {
		t.Errorf("resume: %+v, %v", r, err)
	}
	for n := 1; n <= 2; n++ {
		if err := s.send(alice, c.UploadID, u, n); err != nil {
			t.Errorf("part %d: %v", n, err)
		}
	}
	if _, err := s.e.Status(asUser(alice), c.UploadID, nil); err != nil {
		t.Errorf("status: %v", err)
	}
	if _, err := s.e.Complete(asUser(alice), c.UploadID, u.composite()); !errors.Is(err, events.ErrChangesPaused) {
		t.Errorf("complete: %v", err)
	}
	if exists(filepath.Join(s.dir, "public", "a.bin")) {
		t.Error("a paused completion placed the file")
	}
	if _, err := s.e.Abort(asUser(alice), c.UploadID); err != nil {
		t.Errorf("abort: %v", err)
	}
}

func TestARoleTakenAwayStopsTheUpload(t *testing.T) {
	s := newStack(t)
	u := newUpload(8<<20+1, 2)
	c, err := s.e.Create(asUser(alice), CreateRequest{Dir: "public", Name: "a.bin", Size: int64(len(u.data))})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.send(alice, c.UploadID, u, 1); err != nil {
		t.Fatal(err)
	}
	s.policy.mu.Lock()
	s.policy.bind(authz.GrantViewer)
	s.policy.mu.Unlock()
	if err := s.send(alice, c.UploadID, u, 2); !errors.Is(err, fsops.ErrForbidden) {
		t.Errorf("a part after demotion: %v", err)
	}
	s.policy.mu.Lock()
	s.policy.bind(authz.GrantContributor)
	s.policy.mu.Unlock()
	if err := s.send(alice, c.UploadID, u, 2); err != nil {
		t.Fatal(err)
	}
	s.policy.mu.Lock()
	s.policy.bind(authz.GrantViewer)
	s.policy.mu.Unlock()
	if _, err := s.e.Complete(asUser(alice), c.UploadID, u.composite()); !errors.Is(err, fsops.ErrForbidden) {
		t.Errorf("complete after demotion: %v", err)
	}
	if exists(filepath.Join(s.dir, "public", "a.bin")) {
		t.Error("placed after demotion")
	}
}

func TestTwoUsersUploadTheSameName(t *testing.T) {
	s := newStack(t)
	a, err := s.upload(alice, "public", "x.bin", newUpload(100, 3))
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.upload(bob, "public", "x.bin", newUpload(200, 4))
	if err != nil {
		t.Fatal(err)
	}
	if a.Path != "public/x.bin" || b.Path != "public/x (1).bin" {
		t.Errorf("paths %s and %s", a.Path, b.Path)
	}
	s.db.View(func(tx *state.Tx) error {
		for path, who := range map[string]string{a.Path: alice, b.Path: bob} {
			if r, ok, err := tx.Uploader(path); err != nil || !ok || r.User != who {
				t.Errorf("%s: %+v %v %v", path, r, ok, err)
			}
		}
		return nil
	})
}

func TestWithoutAnyoneTheEngineAnswersNoOne(t *testing.T) {
	s := newStack(t)
	u := newUpload(10, 5)
	c, err := s.e.Create(asUser(alice), CreateRequest{Dir: "public", Name: "a.bin", Size: int64(len(u.data))})
	if err != nil {
		t.Fatal(err)
	}
	s.send(alice, c.UploadID, u, 1)
	s.policy.mu.Lock()
	s.policy.denyAll = true
	s.policy.mu.Unlock()
	for name, err := range map[string]error{
		"part":     s.send(alice, c.UploadID, u, 1),
		"status":   second(s.e.Status(asUser(alice), c.UploadID, nil)),
		"abort":    second(s.e.Abort(asUser(alice), c.UploadID)),
		"complete": second(s.e.Complete(asUser(alice), c.UploadID, u.composite())),
	} {
		if !errors.Is(err, ErrUploadNotFound) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := s.e.List(asUser(alice), false); !errors.Is(err, ErrNoAccount) {
		t.Errorf("list: %v", err)
	}
	if _, err := s.e.Create(asUser(alice), CreateRequest{Dir: "public", Name: "b", Size: 1}); !errors.Is(err, fsops.ErrParentNotFound) {
		t.Errorf("create: %v", err)
	}
}

func second[T any](_ T, err error) error { return err }

func TestCreateIsDecidedLikeAnyUpload(t *testing.T) {
	s := newStack(t)
	s.policy.mu.Lock()
	s.policy.bind(authz.GrantViewer)
	s.policy.mu.Unlock()
	for dir, want := range map[string]error{
		"public":            fsops.ErrForbidden,
		"users/bob":         fsops.ErrParentNotFound,
		"users/alice/nope":  fsops.ErrParentNotFound,
		".gocalbox/uploads": sandbox.ErrReserved,
	} {
		if _, err := s.e.Create(asUser(alice), CreateRequest{Dir: dir, Name: "a", Size: 1}); !errors.Is(err, want) {
			t.Errorf("%s: %v, want %v", dir, err, want)
		}
	}
	if _, err := s.e.Create(asUser(alice), CreateRequest{Dir: "users/alice", Name: ".gocalbox", Size: 1}); !errors.Is(err, sandbox.ErrReserved) {
		t.Errorf("a reserved name: %v", err)
	}
}

func TestCompleteDecidesOnTheFolderAsItIsNow(t *testing.T) {
	s := newStack(t)
	if _, err := s.files.Mkdir(asUser(alice), "public", "sub"); err != nil {
		t.Fatal(err)
	}
	u := newUpload(1000, 6)
	c, err := s.e.Create(asUser(alice), CreateRequest{Dir: "public/sub", Name: "a.bin", Size: int64(len(u.data))})
	if err != nil {
		t.Fatal(err)
	}
	s.send(alice, c.UploadID, u, 1)
	if _, err := s.files.Move(asUser(alice), "public/sub", "public/moved"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.e.Complete(asUser(alice), c.UploadID, u.composite()); !errors.Is(err, fsops.ErrParentNotFound) {
		t.Fatalf("complete into a folder that moved away: %v", err)
	}
	if st, _ := s.e.Status(asUser(alice), c.UploadID, nil); st.State != Receiving {
		t.Errorf("state %s", st.State)
	}
	if _, err := s.files.Mkdir(asUser(alice), "public", "sub"); err != nil {
		t.Fatal(err)
	}
	res, err := s.e.Complete(asUser(alice), c.UploadID, u.composite())
	if err != nil || res.Path != "public/sub/a.bin" {
		t.Errorf("complete into the new folder: %+v, %v", res, err)
	}
}

func TestPolicyDWithAFailingAuditLog(t *testing.T) {
	s := newStack(t)
	u := newUpload(1000, 7)
	c, err := s.e.Create(asUser(alice), CreateRequest{Dir: "users/alice", Name: "a.bin", Size: int64(len(u.data))})
	if err != nil {
		t.Fatal(err)
	}
	s.send(alice, c.UploadID, u, 1)
	restore := events.SetLostOutput(io.Discard)
	defer restore()
	s.writer.Close()
	res, err := s.e.Complete(asUser(alice), c.UploadID, u.composite())
	if !errors.Is(err, events.ErrNotRecorded) || res.Path != "users/alice/a.bin" {
		t.Fatalf("complete with the audit log closed: %+v, %v", res, err)
	}
	var up state.Uploader
	var ok bool
	s.db.View(func(tx *state.Tx) error { up, ok, err = tx.Uploader("users/alice/a.bin"); return err })
	if !ok || up.User != alice || !exists(filepath.Join(s.dir, "users", "alice", "a.bin")) {
		t.Errorf("uploader %+v %v", up, ok)
	}
	if again, err2 := s.e.Complete(asUser(alice), c.UploadID, u.composite()); again != res || !errors.Is(err2, events.ErrNotRecorded) {
		t.Errorf("the tombstone: %+v, %v", again, err2)
	}
	if _, err := s.e.Create(asUser(alice), CreateRequest{Dir: "users/alice", Name: "b", Size: 1}); !errors.Is(err, events.ErrChangesPaused) {
		t.Errorf("a new session after the failure: %v", err)
	}
}

func TestAnUploadPlacedByRenaming(t *testing.T) {
	s := newStack(t, false)
	u := newUpload(8<<20+10, 8)
	res, err := s.upload(alice, "users/alice", "a.bin", u)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(s.dir, filepath.FromSlash(res.Path))); !bytes.Equal(got, u.data) {
		t.Error("the placed file differs")
	}
	var up state.Uploader
	var ok bool
	s.db.View(func(tx *state.Tx) error { up, ok, err = tx.Uploader(res.Path); return err })
	if !ok || up.User != alice || up.Size == nil || *up.Size != int64(len(u.data)) {
		t.Errorf("uploader %+v %v", up, ok)
	}
}

func TestAFolderChangeIsntHeldUpByASlowCompletion(t *testing.T) {
	s := newStack(t)
	u := newUpload(1000, 9)
	c, err := s.e.Create(asUser(alice), CreateRequest{Dir: "users/alice", Name: "a.bin", Size: int64(len(u.data))})
	if err != nil {
		t.Fatal(err)
	}
	s.send(alice, c.UploadID, u, 1)
	held, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	s.e.syncFile = func(f *os.File) error {
		if strings.HasSuffix(f.Name(), logName) {
			once.Do(func() { close(held); <-release })
		}
		return f.Sync()
	}
	done := make(chan error)
	go func() {
		_, err := s.e.Complete(asUser(alice), c.UploadID, u.composite())
		done <- err
	}()
	within(t, held) // the finishing line is being flushed
	made := make(chan error)
	go func() {
		_, err := s.files.Mkdir(asUser(bob), "users/bob", "d")
		made <- err
	}()
	select {
	case err := <-made:
		if err != nil {
			t.Error(err)
		}
	case <-time.After(5 * time.Second):
		t.Error("a new folder waited for the completion's log")
	}
	close(release)
	if err := within(t, done); err != nil {
		t.Fatal(err)
	}
}
