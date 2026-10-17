package load

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/nobletk/gocalbox/internal/audit"
	"github.com/nobletk/gocalbox/internal/authz"
	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/fsops"
	"github.com/nobletk/gocalbox/internal/sandbox"
	"github.com/nobletk/gocalbox/internal/space"
	"github.com/nobletk/gocalbox/internal/state"
	"github.com/nobletk/gocalbox/internal/transfer"
	"github.com/nobletk/gocalbox/internal/transfer/registry"
)

type StackOptions struct {
	// Work holds the served folder, the audit log and the state file. It
	// must be on the disk being measured.
	Work       string
	Users      int
	AuditWait  bool
	AuditParts bool
	MinFree    int64
}

// Stack is a server's upload path in one process, as start-up wires it, but
// without HTTP and without logins: the sandbox, the staging folder, the
// state file, the audit log with its policies, fsops and the engine.
type Stack struct {
	Engine *transfer.Engine
	Root   string
	Audit  string
	Users  []User
	undo   []func() error
}

// NewStack builds a stack in opts.Work for opts.Users contributors, each
// uploading into their home.
func NewStack(opts StackOptions) (_ *Stack, err error) {
	s := &Stack{Root: filepath.Join(opts.Work, "root"), Audit: filepath.Join(opts.Work, "audit.jsonl")}
	defer func() {
		if err != nil {
			s.Close()
		}
	}()
	pol := &staticPolicy{roles: map[string]authz.Role{}, names: map[string]string{}}
	var binds []authz.Binding
	for i := range opts.Users {
		id, name := fmt.Sprintf("u-load%02d", i), fmt.Sprintf("load%02d", i)
		home := "users/" + name
		if err := os.MkdirAll(filepath.Join(s.Root, filepath.FromSlash(home)), 0o755); err != nil {
			return nil, err
		}
		pol.roles[id], pol.names[id] = authz.Contributor, name
		binds = append(binds, authz.Binding{Subject: id, Folder: home, Grant: authz.GrantContributor, Home: true})
		s.Users = append(s.Users, User{API: &inProcess{id: id, name: name, s: s}, Dir: home})
	}
	pol.bindings = authz.NewBindings(binds)

	sb, err := sandbox.New(s.Root)
	if err != nil {
		return nil, err
	}
	s.undo = append(s.undo, sb.Close)
	w, err := audit.Open(s.Audit)
	if err != nil {
		return nil, err
	}
	s.undo = append(s.undo, w.Close)
	db, err := state.Open(filepath.Join(opts.Work, "state.db"))
	if err != nil {
		return nil, err
	}
	s.undo = append(s.undo, db.Close)
	st, err := sandbox.CheckStaging(sb.OSRoot())
	if err != nil {
		return nil, err
	}
	s.undo = append(s.undo, st.Close)
	if !st.Usable() {
		return nil, fmt.Errorf("the staging folder can't be used: %w", st.Problem)
	}
	volume, err := sb.OSRoot().Open(".")
	if err != nil {
		return nil, err
	}
	s.undo = append(s.undo, volume.Close)
	var ledger *space.Ledger
	if _, err := space.Free(volume); err == nil {
		ledger = space.NewLedger(func() (int64, error) { return space.Free(volume) }, opts.MinFree)
	}

	co := audit.NewCoalescer(w, 0, audit.LoginWindow)
	s.undo = append(s.undo, func() error { co.Close(); return nil })
	guard := audit.NewGuard(w.Err)
	bus := events.New()
	s.undo = append(s.undo, func() error { return bus.Close(context.Background()) })
	const wait = 10 * time.Second
	audit.Subscribe(bus, co, guard, audit.Keep{Parts: opts.AuditParts}, wait)
	rec := audit.NewRecorder(bus, guard, audit.RecorderOptions{Wait: opts.AuditWait, Timeout: wait})
	files := fsops.New(sb, bus, fsops.WithSpace(ledger), fsops.WithRecords(db), fsops.WithAudit(rec), fsops.WithStaging(st))
	files.SetPolicy(pol)
	e, err := transfer.New(transfer.Config{Root: sb.OSRoot(), Staging: st, Files: files, Registry: registry.New(db),
		Events: bus, Audit: rec, Ledger: ledger, AuditParts: opts.AuditParts})
	if err != nil {
		return nil, err
	}
	s.undo = append(s.undo, func() error { return e.Close(context.Background()) })
	s.Engine = e
	return s, nil
}

// Close stops the engine, then everything it used.
func (s *Stack) Close() error {
	var errs []error
	for i := len(s.undo) - 1; i >= 0; i-- {
		errs = append(errs, s.undo[i]())
	}
	s.undo = nil
	return errors.Join(errs...)
}

type staticPolicy struct {
	roles    map[string]authz.Role
	names    map[string]string
	bindings *authz.Bindings
}

func (p *staticPolicy) Subject(ctx context.Context) (fsops.Subject, bool) {
	id := events.ActorFrom(ctx).ID
	r, ok := p.roles[id]
	return fsops.Subject{ID: id, Role: r, Bindings: p.bindings}, ok
}

func (p *staticPolicy) UserName(id string) (string, bool) {
	n, ok := p.names[id]
	return n, ok
}

// inProcess calls the engine as one user, each call as its own request.
type inProcess struct {
	id, name string
	s        *Stack
}

func (a *inProcess) ctx(ctx context.Context) context.Context {
	return events.WithWaitBudget(events.WithActor(ctx, events.Actor{ID: a.id, Name: a.name, RemoteAddr: "127.0.0.1"}))
}

func (a *inProcess) Create(ctx context.Context, req transfer.CreateRequest) (transfer.Created, error) {
	return a.s.Engine.Create(a.ctx(ctx), req)
}

func (a *inProcess) Part(ctx context.Context, req transfer.PartRequest) (transfer.PartResult, error) {
	return a.s.Engine.Part(a.ctx(ctx), req)
}

func (a *inProcess) Complete(ctx context.Context, id, composite string) (transfer.Result, error) {
	return a.s.Engine.Complete(a.ctx(ctx), id, composite)
}
