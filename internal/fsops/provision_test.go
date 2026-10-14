package fsops

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/nobletk/gocalbox/internal/events"
)

func TestProvisionCreatesMissingFoldersAndCommits(t *testing.T) {
	e, rec := newObservedEnv(t)
	os.Mkdir(filepath.Join(e.root, "users"), 0o755)
	committed := false
	err := e.svc.Provision(bg, []Folder{
		{Path: "users", Detail: "layout", IfExists: Reuse},
		{Path: "users/alice", Detail: "home", IfExists: TakeOverEmpty},
		{Path: "public", Detail: "layout", IfExists: Refuse},
	}, func() error { committed = true; return nil })
	if err != nil || !committed {
		t.Fatalf("Provision: %v, committed %v", err, committed)
	}
	if !e.exists("users/alice") || !e.exists("public") {
		t.Error("folders missing")
	}
	evs := rec.all()
	if len(evs) != 2 {
		t.Fatalf("events: %+v", evs)
	}
	check(t, evs[0], events.FolderCreated, events.OutcomeOK, "users/alice")
	check(t, evs[1], events.FolderCreated, events.OutcomeOK, "public")
	if evs[0].Detail != "home" || evs[1].Detail != "layout" {
		t.Errorf("details %q, %q", evs[0].Detail, evs[1].Detail)
	}
}

func TestProvisionReportsEveryConflictAndCreatesNothing(t *testing.T) {
	e, rec := newObservedEnv(t)
	e.write("users/alice/notes.txt", "mine")
	e.write("public", "a file, not a folder")
	os.Mkdir(filepath.Join(e.root, "media"), 0o755)
	err := e.svc.Provision(bg, []Folder{
		{Path: "new", IfExists: Reuse},
		{Path: "users", IfExists: Reuse},
		{Path: "users/alice", IfExists: TakeOverEmpty},
		{Path: "public", IfExists: Reuse},
		{Path: "media", IfExists: Refuse},
	}, func() error { t.Error("commit ran despite conflicts"); return nil })
	var ce *ConflictError
	if !errors.As(err, &ce) || !errors.Is(err, ErrExists) || !slices.Equal(ce.Paths, []string{"users/alice", "public", "media"}) {
		t.Fatalf("err = %v", err)
	}
	if e.exists("new") || len(rec.all()) != 0 {
		t.Error("something was created")
	}
}

func TestProvisionTakesOverAnEmptyFolder(t *testing.T) {
	e, rec := newObservedEnv(t)
	os.MkdirAll(filepath.Join(e.root, "users", "alice"), 0o755)
	if err := e.svc.Provision(bg, []Folder{{Path: "users/alice", IfExists: TakeOverEmpty}}, nil); err != nil {
		t.Fatal(err)
	}
	if len(rec.all()) != 0 {
		t.Error("an existing folder was reported as created")
	}
}

func TestProvisionRefusesASymlinkInAFoldersPlace(t *testing.T) {
	e, _ := newObservedEnv(t)
	os.Mkdir(filepath.Join(e.root, "real"), 0o755)
	e.symlink("real", "users")
	err := e.svc.Provision(bg, []Folder{{Path: "users", IfExists: Reuse}}, nil)
	var ce *ConflictError
	if !errors.As(err, &ce) {
		t.Errorf("err = %v", err)
	}
}

func TestProvisionUndoesItsFoldersWhenCommitFails(t *testing.T) {
	e, rec := newObservedEnv(t)
	boom := errors.New("boom")
	err := e.svc.Provision(bg, []Folder{
		{Path: "users", IfExists: Reuse},
		{Path: "users/alice", IfExists: TakeOverEmpty},
	}, func() error { return boom })
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if e.exists("users") || len(rec.all()) != 0 {
		t.Error("folders or events left after a failed commit")
	}

	os.Mkdir(filepath.Join(e.root, "users"), 0o755)
	e.svc.Provision(bg, []Folder{{Path: "users", IfExists: Reuse}, {Path: "users/bob", IfExists: Reuse}}, func() error { return boom })
	if !e.exists("users") || e.exists("users/bob") {
		t.Error("a folder that existed before was removed, or the new one kept")
	}
}

func TestProvisionRejectsPathsOutsideTheLayout(t *testing.T) {
	e, _ := newObservedEnv(t)
	for _, p := range []string{"", "/users", "users/../x", "users/", "a//b", "..", "users/a\\b"} {
		if err := e.svc.Provision(bg, []Folder{{Path: p}}, nil); !errors.Is(err, ErrInvalidName) {
			t.Errorf("%q: %v", p, err)
		}
	}
}
