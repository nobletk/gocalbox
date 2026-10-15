package fsops

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/sandbox"
)

func TestMoveHomeMovesTheFolderWithItsRecords(t *testing.T) {
	a := newAccessEnv(t)
	a.upload(alice, "users/alice", "a.txt", "a")
	a.mkdir(alice, "users/alice", "docs")
	a.upload(alice, "users/alice/docs", "b.txt", "b")
	os.Mkdir(filepath.Join(a.root, "users", ".deleted"), 0o755)
	actx := as(admin)

	to := "users/.deleted/alice-20261015-u-alice"
	if err := a.svc.MoveHome(actx, "users/alice", to, "home of deleted user alice"); err != nil {
		t.Fatal(err)
	}
	if a.exists("users/alice") || a.read(to+"/docs/b.txt") != "b" {
		t.Error("the home wasn't moved")
	}
	for _, p := range []string{"a.txt", "docs", "docs/b.txt"} {
		if got := a.uploader(to + "/" + p); got != alice {
			t.Errorf("%s: uploader %q", p, got)
		}
		if _, ok := a.record("users/alice/" + p); ok {
			t.Errorf("%s: a record is left at the old place", p)
		}
	}
	ev := a.rec.last(t)
	check(t, ev, events.FileMoved, events.OutcomeOK, "users/alice")
	if ev.Target != to || ev.ResolvedTarget != to || ev.Detail != "home of deleted user alice" || ev.Actor.ID != admin {
		t.Errorf("event %+v", ev)
	}

	if err := a.svc.MoveHome(actx, to, "users/alice", "home restored"); err != nil || !a.exists("users/alice/a.txt") || a.uploader("users/alice/a.txt") != alice {
		t.Errorf("moving it back: %v", err)
	}
}

func TestMoveHomeRefusals(t *testing.T) {
	a := newAccessEnv(t)
	a.write("users/file.txt", "f")
	for _, tc := range []struct {
		from, to string
		want     error
	}{
		{"users/nobody", "users/x", ErrNotFound},
		{"users/file.txt", "users/x", ErrNotDir},
		{"users/alice", "users/bob", ErrExists},
		{"users/alice", "users/.deleted/alice", ErrParentNotFound},
		{"users/alice", "../alice", ErrInvalidName},
		{"users/alice", "/users/x", ErrInvalidName},
		{"users/../users/alice", "users/x", ErrInvalidName},
		{"", "users/x", ErrInvalidName},
	} {
		if err := a.svc.MoveHome(bg, tc.from, tc.to, "test"); !errors.Is(err, tc.want) {
			t.Errorf("%q to %q: %v, want %v", tc.from, tc.to, err, tc.want)
		}
	}
	if !a.exists("users/alice") || !a.exists("users/bob") {
		t.Error("a refused move moved a home")
	}
}

// A bound folder can't be moved by a user, but the server moves a home.
func TestMoveHomeIgnoresTheBoundFolderRule(t *testing.T) {
	a := newAccessEnv(t)
	shown(t, errOf(a.svc.Move(as(admin), "users/bob", "public/bob")), ErrBoundFolder, "the admin moves bob's home")
	ok(t, a.svc.MoveHome(bg, "users/bob", "users/bob-old", "test"), "the server moves bob's home")
}

func TestMoveHomeMovesTheFolderBackWhenTheRecordsFail(t *testing.T) {
	a := newAccessEnv(t)
	a.upload(alice, "users/alice", "a.txt", "a")
	a.db.Close()
	if err := a.svc.MoveHome(bg, "users/alice", "users/alice-old", "test"); err == nil {
		t.Fatal("moved without its records")
	}
	if !a.exists("users/alice/a.txt") || a.exists("users/alice-old") {
		t.Error("the folder wasn't moved back")
	}
}

func TestBindFolderCommitsTheStoredSpelling(t *testing.T) {
	a := newAccessEnv(t)
	a.write("notes.txt", "n")
	for _, tc := range []struct{ folder, want string }{
		{"media", "media"},
		{"/projects/team/", "projects/team"},
		{"projects/../media", "media"},
		{"/", "."},
	} {
		var got string
		err := a.svc.BindFolder(as(admin), tc.folder, func(stored string) error { got = stored; return nil })
		if err != nil || got != tc.want {
			t.Errorf("bind %q: committed %q, %v; want %q", tc.folder, got, err, tc.want)
		}
	}
	if _, err := os.Stat(filepath.Join(a.root, "MEDIA")); err == nil {
		var got string
		if err := a.svc.BindFolder(as(admin), "MEDIA", func(stored string) error { got = stored; return nil }); err != nil || got != "media" {
			t.Errorf("bind another spelling: committed %q, %v; want the stored one", got, err)
		}
	}
	if err := os.Symlink(filepath.Join(a.root, "secret"), filepath.Join(a.root, "link")); err == nil {
		var got string
		if err := a.svc.BindFolder(as(admin), "link", func(stored string) error { got = stored; return nil }); err != nil || got != "secret" {
			t.Errorf("bind a symlink: committed %q, %v; want its target", got, err)
		}
	}

	for _, tc := range []struct {
		user, folder string
		want         error
	}{
		{admin, "missing", ErrNotFound},
		{admin, "notes.txt", ErrNotDir},
		{admin, "../outside", sandbox.ErrTraversal},
		{admin, ".gocalbox", sandbox.ErrReserved},
		{alice, "users/alice", ErrForbidden},
		{"u-nobody", "media", ErrForbidden},
	} {
		err := a.svc.BindFolder(as(tc.user), tc.folder, func(string) error { t.Errorf("%s binds %q: commit ran", tc.user, tc.folder); return nil })
		if !errors.Is(err, tc.want) {
			t.Errorf("%s binds %q: %v, want %v", tc.user, tc.folder, err, tc.want)
		}
	}
	refused := errors.New("refused")
	if err := a.svc.BindFolder(as(admin), "media", func(string) error { return refused }); err != refused {
		t.Errorf("the commit's error: %v", err)
	}
}

// The folder can't move between being checked and the binding's commit.
func TestBindFolderHoldsTheFolderWhileCommitting(t *testing.T) {
	a := newAccessEnv(t)
	moved := make(chan error, 1)
	err := a.svc.BindFolder(as(admin), "secret", func(stored string) error {
		go func() { _, err := a.svc.Move(as(admin), "secret", "public/secret"); moved <- err }()
		time.Sleep(50 * time.Millisecond)
		if !a.exists("secret") {
			t.Error("the folder moved during the commit")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-moved; err != nil {
		t.Errorf("the move after the commit: %v", err)
	}
}
