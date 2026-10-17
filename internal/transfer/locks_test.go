package transfer

import (
	"bytes"
	"context"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/nobletk/gocalbox/internal/events"
)

// lockSpy notes each publish and each call into Files made while the engine
// lock or a session lock is held. The test makes its calls one at a time,
// so a lock TryLock can't take is held by the caller.
type lockSpy struct {
	e      *Engine
	mu     sync.Mutex
	broken []string
}

func (l *lockSpy) check(where string) {
	if !l.e.mu.TryLock() {
		l.note(where + " under the engine lock")
		return
	}
	list := l.e.list()
	l.e.mu.Unlock()
	for _, s := range list {
		if !s.mu.TryLock() {
			l.note(where + " under a session lock")
			continue
		}
		s.mu.Unlock()
	}
}

func (l *lockSpy) note(what string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.broken = append(l.broken, what)
}

type spyFiles struct {
	*fakeFiles
	spy *lockSpy
}

func (f spyFiles) Who(ctx context.Context) (string, bool, bool) {
	f.spy.check("Who")
	return f.fakeFiles.Who(ctx)
}

func (f spyFiles) UserName(id string) (string, bool) {
	f.spy.check("UserName")
	return f.fakeFiles.UserName(id)
}

func (f spyFiles) MayUpload(ctx context.Context, folder string) error {
	f.spy.check("MayUpload")
	return f.fakeFiles.MayUpload(ctx, folder)
}

func (f spyFiles) PrepareUpload(ctx context.Context, dir, name string) (string, string, error) {
	f.spy.check("PrepareUpload")
	return f.fakeFiles.PrepareUpload(ctx, dir, name)
}

func (f spyFiles) Adopt(ctx context.Context, staged, dir, name string, intent func(string) error) (string, events.Event, error) {
	f.spy.check("Adopt")
	return f.fakeFiles.Adopt(ctx, staged, dir, name, intent)
}

func (f spyFiles) Outcome(err error) events.Outcome {
	f.spy.check("Outcome")
	return f.fakeFiles.Outcome(err)
}

func TestNoLockIsHeldWhilePublishingOrCallingFiles(t *testing.T) {
	en := newEnv(t, withFree(1<<30))
	spy := &lockSpy{e: en.e}
	en.e.files = spyFiles{en.files, spy}
	en.bus.publish = func(events.Event) { spy.check("Publish") }

	f := newFile(3 * testPartSize)
	c := en.create(alice, "public", "a.bin", f)
	en.e.Create(as(alice), CreateRequest{Dir: "public", Name: "a.bin", Size: int64(len(f.data)), ClientKey: "k"})
	en.e.Create(as(alice), CreateRequest{Dir: "public", Name: "a.bin", Size: int64(len(f.data)), ClientKey: "k"})
	en.e.Create(as(alice), CreateRequest{Dir: "../x", Name: "a", Size: 1})
	en.send(alice, c.UploadID, f, 1)
	en.e.Part(as(alice), PartRequest{ID: c.UploadID, N: 2, SHA256: f.sum(1), Length: -1, Body: bytes.NewReader(f.part(2))})
	en.e.Part(as(bob), PartRequest{ID: c.UploadID, N: 2, SHA256: f.sum(2), Length: -1, Body: bytes.NewReader(f.part(2))})
	en.files.set(func(ff *fakeFiles) { ff.deny["key:public"] = true })
	en.send(alice, c.UploadID, f, 2)
	en.files.set(func(ff *fakeFiles) { ff.deny["key:public"] = false })
	en.e.Status(as(admin), c.UploadID, []int{1})
	en.e.List(as(admin), true)
	en.e.Complete(as(alice), c.UploadID, f.composite())
	en.sendAll(alice, c.UploadID, f)
	en.files.set(func(ff *fakeFiles) { ff.adopt = func(string) error { return errForbidden } })
	en.e.Complete(as(alice), c.UploadID, f.composite())
	en.files.set(func(ff *fakeFiles) { ff.adopt = nil })
	en.e.Complete(as(alice), c.UploadID, f.composite())
	en.e.Complete(as(alice), c.UploadID, f.composite())

	d := en.create(bob, "public", "b.bin", f)
	en.e.Abort(as(admin), d.UploadID)
	g := en.create(bob, "public", "g.bin", f)
	en.e.syncFile = func(file *os.File) error {
		if strings.HasSuffix(file.Name(), dataName) {
			return syscall.EIO
		}
		return file.Sync()
	}
	en.send(bob, g.UploadID, f, 1)
	en.e.syncFile = (*os.File).Sync
	en.create(alice, "public", "x.bin", f)
	en.clock.add(2 * time.Hour)
	en.e.sweep()
	en.clock.add(48 * time.Hour)
	en.e.sweep()

	for _, b := range spy.broken {
		t.Error(b)
	}
}
