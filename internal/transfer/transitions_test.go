package transfer

import (
	"bytes"
	"errors"
	"os"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/nobletk/gocalbox/internal/events"
)

// TestTheTransitionTable runs each row of the session's state machine: the
// state before, the trigger, the state after and the events it publishes.
func TestTheTransitionTable(t *testing.T) {
	f := newFile(2 * testPartSize)
	full := func(en *env, id string) { en.sendAll(alice, id, f) }
	for _, row := range []struct {
		name    string
		before  func(en *env, id string)
		trigger func(en *env, id string) error
		from    State
		to      State
		events  []events.Type
	}{
		{"create", nil, nil, "", Receiving, []events.Type{events.UploadCreated}},
		{"create with the same client key", nil, func(en *env, id string) error {
			c, err := en.e.Create(as(alice), CreateRequest{Dir: "public", Name: "a.bin", Size: int64(len(f.data)), ClientKey: "k"})
			if err == nil && c.UploadID != id {
				return errors.New("not resumed")
			}
			return err
		}, Receiving, Receiving, []events.Type{events.UploadCreated}},
		{"a part accepted", nil, func(en *env, id string) error { _, err := en.send(alice, id, f, 1); return err },
			Receiving, Receiving, []events.Type{events.UploadPartReceived}},
		{"a part refused", nil, func(en *env, id string) error {
			_, err := en.e.Part(as(alice), PartRequest{ID: id, N: 1, SHA256: f.sum(2), Length: -1, Body: bytes.NewReader(f.part(1))})
			return expect(err, ErrChecksumMismatch)
		}, Receiving, Receiving, []events.Type{events.UploadRejected}},
		{"complete", full, func(en *env, id string) error { _, err := en.e.Complete(as(alice), id, f.composite()); return err },
			Receiving, Completed, []events.Type{events.FileUploaded, events.UploadCompleted}},
		{"complete whose precondition fails", nil, func(en *env, id string) error {
			_, err := en.e.Complete(as(alice), id, f.composite())
			return expect(err, ErrPartsMissing)
		}, Receiving, Receiving, []events.Type{events.UploadRejected}},
		{"complete whose Adopt fails", full, func(en *env, id string) error {
			en.files.set(func(ff *fakeFiles) { ff.adopt = func(string) error { return errForbidden } })
			_, err := en.e.Complete(as(alice), id, f.composite())
			return expect(err, errForbidden)
		}, Receiving, Receiving, []events.Type{events.UploadRejected}},
		{"abort", nil, func(en *env, id string) error { _, err := en.e.Abort(as(alice), id); return err },
			Receiving, Aborted, []events.Type{events.UploadAborted}},
		{"the janitor", nil, func(en *env, id string) error {
			en.clock.add(DefaultLimits.FirstPartTTL)
			en.e.sweep()
			return nil
		}, Receiving, Expired, []events.Type{events.UploadExpired}},
		{"an I/O error", nil, func(en *env, id string) error {
			en.e.syncFile = func(file *os.File) error {
				if strings.HasSuffix(file.Name(), dataName) {
					return syscall.EIO
				}
				return file.Sync()
			}
			_, err := en.send(alice, id, f, 1)
			return expect(err, ErrClosed)
		}, Receiving, Failed, []events.Type{events.UploadFailed}},
		{"an I/O error while completing", full, func(en *env, id string) error {
			en.e.syncFile = func(file *os.File) error {
				if strings.HasSuffix(file.Name(), logName) {
					return syscall.EIO
				}
				return file.Sync()
			}
			_, err := en.e.Complete(as(alice), id, f.composite())
			return expect(err, ErrClosed)
		}, Receiving, Failed, []events.Type{events.UploadFailed}},
	} {
		t.Run(row.name, func(t *testing.T) {
			en := newEnv(t)
			c, err := en.e.Create(as(alice), CreateRequest{Dir: "public", Name: "a.bin", Size: int64(len(f.data)), ClientKey: "k"})
			if err != nil {
				t.Fatal(err)
			}
			if row.trigger == nil {
				checkTransition(t, en, c.UploadID, row.to, row.events)
				return
			}
			if row.before != nil {
				row.before(en, c.UploadID)
			}
			if st := en.state(c.UploadID); st != row.from {
				t.Fatalf("before: %s, want %s", st, row.from)
			}
			en.bus.reset()
			if err := row.trigger(en, c.UploadID); err != nil {
				t.Fatal(err)
			}
			checkTransition(t, en, c.UploadID, row.to, row.events)
		})
	}

	for _, end := range []State{Completed, Aborted, Expired, Failed} {
		t.Run("a "+string(end)+" tombstone's time", func(t *testing.T) {
			en := newEnv(t)
			c := en.create(alice, "public", "a.bin", f)
			s := en.session(c.UploadID)
			s.mu.Lock()
			s.state, s.over = end, en.clock.now()
			s.closeFiles()
			s.mu.Unlock()
			en.e.closeSlot(s)
			en.bus.reset()
			en.clock.add(DefaultLimits.TombstoneTTL)
			en.e.sweep()
			if en.e.lookup(c.UploadID) != nil || en.reg.has(c.UploadID) || len(en.bus.all()) != 0 {
				t.Errorf("still there: %v, record %v, events %+v", en.e.lookup(c.UploadID) != nil, en.reg.has(c.UploadID), en.bus.all())
			}
		})
	}
}

func checkTransition(t *testing.T, en *env, id string, to State, want []events.Type) {
	t.Helper()
	if st := en.state(id); st != to {
		t.Errorf("after: %s, want %s", st, to)
	}
	var got []events.Type
	for _, ev := range en.bus.all() {
		got = append(got, ev.Type)
	}
	if !slices.Equal(got, want) {
		t.Errorf("events %v, want %v", got, want)
	}
}

func expect(err, want error) error {
	if errors.Is(err, want) {
		return nil
	}
	return errors.Join(errors.New("unexpected answer"), err)
}
