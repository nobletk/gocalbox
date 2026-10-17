package fsops

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/space"
)

func newSpaceEnv(t *testing.T, free func() (int64, error), minFree int64) (*env, *recorder, *space.Ledger) {
	t.Helper()
	e := newEnv(t)
	rec := &recorder{}
	l := space.NewLedger(free, minFree)
	e.svc = asAdmin(New(e.sb, rec, WithSpace(l)))
	return e, rec, l
}

func TestUploadThatDoesNotFitIsRefusedBeforeWriting(t *testing.T) {
	e, rec, l := newSpaceEnv(t, func() (int64, error) { return 10 << 20, nil }, 4<<20)

	_, _, err := e.svc.Create(bg, "", "big.bin", strings.NewReader("x"), 7<<20)
	is(t, err, ErrInsufficientStorage, "7 MiB with 6 MiB above the floor")
	if e.exists("big.bin") {
		t.Error("a refused upload left a file")
	}
	check(t, rec.last(t), events.FileUploaded, events.OutcomeNoSpace, "big.bin")

	if _, _, err := e.svc.Create(bg, "", "fits.bin", strings.NewReader("x"), 6<<20); err != nil {
		t.Fatalf("6 MiB: %v", err)
	}
	if l.Reserved() != 0 {
		t.Errorf("reservation not released: %d", l.Reserved())
	}
}

type shrinking struct {
	free atomic.Int64
	left int64
}

func (s *shrinking) Read(p []byte) (int, error) {
	if s.left == 0 {
		return 0, io.EOF
	}
	n := int(min(int64(len(p)), s.left))
	clear(p[:n])
	s.left -= int64(n)
	s.free.Add(-int64(n))
	return n, nil
}

func TestUploadOfUnknownSizeStopsAtTheFloor(t *testing.T) {
	src := &shrinking{left: 1 << 20}
	src.free.Store(600 << 10)
	e, rec, l := newSpaceEnv(t, func() (int64, error) { return src.free.Load(), nil }, 100<<10)
	l.CheckEvery = 64 << 10

	_, size, err := e.svc.Create(bg, "", "stream.bin", src, -1)
	is(t, err, ErrInsufficientStorage, "stream larger than the free space")
	if size > 600<<10 || e.exists("stream.bin") {
		t.Errorf("wrote %d bytes and left the file: %v", size, e.exists("stream.bin"))
	}
	check(t, rec.last(t), events.FileUploaded, events.OutcomeNoSpace, "stream.bin")
}

func TestWithoutALedgerUploadsAreNotLimited(t *testing.T) {
	e := newEnv(t)
	if _, _, err := e.svc.Create(bg, "", "a.bin", strings.NewReader("abc"), 1<<50); err != nil {
		t.Fatal(err)
	}
}

func TestOSErrorsAreNamed(t *testing.T) {
	for _, tc := range []struct {
		raw     error
		want    error
		outcome events.Outcome
	}{
		{noSpaceErr, ErrInsufficientStorage, events.OutcomeNoSpace},
		{quotaErr, ErrInsufficientStorage, events.OutcomeNoSpace},
		{crossDeviceErr, ErrCrossDevice, events.OutcomeInvalid},
		{readOnlyErr, ErrReadOnly, events.OutcomeDenied},
	} {
		err := osErr(&fs.PathError{Op: "write", Path: "x", Err: tc.raw})
		is(t, err, tc.want, tc.raw.Error())
		if got := outcomeOf(err); got != tc.outcome {
			t.Errorf("%v: outcome %s, want %s", tc.raw, got, tc.outcome)
		}
	}
	other := errors.New("disk on fire")
	if osErr(other) != other || osErr(nil) != nil {
		t.Error("osErr changed an unrelated error")
	}
}

func TestCreateNamesADiskFullError(t *testing.T) {
	e, rec := newObservedEnv(t)
	_, _, err := e.svc.Create(bg, "", "a.bin", &failingReader{data: "half", err: &fs.PathError{Op: "write", Path: "a.bin", Err: noSpaceErr}}, -1)
	is(t, err, ErrInsufficientStorage, "write failing with a disk-full error")
	check(t, rec.last(t), events.FileUploaded, events.OutcomeNoSpace, "a.bin")
	if e.exists("a.bin") {
		t.Error("partial file left behind")
	}
}

func TestReadOnlyIsAPermissionError(t *testing.T) {
	e, rec := newObservedEnv(t)
	_, _, err := e.svc.Create(bg, "", "a.bin", &failingReader{data: "half", err: &fs.PathError{Op: "write", Path: "a.bin", Err: readOnlyErr}}, -1)
	is(t, err, ErrReadOnly, "write failing on a read-only file system")
	is(t, err, fs.ErrPermission, "read-only counts as a permission error")
	check(t, rec.last(t), events.FileUploaded, events.OutcomeDenied, "a.bin")
}

func TestUploadIntoAnotherFileSystemIsNotMeasured(t *testing.T) {
	e, _, _ := newSpaceEnv(t, func() (int64, error) { return 0, nil }, 1<<20)
	e.write("ext/keep", "")
	fakeVolumes(t, "ext")

	if _, _, err := e.svc.Create(bg, "ext", "a.bin", strings.NewReader("abc"), 3); err != nil {
		t.Fatalf("upload into another file system: %v", err)
	}
	_, _, err := e.svc.Create(bg, "", "b.bin", strings.NewReader("abc"), 3)
	is(t, err, ErrInsufficientStorage, "the served file system is still measured")
}

func TestServedFolderAndItsSubfoldersShareAVolume(t *testing.T) {
	e := newEnv(t)
	e.write("sub/keep", "")
	if !e.svc.onServedVolume("sub") || !e.svc.onServedVolume(".") {
		t.Error("a folder on the served file system was treated as another one")
	}
}

// fakeVolumes makes the folders named other count as being on another file
// system.
func fakeVolumes(t *testing.T, other ...string) {
	orig := sameVolume
	sameVolume = func(_ *os.Root, a, b string) (bool, bool, error) {
		same := slices.Contains(other, path.Base(filepath.ToSlash(a))) == slices.Contains(other, path.Base(filepath.ToSlash(b)))
		return same, same, nil
	}
	t.Cleanup(func() { sameVolume = orig })
}

// A folder whose volume can't be told counts as sharing the served disk's
// free space, so the ledger still measures uploads into it.
func TestTheLedgerMeasuresAFolderOfUnknownVolume(t *testing.T) {
	e, _, _ := newSpaceEnv(t, func() (int64, error) { return 0, nil }, 1<<20)
	e.write("sub/keep", "")
	orig := sameVolume
	sameVolume = func(*os.Root, string, string) (bool, bool, error) { return false, false, errors.New("no identity") }
	t.Cleanup(func() { sameVolume = orig })
	_, _, err := e.svc.Create(bg, "sub", "a.bin", strings.NewReader("abc"), 3)
	is(t, err, ErrInsufficientStorage, "an upload into a folder of unknown volume")
}
