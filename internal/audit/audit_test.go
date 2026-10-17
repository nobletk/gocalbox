package audit

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nobletk/gocalbox/internal/events"
)

func ev(i int) events.Event {
	return events.Event{
		Seq:       uint64(i),
		Time:      time.Date(2026, 10, 5, 12, 0, i, 0, time.UTC),
		Type:      events.FileDeleted,
		Actor:     events.Actor{ID: "anonymous", RemoteAddr: "127.0.0.1:1234"},
		RequestID: fmt.Sprintf("req%d", i),
		Outcome:   events.OutcomeOK,
		Path:      fmt.Sprintf("dir/file%d.txt", i),
	}
}

func writeLog(t *testing.T, n int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	w, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= n; i++ {
		w.Handle(ev(i))
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func lines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.SplitAfter(strings.TrimSuffix(string(b), "\n"), "\n")
}

func rewrite(t *testing.T, path string, ls []string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.Join(ls, "")), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestWriteAndVerify(t *testing.T) {
	path := writeLog(t, 5)

	rep, err := Verify(path)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if rep.Records != 5 || rep.LastHash == GenesisHash || len(rep.LastHash) != 64 {
		t.Errorf("report = %+v", rep)
	}

	info, _ := os.Stat(path)
	if perm := info.Mode().Perm(); perm != 0o600 && runtime.GOOS != "windows" {
		t.Errorf("file mode = %o, want 600", perm)
	}
	if n := len(lines(t, path)); n != 5 {
		t.Errorf("%d lines, want 5", n)
	}
	if rep.Size != info.Size() {
		t.Errorf("report size %d, file size %d", rep.Size, info.Size())
	}
}

func TestBatchIsOneChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	w, _ := Open(path)
	w.HandleBatch([]events.Event{ev(1), ev(2), ev(3)})
	w.HandleBatch(nil)
	w.Handle(ev(4))
	w.HandleBatch([]events.Event{ev(5), ev(6)})
	w.Close()

	rep, err := Verify(path)
	if err != nil || rep.Records != 6 {
		t.Errorf("batched writes: %+v, %v", rep, err)
	}
}

type flakyFile struct {
	*os.File
	failWrites   int
	failSyncs    int
	failTruncate bool
}

func (f *flakyFile) Sync() error {
	if f.failSyncs > 0 {
		f.failSyncs--
		return errors.New("input/output error")
	}
	return f.File.Sync()
}

func (f *flakyFile) Write(p []byte) (int, error) {
	if f.failWrites > 0 {
		f.failWrites--
		n, _ := f.File.Write(p[:len(p)/2])
		return n, errors.New("no space left on device")
	}
	return f.File.Write(p)
}

func (f *flakyFile) Truncate(size int64) error {
	if f.failTruncate {
		return errors.New("read-only file system")
	}
	return f.File.Truncate(size)
}

// Windows can't remove a test's folder while a file in it is still open.
func reopen(path string) error {
	w, err := Open(path)
	if err == nil {
		w.Close()
	}
	return err
}

func TestFailedWriteIsRolledBackAndTheChainContinues(t *testing.T) {
	captureLost(t)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	w, _ := Open(path)
	w.Handle(ev(1))
	w.f = &flakyFile{File: w.f.(*os.File), failWrites: 1}

	w.HandleBatch([]events.Event{ev(2), ev(3)})
	if w.Err() == nil {
		t.Fatal("failed write not reported by Err")
	}
	w.Handle(ev(4))
	w.Close()

	rep, err := Verify(path)
	if err != nil || rep.Records != 2 {
		t.Errorf("after rolled-back write: %+v, %v (want records 1 and 4 only)", rep, err)
	}
	if err := reopen(path); err != nil {
		t.Errorf("log refused at next start: %v", err)
	}
}

func TestWriterStopsWhenRollbackFails(t *testing.T) {
	captureLost(t)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	w, _ := Open(path)
	w.Handle(ev(1))
	w.f = &flakyFile{File: w.f.(*os.File), failWrites: 1, failTruncate: true}

	w.Handle(ev(2))
	if !errors.Is(w.Err(), ErrBroken) {
		t.Fatalf("Err = %v, want ErrBroken", w.Err())
	}
	before, _ := os.ReadFile(path)
	w.Handle(ev(3))
	w.Close()
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
		t.Error("a broken writer kept appending")
	}
	if err := reopen(path); err != nil {
		t.Errorf("Open after a stopped writer: %v", err)
	}
}

func TestFailedSyncRollsTheBatchBackAndTheChainContinues(t *testing.T) {
	captureLost(t)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	w, _ := Open(path)
	w.Handle(ev(1))
	before, _ := os.ReadFile(path)
	w.f = &flakyFile{File: w.f.(*os.File), failSyncs: 1}

	w.HandleBatch([]events.Event{ev(2), ev(3)})
	if w.Err() == nil || errors.Is(w.Err(), ErrBroken) {
		t.Fatalf("Err = %v, want a sync error that was recovered from", w.Err())
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
		t.Error("the unsynced batch was left in the file")
	}
	if w.Records() != 1 {
		t.Errorf("Records = %d, want 1: the lost batch must not be counted", w.Records())
	}
	w.Handle(ev(4))
	w.Close()

	rep, err := Verify(path)
	if err != nil || rep.Records != 2 {
		t.Errorf("after a failed sync: %+v, %v (want records 1 and 4)", rep, err)
	}
	if err := reopen(path); err != nil {
		t.Errorf("log refused at next start: %v", err)
	}
}

func TestWriterStopsWhenSyncRollbackFails(t *testing.T) {
	captureLost(t)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	w, _ := Open(path)
	w.Handle(ev(1))
	w.f = &flakyFile{File: w.f.(*os.File), failSyncs: 1, failTruncate: true}

	w.Handle(ev(2))
	if !errors.Is(w.Err(), ErrBroken) {
		t.Fatalf("Err = %v, want ErrBroken", w.Err())
	}
	before, _ := os.ReadFile(path)
	w.Handle(ev(3))
	w.Close()
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
		t.Error("a broken writer kept appending")
	}
}

func TestVerifyEmptyAndMissing(t *testing.T) {
	empty := filepath.Join(t.TempDir(), "empty.jsonl")
	os.WriteFile(empty, nil, 0o600)
	rep, err := Verify(empty)
	if err != nil || rep.Records != 0 || rep.LastHash != GenesisHash {
		t.Errorf("empty file: %+v, %v", rep, err)
	}

	_, err = Verify(filepath.Join(t.TempDir(), "missing.jsonl"))
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing file err = %v", err)
	}
}

func TestSpecialCharactersSurviveTheChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	w, _ := Open(path)
	e := ev(1)
	e.Path = "weird <name> & \"quotes\"\nnewline\tünïcödé 日本語   ../../etc/passwd"
	e.Detail = "<script>alert(1)</script>"
	w.Handle(e)
	w.Close()

	if _, err := Verify(path); err != nil {
		t.Errorf("Verify with special characters: %v", err)
	}
	if n := len(lines(t, path)); n != 1 {
		t.Errorf("a newline in a field produced %d lines, want 1", n)
	}
}

func TestChainContinuesAcrossReopen(t *testing.T) {
	path := writeLog(t, 3)

	w, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if w.Records() != 3 {
		t.Errorf("Records after reopen = %d, want 3", w.Records())
	}
	w.Handle(ev(4))
	w.Handle(ev(5))
	w.Close()

	rep, err := Verify(path)
	if err != nil || rep.Records != 5 {
		t.Errorf("after reopen: %+v, %v", rep, err)
	}
}

func TestTamperingIsDetected(t *testing.T) {
	cases := map[string]struct {
		mutate   func([]string) []string
		wantLine int
	}{
		"edited content": {
			func(l []string) []string { l[2] = strings.Replace(l[2], "file3.txt", "other.txt", 1); return l },
			3,
		},
		"edited outcome": {
			func(l []string) []string { l[1] = strings.Replace(l[1], `"ok"`, `"denied"`, 1); return l },
			2,
		},
		"removed middle record": {
			func(l []string) []string { return append(l[:2:2], l[3:]...) },
			3,
		},
		"swapped records": {
			func(l []string) []string { l[1], l[2] = l[2], l[1]; return l },
			2,
		},
		"inserted copy": {
			func(l []string) []string { return append(l[:3:3], append([]string{l[1]}, l[3:]...)...) },
			4,
		},
		"removed first record": {
			func(l []string) []string { return l[1:] },
			1,
		},
		"garbage line": {
			func(l []string) []string { l[3] = "not json\n"; return l },
			4,
		},
		"extra field": {
			func(l []string) []string {
				l[1] = strings.Replace(l[1], `{"event"`, `{"note":"x","event"`, 1)
				return l
			},
			2,
		},
		"key letter case changed": {
			func(l []string) []string { l[1] = strings.Replace(l[1], `{"event"`, `{"eveNt"`, 1); return l },
			2,
		},
		"whitespace added": {
			func(l []string) []string { l[2] = strings.Replace(l[2], `"event":`, `"event": `, 1); return l },
			3,
		},
		"trailing data": {
			func(l []string) []string { l[2] = strings.TrimSuffix(l[2], "\n") + " {}\n"; return l },
			3,
		},
		"edited hash": {
			func(l []string) []string {
				i := strings.LastIndex(l[1], `"hash":"`) + len(`"hash":"`)
				l[1] = l[1][:i] + "0" + l[1][i+1:]
				return l
			},
			2,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			path := writeLog(t, 5)
			rewrite(t, path, tc.mutate(lines(t, path)))

			_, err := Verify(path)
			if !errors.Is(err, ErrTampered) {
				t.Fatalf("err = %v, want ErrTampered", err)
			}
			var te *TamperError
			if !errors.As(err, &te) || te.Line != tc.wantLine {
				t.Errorf("reported line %v, want %d (err: %v)", te, tc.wantLine, err)
			}
		})
	}
}

func TestOpenRefusesTamperedFileAndLeavesItAlone(t *testing.T) {
	path := writeLog(t, 4)
	ls := lines(t, path)
	ls[1] = strings.Replace(ls[1], "file2.txt", "x.txt", 1)
	rewrite(t, path, ls)
	before, _ := os.ReadFile(path)

	if _, err := Open(path); !errors.Is(err, ErrTampered) {
		t.Fatalf("Open err = %v, want ErrTampered", err)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Error("Open modified a file that failed verification")
	}
}

func TestTornTailIsRepairedOnOpen(t *testing.T) {
	path := writeLog(t, 3)
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString(`{"event":{"seq":4,"type":"file.del`)
	f.Close()

	_, err := Verify(path)
	var torn *TornTailError
	if !errors.Is(err, ErrTornTail) || !errors.As(err, &torn) {
		t.Fatalf("Verify err = %v, want a torn tail", err)
	}

	w, err := Open(path)
	if err != nil {
		t.Fatalf("Open should repair a torn tail: %v", err)
	}
	w.Handle(ev(4))
	w.Close()

	rep, err := Verify(path)
	if err != nil || rep.Records != 4 {
		t.Errorf("after repair: %+v, %v", rep, err)
	}
}

func TestConcurrentHandleKeepsChainValid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	w, _ := Open(path)

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				w.Handle(ev(g*100 + i))
			}
		}(g)
	}
	wg.Wait()
	w.Close()

	rep, err := Verify(path)
	if err != nil || rep.Records != 200 {
		t.Errorf("concurrent writes: %+v, %v", rep, err)
	}
}

func TestHandleAfterCloseIsIgnored(t *testing.T) {
	path := writeLog(t, 2)
	w, _ := Open(path)
	w.Close()
	w.Handle(ev(3))
	if err := w.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	if rep, _ := Verify(path); rep.Records != 2 {
		t.Errorf("record written after Close: %+v", rep)
	}
}

func TestFilter(t *testing.T) {
	listedOK := events.Event{Type: events.FileListed, Outcome: events.OutcomeOK}
	listedDenied := events.Event{Type: events.FileListed, Outcome: events.OutcomeDenied}
	listedMissing := events.Event{Type: events.FileListed, Outcome: events.OutcomeNotFound}
	deleted := events.Event{Type: events.FileDeleted, Outcome: events.OutcomeOK}
	checkedOK := events.Event{Type: events.FileChecked, Outcome: events.OutcomeOK}
	checkedDenied := events.Event{Type: events.FileChecked, Outcome: events.OutcomeDenied}
	downloaded := events.Event{Type: events.FileDownloaded, Outcome: events.OutcomeOK}

	def := Filter(Keep{})
	if def(listedOK) || def(checkedOK) {
		t.Error("default filter must drop successful listings and file checks")
	}
	if !def(listedDenied) || !def(listedMissing) || !def(checkedDenied) || !def(deleted) || !def(downloaded) {
		t.Error("failed metadata reads and other events must be recorded")
	}
	all := Filter(Keep{Metadata: true})
	if !all(listedOK) || !all(checkedOK) || !all(listedDenied) || !all(deleted) {
		t.Error("metadata filter must keep everything")
	}

	part := events.Event{Type: events.UploadPartReceived, Outcome: events.OutcomeOK}
	if def(part) || all(part) {
		t.Error("accepted parts are kept only when asked for")
	}
	if !Filter(Keep{Parts: true})(part) {
		t.Error("Keep.Parts drops accepted parts")
	}
	for _, typ := range []events.Type{events.UploadCreated, events.UploadRejected, events.UploadCompleted, events.UploadAborted, events.UploadExpired, events.UploadFailed} {
		if !def(events.Event{Type: typ, Outcome: events.OutcomeOK}) {
			t.Errorf("%s dropped", typ)
		}
	}
	if !def(events.Event{Type: events.UploadPartReceived, Outcome: events.OutcomeOK, Ack: events.NewAck()}) {
		t.Error("an event with an Ack must always pass")
	}
}

func TestEnsureOutside(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	other := filepath.Join(base, "other")
	os.MkdirAll(filepath.Join(root, "sub"), 0o755)
	os.MkdirAll(other, 0o755)
	root, _ = filepath.EvalSymlinks(root)

	got, err := EnsureOutside(root, filepath.Join(other, "new", "dir", "audit.jsonl"))
	if err != nil {
		t.Fatalf("outside path rejected: %v", err)
	}
	if !strings.HasSuffix(got, filepath.Join("new", "dir", "audit.jsonl")) {
		t.Errorf("resolved path = %q", got)
	}

	for name, p := range map[string]string{
		"direct":    filepath.Join(root, "audit.jsonl"),
		"subfolder": filepath.Join(root, "sub", "audit.jsonl"),
		"dotdot":    filepath.Join(other, "..", "root", "audit.jsonl"),
	} {
		if _, err := EnsureOutside(root, p); err == nil {
			t.Errorf("%s: path inside the root was accepted", name)
		}
	}

	link := filepath.Join(other, "link")
	if err := os.Symlink(filepath.Join(root, "sub"), link); err == nil {
		if _, err := EnsureOutside(root, filepath.Join(link, "audit.jsonl")); err == nil {
			t.Error("symlinked folder into the root was accepted")
		}
	}

	target := filepath.Join(root, "sub", "real.jsonl")
	os.WriteFile(target, nil, 0o600)
	fileLink := filepath.Join(other, "log.jsonl")
	if err := os.Symlink(target, fileLink); err == nil {
		if _, err := EnsureOutside(root, fileLink); err == nil {
			t.Error("symlinked log file into the root was accepted")
		}
	}

	if _, err := EnsureOutside(root, root+"-backup/audit.jsonl"); err != nil {
		t.Errorf("sibling with common prefix rejected: %v", err)
	}
}

// FuzzAuditTamper checks that any event content round-trips through a valid
// file and that flipping any single byte of the file fails verification.
//
// go test -fuzz=FuzzAuditTamper ./internal/audit
func FuzzAuditTamper(f *testing.F) {
	f.Add("docs/a.txt", "", uint(0), byte(1))
	f.Add("../../etc/passwd", "security violation: path escapes the sandbox", uint(77), byte(0x20))
	f.Add("weird\nname\t\"quoted\" <b>&amp;</b>", "détail   日本語", uint(500), byte(0xff))
	f.Add("\xff\xfe invalid utf8", "\x00 nul", uint(3), byte(0x80))
	f.Add(strings.Repeat("x", 5000), strings.Repeat("y", 5000), uint(12345), byte(7))

	f.Fuzz(func(t *testing.T, path, detail string, offset uint, delta byte) {
		file := filepath.Join(t.TempDir(), "audit.jsonl")
		w, err := Open(file)
		if err != nil {
			t.Fatal(err)
		}
		w.Handle(ev(1))
		e := ev(2)
		e.Path, e.Detail = path, detail
		w.Handle(e)
		w.Handle(ev(3))
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}

		if _, err := Verify(file); err != nil {
			t.Fatalf("a freshly written log does not verify (path %q, detail %q): %v", path, detail, err)
		}
		if n := len(lines(t, file)); n != 3 {
			t.Fatalf("%d lines for 3 events: a value broke the one-record-per-line format", n)
		}

		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if delta == 0 {
			delta = 1
		}
		pos := int(offset % uint(len(data)))
		data[pos] ^= delta
		if err := os.WriteFile(file, data, 0o600); err != nil {
			t.Fatal(err)
		}

		if _, err := Verify(file); err == nil {
			t.Fatalf("changing byte %d (xor %#x) of %d went undetected", pos, delta, len(data))
		}
	})
}

func TestOpenRefusesALogInUse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	w, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); !errors.Is(err, ErrLocked) {
		t.Fatalf("second Open = %v, want ErrLocked", err)
	}
	if _, err := Verify(path); err != nil {
		t.Errorf("Verify while the log is open: %v", err)
	}
	w.Close()
	again, err := Open(path)
	if err != nil {
		t.Fatalf("Open after Close: %v", err)
	}
	again.Close()
}
