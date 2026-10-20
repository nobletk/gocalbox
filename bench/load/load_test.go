package load

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/fsops"
	"github.com/nobletk/gocalbox/internal/sandbox"
	"github.com/nobletk/gocalbox/internal/space"
	"github.com/nobletk/gocalbox/internal/transfer"
)

func TestTheLoadClientUploadsThroughTheEngine(t *testing.T) {
	work := t.TempDir()
	s, err := NewStack(StackOptions{Work: work, Users: 2, AuditWait: true})
	if err != nil {
		t.Fatal(err)
	}
	const size = 8<<20 + 5
	res := Run(context.Background(), Config{Users: s.Users, Files: 2, Size: size, Parallel: 2})
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if res.Files != 4 || res.Bytes != 4*size || res.CodeColumn() != "201" || len(res.Parts) != 8 || res.Duration <= 0 {
		t.Fatalf("result %+v", res)
	}
	want := make([]byte, size)
	fill(want, 0, byte(1*31+1))
	got, err := os.ReadFile(filepath.Join(work, "root", "users", "load01", "load-001-0001.bin"))
	if err != nil || !bytes.Equal(got, want) {
		t.Errorf("an uploaded file differs: %v", err)
	}
	audit, err := os.ReadFile(filepath.Join(work, "audit.jsonl"))
	if err != nil || strings.Count(string(audit), `"type":"upload.completed"`) != 4 {
		t.Errorf("audit log: %v", err)
	}

	row := res.Row("abc1234", false, "engine_upload_2u", size, 4, 1, "inprocess")
	cols := strings.Split(row, ",")
	if len(cols) != len(strings.Split(Header, ",")) || cols[0] != "abc1234" || cols[1] != "0" || cols[4] != "4" ||
		cols[7] != cols[9] || cols[10] != "" || cols[11] != "201" || cols[12] != "inprocess" {
		t.Errorf("row %q", row)
	}
}

// Each column of the load client's own lands under its name.
func TestTheRowsOwnColumns(t *testing.T) {
	ms := time.Millisecond
	r := Result{
		Files: 2, Bytes: 2 << 20, Duration: 2 * time.Second, Codes: map[string]int{"201": 2},
		Retried:   map[string]int{"503": 2, "000": 1, "429": 0},
		Parts:     []time.Duration{4 * ms, 1 * ms, 3 * ms, 2 * ms},
		Completes: []time.Duration{30 * ms, 10 * ms, 20 * ms},
		Resent:    12345,
		Resumes:   []time.Duration{3 * time.Second, time.Second, 2 * time.Second},
		Stalled:   1500 * ms,
		UserRates: []float64{2.5, 0.75, 1},
		CPU:       1250 * ms,
		Start:     time.UnixMicro(1760000000123456),
	}
	header := strings.Split(Header, ",")
	if strings.Join(header[:13], ",") != ScriptColumns {
		t.Fatalf("the scripts' columns don't come first: %s", Header)
	}
	col := func(row, name string) string {
		cols := strings.Split(row, ",")
		if len(cols) != len(header) {
			t.Fatalf("%d columns, want %d: %s", len(cols), len(header), row)
		}
		return cols[slices.Index(header, name)]
	}
	row := r.Row("c", true, "s", 1<<20, 4, 1, "https-h2")
	for name, want := range map[string]string{
		"dirty": "1", "mib_per_s": "1.000",
		"part_p50_ms": "3.000", "part_p99_ms": "4.000", "complete_p50_ms": "20.000", "complete_max_ms": "30.000",
		"retried": "000x1 503x2", "resent_bytes": "12345", "user_min_mib_s": "0.750", "user_max_mib_s": "2.500",
		"client_cpu_s": "1.250", "resumed": "3", "resume_p50_s": "2.000", "resume_max_s": "3.000", "stalled_s": "1.500",
		"started_unix": "1760000000.123456",
	} {
		if got := col(row, name); got != want {
			t.Errorf("%s: %q, want %q", name, got, want)
		}
	}
	if got := col(r.Row("c", false, "s", 1, 4, 1, "inprocess"), "client_cpu_s"); got != "" {
		t.Errorf("in process, the client's CPU: %q", got)
	}
	r.CPU = -1
	if got := col(r.Row("c", false, "s", 1, 4, 1, "https-h1"), "client_cpu_s"); got != "" {
		t.Errorf("CPU unknown: %q", got)
	}
	empty := Result{Codes: map[string]int{"000": 1}, CPU: -1}
	row = empty.Row("c", false, "s", 1, 4, 1, "https-h2")
	for name, want := range map[string]string{"mib_per_s": "0.000", "part_p50_ms": "0.000", "retried": "", "user_min_mib_s": "0.000", "resumed": "0"} {
		if got := col(row, name); got != want {
			t.Errorf("nothing measured, %s: %q, want %q", name, got, want)
		}
	}
	if got := Percentile([]time.Duration{5, 1, 4, 2, 3}, 0.5); got != 3 {
		t.Errorf("median %v", got)
	}
}

// The run's CPU time is read where the system tells it.
func TestTheRunsCPUTimeIsRead(t *testing.T) {
	res := Run(context.Background(), Config{Users: []User{{API: newKeyed(1 << 20), Dir: "x"}}, Files: 4, Size: 16 << 20, Parallel: 2})
	if res.CPU <= 0 {
		t.Errorf("CPU %v", res.CPU)
	}
	if d := time.Since(res.Start); d < res.Duration || d > res.Duration+time.Second {
		t.Errorf("started %v ago, took %v", d, res.Duration)
	}
}

func TestCodeColumn(t *testing.T) {
	for want, codes := range map[string]map[string]int{
		"201":         {"201": 3},
		"201x2 507x1": {"201": 2, "507": 1},
		"503x1":       {"503": 1},
	} {
		if got := (Result{Codes: codes}).CodeColumn(); got != want {
			t.Errorf("%v: %q", codes, got)
		}
	}
}

func newState() *userState { return &userState{res: Result{Retried: map[string]int{}}} }

func TestRetryWaitsOutBusyAnswers(t *testing.T) {
	for _, busy := range []*transfer.Error{transfer.ErrBusy, transfer.ErrTooManyRequests, transfer.ErrPartInProgress} {
		calls := 0
		st := newState()
		v, _, err := retry(context.Background(), retrier{st: st}, func() (int, error) {
			if calls++; calls < 3 {
				return 0, busy
			}
			return 7, nil
		})
		code := strconv.Itoa(busy.Status)
		if v != 7 || err != nil || calls != 3 || st.res.Retried[code] != 2 || len(st.res.Retried) != 1 {
			t.Errorf("%v: %d, %v after %d calls, retried %v", busy, v, err, calls, st.res.Retried)
		}
	}
	calls := 0
	st := newState()
	if _, _, err := retry(context.Background(), retrier{st: st}, func() (int, error) { calls++; return 0, transfer.ErrChecksumMismatch }); err == nil || calls != 1 || len(st.res.Retried) != 0 {
		t.Errorf("a refusal was retried: %v, %d calls, %v", err, calls, st.res.Retried)
	}
}

// fakeServer cuts files into parts of partSize, keeps what it is sent, and
// answers completions with refuse when it is set.
type fakeServer struct {
	partSize int64
	refuse   error
	failPart error // the answer to part 1, when set
	mu       sync.Mutex
	parts    map[int][]byte
	calls    int
}

func (f *fakeServer) Create(_ context.Context, req transfer.CreateRequest) (transfer.Created, error) {
	return transfer.Created{UploadID: "id", PartSize: f.partSize, PartCount: transfer.PartCount(req.Size, f.partSize)}, nil
}

func (f *fakeServer) Part(_ context.Context, req transfer.PartRequest) (transfer.PartResult, error) {
	b, _ := io.ReadAll(req.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if req.N == 1 && f.failPart != nil {
		return transfer.PartResult{}, f.failPart
	}
	f.parts[req.N] = b
	return transfer.PartResult{Part: req.N}, nil
}

func (f *fakeServer) Complete(_ context.Context, _, composite string) (transfer.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var hs [][sha256.Size]byte
	for n := 1; n <= len(f.parts); n++ {
		hs = append(hs, sha256.Sum256(f.parts[n]))
	}
	if composite != transfer.Composite(hs) {
		return transfer.Result{}, transfer.ErrChecksumMismatch
	}
	return transfer.Result{}, f.refuse
}

func TestRefusedUploadsAreCountedApart(t *testing.T) {
	srv := &fakeServer{partSize: 4, refuse: transfer.ErrPartsMissing, parts: map[int][]byte{}}
	res := Run(context.Background(), Config{Users: []User{{API: srv, Dir: "x"}}, Files: 2, Size: 10, Parallel: 1})
	if res.Files != 2 || res.Bytes != 20 || res.Uploaded() != 0 || res.CodeColumn() != "409x2" {
		t.Errorf("result %+v, codes %s", res, res.CodeColumn())
	}
}

func TestTheServersPartSizeIsUsed(t *testing.T) {
	for _, ps := range []int64{3 << 20, 16 << 20} {
		srv := &fakeServer{partSize: ps, parts: map[int][]byte{}}
		const size = 20 << 20
		res := Run(context.Background(), Config{Users: []User{{API: srv, Dir: "x"}}, Files: 1, Size: size, Parallel: 2})
		n := transfer.PartCount(size, ps)
		if res.CodeColumn() != "201" || len(srv.parts) != n {
			t.Fatalf("parts of %d: codes %s, %d parts", ps, res.CodeColumn(), len(srv.parts))
		}
		want := make([]byte, min(ps, size-ps))
		fill(want, ps, 0)
		if !bytes.Equal(srv.parts[2], want) {
			t.Errorf("parts of %d: part 2 holds other bytes than the file's", ps)
		}
	}
}

func TestStatusesAreTheServers(t *testing.T) {
	for _, c := range []struct {
		err  error
		want string
	}{
		{transfer.ErrBusy, "503"},
		{fmt.Errorf("%w: big", transfer.ErrTooLargeForVolume), "413"},
		{fmt.Errorf("%w: full", space.ErrInsufficient), "507"},
		{events.ErrChangesPaused, "503"},
		{sandbox.ErrReserved, "403"},
		{fsops.ErrForbidden, "403"},
		{fsops.ErrBoundFolder, "409"},
		{fmt.Errorf("%w: ../x", sandbox.ErrTraversal), "403"},
		{sandbox.ErrRootTarget, "400"},
		{sandbox.ErrBrokenLink, "400"},
		{sandbox.ErrInvalidPath, "400"},
		{fsops.ErrNotFound, "404"},
		{fmt.Errorf("hidden: %w", fsops.ErrParentNotFound), "400"},
		{fsops.ErrNotDir, "400"},
		{fsops.ErrInvalidName, "400"},
		{fsops.ErrMoveIntoSelf, "400"},
		{fsops.ErrExists, "409"},
		{fsops.ErrUploadMoved, "409"},
		{fmt.Errorf("%w: unexpected EOF", fsops.ErrBodyAborted), "400"},
		{fsops.ErrCrossDevice, "409"},
		{fsops.ErrReadOnly, "403"},
		{&fs.PathError{Op: "open", Path: "x", Err: fs.ErrPermission}, "403"},
		{fmt.Errorf("%w: %w", events.ErrNotRecorded, &fs.PathError{Op: "write", Path: "audit.log", Err: fs.ErrPermission}), "500"},
		{events.ErrNotConfirmed, "500"},
		{fmt.Errorf("%w: %w", transfer.ErrTooLargeForVolume, fs.ErrPermission), "413"},
		{fmt.Errorf("%w: %w", fsops.ErrCrossDevice, space.ErrInsufficient), "409"},
		{fmt.Errorf("%w: %w", fsops.ErrNotFound, fsops.ErrParentNotFound), "404"},
		{errors.New("something else"), "500"},
	} {
		if got := status(c.err); got != c.want {
			t.Errorf("%v: %s, want %s", c.err, got, c.want)
		}
	}
	srv := &fakeServer{partSize: 4, refuse: fmt.Errorf("%w: full", space.ErrInsufficient), parts: map[int][]byte{}}
	if res := Run(context.Background(), Config{Users: []User{{API: srv, Dir: "x"}}, Files: 1, Size: 10, Parallel: 1}); res.CodeColumn() != "507x1" {
		t.Errorf("codes %s", res.CodeColumn())
	}
}

func TestAFailedUploadSendsNoMoreParts(t *testing.T) {
	srv := &fakeServer{partSize: 4, failPart: transfer.ErrPartConflict, parts: map[int][]byte{}}
	res := Run(context.Background(), Config{Users: []User{{API: srv, Dir: "x"}}, Files: 1, Size: 40, Parallel: 1})
	if res.CodeColumn() != "409x1" || srv.calls != 1 {
		t.Errorf("codes %s, %d parts sent", res.CodeColumn(), srv.calls)
	}
}
