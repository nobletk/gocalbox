//go:build bench

package transfer

import (
	"os"
	"testing"

	"github.com/nobletk/gocalbox/internal/benchmode"
)

func benchPartSize(t *testing.T, v string) {
	t.Helper()
	t.Cleanup(func() {
		os.Unsetenv(benchmode.EnvPartSize)
		benchmode.Init()
	})
	t.Setenv(benchmode.EnvPartSize, v)
	if err := benchmode.Init(); err != nil {
		t.Fatal(err)
	}
}

// withSchedule leaves the engine the server's part sizes, instead of the
// tests' small one.
func withSchedule() option { return func(c *Config, _ *env) { c.prepare = nil } }

// A benchmark build cuts every file into parts of the size it is given, as
// long as that keeps the parts within what the schedule allows.
func TestABenchmarkPartSizeIsUsedForEveryFile(t *testing.T) {
	benchPartSize(t, "16M")
	for _, size := range []int64{0, 1, 8 << 20, 1 << 30, 80 << 30} {
		if got := PartSize(size); got != 16<<20 {
			t.Errorf("PartSize(%d) = %d", size, got)
		}
	}
	most := int64(MaxSize/MaxPartSize) * (16 << 20)
	if got := PartSize(most); got != 16<<20 {
		t.Errorf("PartSize(%d), in the most parts allowed, = %d", most, got)
	}
	if got := PartSize(most + 1); got != 64<<20 {
		t.Errorf("PartSize(%d), one part more, = %d, want the schedule's", most+1, got)
	}
	if !IsPartSize(PartSize(1 << 30)) {
		t.Error("a benchmark part size that -verify-upload doesn't know")
	}
}

// A session made with a benchmark part size is recovered after a restart of
// the same build with the same setting.
func TestASessionWithABenchmarkPartSizeIsRecovered(t *testing.T) {
	benchPartSize(t, "32M")
	en := newEnv(t, withSchedule(), withFree(1<<40))
	created, err := en.e.Create(as(alice), CreateRequest{Dir: "public", Name: "declared.bin", Size: 1 << 30})
	if err != nil {
		t.Fatal(err)
	}
	if created.PartSize != 32<<20 || created.PartCount != 32 {
		t.Fatalf("created %+v", created)
	}
	next := en.restart(withSchedule(), withFree(1<<40))
	if next.state(created.UploadID) != Receiving {
		t.Errorf("after a restart: %s", next.state(created.UploadID))
	}
}
