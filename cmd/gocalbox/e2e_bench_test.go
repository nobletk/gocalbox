package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nobletk/gocalbox/internal/benchmode"
	"github.com/nobletk/gocalbox/internal/transfer"
)

var (
	benchOnce sync.Once
	benchPath string
	benchErr  error
)

// benchBinary builds the server with the bench tag, next to the binary of
// the other end-to-end tests.
func benchBinary(t *testing.T) string {
	t.Helper()
	bin := binary(t)
	benchOnce.Do(func() {
		benchPath = bin + "-bench"
		out, err := exec.Command("go", "build", "-tags", "bench", "-o", benchPath, ".").CombinedOutput()
		if err != nil {
			benchErr = fmt.Errorf("%v\n%s", err, out)
		}
	})
	if benchErr != nil {
		t.Fatalf("building the benchmark binary: %v", benchErr)
	}
	return benchPath
}

func setBenchEnv(t *testing.T) string {
	t.Helper()
	logPath := filepath.Join(t.TempDir(), "requests.jsonl")
	t.Setenv(benchmode.EnvConnWindow, "16M")
	t.Setenv(benchmode.EnvStreamWindow, "1M")
	t.Setenv(benchmode.EnvPartSize, "16M")
	t.Setenv(benchmode.EnvRequestLog, logPath)
	return logPath
}

// createdPartSize declares an upload of 256 MiB and returns the part size the
// server answers.
func createdPartSize(t *testing.T, s *liveServer) int64 {
	t.Helper()
	body := `{"dir":"","name":"declared.bin","size":268435456}`
	resp, err := s.client.Post(s.url+"/api/upload/create", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var c transfer.Created
	if err := json.NewDecoder(resp.Body).Decode(&c); err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: %d, %v", resp.StatusCode, err)
	}
	return c.PartSize
}

// A binary built without the bench tag ignores the benchmark settings.
func TestE2EANormalBinaryIgnoresTheBenchmarkSettings(t *testing.T) {
	logPath := setBenchEnv(t)
	s := startServer(t)
	if stream, conn := advertisedWindows(t, s); stream != 256<<10 || conn != 4<<20-1 {
		t.Errorf("windows %d, %d", stream, conn)
	}
	if p := createdPartSize(t, s); p != 8<<20 {
		t.Errorf("part size %d", p)
	}
	if strings.Contains(s.out.String(), "BENCHMARK") {
		t.Errorf("output: %s", s.out)
	}
	if _, err := os.Stat(logPath); !os.IsNotExist(err) {
		t.Errorf("the request log was made: %v", err)
	}
}

// A benchmark binary takes the settings, says so, and logs every request.
func TestE2EABenchmarkBinaryTakesItsSettings(t *testing.T) {
	logPath := setBenchEnv(t)
	s := newLiveServer(t)
	s.bin = benchBinary(t)
	seedAdmin(t, s.statePath, s.root)
	s.start()
	if stream, conn := advertisedWindows(t, s); stream != 1<<20 || conn != 16<<20 {
		t.Errorf("windows %d, %d", stream, conn)
	}
	if p := createdPartSize(t, s); p != 16<<20 {
		t.Errorf("part size %d", p)
	}
	for _, want := range []string{"BENCHMARK BUILD: not for serving users", "part size 16777216", "logging every request to " + logPath} {
		if !strings.Contains(s.out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, s.out)
		}
	}
	var found bool
	for deadline := time.Now().Add(5 * time.Second); !found && time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		b, _ := os.ReadFile(logPath)
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			var e struct {
				Path   string `json:"path"`
				Status int    `json:"status"`
				In     int64  `json:"in"`
			}
			if json.Unmarshal(sc.Bytes(), &e) == nil && e.Path == "/api/upload/create" && e.Status == 201 && e.In > 0 {
				found = true
			}
		}
	}
	if !found {
		b, _ := os.ReadFile(logPath)
		t.Errorf("no line for the create in the request log:\n%s", b)
	}
}

// A benchmark binary given a setting out of range stops before it serves.
func TestE2EABenchmarkBinaryRefusesABadSetting(t *testing.T) {
	bin := benchBinary(t)
	for name, value := range map[string]string{
		benchmode.EnvPartSize:     "24M",
		benchmode.EnvConnWindow:   "1K",
		benchmode.EnvStreamWindow: "0",
		benchmode.EnvRequestLog:   filepath.Join(t.TempDir(), "missing", "log"),
		benchmode.EnvSync:         "all",
	} {
		dir := t.TempDir()
		cmd := exec.Command(bin, "-host=127.0.0.1", fmt.Sprintf("-port=%d", freePort(t)), "-root="+dir,
			"-audit-log="+filepath.Join(t.TempDir(), "audit.jsonl"), "-state="+filepath.Join(t.TempDir(), "state.db"),
			"-tls-dir="+filepath.Join(t.TempDir(), "tls"))
		cmd.Env = append(isolatedEnv(t), name+"="+value)
		done := make(chan struct{})
		var out []byte
		var err error
		go func() { out, err = cmd.CombinedOutput(); close(done) }()
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			cmd.Process.Kill()
			<-done
			t.Fatalf("%s=%s: still running", name, value)
		}
		if err == nil || !strings.Contains(string(out), name) {
			t.Errorf("%s=%s: %v\n%s", name, value, err, out)
		}
		if entries, _ := os.ReadDir(dir); len(entries) != 0 {
			t.Errorf("%s=%s: the served folder holds %d entries", name, value, len(entries))
		}
	}
}

// A benchmark binary that flushes nothing per part says so, and still stores
// the whole file.
func TestE2EABenchmarkBinaryWithoutPartFlushesStoresTheFile(t *testing.T) {
	t.Setenv(benchmode.EnvSync, "none")
	s := newLiveServer(t)
	s.bin = benchBinary(t)
	tokens := addUsers(t, s, "alice:contributor")
	s.start()
	f := source{dir: "public", name: "unflushed.bin", data: randomData(t, 20<<20+7), modified: time.Now()}
	res, err := s.uploader(tokens["alice"]).upload(f)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(s.root, filepath.FromSlash(res.Path)))
	if err != nil || !bytes.Equal(b, f.data) {
		t.Fatalf("the stored file: %d bytes, %v", len(b), err)
	}
	if want := "flushes nothing before its answer (" + benchmode.EnvSync + ")"; !strings.Contains(s.out.String(), want) {
		t.Errorf("output lacks %q:\n%s", want, s.out)
	}
}
