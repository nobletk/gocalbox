//go:build bench

package benchmode

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestSettingsAreReadAndChecked(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "requests.jsonl")
	s, err := load(env(map[string]string{
		EnvConnWindow: "16M", EnvStreamWindow: "1M", EnvPartSize: "16M", EnvRequestLog: logPath,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if s.conn != 16<<20 || s.stream != 1<<20 || s.partSize != 16<<20 || s.log == nil {
		t.Errorf("settings %+v", s)
	}
	if _, err := os.Stat(logPath); err != nil {
		t.Errorf("the request log: %v", err)
	}
	if s, err := load(env(map[string]string{EnvConnWindow: "65535", EnvStreamWindow: "1", EnvPartSize: "8388608"})); err != nil ||
		s.conn != 65535 || s.stream != 1 || s.partSize != 8<<20 {
		t.Errorf("the smallest values: %+v, %v", s, err)
	}
	if s, err := load(env(map[string]string{EnvConnWindow: "2147483647", EnvStreamWindow: "2147483647", EnvPartSize: "64M"})); err != nil ||
		s.conn != 1<<31-1 || s.stream != 1<<31-1 || s.partSize != 64<<20 {
		t.Errorf("the largest values: %+v, %v", s, err)
	}
	if s, err := load(env(nil)); err != nil || s.conn != 0 || s.stream != 0 || s.partSize != 0 || s.log != nil {
		t.Errorf("nothing set: %+v, %v", s, err)
	}
	for name, values := range map[string][]string{
		EnvConnWindow:   {"65534", "2G", "-1", "1x", "K", "0", "9223372036854775807K", "8589934592G", "17179869185G"},
		EnvStreamWindow: {"0", "2147483648", "2G", "-5"},
		EnvPartSize:     {"4M", "128M", "24M", "8388609", "16m", "x"},
		EnvRequestLog:   {filepath.Join(t.TempDir(), "missing", "log.jsonl")},
		EnvSync:         {"Part", "all", "data,log", " none", "0"},
	} {
		for _, v := range values {
			if _, err := load(env(map[string]string{name: v})); err == nil || !strings.Contains(err.Error(), name) {
				t.Errorf("%s=%s: %v", name, v, err)
			}
		}
	}
}

// The part flushes are both by default, and the setting names what is kept.
func TestThePartFlushesAreRead(t *testing.T) {
	t.Cleanup(func() { current = settings{} })
	for v, want := range map[string][2]bool{"": {true, true}, "part": {true, true}, "data": {true, false}, "log": {false, true}, "none": {false, false}} {
		s, err := load(env(map[string]string{EnvSync: v}))
		if err != nil {
			t.Fatalf("%q: %v", v, err)
		}
		current = s
		if d, l := PartSyncs(); [2]bool{d, l} != want {
			t.Errorf("%q: data %v, log %v, want %v", v, d, l, want)
		}
	}
}

// A setting that drops a flush says so in the log, and what it drops; the
// default says nothing.
func TestInitSaysWhichFlushesAreDropped(t *testing.T) {
	t.Cleanup(func() { current = settings{} })
	var out bytes.Buffer
	log.SetOutput(&out)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	for v, want := range map[string]string{"data": "flushes only its data", "log": "flushes only its log line", "none": "flushes nothing", "part": "", "": ""} {
		out.Reset()
		t.Setenv(EnvSync, v)
		if err := Init(); err != nil {
			t.Fatal(err)
		}
		got := out.String()
		if want == "" && strings.Contains(got, EnvSync) || want != "" && (!strings.Contains(got, want) || !strings.Contains(got, "may not be on disk")) {
			t.Errorf("%q: log %q", v, got)
		}
	}
}

// Init takes what the environment sets, says so in the log, and changes
// only what is set.
func TestInitTakesTheEnvironment(t *testing.T) {
	t.Cleanup(func() { current = settings{} })
	var out bytes.Buffer
	log.SetOutput(&out)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	t.Setenv(EnvStreamWindow, "512K")
	t.Setenv(EnvPartSize, "32M")
	if err := Init(); err != nil {
		t.Fatal(err)
	}
	if c, s := H2Windows(7, 9); c != 7 || s != 512<<10 {
		t.Errorf("H2Windows = %d, %d", c, s)
	}
	if PartSize() != 32<<20 || RequestLog() != nil {
		t.Errorf("PartSize %d, RequestLog %v", PartSize(), RequestLog())
	}
	for _, want := range []string{"BENCHMARK BUILD: not for serving users", "stream window 524288", "part size 33554432"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("log %q lacks %q", out.String(), want)
		}
	}
	if strings.Contains(out.String(), "connection window") {
		t.Errorf("log %q names a window that wasn't set", out.String())
	}
	t.Setenv(EnvPartSize, "3")
	if err := Init(); err == nil {
		t.Error("an invalid setting was taken")
	}
	if PartSize() != 32<<20 {
		t.Errorf("a refused setting changed the part size: %d", PartSize())
	}
}

func TestTheRequestLogWritesWholeLines(t *testing.T) {
	w, err := openLineWriter(filepath.Join(t.TempDir(), "log"))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan bool)
	for i := range 8 {
		go func() {
			for range 100 {
				w.Write([]byte(strings.Repeat(string(rune('a'+i)), 1000) + "\n"))
			}
			done <- true
		}()
	}
	for range 8 {
		<-done
	}
	b, _ := os.ReadFile(w.f.Name())
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	if len(lines) != 800 {
		t.Fatalf("%d lines", len(lines))
	}
	for _, l := range lines {
		if len(l) != 1000 || strings.Trim(l, l[:1]) != "" {
			t.Fatalf("a mixed line: %.40q", l)
		}
	}
}
