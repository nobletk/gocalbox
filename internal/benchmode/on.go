//go:build bench

package benchmode

import (
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"strconv"
	"strings"
)

// Enabled reports whether this is a benchmark build.
const Enabled = true

type settings struct {
	conn, stream int
	partSize     int64
	// sync is EnvSync's value; "" is SyncPart.
	sync string
	log  *lineWriter
}

var current settings

// Init reads the benchmark settings from the environment and logs each one
// it takes. A value out of range is an error: HTTP/2 would quietly use its
// default instead, and the run would measure something else. Settings taken
// again close the request log they replace: Windows can't delete an open
// file.
func Init() error {
	s, err := load(os.Getenv)
	if err != nil {
		return err
	}
	if current.log != nil {
		current.log.close()
	}
	current = s
	log.Printf("BENCHMARK BUILD: not for serving users")
	if s.conn > 0 {
		log.Printf("BENCHMARK BUILD: HTTP/2 connection window %d bytes (%s)", s.conn, EnvConnWindow)
	}
	if s.stream > 0 {
		log.Printf("BENCHMARK BUILD: HTTP/2 stream window %d bytes (%s)", s.stream, EnvStreamWindow)
	}
	if s.partSize > 0 {
		log.Printf("BENCHMARK BUILD: part size %d bytes for every resumable upload (%s)", s.partSize, EnvPartSize)
	}
	if s.sync != "" && s.sync != SyncPart {
		log.Printf("BENCHMARK BUILD: an accepted part flushes %s before its answer (%s); answered parts may not be on disk", flushes(s.sync), EnvSync)
	}
	if s.log != nil {
		log.Printf("BENCHMARK BUILD: logging every request to %s (%s)", s.log.f.Name(), EnvRequestLog)
	}
	return nil
}

func load(getenv func(string) string) (settings, error) {
	var s settings
	var err error
	// The ranges Go's HTTP/2 server takes; outside them it uses its default.
	if s.conn, err = sizeIn(getenv, EnvConnWindow, 65535, math.MaxInt32); err != nil {
		return s, err
	}
	if s.stream, err = sizeIn(getenv, EnvStreamWindow, 1, math.MaxInt32); err != nil {
		return s, err
	}
	part, err := sizeIn(getenv, EnvPartSize, 8<<20, 64<<20)
	if err != nil {
		return s, err
	}
	if part&(part-1) != 0 {
		return s, fmt.Errorf("%s=%s: the part size must be a power of two", EnvPartSize, getenv(EnvPartSize))
	}
	s.partSize = int64(part)
	switch v := getenv(EnvSync); v {
	case "", SyncPart, SyncData, SyncLog, SyncNone:
		s.sync = v
	default:
		return s, fmt.Errorf("%s=%s: give %s, %s, %s or %s", EnvSync, v, SyncPart, SyncData, SyncLog, SyncNone)
	}
	if p := getenv(EnvRequestLog); p != "" {
		if s.log, err = openLineWriter(p); err != nil {
			return s, fmt.Errorf("%s: %w", EnvRequestLog, err)
		}
	}
	return s, nil
}

// sizeIn reads the size in name, 0 if it is unset, and checks it lies in
// [lo, hi].
func sizeIn(getenv func(string) string, name string, lo, hi int64) (int, error) {
	v := getenv(name)
	if v == "" {
		return 0, nil
	}
	n, err := parseSize(v)
	if err != nil || n < lo || n > hi {
		return 0, fmt.Errorf("%s=%s: give a size from %d to %d bytes", name, v, lo, hi)
	}
	return int(n), nil
}

func parseSize(s string) (int64, error) {
	mult := int64(1)
	switch {
	case strings.HasSuffix(s, "K"):
		mult, s = 1<<10, strings.TrimSuffix(s, "K")
	case strings.HasSuffix(s, "M"):
		mult, s = 1<<20, strings.TrimSuffix(s, "M")
	case strings.HasSuffix(s, "G"):
		mult, s = 1<<30, strings.TrimSuffix(s, "G")
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, err
	}
	if n < 0 || n > math.MaxInt64/mult {
		return 0, errors.New("out of range")
	}
	return n * mult, nil
}

// H2Windows returns HTTP/2's receive windows: those the environment set, and
// conn and stream for the others.
func H2Windows(conn, stream int) (int, int) {
	if current.conn > 0 {
		conn = current.conn
	}
	if current.stream > 0 {
		stream = current.stream
	}
	return conn, stream
}

// PartSize returns the part size every resumable upload uses, or 0 for the
// schedule's.
func PartSize() int64 { return current.partSize }

// PartSyncs reports whether an accepted part's data and its log line are
// flushed before it is answered.
func PartSyncs() (data, log bool) {
	switch current.sync {
	case SyncData:
		return true, false
	case SyncLog:
		return false, true
	case SyncNone:
		return false, false
	}
	return true, true
}

func flushes(v string) string {
	switch v {
	case SyncData:
		return "only its data"
	case SyncLog:
		return "only its log line"
	}
	return "nothing"
}

// RequestLog returns where to log every request, or nil if the environment
// named no log. Each Write to it is written whole, and others wait for it.
func RequestLog() io.Writer {
	if current.log == nil {
		return nil
	}
	return current.log
}
