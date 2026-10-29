//go:build !bench

package benchmode

import "io"

// Enabled reports whether this is a benchmark build.
const Enabled = false

// Init reads the benchmark settings; in this build there are none.
func Init() error { return nil }

// H2Windows returns HTTP/2's receive windows: in this build, conn and stream.
func H2Windows(conn, stream int) (int, int) { return conn, stream }

// PartSize returns the part size every resumable upload uses, or 0 for the
// schedule's: in this build, always 0.
func PartSize() int64 { return 0 }

// PartSyncs reports whether an accepted part's data and its log line are
// flushed before it is answered: in this build, both.
func PartSyncs() (data, log bool) { return true, true }

// RequestLog returns where to log every request, or nil: in this build,
// nil.
func RequestLog() io.Writer { return nil }
