// Package benchmode holds what a benchmark build reads from its environment:
// HTTP/2's receive windows, the part size of resumable uploads, which of a
// part's flushes are made, and a log of every request. Only a build with the
// bench tag reads them; any other build has none of them, and its functions
// leave everything as it is.
package benchmode

// The variables a benchmark build reads. Sizes are in bytes, or with K, M or
// G (powers of 1024).
const (
	EnvConnWindow   = "GOCALBOX_BENCH_H2_CONN_WINDOW"
	EnvStreamWindow = "GOCALBOX_BENCH_H2_STREAM_WINDOW"
	EnvPartSize     = "GOCALBOX_BENCH_PART_SIZE"
	EnvRequestLog   = "GOCALBOX_BENCH_REQUEST_LOG"
	EnvSync         = "GOCALBOX_BENCH_SYNC"
)

// The values of EnvSync: which of an accepted part's two flushes, of its data
// and of its line in the upload's log, are made before the part is answered.
// Only "part", both, keeps the promise that an answered part is on disk. With
// "log" or "none", a power cut can keep a part's line but lose its data, and
// recovery, which trusts the line, would then let the upload complete with
// other bytes.
const (
	SyncPart = "part"
	SyncData = "data"
	SyncLog  = "log"
	SyncNone = "none"
)
