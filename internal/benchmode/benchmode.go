// Package benchmode holds what a benchmark build reads from its environment:
// HTTP/2's receive windows, the part size of resumable uploads, and a log of
// every request. Only a build with the bench tag reads them; any other build
// has none of them, and its functions leave everything as it is.
package benchmode

// The variables a benchmark build reads. Sizes are in bytes, or with K, M or
// G (powers of 1024).
const (
	EnvConnWindow   = "GOCALBOX_BENCH_H2_CONN_WINDOW"
	EnvStreamWindow = "GOCALBOX_BENCH_H2_STREAM_WINDOW"
	EnvPartSize     = "GOCALBOX_BENCH_PART_SIZE"
	EnvRequestLog   = "GOCALBOX_BENCH_REQUEST_LOG"
)
