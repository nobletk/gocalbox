package httpapi

import (
	"net/http"
	"time"
)

// HTTP/2's receive windows. A request body whose handler stops reading, an
// upload whose writes block for one, keeps what it has received counted
// against its connection's window until the handler returns. With these
// windows each such body holds at most 256 KiB, so up to 15 of them leave
// 256 KiB − 1 for the connection's other requests, and 16 fill it. The room
// is per connection: it assumes that one connection carries one client's
// requests, which a proxy multiplexing several users over one HTTP/2
// connection breaks. 4 MiB − 1 is the largest connection window Go
// documents as valid.
const (
	receiveWindowPerConnection = 4<<20 - 1
	receiveWindowPerStream     = 256 << 10
)

// NewServer returns the HTTP server for h.
func NewServer(h http.Handler) *http.Server {
	return &http.Server{
		Handler: h,
		// No read or write timeout: they would cut off long uploads and media
		// streams. Stalled request bodies are limited per request
		// (Options.BodyTimeout).
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		HTTP2: &http.HTTP2Config{
			MaxReceiveBufferPerConnection: receiveWindowPerConnection,
			MaxReceiveBufferPerStream:     receiveWindowPerStream,
		},
	}
}
