package httpapi

import (
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

type namedHandler struct{ http.Handler }

func TestNewServerKeepsTheServersTimeouts(t *testing.T) {
	h := &namedHandler{http.NotFoundHandler()}
	srv := NewServer(h)
	if srv.Handler != h || srv.ReadHeaderTimeout != 10*time.Second || srv.IdleTimeout != 2*time.Minute ||
		srv.ReadTimeout != 0 || srv.WriteTimeout != 0 {
		t.Errorf("server: handler %v, header %v, idle %v, read %v, write %v", srv.Handler, srv.ReadHeaderTimeout, srv.IdleTimeout, srv.ReadTimeout, srv.WriteTimeout)
	}
}

// An HTTP/2 client learns the windows from the server's first frames: the
// stream's in SETTINGS, the connection's as a WINDOW_UPDATE above the
// protocol's initial 65535.
func TestNewServerAdvertisesTheWindows(t *testing.T) {
	srv := NewServer(http.NotFoundHandler())
	srv.Protocols = new(http.Protocols)
	srv.Protocols.SetUnencryptedHTTP2(true)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	defer srv.Close()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(c, h2Preface+"\x00\x00\x00\x04\x00\x00\x00\x00\x00"); err != nil {
		t.Fatal(err)
	}
	stream, conn := -1, -1
	for stream < 0 || conn < 0 {
		var hdr [9]byte
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			t.Fatalf("reading a frame: %v", err)
		}
		payload := make([]byte, int(hdr[0])<<16|int(hdr[1])<<8|int(hdr[2]))
		if _, err := io.ReadFull(c, payload); err != nil {
			t.Fatalf("reading a frame: %v", err)
		}
		switch id := binary.BigEndian.Uint32(hdr[5:]) & (1<<31 - 1); {
		case hdr[3] == 0x4 && hdr[4]&0x1 == 0:
			stream = 65535
			for i := 0; i+6 <= len(payload); i += 6 {
				if binary.BigEndian.Uint16(payload[i:]) == 0x4 {
					stream = int(binary.BigEndian.Uint32(payload[i+2:]))
				}
			}
		case hdr[3] == 0x8 && id == 0:
			conn = 65535 + int(binary.BigEndian.Uint32(payload)&(1<<31-1))
		}
	}
	if stream != streamWindow || conn != connWindow {
		t.Errorf("windows: %d per stream and %d for the connection, want %d and %d", stream, conn, streamWindow, connWindow)
	}
}
