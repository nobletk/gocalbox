package main

import (
	"context"
	"crypto/tls"
	be "encoding/binary"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/nobletk/gocalbox/bench/load"
)

// readFrame reads one HTTP/2 frame.
func readFrame(t *testing.T, r io.Reader) (typ, flags byte, stream uint32, payload []byte) {
	t.Helper()
	var hdr [9]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		t.Fatalf("reading a frame: %v", err)
	}
	payload = make([]byte, int(hdr[0])<<16|int(hdr[1])<<8|int(hdr[2]))
	if _, err := io.ReadFull(r, payload); err != nil {
		t.Fatalf("reading a frame: %v", err)
	}
	return hdr[3], hdr[4], be.BigEndian.Uint32(hdr[5:]) & (1<<31 - 1), payload
}

// The binary's HTTPS port gives an HTTP/2 client the receive windows that
// internal/httpapi's stall tests measure: 256 KiB per stream, 4 MiB − 1 for
// the connection.
func TestE2EHTTPSAdvertisesTheHTTP2Windows(t *testing.T) {
	s := startServer(t)
	cfg := s.tlsConfig.Clone()
	cfg.NextProtos = []string{"h2"}
	c, err := tls.Dial("tcp", s.addr, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if p := c.ConnectionState().NegotiatedProtocol; p != "h2" {
		t.Fatalf("negotiated %q", p)
	}
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(c, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00"); err != nil {
		t.Fatal(err)
	}
	stream, conn := -1, -1
	for stream < 0 || conn < 0 {
		typ, flags, id, payload := readFrame(t, c)
		switch {
		case typ == 0x4 && flags&0x1 == 0:
			stream = 65535
			for i := 0; i+6 <= len(payload); i += 6 {
				if be.BigEndian.Uint16(payload[i:]) == 0x4 {
					stream = int(be.BigEndian.Uint32(payload[i+2:]))
				}
			}
		case typ == 0x8 && id == 0:
			conn = 65535 + int(be.BigEndian.Uint32(payload)&(1<<31-1))
		}
	}
	if stream != 256<<10 || conn != 4<<20-1 {
		t.Errorf("windows: %d per stream and %d for the connection, want %d and %d", stream, conn, 256<<10, 4<<20-1)
	}
}

// The load client logs its users in to the real server over HTTPS, each on
// a connection of its own, uploads with both protocols, and removes what it
// uploaded.
func TestE2ETheLoadClientUploadsOverHTTPS(t *testing.T) {
	s := newLiveServer(t)
	addUsers(t, s, "load00:contributor", "load01:contributor")
	s.start()
	ca, err := os.ReadFile(filepath.Join(s.tlsDir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	const size = 8<<20 + 5
	completed := 0
	for _, http1 := range []bool{false, true} {
		ctx := context.Background()
		users, err := load.LogIn(ctx, load.Remote{URL: s.url, CA: ca, HTTP1: http1}, []string{"load00", "load01"}, testPassword)
		if err != nil {
			t.Fatal(err)
		}
		res := load.Run(ctx, load.Config{Users: users, Files: 2, Size: size, Parallel: 2})
		if res.CodeColumn() != "201" || res.Files != 4 || len(res.Parts) != 8 {
			t.Fatalf("HTTP/1.1 %v: codes %s, %d parts", http1, res.CodeColumn(), len(res.Parts))
		}
		completed += 4
		for _, p := range []string{"users/load00/load-000-0000.bin", "users/load00/load-000-0001.bin", "users/load01/load-001-0000.bin", "users/load01/load-001-0001.bin"} {
			if info, err := os.Stat(filepath.Join(s.root, filepath.FromSlash(p))); err != nil || info.Size() != size {
				t.Errorf("HTTP/1.1 %v: %s: %v", http1, p, err)
			}
		}
		if err := load.Clean(ctx, users); err != nil {
			t.Fatal(err)
		}
		for _, home := range []string{"users/load00", "users/load01"} {
			if entries, err := os.ReadDir(filepath.Join(s.root, filepath.FromSlash(home))); err != nil || len(entries) != 0 {
				t.Errorf("HTTP/1.1 %v: %s holds %v after the clean (%v)", http1, home, entries, err)
			}
		}
	}
	if err := s.stop(syscall.SIGTERM); err != nil {
		t.Fatalf("exit: %v", err)
	}
	log, err := os.ReadFile(s.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(log), `"type":"upload.completed"`); n != completed {
		t.Errorf("%d completions in the audit log, want %d", n, completed)
	}
}
