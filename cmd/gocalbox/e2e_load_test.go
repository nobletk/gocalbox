package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/nobletk/gocalbox/bench/load"
)

// The load client's resume against the real server: each file stops with
// parts in flight, which are cut off, and resumes the session the server
// kept by its client key; the stored files are whole, and the client's clean
// up deletes them.
func TestE2ELoadClientResumesOverHTTPS(t *testing.T) {
	for _, h1 := range []bool{false, true} {
		t.Run(fmt.Sprintf("http1=%v", h1), func(t *testing.T) {
			s := startServer(t)
			ca, err := os.ReadFile(filepath.Join(s.tlsDir, "ca.crt"))
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			users, err := load.LogIn(ctx, load.Remote{URL: s.url, CA: ca, HTTP1: h1}, []string{"admin"}, testPassword)
			if err != nil {
				t.Fatal(err)
			}
			const size = 4*(8<<20) + 7
			res := load.Run(ctx, load.Config{Users: users, Files: 2, Size: size, Parallel: 3, ResumeAt: 0.5})
			if res.CodeColumn() != "201" || len(res.Resumes) != 2 {
				t.Fatalf("codes %s, resumes %v, tried again %v\n%s", res.CodeColumn(), res.Resumes, res.Retried, s.out)
			}
			for f := range 2 {
				want := make([]byte, size)
				for i := range want {
					want[i] = byte(i%251) + byte(f)
				}
				got, err := os.ReadFile(filepath.Join(s.root, "users", "admin", fmt.Sprintf("load-000-%04d.bin", f)))
				if err != nil || !bytes.Equal(got, want) {
					t.Errorf("file %d: %d bytes, %v", f, len(got), err)
				}
			}
			if err := load.Clean(ctx, users); err != nil {
				t.Fatal(err)
			}
			if entries, err := os.ReadDir(filepath.Join(s.root, "users", "admin")); err != nil || len(entries) != 0 {
				t.Errorf("after the clean up: %v, %v", entries, err)
			}
		})
	}
}
