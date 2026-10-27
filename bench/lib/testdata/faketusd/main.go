// Command faketusd stands in for tusd in the tests of the benchmark
// scripts: the flags they give tusd, and the tus core protocol with the
// creation extension over HTTPS, storing each upload as tusd's file store
// does, as a file named by its ID next to an .info file. With
// FAKE_TUSD_CORRUPT set, it stores a byte more than each upload brought,
// and with FAKE_TUSD_EXTRA, a file more than the upload's.
package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

func main() {
	host := flag.String("host", "0.0.0.0", "Host to bind the server to")
	port := flag.String("port", "8080", "Port to bind the server to")
	dir := flag.String("upload-dir", "./data", "Directory to store uploads in")
	base := flag.String("base-path", "/files/", "Basepath of the HTTP server")
	cert := flag.String("tls-certificate", "", "Path to the file containing the x509 TLS certificate")
	key := flag.String("tls-key", "", "Path to the file containing the key for the TLS certificate")
	verbose := flag.Bool("verbose", true, "Enable verbose logging output")
	version := flag.Bool("version", false, "Print tusd version information")
	flag.Parse()
	if *version {
		fmt.Println("Version: faketusd\nCommit: none")
		return
	}
	var mu sync.Mutex
	offsets := map[string]int64{}
	lengths := map[string]int64{}
	http.HandleFunc(*base, func(w http.ResponseWriter, r *http.Request) {
		if *verbose {
			log.Printf("%s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Tus-Resumable", "1.0.0")
		id := strings.TrimPrefix(r.URL.Path, *base)
		switch {
		case r.Method == http.MethodOptions:
			w.Header().Set("Tus-Version", "1.0.0")
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && id == "":
			n, err := strconv.ParseInt(r.Header.Get("Upload-Length"), 10, 64)
			if err != nil || r.Header.Get("Tus-Resumable") != "1.0.0" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			id = strings.ToLower(rand.Text())
			if err := os.WriteFile(filepath.Join(*dir, id), nil, 0o644); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			os.WriteFile(filepath.Join(*dir, id+".info"), fmt.Appendf(nil, `{"ID":%q,"Size":%d}`, id, n), 0o644)
			if os.Getenv("FAKE_TUSD_EXTRA") != "" {
				os.WriteFile(filepath.Join(*dir, id+".extra"), nil, 0o644)
			}
			mu.Lock()
			offsets[id], lengths[id] = 0, n
			mu.Unlock()
			w.Header().Set("Location", *base+id)
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodHead:
			mu.Lock()
			off, ok := offsets[id]
			mu.Unlock()
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Upload-Offset", strconv.FormatInt(off, 10))
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPatch:
			mu.Lock()
			off, ok := offsets[id]
			length := lengths[id]
			mu.Unlock()
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if r.Header.Get("Upload-Offset") != strconv.FormatInt(off, 10) || r.Header.Get("Content-Type") != "application/offset+octet-stream" {
				w.WriteHeader(http.StatusConflict)
				return
			}
			f, err := os.OpenFile(filepath.Join(*dir, id), os.O_WRONLY|os.O_APPEND, 0)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			n, _ := io.Copy(f, io.LimitReader(r.Body, length-off))
			if off+n == length && os.Getenv("FAKE_TUSD_CORRUPT") != "" {
				f.Write([]byte("x"))
			}
			f.Close()
			mu.Lock()
			offsets[id] = off + n
			mu.Unlock()
			w.Header().Set("Upload-Offset", strconv.FormatInt(off+n, 10))
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	l, err := net.Listen("tcp", net.JoinHostPort(*host, *port))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("You can now upload files to: https://%s%s", l.Addr(), *base)
	log.Fatal(http.ServeTLS(l, nil, *cert, *key))
}
