// Package httpapi is the HTTP interface: routing, request decoding, JSON
// responses and the mapping of service errors to status codes.
package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/fsops"
)

type FileService interface {
	List(ctx context.Context, dir string) ([]fsops.Entry, error)
	Open(ctx context.Context, path string) (*fsops.File, error)
	Create(ctx context.Context, dir, name string, r io.Reader, sizeHint int64) (string, int64, error)
	Mkdir(ctx context.Context, parent, name string) (string, error)
	Delete(ctx context.Context, path string) (string, error)
	Move(ctx context.Context, oldPath, newPath string) (string, error)
}

type Options struct {
	MaxUploadBytes int64 // 0 = unlimited

	AllowedHosts []string

	Ready func() error

	BodyTimeout time.Duration

	Tracker *Tracker

	// RequireTLS answers plain HTTP requests with a redirect to HTTPS.
	RequireTLS bool

	// CACert, if set, is served at /ca.crt for devices to install.
	CACert []byte
}

type ClientFileInfo struct {
	Name  string `json:"name"`
	Size  int64  `json:"size"`
	IsDir bool   `json:"isDir"`
}

type DeleteRequest struct {
	Path string `json:"path"`
}

type MoveRequest struct {
	OldPath string `json:"oldPath"`
	NewPath string `json:"newPath"`
}

type CreateFolderRequest struct {
	Name       string `json:"name"`
	TargetPath string `json:"targetPath"`
}

type PathResponse struct {
	Path string `json:"path"`
	Name string `json:"name,omitempty"`
	Size int64  `json:"size,omitempty"`
}

type ErrorResponse struct {
	Error     ErrorBody `json:"error"`
	RequestID string    `json:"requestId,omitempty"`
}

type ErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type api struct {
	files     FileService
	maxUpload int64
	ready     func() error
	tracker   *Tracker
}

func New(files FileService, webFS fs.FS, opts Options) http.Handler {
	a := &api{files: files, maxUpload: opts.MaxUploadBytes, ready: opts.Ready, tracker: opts.Tracker}

	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(webFS)))
	mux.Handle("/files/", a.gate(http.StripPrefix("/files/", http.HandlerFunc(a.handleFile))))
	mux.Handle("/api/files", a.gate(http.HandlerFunc(a.handleListFiles)))
	mux.Handle("/api/upload", a.gate(http.HandlerFunc(a.handleUpload)))
	mux.Handle("/api/fs/delete", a.gate(http.HandlerFunc(a.handleDelete)))
	mux.Handle("/api/fs/rename", a.gate(http.HandlerFunc(a.handleMove)))
	mux.Handle("/api/fs/move", a.gate(http.HandlerFunc(a.handleMove)))
	mux.Handle("/api/fs/mkdir", a.gate(http.HandlerFunc(a.handleCreateFolder)))
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeErrorJSON(w, r, http.StatusNotFound, "not_found", "Unknown API endpoint")
	})
	if opts.CACert != nil {
		mux.Handle("/ca.crt", serveCACert(opts.CACert))
	}

	cop := http.NewCrossOriginProtection()
	cop.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("SECURITY ALERT: Blocked cross-origin %s %s (Origin %q, Sec-Fetch-Site %q)",
			r.Method, r.URL.Path, r.Header.Get("Origin"), r.Header.Get("Sec-Fetch-Site"))
		writeErrorJSON(w, r, http.StatusForbidden, "cross_origin", "Cross-origin requests are not allowed")
	}))

	// The body limit is outermost: net/http reads the unread rest of a body
	// before it replies, so requests refused early must be bounded too.
	inner := cop.Handler(isolateResources(rejectUnclean(mux)))
	if opts.RequireTLS {
		inner = redirectPlain(inner)
	}
	return requestContext(limitBodyStalls(opts.BodyTimeout,
		securityHeaders(checkHost(opts.AllowedHosts, inner))))
}

func rejectUnclean(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if strings.HasPrefix(p, "/api/") || strings.HasPrefix(p, "/files/") {
			clean := path.Clean(p)
			if strings.HasSuffix(p, "/") && clean != "/" {
				clean += "/"
			}
			if clean != p {
				writeErrorJSON(w, r, http.StatusBadRequest, "invalid_path", "Invalid path")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (a *api) gate(next http.Handler) http.Handler {
	h := next
	if a.ready != nil {
		inner := h
		h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := a.ready(); err != nil {
				log.Printf("Refusing %s %s: %v", r.Method, r.URL.Path, err)
				writeErrorJSON(w, r, http.StatusServiceUnavailable, "unavailable", "File operations are suspended because they cannot be audited")
				return
			}
			inner.ServeHTTP(w, r)
		})
	}
	if a.tracker != nil {
		h = a.tracker.track(h)
	}
	return h
}

func requestContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := newRequestID()
		w.Header().Set("X-Request-ID", id)

		ctx := events.WithRequestID(r.Context(), id)
		// X-Forwarded-For is ignored because any client can forge it.
		ctx = events.WithActor(ctx, events.Actor{ID: events.AnonymousID, RemoteAddr: r.RemoteAddr})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func checkHost(allowed []string, next http.Handler) http.Handler {
	if len(allowed) == 0 {
		return next
	}
	set := make(map[string]bool, len(allowed))
	for _, h := range allowed {
		set[normalizeHost(h)] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := normalizeHost(r.Host)
		if !set[host] && !isLocalAddr(r, host) {
			log.Printf("SECURITY ALERT: Rejected request for unknown host %q from %s", r.Host, r.RemoteAddr)
			writeErrorJSON(w, r, http.StatusMisdirectedRequest, "host_not_allowed", "Unknown host name")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// isLocalAddr reports whether host is the IP address the request arrived
// on, which may be newer than the allowlist. A rebinding attack names its
// own domain, never an IP address.
func isLocalAddr(r *http.Request, host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	addr, ok := r.Context().Value(http.LocalAddrContextKey).(*net.TCPAddr)
	return ok && addr.IP.Equal(ip)
}

func redirectPlain(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Connection", "close")
		if (r.Method != http.MethodGet && r.Method != http.MethodHead) || r.Host == "" {
			writeErrorJSON(w, r, http.StatusBadRequest, "https_required", "This server only accepts HTTPS")
			return
		}
		// HTTPS is on the port this request came in on; a Host without a port
		// means the client used port 80.
		host, port, err := net.SplitHostPort(r.Host)
		if err != nil {
			host, port = strings.Trim(r.Host, "[]"), "80"
		}
		// Temporary, so browsers do not cache it: plain HTTP may serve this
		// address later (-insecure-http on loopback).
		http.Redirect(w, r, "https://"+net.JoinHostPort(host, port)+r.URL.RequestURI(), http.StatusTemporaryRedirect)
	})
}

func serveCACert(pemData []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodGet, http.MethodHead) {
			return
		}
		h := w.Header()
		// This type opens the certificate installer on iOS and Android.
		h.Set("Content-Type", "application/x-x509-ca-cert")
		h.Set("Content-Disposition", `attachment; filename="gocalbox-ca.crt"`)
		h.Set("Cache-Control", "no-cache")
		w.Write(pemData)
	})
}

func normalizeHost(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.TrimSuffix(strings.Trim(h, "[]"), ".")
	return strings.ToLower(h)
}

func newRequestID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(b[:])
}
