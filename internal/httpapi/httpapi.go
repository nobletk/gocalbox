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

	"github.com/nobletk/gocalbox/internal/auth"
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

	// ChangesPaused reports whether the audit log's failure pauses changes,
	// for /api/status.
	ChangesPaused func() bool

	// LinkTarget tells the address and CA fingerprint a new link's
	// recipient needs; it may change once the server listens.
	LinkTarget func() LinkTarget

	BodyTimeout time.Duration

	Tracker *Tracker

	// RequireTLS answers plain HTTP requests with a redirect to HTTPS.
	RequireTLS bool

	// CACert, if set, is served at /ca.crt for devices to install.
	CACert []byte

	// Accounts serves setup, logins and sessions, and holds back every other
	// API request and every file until the first admin exists. Without it,
	// every route but the UI and /ca.crt answers 401.
	Accounts AccountService

	// Uploads serves the resumable uploads under /api/upload/; without it
	// they answer 503 uploads_unavailable.
	Uploads UploadService
}

type ClientFileInfo struct {
	Name     string   `json:"name"`
	Size     int64    `json:"size"`
	IsDir    bool     `json:"isDir"`
	Uploader *string  `json:"uploader"`
	Actions  []string `json:"actions"`
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
	// Result is what a change that was made would have answered, when its
	// record is missing from the audit log.
	Result any `json:"result,omitempty"`
}

type ErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type api struct {
	files         FileService
	accounts      AccountService
	uploads       UploadService
	maxUpload     int64
	changesPaused func() bool
	linkTarget    func() LinkTarget
	tracker       *Tracker
}

func New(files FileService, webFS fs.FS, opts Options) http.Handler {
	a := &api{
		files: files, accounts: opts.Accounts, uploads: opts.Uploads, maxUpload: opts.MaxUploadBytes,
		changesPaused: opts.ChangesPaused, linkTarget: opts.LinkTarget, tracker: opts.Tracker,
	}

	mux := http.NewServeMux()
	for _, rt := range a.routes(webFS, opts) {
		mux.Handle(rt.pattern, rt.handler)
	}

	cop := http.NewCrossOriginProtection()
	cop.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("SECURITY ALERT: Blocked cross-origin %s %s (Origin %q, Sec-Fetch-Site %q)",
			r.Method, r.URL.Path, r.Header.Get("Origin"), r.Header.Get("Sec-Fetch-Site"))
		writeErrorJSON(w, r, http.StatusForbidden, "cross_origin", "Cross-origin requests are not allowed")
	}))

	// The body limit is outermost: net/http reads the unread rest of a body
	// before it replies, so requests refused early must be bounded too.
	var routes http.Handler = requireSession(mux)
	if a.accounts != nil {
		routes = requireSetupDone(a.accounts, routes)
	}
	inner := cop.Handler(isolateResources(rejectUnclean(authenticate(a.accounts, routes))))
	if opts.RequireTLS {
		inner = redirectPlain(inner)
	}
	return requestContext(limitBodyStalls(opts.BodyTimeout,
		securityHeaders(checkHost(opts.AllowedHosts, inner))))
}

// access is what a route needs before its handler runs. The deny-all test
// sends a request to every route that isn't public.
type access int

const (
	accessPublic  access = iota // nothing: the UI, /ca.crt, setup, login and links
	accessSession               // a session; acts on the session's own account
	accessFiles                 // a session; fsops decides on every path it touches
	accessAdmin                 // a session; the accounts check it is an admin's, and the reauth window for changes
	// accessUploads: a session; the engine answers only the owner of an
	// upload, or an admin where the protocol allows it, and fsops decides on
	// the folder.
	accessUploads
)

type route struct {
	pattern string
	access  access
	handler http.Handler
}

func (a *api) routes(webFS fs.FS, opts Options) []route {
	rs := []route{
		{"/", accessPublic, http.FileServer(http.FS(webFS))},
		{"/files/", accessFiles, a.track(http.StripPrefix("/files/", http.HandlerFunc(a.handleFile)))},
		{"/api/files", accessFiles, a.track(http.HandlerFunc(a.handleListFiles))},
		{"/api/upload", accessFiles, a.track(http.HandlerFunc(a.handleUpload))},
		{"/api/fs/delete", accessFiles, a.track(http.HandlerFunc(a.handleDelete))},
		{"/api/fs/rename", accessFiles, a.track(http.HandlerFunc(a.handleMove))},
		{"/api/fs/move", accessFiles, a.track(http.HandlerFunc(a.handleMove))},
		{"/api/fs/mkdir", accessFiles, a.track(http.HandlerFunc(a.handleCreateFolder))},
		{"/api/", accessSession, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeErrorJSON(w, r, http.StatusNotFound, "not_found", "Unknown API endpoint")
		})},
	}
	rs = append(rs, a.uploadRoutes()...)
	if a.accounts != nil {
		rs = append(rs,
			route{"/api/setup", accessPublic, a.track(http.HandlerFunc(a.handleSetup))},
			route{"/api/status", accessPublic, http.HandlerFunc(a.handleStatus)},
			route{"/api/auth/login", accessPublic, a.track(http.HandlerFunc(a.handleLogin))},
			route{"/api/invite/inspect", accessPublic, a.track(http.HandlerFunc(a.handleInviteInspect))},
			route{"/api/invite/accept", accessPublic, a.track(http.HandlerFunc(a.handleInviteAccept))},
			route{"/api/reset/inspect", accessPublic, a.track(http.HandlerFunc(a.handleResetInspect))},
			route{"/api/reset/accept", accessPublic, a.track(http.HandlerFunc(a.handleResetAccept))},
		)
		for _, s := range []struct {
			pattern string
			h       func(http.ResponseWriter, *http.Request, auth.Identity)
		}{
			{"/api/auth/logout", a.handleLogout},
			{"/api/auth/me", a.handleMe},
			{"/api/auth/confirm", a.handleConfirm},
			{"/api/auth/password", a.handlePassword},
			{"/api/auth/sessions", a.handleSessions},
			{"/api/auth/sessions/revoke", a.handleRevokeSession},
			{"/api/auth/sessions/revoke-others", a.handleRevokeOthers},
		} {
			rs = append(rs, route{s.pattern, accessSession, a.track(withIdentity(s.h))})
		}
		for _, s := range []struct {
			pattern string
			h       func(http.ResponseWriter, *http.Request, auth.Identity)
		}{
			{"/api/admin/users/list", a.handleAdminUsers},
			{"/api/admin/users/update", a.handleAdminUserUpdate},
			{"/api/admin/users/reset-link", a.handleAdminResetLink},
			{"/api/admin/users/delete", a.handleAdminUserDelete},
			{"/api/admin/invites/create", a.handleAdminInvite},
			{"/api/admin/links/list", a.handleAdminLinks},
			{"/api/admin/links/revoke", a.handleAdminLinkRevoke},
			{"/api/admin/bindings/list", a.handleAdminBindings},
			{"/api/admin/bindings/create", a.handleAdminBindingCreate},
			{"/api/admin/bindings/delete", a.handleAdminBindingDelete},
			{"/api/admin/sessions/list", a.handleAdminSessions},
			{"/api/admin/sessions/revoke", a.handleAdminSessionRevoke},
		} {
			rs = append(rs, route{s.pattern, accessAdmin, a.track(withIdentity(s.h))})
		}
	}
	if opts.CACert != nil {
		rs = append(rs, route{"/ca.crt", accessPublic, serveCACert(opts.CACert)})
	}
	return rs
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

// track counts the request among the operations in progress, which a
// shutdown waits for.
func (a *api) track(h http.Handler) http.Handler {
	if a.tracker != nil {
		return a.tracker.track(h)
	}
	return h
}

func requestContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := newRequestID()
		w.Header().Set("X-Request-ID", id)

		ctx := events.WithWaitBudget(events.WithRequestID(r.Context(), id))
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
