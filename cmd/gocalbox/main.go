package main

import (
	"bufio"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/nobletk/gocalbox/internal/audit"
	"github.com/nobletk/gocalbox/internal/auth"
	"github.com/nobletk/gocalbox/internal/benchmode"
	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/fsops"
	"github.com/nobletk/gocalbox/internal/httpapi"
	"github.com/nobletk/gocalbox/internal/sandbox"
	"github.com/nobletk/gocalbox/internal/space"
	"github.com/nobletk/gocalbox/internal/state"
	"github.com/nobletk/gocalbox/internal/transfer"
	"github.com/nobletk/gocalbox/internal/transfer/registry"
	"github.com/nobletk/gocalbox/web"
)

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "users" || os.Args[1] == "state") {
		os.Exit(command(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
	}
	if err := run(); err != nil {
		var unchecked *uncheckedError
		if errors.As(err, &unchecked) {
			log.Printf("Fatal Error: %v", err)
			os.Exit(2)
		}
		log.Fatalf("Fatal Error: %v", err)
	}
}

func run() error {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage:\n  gocalbox [flags]\n%s\nFlags:\n", commandsUsage)
		flag.PrintDefaults()
	}
	host := flag.String("host", "localhost", "Address to listen on (use 0.0.0.0 to expose the server to the network)")
	port := flag.String("port", "8080", "Port to run the server on")
	rootDir := flag.String("root", ".", "The local directory to sandbox and serve")
	webDir := flag.String("web", "", "Serve the web UI from this directory instead of the embedded copy (for frontend development)")
	maxUploadMB := flag.Int64("max-upload-mb", 0, "Largest upload in MiB, single-request or resumable, from 0 to 67108864 (64 TiB); 0 = no limit beyond the free space")
	minFreeMB := flag.Int64("min-free-mb", 1024, "Free space in MiB that uploads must leave on the served volume (0 = only refuse uploads that do not fit)")
	allowedHosts := flag.String("allowed-hosts", "", "Extra comma-separated host names clients may use to reach the server (e.g. a DNS name)")
	auditLog := flag.String("audit-log", defaultAuditPath(), "Audit log file; must be outside the served directory")
	auditListings := flag.Bool("audit-listings", false, "Also record successful directory listings and file checks (HEAD requests, 304 revalidations) in the audit log")
	auditRangeWindow := flag.Duration("audit-range-window", 5*time.Minute, "Collapse ranged downloads of a file by one client within this window into one summary record (0 = record every request)")
	auditWait := flag.Bool("audit-wait", true, "Reply to a change only once its audit record is on disk (false only for measurements)")
	auditWaitTimeout := flag.Duration("audit-wait-timeout", 10*time.Second, "Longest a change waits for its audit record; a record not confirmed by then pauses changes")
	auditFailOpen := flag.Bool("audit-fail-open", false, "Keep accepting changes after the audit log failed (only for measurements)")
	auditParts := flag.Bool("audit-parts", false, "Record every accepted part of a resumable upload in the audit log; parts then wait for the log when it falls behind")
	logEvents := flag.Bool("log-events", true, "Print every file event to the console (the audit log is not affected)")
	bodyTimeout := flag.Duration("body-timeout", 30*time.Second, "Abort an upload or other request whose body delivers less than 64 KiB in this long (0 = never)")
	tlsDir := flag.String("tls-dir", defaultTLSDir(), "Folder of the local CA that issues the HTTPS certificate when -tls-cert is not given; must be outside the served directory")
	tlsCert := flag.String("tls-cert", "", "HTTPS certificate chain (PEM) to use instead of one from the local CA, reloaded when the file changes; needs -tls-key")
	tlsKey := flag.String("tls-key", "", "Private key (PEM) of -tls-cert; must be outside the served directory")
	insecureHTTP := flag.Bool("insecure-http", false, "Serve plain HTTP instead of HTTPS; allowed only on a loopback -host (for development and benchmarks)")
	stateFile := flag.String("state", defaultStatePath(), "State file with the accounts and folder bindings; must be outside the served directory")
	minPasswordLength := flag.Int("min-password-length", auth.DefaultMinPasswordLength, fmt.Sprintf("Fewest characters a password may have (%d to %d)", auth.LowestMinPasswordLength, auth.MaxPasswordBytes))
	sessionIdle := flag.Duration("session-idle", auth.DefaultSessions.Idle, "Log a browser out after this long without a request")
	sessionMax := flag.Duration("session-max", auth.DefaultSessions.Max, "Log a browser out this long after it logged in, however active it is")
	reauthWindow := flag.Duration("reauth-window", auth.DefaultSessions.Reauth, "How long after entering their password an admin may change users and folder access")
	inviteTTL := flag.Duration("invite-ttl", auth.DefaultLinks.InviteTTL, "How long an invite link stays usable (an admin invite at most 24 hours)")
	resetTTL := flag.Duration("reset-ttl", auth.DefaultLinks.ResetTTL, "How long a password reset link stays usable (-recover-admin's at most 1 hour)")
	recoverAdmin := flag.String("recover-admin", "", "Print a one-time password reset link for this admin on the console at start-up")
	defaults := transfer.DefaultLimits
	uploadWindowMB := flag.Int64("upload-window-mb", defaults.Window>>20, "Free space in MiB one resumable upload holds ahead for its parts, or more when the parts it may have in flight need it")
	uploadIdleTTL := flag.Duration("upload-idle-ttl", defaults.IdleTTL, "A resumable upload that receives no new part for this long expires")
	uploadFirstPartTTL := flag.Duration("upload-first-part-ttl", defaults.FirstPartTTL, "A resumable upload that receives no part at all for this long expires")
	uploadMaxAge := flag.Duration("upload-max-age", defaults.MaxAge, "A resumable upload expires this long after it began, however active it is")
	uploadTombstoneTTL := flag.Duration("upload-tombstone-ttl", defaults.TombstoneTTL, "How long a finished resumable upload still answers a client that repeats a call")
	uploadMaxSessions := flag.Int("upload-max-sessions", defaults.MaxSessions, "Resumable uploads one user may have open at once")
	uploadMaxSessionsTotal := flag.Int("upload-max-sessions-total", defaults.MaxSessionsTotal, "Resumable uploads open at once on the server")
	uploadMaxInflight := flag.Int("upload-max-inflight", defaults.MaxInflight, "Parts of resumable uploads being received at once on the server")
	verifyLog := flag.String("verify-audit", "", "Verify the integrity of this audit log file and exit")
	verifyFile := flag.String("verify-upload", "", "Check this stored file against its upload.completed record and exit; needs -part-size and -composite")
	partSize := flag.Int64("part-size", 0, "With -verify-upload: the part size in bytes, part_size in the upload's record")
	composite := flag.String("composite", "", "With -verify-upload: the composite SHA-256, sha256 in the upload's record")
	flag.Parse()

	set := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { set[f.Name] = true })
	switch {
	case set["verify-audit"] && set["verify-upload"]:
		return &uncheckedError{errors.New("-verify-audit and -verify-upload: give one at a time")}
	case set["verify-upload"]:
		return verifyUpload(*verifyFile, *partSize, *composite)
	case set["part-size"] || set["composite"]:
		return errors.New("-part-size and -composite are only for -verify-upload")
	case *verifyLog != "":
		return verifyAudit(*verifyLog)
	}
	if err := benchmode.Init(); err != nil {
		return err
	}
	if err := checkTLSFlags(*host, *tlsCert, *tlsKey, *tlsDir, *insecureHTTP); err != nil {
		return err
	}
	if *insecureHTTP {
		*tlsDir = ""
	}
	if err := checkMinLength(*minPasswordLength); err != nil {
		return err
	}
	sessions := auth.SessionConfig{Idle: *sessionIdle, Max: *sessionMax, Reauth: *reauthWindow}
	if err := checkSessions(sessions); err != nil {
		return err
	}
	if *inviteTTL <= 0 || *resetTTL <= 0 {
		return errors.New("-invite-ttl and -reset-ttl must be longer than 0")
	}
	if *auditWaitTimeout <= 0 {
		return errors.New("-audit-wait-timeout must be longer than 0")
	}
	if *minFreeMB < 0 || *minFreeMB > math.MaxInt64>>20 {
		return fmt.Errorf("-min-free-mb must be between 0 and %d, got %d", int64(math.MaxInt64>>20), *minFreeMB)
	}
	maxUpload, err := maxUploadBytes(*maxUploadMB)
	if err != nil {
		return err
	}
	uploads, err := uploadLimits(*uploadWindowMB, transfer.Limits{
		IdleTTL:          *uploadIdleTTL,
		FirstPartTTL:     *uploadFirstPartTTL,
		MaxAge:           *uploadMaxAge,
		TombstoneTTL:     *uploadTombstoneTTL,
		MaxSessions:      *uploadMaxSessions,
		MaxSessionsTotal: *uploadMaxSessionsTotal,
		MaxInflight:      *uploadMaxInflight,
	})
	if err != nil {
		return err
	}

	a, err := newApp(config{
		RootDir:          *rootDir,
		WebDir:           *webDir,
		MaxUploadBytes:   maxUpload,
		MinFreeBytes:     *minFreeMB << 20,
		AllowedHosts:     hostAllowlist(*host, *allowedHosts),
		AuditLog:         *auditLog,
		AuditListings:    *auditListings,
		AuditRangeWindow: *auditRangeWindow,
		AuditNoWait:      !*auditWait,
		AuditWaitTimeout: *auditWaitTimeout,
		AuditFailOpen:    *auditFailOpen,
		AuditParts:       *auditParts,
		LogEvents:        *logEvents,
		BodyTimeout:      *bodyTimeout,
		TLSCert:          *tlsCert,
		TLSKey:           *tlsKey,
		TLSDir:           *tlsDir,
		StateFile:        *stateFile,
		MinPasswordLen:   *minPasswordLength,
		Sessions:         sessions,
		Links:            auth.LinkConfig{InviteTTL: *inviteTTL, ResetTTL: *resetTTL},
		RecoverAdmin:     *recoverAdmin,
		Uploads:          uploads,
	})
	if err != nil {
		return err
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), drainTimeout)
		defer cancel()
		if err := a.Close(ctx); err != nil {
			log.Printf("AUDIT ERROR: closing the audit log: %v", err)
		}
	}()

	ln, err := net.Listen("tcp", net.JoinHostPort(*host, *port))
	if err != nil {
		return err
	}
	scheme := "http"
	if a.TLS != nil {
		scheme = "https"
		ln = httpapi.SplitTLS(ln, a.TLS.Config, sniffTimeout)
	}
	_, boundPort, _ := net.SplitHostPort(ln.Addr().String())
	target := a.linkTarget(*host, boundPort)
	a.target.Store(&target)

	srv := httpapi.NewServer(a.Handler)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-ctx.Done()
		stop()
		log.Printf("Shutting down; waiting for transfers and file operations to finish (signal again to exit immediately)...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Printf("Graceful shutdown failed: %v", err)
			srv.Close()
		}
	}()

	log.Printf("Starting server on %s://%s", scheme, net.JoinHostPort(*host, boundPort))
	log.Printf("Sandboxing directory: %s", a.Root)
	log.Printf("Accepted host names: %s", strings.Join(a.AllowedHosts, ", "))
	log.Printf("Audit log: %s (%d existing records)", a.AuditPath, a.audit.Records())
	log.Printf("State file: %s", a.StatePath)
	a.logSpace()
	a.logTLS(caURL(*host, boundPort, a.AllowedHosts))
	a.logSetup(*host, boundPort)
	a.logRecovery(*host, boundPort)

	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("server crashed: %w", err)
	}
	<-shutdownDone
	return nil
}

const (
	drainTimeout = 30 * time.Second
	flushTimeout = 10 * time.Second
	sniffTimeout = 10 * time.Second
)

type config struct {
	RootDir          string
	WebDir           string
	MaxUploadBytes   int64
	MinFreeBytes     int64
	AllowedHosts     []string // nil disables the Host check
	AuditLog         string
	AuditListings    bool
	AuditRangeWindow time.Duration
	AuditNoWait      bool          // changes reply without waiting for their records
	AuditWaitTimeout time.Duration // 10 s when 0
	AuditFailOpen    bool
	AuditParts       bool // every accepted part of a resumable upload is recorded
	LogEvents        bool
	BodyTimeout      time.Duration

	// HTTPS uses TLSCert and TLSKey if set, else a certificate from the local
	// CA in TLSDir. With neither, the server speaks plain HTTP.
	TLSCert, TLSKey string
	TLSDir          string

	StateFile      string
	MinPasswordLen int                // auth.DefaultMinPasswordLength when 0
	Sessions       auth.SessionConfig // auth.DefaultSessions when zero
	Links          auth.LinkConfig    // auth.DefaultLinks when zero
	RecoverAdmin   string             // an admin to print a reset link for

	// Uploads bounds the resumable uploads; a zero field takes its default,
	// and MaxUploadBytes is the largest size.
	Uploads transfer.Limits
}

type app struct {
	Handler      http.Handler
	Root         string
	AuditPath    string
	AllowedHosts []string
	TLS          *tlsSetup // nil for plain HTTP
	StatePath    string

	sb        *sandbox.Sandbox
	staging   *sandbox.Staging
	state     *state.DB
	accounts  *auth.Accounts
	setupCode string       // shown once on the console, then cleared
	recovery  auth.NewLink // -recover-admin's link, shown once, then cleared
	target    *atomic.Pointer[httpapi.LinkTarget]
	minPwLen  int
	bus       *events.Bus
	coalescer *audit.Coalescer
	audit     *audit.Writer
	inflight  *httpapi.Tracker
	uploads   *transfer.Engine
	// kept is set when shutdown left the served folder and the lock of its
	// staging folder to the process's exit.
	kept     bool
	volume   *os.File
	space    *space.Ledger // nil where free space cannot be measured
	spaceErr error
	minFree  int64
}

func newApp(cfg config) (_ *app, err error) {
	var undo []func() error
	defer func() {
		if err != nil {
			for _, f := range slices.Backward(undo) {
				f()
			}
		}
	}()

	sb, err := sandbox.New(cfg.RootDir)
	if err != nil {
		return nil, fmt.Errorf("invalid root directory: %w", err)
	}
	undo = append(undo, sb.Close)
	auditPath, err := audit.EnsureOutside(sb.Root(), cfg.AuditLog)
	if err != nil {
		return nil, err
	}
	auditWriter, err := audit.Open(auditPath)
	if errors.Is(err, audit.ErrLocked) {
		return nil, fmt.Errorf("audit log %s is in use by another gocalbox process, a server or a users command; stop it, or give each server its own -audit-log", auditPath)
	}
	if err != nil {
		return nil, err
	}
	undo = append(undo, auditWriter.Close)
	statePath, err := prepareStateFile(sb.Root(), cfg.StateFile)
	if err != nil {
		return nil, err
	}
	db, err := state.Open(statePath)
	if errors.Is(err, state.ErrLocked) {
		return nil, fmt.Errorf("state file %s is in use by another gocalbox process, a server or a users command; stop it, or give each server its own -state", statePath)
	}
	if err != nil {
		return nil, fmt.Errorf("state file %s: %w", statePath, err)
	}
	undo = append(undo, db.Close)
	// After the audit log checks, so a start they refuse creates no CA.
	tlsSetup, err := setupTLS(sb.Root(), cfg)
	if err != nil {
		return nil, err
	}
	// After the audit log's and the state file's checks, so a start they
	// refuse leaves nothing in the served folder.
	staging, err := sandbox.CheckStaging(sb.OSRoot())
	if errors.Is(err, sandbox.ErrStagingLocked) {
		return nil, fmt.Errorf("%s/%s is in use: another gocalbox serves this folder; stop it first", sb.Root(), sandbox.ReservedName)
	}
	if err != nil {
		return nil, err
	}
	undo = append(undo, staging.Close)
	logStaging(staging)
	volume, err := sb.OSRoot().Open(".")
	if err != nil {
		return nil, fmt.Errorf("open root directory: %w", err)
	}
	undo = append(undo, volume.Close)
	var ledger *space.Ledger
	_, spaceErr := space.Free(volume)
	if spaceErr == nil {
		ledger = space.NewLedger(func() (int64, error) { return space.Free(volume) }, cfg.MinFreeBytes)
	}

	coalescer := audit.NewCoalescer(auditWriter, cfg.AuditRangeWindow, audit.LoginWindow)
	undo = append(undo, func() error { coalescer.Close(); return nil })
	waitTimeout := cmp.Or(cfg.AuditWaitTimeout, 10*time.Second)

	guard := audit.NewGuard(auditWriter.Err)

	bus := events.New()
	undo = append(undo, func() error { return bus.Close(context.Background()) })
	audit.Subscribe(bus, coalescer, guard, audit.Keep{Metadata: cfg.AuditListings, Parts: cfg.AuditParts}, waitTimeout)
	if cfg.LogEvents {
		bus.Subscribe("console", events.LogHandler, events.Options{
			Mode: events.Drop, Buffer: 1024,
			Filter: func(ev events.Event) bool { return !ev.Progress() },
		})
	}

	var webFS fs.FS = web.Assets
	if cfg.WebDir != "" {
		webFS = os.DirFS(cfg.WebDir)
	}
	inflight := httpapi.NewTracker()
	opts := httpapi.Options{
		MaxUploadBytes: cfg.MaxUploadBytes,
		AllowedHosts:   cfg.AllowedHosts,
		BodyTimeout:    cfg.BodyTimeout,
		Tracker:        inflight,
	}
	target := &atomic.Pointer[httpapi.LinkTarget]{}
	opts.LinkTarget = func() httpapi.LinkTarget {
		if t := target.Load(); t != nil {
			return *t
		}
		return httpapi.LinkTarget{}
	}
	if tlsSetup != nil {
		opts.RequireTLS = true
		if tlsSetup.CA != nil {
			opts.CACert = tlsSetup.CA.PEM
		}
	}

	recorder := audit.NewRecorder(bus, guard, audit.RecorderOptions{
		Wait:     !cfg.AuditNoWait,
		Timeout:  waitTimeout,
		FailOpen: cfg.AuditFailOpen,
	})
	opts.ChangesPaused = recorder.Paused

	minPwLen := cmp.Or(cfg.MinPasswordLen, auth.DefaultMinPasswordLength)
	files := fsops.New(sb, bus, fsops.WithSpace(ledger), fsops.WithRecords(db), fsops.WithAudit(recorder), fsops.WithStaging(staging))
	if err := files.EmptyTrash(); err != nil {
		log.Printf("WARNING: cannot empty the trash of deleted folders: %v", err)
	}
	accounts := auth.New(auth.Config{
		DB:       db,
		Hasher:   auth.NewHasher(auth.DefaultParams, hashSlots, hashWait),
		Policy:   auth.Policy{MinLength: minPwLen},
		Folders:  files,
		Events:   bus,
		Audit:    recorder,
		Sessions: cfg.Sessions,
		Links:    cfg.Links,
	})
	files.SetPolicy(accounts)
	opts.Accounts = accounts
	setupCode, err := accounts.StartSetup()
	if err != nil {
		return nil, fmt.Errorf("read the accounts: %w", err)
	}
	if setupCode == "" {
		for _, w := range accounts.EnsureLayout(context.Background()) {
			log.Printf("WARNING: %s", w)
		}
	}
	if err := accounts.Start(); err != nil {
		return nil, fmt.Errorf("read the sessions: %w", err)
	}
	undo = append(undo, accounts.Close)
	limits := cfg.Uploads
	limits.MaxSize = cfg.MaxUploadBytes
	uploads, err := transfer.New(transfer.Config{
		Root: sb.OSRoot(), Staging: staging, Files: files, Registry: registry.New(db),
		Events: bus, Audit: recorder, Ledger: ledger, Limits: limits, AuditParts: cfg.AuditParts,
	})
	if err != nil {
		return nil, err
	}
	undo = append(undo, func() error { return uploads.Close(context.Background()) })
	if staging.Usable() && uploads.Off() != nil {
		log.Printf("WARNING: resumable uploads are off: %v", uploads.Off())
	}
	opts.Uploads = uploads
	var recovery auth.NewLink
	if cfg.RecoverAdmin != "" {
		if recovery, err = accounts.ConsoleResetLink(context.Background(), cfg.RecoverAdmin); err != nil && !events.IsUnrecorded(err) {
			return nil, fmt.Errorf("-recover-admin: %w", err)
		}
	}

	return &app{
		Handler:      httpapi.New(files, webFS, opts),
		Root:         sb.Root(),
		AuditPath:    auditPath,
		AllowedHosts: cfg.AllowedHosts,
		TLS:          tlsSetup,
		StatePath:    statePath,
		sb:           sb,
		staging:      staging,
		state:        db,
		accounts:     accounts,
		setupCode:    setupCode,
		recovery:     recovery,
		target:       target,
		minPwLen:     minPwLen,
		bus:          bus,
		coalescer:    coalescer,
		audit:        auditWriter,
		inflight:     inflight,
		uploads:      uploads,
		volume:       volume,
		space:        ledger,
		spaceErr:     spaceErr,
		minFree:      cfg.MinFreeBytes,
	}, nil
}

const (
	hashSlots = 2
	hashWait  = 5 * time.Second
)

func (a *app) Close(ctx context.Context) error {
	if left, err := a.inflight.Drain(ctx); err != nil {
		log.Printf("SHUTDOWN: %d file operation(s) still running at exit; they may be left incomplete and missing from the audit log: %s",
			len(left), strings.Join(left, "; "))
	}
	// An engine that missed the deadline still has calls or a janitor run
	// writing in the staging folder: its lock stays held until the process
	// exits, so that no other server recovers those uploads meanwhile.
	if err := a.uploads.Close(ctx); errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		a.kept = true
		log.Printf("SHUTDOWN: %v. The lock of %s is kept until the server exits; the next start recovers those uploads", err, sandbox.ReservedName)
	} else if err != nil {
		log.Printf("SHUTDOWN: closing the upload engine: %v", err)
	}

	flushCtx, cancel := context.WithTimeout(context.Background(), flushTimeout)
	defer cancel()
	err := a.bus.Close(flushCtx)
	a.coalescer.Close()
	if cerr := a.audit.Close(); err == nil {
		err = cerr
	}
	if cerr := a.accounts.Close(); err == nil {
		err = cerr
	}
	if cerr := a.state.Close(); err == nil {
		err = cerr
	}
	if a.kept {
		return err
	}
	if cerr := a.volume.Close(); err == nil {
		err = cerr
	}
	if cerr := a.staging.Close(); err == nil {
		err = cerr
	}
	if cerr := a.sb.Close(); err == nil {
		err = cerr
	}
	return err
}

func logStaging(s *sandbox.Staging) {
	if !s.Usable() {
		log.Printf("WARNING: the server's own folder %s can't be used: %v. Resumable uploads are off, and folders are deleted in place instead of through its trash.", sandbox.ReservedName, s.Problem)
	}
	if s.Warning != "" {
		log.Printf("WARNING: %s", s.Warning)
	}
	if len(s.Unknown) > 0 {
		log.Printf("WARNING: %s holds entries the server didn't put there, left alone: %s", sandbox.TmpDir, strings.Join(s.Unknown, ", "))
	}
}

func (a *app) logSpace() {
	if a.space == nil {
		log.Printf("Free space: cannot be measured (%v); uploads are refused with 507 only when the disk is full", a.spaceErr)
		return
	}
	free, err := space.Free(a.volume)
	if err != nil {
		log.Printf("Free space: %v", err)
		return
	}
	log.Printf("Free space: %.1f GiB on the served volume; uploads leave at least %d MiB free", float64(free)/(1<<30), a.minFree>>20)
}

// maxUploadBytes checks -max-upload-mb and gives it in bytes. Its largest
// value is the largest file the upload engine takes.
func maxUploadBytes(mb int64) (int64, error) {
	if mb < 0 || mb > transfer.MaxSize>>20 {
		return 0, fmt.Errorf("-max-upload-mb must be between 0 and %d, got %d", int64(transfer.MaxSize>>20), mb)
	}
	return mb << 20, nil
}

// uploadLimits checks the limits the upload flags set, and adds the window
// of windowMB MiB.
func uploadLimits(windowMB int64, l transfer.Limits) (transfer.Limits, error) {
	if windowMB <= 0 || windowMB > math.MaxInt64>>20 {
		return l, fmt.Errorf("-upload-window-mb must be between 1 and %d, got %d", int64(math.MaxInt64>>20), windowMB)
	}
	for _, d := range []struct {
		flag string
		v    time.Duration
	}{
		{"-upload-idle-ttl", l.IdleTTL}, {"-upload-first-part-ttl", l.FirstPartTTL},
		{"-upload-max-age", l.MaxAge}, {"-upload-tombstone-ttl", l.TombstoneTTL},
	} {
		if d.v <= 0 {
			return l, fmt.Errorf("%s must be longer than 0, got %v", d.flag, d.v)
		}
	}
	for _, n := range []struct {
		flag string
		v    int
	}{
		{"-upload-max-sessions", l.MaxSessions}, {"-upload-max-sessions-total", l.MaxSessionsTotal},
		{"-upload-max-inflight", l.MaxInflight},
	} {
		if n.v <= 0 {
			return l, fmt.Errorf("%s must be at least 1, got %d", n.flag, n.v)
		}
	}
	l.Window = windowMB << 20
	return l, nil
}

func checkSessions(c auth.SessionConfig) error {
	if c.Idle <= 0 || c.Max <= 0 || c.Reauth <= 0 {
		return errors.New("-session-idle, -session-max and -reauth-window must be longer than 0")
	}
	return nil
}

func checkTLSFlags(host, cert, key, dir string, insecureHTTP bool) error {
	switch {
	case (cert == "") != (key == ""):
		return errors.New("-tls-cert and -tls-key must be given together")
	case cert == "" && dir == "" && !insecureHTTP:
		return errors.New("-tls-dir is empty; give a folder for the local CA, or -tls-cert and -tls-key")
	case insecureHTTP && cert != "":
		return errors.New("-insecure-http cannot be combined with -tls-cert")
	case insecureHTTP && !isLoopback(host):
		return fmt.Errorf("refusing plain HTTP on %q: browsers on other machines need HTTPS, and anyone on the network could read "+
			"and change the traffic. -insecure-http is allowed only with a loopback -host", host)
	}
	return nil
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

func hostAllowlist(listenHost, extra string) []string {
	hosts := []string{"localhost", "127.0.0.1", "::1"}
	add := func(h string) {
		if h = strings.TrimSpace(h); h != "" {
			hosts = append(hosts, h)
		}
	}

	if ip := net.ParseIP(listenHost); listenHost == "" || (ip != nil && ip.IsUnspecified()) {
		if addrs, err := net.InterfaceAddrs(); err == nil {
			for _, a := range addrs {
				if ipnet, ok := a.(*net.IPNet); ok {
					add(ipnet.IP.String())
				}
			}
		}
		if name, err := os.Hostname(); err == nil {
			add(name)
			add(name + ".local")
		}
	} else {
		add(listenHost)
	}
	for _, h := range strings.Split(extra, ",") {
		add(h)
	}
	return dedupe(hosts)
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := in[:0]
	for _, s := range in {
		k := strings.ToLower(s)
		if !seen[k] {
			seen[k] = true
			out = append(out, s)
		}
	}
	return out
}

func defaultTLSDir() string {
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "gocalbox", "tls")
	}
	return "gocalbox-tls"
}

func defaultStatePath() string {
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "gocalbox", "state.db")
	}
	return "gocalbox-state.db"
}

func defaultAuditPath() string {
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "gocalbox", "audit.jsonl")
	}
	return "gocalbox-audit.jsonl"
}

// uncheckedError is a -verify-upload that couldn't check the file: it exits
// with 2, where a file that doesn't match its record exits with 1.
type uncheckedError struct{ err error }

func (e *uncheckedError) Error() string { return e.err.Error() }
func (e *uncheckedError) Unwrap() error { return e.err }

// beforeVerifyOpen and afterVerifyRead, when set, run before -verify-upload
// opens the file and once it has read it.
var beforeVerifyOpen, afterVerifyRead func()

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// verifyUpload checks a stored file against the part size and composite
// SHA-256 its upload.completed record carries.
func verifyUpload(path string, partSize int64, composite string) error {
	unchecked := func(err error) error { return &uncheckedError{err} }
	if path == "" {
		return unchecked(errors.New("-verify-upload needs the stored file's path"))
	}
	if partSize <= 0 {
		return unchecked(fmt.Errorf("-verify-upload needs -part-size, part_size in the upload's record, at least 1; got %d", partSize))
	}
	want := strings.ToLower(composite)
	if b, err := hex.DecodeString(want); err != nil || len(b) != sha256.Size {
		return unchecked(fmt.Errorf("-verify-upload needs -composite, sha256 in the upload's record: 64 hex digits, got %q", composite))
	}
	// Opening a device may act on it, and opening a FIFO waits for a writer:
	// only a regular file is opened, and in case the path is replaced in the
	// meantime, without waiting.
	before, err := os.Stat(path)
	if err != nil {
		return unchecked(err)
	}
	if !before.Mode().IsRegular() {
		return unchecked(fmt.Errorf("%s is not a regular file", path))
	}
	if beforeVerifyOpen != nil {
		beforeVerifyOpen()
	}
	f, err := openToVerify(path)
	if err != nil {
		return unchecked(err)
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return unchecked(err)
	}
	if !opened.Mode().IsRegular() {
		return unchecked(fmt.Errorf("%s is not a regular file", path))
	}
	r := &countingReader{r: f}
	got, parts, err := transfer.CompositeOf(bufio.NewReaderSize(r, 1<<20), partSize)
	if err != nil {
		return unchecked(fmt.Errorf("%s: %w", path, err))
	}
	if afterVerifyRead != nil {
		afterVerifyRead()
	}
	after, err := f.Stat()
	if err != nil {
		return unchecked(err)
	}
	if r.n != opened.Size() || after.Size() != opened.Size() || !after.ModTime().Equal(opened.ModTime()) {
		return unchecked(fmt.Errorf("%s changed while it was read: %d bytes when opened, %d read, %d after", path, opened.Size(), r.n, after.Size()))
	}
	if got != want {
		msg := fmt.Sprintf("%s doesn't match its record: its %d parts of %d bytes give the composite %s, not %s", path, parts, partSize, got, want)
		if !transfer.IsPartSize(partSize) {
			msg += fmt.Sprintf("; the server only cuts files into parts of a power of two from %d to %d bytes, so take -part-size from the record", transfer.MinPartSize, transfer.MaxPartSize)
		}
		return errors.New(msg)
	}
	fmt.Printf("OK: %s matches its record: %d bytes, %d parts of %d bytes, composite %s\n", path, r.n, parts, partSize, got)
	return nil
}

func verifyAudit(path string) error {
	rep, err := audit.Verify(path)
	if err != nil {
		if rep.Records > 0 || rep.LastHash != audit.GenesisHash {
			fmt.Printf("%d records verified before the problem\n", rep.Records)
		}
		return fmt.Errorf("%s: %w", path, err)
	}
	fmt.Printf("OK: %d records, chain intact\nhead hash: %s\n", rep.Records, rep.LastHash)
	fmt.Println("Keep the head hash somewhere else: it proves the log was not shortened later.")
	return nil
}
