package main

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
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
	"syscall"
	"time"

	"github.com/nobletk/gocalbox/internal/audit"
	"github.com/nobletk/gocalbox/internal/auth"
	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/fsops"
	"github.com/nobletk/gocalbox/internal/httpapi"
	"github.com/nobletk/gocalbox/internal/sandbox"
	"github.com/nobletk/gocalbox/internal/space"
	"github.com/nobletk/gocalbox/internal/state"
	"github.com/nobletk/gocalbox/web"
)

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "users" || os.Args[1] == "state") {
		os.Exit(command(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
	}
	if err := run(); err != nil {
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
	maxUploadMB := flag.Int64("max-upload-mb", 0, "Maximum size of a single upload in MiB (0 = no limit beyond the free space)")
	minFreeMB := flag.Int64("min-free-mb", 1024, "Free space in MiB that uploads must leave on the served volume (0 = only refuse uploads that do not fit)")
	allowedHosts := flag.String("allowed-hosts", "", "Extra comma-separated host names clients may use to reach the server (e.g. a DNS name)")
	auditLog := flag.String("audit-log", defaultAuditPath(), "Audit log file; must be outside the served directory")
	auditListings := flag.Bool("audit-listings", false, "Also record successful directory listings and file checks (HEAD requests, 304 revalidations) in the audit log")
	auditRangeWindow := flag.Duration("audit-range-window", 5*time.Minute, "Collapse ranged downloads of a file by one client within this window into one summary record (0 = record every request)")
	auditFailClosed := flag.Bool("audit-fail-closed", false, "Refuse file operations with 503 once the audit log cannot be written")
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
	verifyLog := flag.String("verify-audit", "", "Verify the integrity of this audit log file and exit")
	flag.Parse()

	if *verifyLog != "" {
		return verifyAudit(*verifyLog)
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
	if *minFreeMB < 0 || *minFreeMB > math.MaxInt64>>20 {
		return fmt.Errorf("-min-free-mb must be between 0 and %d, got %d", int64(math.MaxInt64>>20), *minFreeMB)
	}

	a, err := newApp(config{
		RootDir:          *rootDir,
		WebDir:           *webDir,
		MaxUploadBytes:   *maxUploadMB << 20,
		MinFreeBytes:     *minFreeMB << 20,
		AllowedHosts:     hostAllowlist(*host, *allowedHosts),
		AuditLog:         *auditLog,
		AuditListings:    *auditListings,
		AuditRangeWindow: *auditRangeWindow,
		AuditFailClosed:  *auditFailClosed,
		LogEvents:        *logEvents,
		BodyTimeout:      *bodyTimeout,
		TLSCert:          *tlsCert,
		TLSKey:           *tlsKey,
		TLSDir:           *tlsDir,
		StateFile:        *stateFile,
		MinPasswordLen:   *minPasswordLength,
		Sessions:         sessions,
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

	srv := &http.Server{
		Handler: a.Handler,
		// No read or write timeout: they would cut off long uploads and media
		// streams. Stalled request bodies are limited per request (-body-timeout).
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}

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
	AuditFailClosed  bool
	LogEvents        bool
	BodyTimeout      time.Duration

	// HTTPS uses TLSCert and TLSKey if set, else a certificate from the local
	// CA in TLSDir. With neither, the server speaks plain HTTP.
	TLSCert, TLSKey string
	TLSDir          string

	StateFile      string
	MinPasswordLen int                // auth.DefaultMinPasswordLength when 0
	Sessions       auth.SessionConfig // auth.DefaultSessions when zero
}

type app struct {
	Handler      http.Handler
	Root         string
	AuditPath    string
	AllowedHosts []string
	TLS          *tlsSetup // nil for plain HTTP
	StatePath    string

	sb        *sandbox.Sandbox
	state     *state.DB
	accounts  *auth.Accounts
	setupCode string // shown once on the console, then cleared
	minPwLen  int
	bus       *events.Bus
	coalescer *audit.Coalescer
	audit     *audit.Writer
	inflight  *httpapi.Tracker
	volume    *os.File
	space     *space.Ledger // nil where free space cannot be measured
	spaceErr  error
	minFree   int64
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

	auditHandler := auditWriter.HandleBatch
	var coalescer *audit.Coalescer
	if cfg.AuditRangeWindow > 0 {
		coalescer = audit.NewCoalescer(auditWriter, cfg.AuditRangeWindow)
		auditHandler = coalescer.HandleBatch
		undo = append(undo, func() error { coalescer.Close(); return nil })
	}

	bus := events.New()
	undo = append(undo, func() error { return bus.Close(context.Background()) })
	bus.SubscribeBatch("audit", auditHandler, events.Options{
		Mode:   events.Block,
		Buffer: 1024,
		Filter: audit.Filter(cfg.AuditListings),
	})
	if cfg.LogEvents {
		bus.Subscribe("console", events.LogHandler, events.Options{Mode: events.Drop, Buffer: 1024})
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
	if cfg.AuditFailClosed {
		opts.Ready = auditWriter.Err
	}
	if tlsSetup != nil {
		opts.RequireTLS = true
		if tlsSetup.CA != nil {
			opts.CACert = tlsSetup.CA.PEM
		}
	}

	minPwLen := cmp.Or(cfg.MinPasswordLen, auth.DefaultMinPasswordLength)
	files := fsops.New(sb, bus, fsops.WithSpace(ledger), fsops.WithRecords(db))
	if err := files.EmptyTrash(); err != nil {
		log.Printf("WARNING: cannot empty the trash of deleted folders: %v", err)
	}
	accounts := auth.New(auth.Config{
		DB:       db,
		Hasher:   auth.NewHasher(auth.DefaultParams, hashSlots, hashWait),
		Policy:   auth.Policy{MinLength: minPwLen},
		Folders:  files,
		Events:   bus,
		Sessions: cfg.Sessions,
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

	return &app{
		Handler:      httpapi.New(files, webFS, opts),
		Root:         sb.Root(),
		AuditPath:    auditPath,
		AllowedHosts: cfg.AllowedHosts,
		TLS:          tlsSetup,
		StatePath:    statePath,
		sb:           sb,
		state:        db,
		accounts:     accounts,
		setupCode:    setupCode,
		minPwLen:     minPwLen,
		bus:          bus,
		coalescer:    coalescer,
		audit:        auditWriter,
		inflight:     inflight,
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

	flushCtx, cancel := context.WithTimeout(context.Background(), flushTimeout)
	defer cancel()
	err := a.bus.Close(flushCtx)
	if a.coalescer != nil {
		a.coalescer.Close()
	}
	if cerr := a.audit.Close(); err == nil {
		err = cerr
	}
	if cerr := a.accounts.Close(); err == nil {
		err = cerr
	}
	if cerr := a.state.Close(); err == nil {
		err = cerr
	}
	if cerr := a.volume.Close(); err == nil {
		err = cerr
	}
	if cerr := a.sb.Close(); err == nil {
		err = cerr
	}
	return err
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
