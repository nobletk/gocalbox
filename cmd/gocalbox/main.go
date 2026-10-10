package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/nobletk/gocalbox/internal/audit"
	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/fsops"
	"github.com/nobletk/gocalbox/internal/httpapi"
	"github.com/nobletk/gocalbox/internal/sandbox"
	"github.com/nobletk/gocalbox/web"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("Fatal Error: %v", err)
	}
}

func run() error {
	host := flag.String("host", "localhost", "Address to listen on (use 0.0.0.0 to expose the server to the network)")
	port := flag.String("port", "8080", "Port to run the server on")
	rootDir := flag.String("root", ".", "The local directory to sandbox and serve")
	webDir := flag.String("web", "", "Serve the web UI from this directory instead of the embedded copy (for frontend development)")
	maxUploadMB := flag.Int64("max-upload-mb", 4096, "Maximum size of a single upload in MiB (0 = unlimited)")
	allowedHosts := flag.String("allowed-hosts", "", "Extra comma-separated host names clients may use to reach the server (e.g. a DNS name)")
	auditLog := flag.String("audit-log", defaultAuditPath(), "Audit log file; must be outside the served directory")
	auditListings := flag.Bool("audit-listings", false, "Also record successful directory listings and file checks (HEAD requests, 304 revalidations) in the audit log")
	auditRangeWindow := flag.Duration("audit-range-window", 5*time.Minute, "Collapse ranged downloads of a file by one client within this window into one summary record (0 = record every request)")
	auditFailClosed := flag.Bool("audit-fail-closed", false, "Refuse file operations with 503 once the audit log cannot be written")
	bodyTimeout := flag.Duration("body-timeout", 30*time.Second, "Abort an upload or other request whose body delivers less than 64 KiB in this long (0 = never)")
	insecureNoAuth := flag.Bool("insecure-no-auth", false, "Allow a non-loopback -host although there is no authentication yet: anyone who can reach the port can read, change and delete the served files")
	verifyLog := flag.String("verify-audit", "", "Verify the integrity of this audit log file and exit")
	flag.Parse()

	if *verifyLog != "" {
		return verifyAudit(*verifyLog)
	}
	if err := checkExposure(*host, *insecureNoAuth); err != nil {
		return err
	}

	a, err := newApp(config{
		RootDir:          *rootDir,
		WebDir:           *webDir,
		MaxUploadBytes:   *maxUploadMB << 20,
		AllowedHosts:     hostAllowlist(*host, *allowedHosts),
		AuditLog:         *auditLog,
		AuditListings:    *auditListings,
		AuditRangeWindow: *auditRangeWindow,
		AuditFailClosed:  *auditFailClosed,
		BodyTimeout:      *bodyTimeout,
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

	srv := &http.Server{
		Addr:              net.JoinHostPort(*host, *port),
		Handler:           a.Handler,
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

	log.Printf("Starting server on http://%s", srv.Addr)
	log.Printf("Sandboxing directory: %s", a.Root)
	log.Printf("Accepted host names: %s", strings.Join(a.AllowedHosts, ", "))
	log.Printf("Audit log: %s (%d existing records)", a.AuditPath, a.audit.Records())

	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("server crashed: %w", err)
	}
	<-shutdownDone
	return nil
}

const (
	drainTimeout = 30 * time.Second
	flushTimeout = 10 * time.Second
)

type config struct {
	RootDir          string
	WebDir           string
	MaxUploadBytes   int64
	AllowedHosts     []string // nil disables the Host check
	AuditLog         string
	AuditListings    bool
	AuditRangeWindow time.Duration
	AuditFailClosed  bool
	BodyTimeout      time.Duration
}

type app struct {
	Handler      http.Handler
	Root         string
	AuditPath    string
	AllowedHosts []string

	sb        *sandbox.Sandbox
	bus       *events.Bus
	coalescer *audit.Coalescer
	audit     *audit.Writer
	inflight  *httpapi.Tracker
}

func newApp(cfg config) (*app, error) {
	sb, err := sandbox.New(cfg.RootDir)
	if err != nil {
		return nil, fmt.Errorf("invalid root directory: %w", err)
	}
	auditPath, err := audit.EnsureOutside(sb.Root(), cfg.AuditLog)
	if err != nil {
		sb.Close()
		return nil, err
	}
	auditWriter, err := audit.Open(auditPath)
	if err != nil {
		sb.Close()
		return nil, err
	}

	auditHandler := auditWriter.HandleBatch
	var coalescer *audit.Coalescer
	if cfg.AuditRangeWindow > 0 {
		coalescer = audit.NewCoalescer(auditWriter, cfg.AuditRangeWindow)
		auditHandler = coalescer.HandleBatch
	}

	bus := events.New()
	bus.SubscribeBatch("audit", auditHandler, events.Options{
		Mode:   events.Block,
		Buffer: 1024,
		Filter: audit.Filter(cfg.AuditListings),
	})
	bus.Subscribe("console", events.LogHandler, events.Options{Mode: events.Drop, Buffer: 1024})

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

	return &app{
		Handler:      httpapi.New(fsops.New(sb, bus), webFS, opts),
		Root:         sb.Root(),
		AuditPath:    auditPath,
		AllowedHosts: cfg.AllowedHosts,
		sb:           sb,
		bus:          bus,
		coalescer:    coalescer,
		audit:        auditWriter,
		inflight:     inflight,
	}, nil
}

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
	if cerr := a.sb.Close(); err == nil {
		err = cerr
	}
	return err
}

func checkExposure(host string, insecureNoAuth bool) error {
	if isLoopback(host) {
		return nil
	}
	if !insecureNoAuth {
		return fmt.Errorf("refusing to listen on %q: there is no authentication yet, so anyone who can reach that address "+
			"could read, change and delete every served file. Use the default -host localhost, or pass -insecure-no-auth to accept the risk", host)
	}
	log.Printf("WARNING: listening on %q WITHOUT AUTHENTICATION (-insecure-no-auth): anyone who can reach this port can read, change and delete the served files", host)
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
