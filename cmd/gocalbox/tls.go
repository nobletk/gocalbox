package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nobletk/gocalbox/internal/certs"
	"github.com/nobletk/gocalbox/internal/sandbox"
)

const expiryWarning = 30 * 24 * time.Hour

type tlsSetup struct {
	Config *tls.Config
	leaf   func() *x509.Certificate

	CA        *certs.CA // nil with a certificate from -tls-cert
	CAPath    string
	CACreated bool
	certPath  string
	skipped   []string
}

func setupTLS(root string, cfg config) (*tlsSetup, error) {
	if cfg.TLSCert == "" && cfg.TLSDir == "" {
		return nil, nil
	}
	s := &tlsSetup{}
	var get func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	if cfg.TLSCert != "" {
		if _, err := outsideRoot(root, cfg.TLSKey, "-tls-key"); err != nil {
			return nil, err
		}
		f, err := certs.NewFile(cfg.TLSCert, cfg.TLSKey, time.Now)
		if err != nil {
			return nil, fmt.Errorf("HTTPS certificate: %w", err)
		}
		s.leaf, s.certPath, get = f.Leaf, cfg.TLSCert, f.GetCertificate
		s.skipped = certs.Uncovered(f.Leaf(), cfg.AllowedHosts)
	} else {
		abs, err := filepath.Abs(cfg.TLSDir)
		if err != nil {
			return nil, err
		}
		if err := refuseInsideRoot(root, abs, "-tls-dir"); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(abs, 0o700); err != nil {
			return nil, fmt.Errorf("create -tls-dir: %w", err)
		}
		dir, err := outsideRoot(root, abs, "-tls-dir")
		if err != nil {
			return nil, err
		}
		ca, created, err := certs.LoadOrCreateCA(dir, time.Now())
		if err != nil {
			return nil, fmt.Errorf("local CA: %w", err)
		}
		local, skipped, err := certs.NewLocal(ca, cfg.AllowedHosts, time.Now)
		if err != nil {
			return nil, fmt.Errorf("issue the HTTPS certificate: %w", err)
		}
		s.CA, s.CAPath, s.CACreated = ca, filepath.Join(dir, certs.CAFile), created
		s.leaf, s.skipped, get = local.Leaf, skipped, local.GetCertificate
	}
	s.Config = &tls.Config{
		MinVersion:     tls.VersionTLS12,
		NextProtos:     []string{"h2", "http/1.1"},
		GetCertificate: get,
	}
	return s, nil
}

// outsideRoot resolves path, which must exist, and refuses it inside the
// served directory, where clients could download it.
func outsideRoot(root, path, flagName string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("%s: %w", flagName, err)
	}
	if sandbox.Within(root, resolved) {
		return "", insideRootError(flagName, resolved, root)
	}
	return resolved, nil
}

func insideRootError(flagName, path, root string) error {
	return fmt.Errorf("%s %s is inside the served directory %s, where clients could download it; choose a location outside it", flagName, path, root)
}

func (a *app) logTLS(caURL string) {
	if a.TLS == nil {
		log.Printf("Serving plain HTTP on loopback only (-insecure-http)")
		return
	}
	s := a.TLS
	leaf := s.leaf()
	covered := append([]string{}, leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		covered = append(covered, ip.String())
	}
	if s.CA == nil {
		log.Printf("HTTPS certificate: %s, valid until %s, reloaded when the file changes", s.certPath, leaf.NotAfter.Format(time.DateOnly))
		if time.Until(leaf.NotAfter) < expiryWarning {
			log.Printf("WARNING: the HTTPS certificate expires on %s; renew it", leaf.NotAfter.Format(time.DateOnly))
		}
		if len(s.skipped) > 0 {
			log.Printf("WARNING: the HTTPS certificate is not valid for %s; browsers reject the server under those names", strings.Join(s.skipped, ", "))
		}
		return
	}
	log.Printf("HTTPS certificate from the local CA, renewed automatically, for: %s", strings.Join(covered, ", "))
	if len(s.skipped) > 0 {
		log.Printf("Not in the HTTPS certificate: %s. The local CA signs only LAN names and private addresses; use -tls-cert to serve under others",
			strings.Join(s.skipped, ", "))
	}
	state := "valid until " + s.CA.Cert.NotAfter.Format(time.DateOnly)
	if s.CACreated {
		state = "created now"
	}
	log.Printf("Local CA: %s (%s)", s.CAPath, state)
	log.Printf("Local CA SHA-256 fingerprint: %s", s.CA.Fingerprint())
	log.Printf("Install the local CA once on each device: open %s, accept the warning this one time, "+
		"and check that the fingerprint the installer shows matches the one above", caURL)
}

// caURL returns where a device on the network can download the local CA.
func caURL(listenHost, port string, allowed []string) string {
	return "https://" + net.JoinHostPort(lanHost(listenHost, allowed), port) + "/ca.crt"
}

// lanHost returns the host other devices can reach the server at, or
// "localhost" when none is known.
func lanHost(listenHost string, allowed []string) string {
	host := "localhost"
	switch ip := net.ParseIP(strings.Trim(listenHost, "[]")); {
	case isLoopback(listenHost):
	case ip == nil && listenHost != "":
		host = listenHost
	case ip != nil && !ip.IsUnspecified():
		host = ip.String()
	default:
		for _, h := range allowed {
			if ip := net.ParseIP(h); ip != nil && ip.To4() != nil && ip.IsPrivate() {
				host = h
				break
			}
		}
	}
	return host
}
