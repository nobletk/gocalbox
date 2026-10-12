package certs

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	leafLifetime = 30 * 24 * time.Hour
	renewBefore  = 10 * 24 * time.Hour
	maxExtraIPs  = 16
	reloadCheck  = time.Minute
)

// Local serves certificates issued by the local CA. It issues a new one
// before the current one expires, and when a client connects to a local
// address the current one does not cover, such as one the machine got after
// start-up.
type Local struct {
	ca          *CA
	now         func() time.Time
	isInterface func(net.IP) bool

	mu      sync.Mutex
	names   []string
	baseIPs []net.IP
	extra   []net.IP // most recent last
	cert    *tls.Certificate
	renewAt time.Time
}

// NewLocal issues the first certificate for hosts, which are names and IP
// addresses. skipped lists the hosts outside the CA's constraints.
func NewLocal(ca *CA, hosts []string, now func() time.Time) (l *Local, skipped []string, err error) {
	l = &Local{ca: ca, now: now, isInterface: isInterfaceAddr}
	for _, raw := range hosts {
		h := strings.Trim(strings.TrimSpace(raw), "[]")
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			if !ca.permitsIP(ip) {
				skipped = append(skipped, h)
			} else if !containsIP(l.baseIPs, ip) {
				l.baseIPs = append(l.baseIPs, canonicalIP(ip))
			}
			continue
		}
		name := normalizeName(h)
		if name == "" || !ca.permitsName(name) {
			skipped = append(skipped, h)
		} else if !slices.Contains(l.names, name) {
			l.names = append(l.names, name)
		}
	}
	if err := l.issue(l.extra); err != nil {
		return nil, skipped, err
	}
	return l, skipped, nil
}

func (l *Local) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	extra := l.extra
	stale := !l.now().Before(l.renewAt)
	if ip := localIP(hello); ip != nil && !containsIP(l.baseIPs, ip) && !containsIP(l.extra, ip) && l.ca.permitsIP(ip) && l.isInterface(ip) {
		extra = append(slices.Clone(l.extra), canonicalIP(ip))
		if len(extra) > maxExtraIPs {
			extra = extra[1:]
		}
		stale = true
	}
	if stale {
		if err := l.issue(extra); err != nil {
			log.Printf("TLS: cannot issue a new certificate, still using the current one: %v", err)
		}
	}
	return l.cert, nil
}

func (l *Local) Leaf() *x509.Certificate {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.cert.Leaf
}

func (l *Local) issue(extra []net.IP) error {
	now := l.now()
	ips := append(slices.Clone(l.baseIPs), extra...)
	cert, err := l.ca.issue(l.names, ips, now, leafLifetime)
	if err != nil {
		return err
	}
	// Wall-clock time: the monotonic reading stops while the machine sleeps,
	// and the certificate expires by the calendar.
	l.extra, l.cert, l.renewAt = extra, cert, now.Add(leafLifetime-renewBefore).Round(0)
	return nil
}

// isInterfaceAddr keeps a client from forcing a new certificate per
// connection by cycling through addresses that reach the machine without
// being its own, such as 127.0.0.2.
func isInterfaceAddr(ip net.IP) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
			return true
		}
	}
	return false
}

func localIP(hello *tls.ClientHelloInfo) net.IP {
	if hello == nil || hello.Conn == nil {
		return nil
	}
	if a, ok := hello.Conn.LocalAddr().(*net.TCPAddr); ok {
		return a.IP
	}
	return nil
}

func canonicalIP(ip net.IP) net.IP {
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip
}

func containsIP(list []net.IP, ip net.IP) bool {
	return slices.ContainsFunc(list, ip.Equal)
}

// File serves a certificate and key the admin supplies, and loads them again
// when the files change, so a renewed certificate needs no restart.
type File struct {
	certPath, keyPath string
	now               func() time.Time

	mu      sync.Mutex
	cert    *tls.Certificate
	stamp   string
	checked time.Time
}

func NewFile(certPath, keyPath string, now func() time.Time) (*File, error) {
	f := &File{certPath: certPath, keyPath: keyPath, now: now}
	stamp, err := f.fileStamp()
	if err != nil {
		return nil, err
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	if t := now(); t.After(cert.Leaf.NotAfter) {
		return nil, fmt.Errorf("%s expired on %s", certPath, cert.Leaf.NotAfter.Format(time.DateOnly))
	}
	f.cert, f.stamp, f.checked = &cert, stamp, now()
	return f, nil
}

func (f *File) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if now := f.now(); now.Sub(f.checked) >= reloadCheck {
		f.checked = now
		if stamp, err := f.fileStamp(); err == nil && stamp != f.stamp {
			// A renewal may have replaced only one of the two files so far;
			// the mismatch fails here and the next check retries.
			if cert, err := tls.LoadX509KeyPair(f.certPath, f.keyPath); err != nil {
				log.Printf("TLS: cannot load the changed certificate, still using the previous one: %v", err)
			} else {
				f.cert, f.stamp = &cert, stamp
				log.Printf("TLS: loaded the changed certificate from %s (valid until %s)", f.certPath, cert.Leaf.NotAfter.Format(time.DateOnly))
			}
		}
	}
	return f.cert, nil
}

func (f *File) Leaf() *x509.Certificate {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cert.Leaf
}

func (f *File) fileStamp() (string, error) {
	var b strings.Builder
	for _, p := range []string{f.certPath, f.keyPath} {
		info, err := os.Stat(p)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "%d/%d;", info.Size(), info.ModTime().UnixNano())
	}
	return b.String(), nil
}

// Uncovered returns the hosts that leaf is not valid for.
func Uncovered(leaf *x509.Certificate, hosts []string) []string {
	var out []string
	for _, h := range hosts {
		if h = strings.Trim(strings.TrimSpace(h), "[]"); h != "" && leaf.VerifyHostname(h) != nil {
			out = append(out, h)
		}
	}
	return out
}
