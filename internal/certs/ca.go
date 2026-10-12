// Package certs provides the HTTPS certificate: issued by a local CA that the
// server creates once, or a certificate the admin supplies.
package certs

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	CAFile    = "ca.crt"
	CAKeyFile = "ca-key.pem"

	caLifetime = 10 * 365 * 24 * time.Hour
	backdate   = time.Hour
)

// LAN-only names and addresses. The CA can sign nothing else, so a stolen CA
// key cannot impersonate public sites to the devices that trust it. The
// machine's bare host name is left out: it can equal a public top-level
// domain such as "dev" or "app", and a constraint covers every name below it.
var (
	lanDomains = []string{"localhost", "local", "lan", "home.arpa", "internal"}
	lanRanges  = []string{
		"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"169.254.0.0/16", "100.64.0.0/10", // link-local; shared address space (CGNAT, Tailscale)
		"::1/128", "fc00::/7", "fe80::/10",
	}
)

type CA struct {
	Cert *x509.Certificate
	PEM  []byte
	key  crypto.Signer
}

// LoadOrCreateCA reads the CA from dir, creating it on first use. created
// reports whether it is new, and so not yet installed on any device.
func LoadOrCreateCA(dir string, now time.Time) (ca *CA, created bool, err error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, false, fmt.Errorf("create TLS folder: %w", err)
	}
	keyPath := filepath.Join(dir, CAKeyFile)
	data, err := os.ReadFile(keyPath)
	if errors.Is(err, os.ErrNotExist) {
		if data, err = newCAFile(keyPath, now); err != nil {
			return nil, false, err
		}
		created = true
	} else if err != nil {
		return nil, false, err
	}
	if err := checkPrivate(keyPath); err != nil {
		return nil, false, err
	}
	if ca, err = parseCA(data); err != nil {
		return nil, false, fmt.Errorf("%s: %w", keyPath, err)
	}
	if now.After(ca.Cert.NotAfter) {
		return nil, false, fmt.Errorf("the local CA in %s expired on %s; move the folder away to create a new one, then install the new %s on every device",
			dir, ca.Cert.NotAfter.Format(time.DateOnly), CAFile)
	}
	if err := writePublic(filepath.Join(dir, CAFile), ca.PEM); err != nil {
		return nil, false, err
	}
	return ca, created, nil
}

// newCAFile links the finished file into place, so a crash leaves no partial
// key and a concurrent first start keeps whichever CA was linked first.
func newCAFile(keyPath string, now time.Time) ([]byte, error) {
	data, err := generateCA(now)
	if err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(keyPath), ".ca-key-*.tmp")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	if err := os.Link(tmp.Name(), keyPath); errors.Is(err, os.ErrExist) {
		return os.ReadFile(keyPath)
	} else if err != nil {
		if err := os.Rename(tmp.Name(), keyPath); err != nil {
			return nil, err
		}
	}
	return data, nil
}

func generateCA(now time.Time) ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	var ranges []*net.IPNet
	for _, cidr := range lanRanges {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, err
		}
		ranges = append(ranges, n)
	}

	name := "gocalbox local CA"
	if host, _ := os.Hostname(); host != "" {
		name += " on " + host
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{"gocalbox"}, CommonName: name},
		NotBefore:             now.Add(-backdate),
		NotAfter:              now.Add(caLifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
		// Critical, so a client that cannot enforce the constraints rejects the CA.
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         lanDomains,
		PermittedIPRanges:           ranges,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	pem.Encode(&buf, &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	return buf.Bytes(), nil
}

func parseCA(data []byte) (*CA, error) {
	var certDER, keyDER []byte
	for {
		var b *pem.Block
		if b, data = pem.Decode(data); b == nil {
			break
		}
		switch b.Type {
		case "CERTIFICATE":
			certDER = b.Bytes
		case "PRIVATE KEY":
			keyDER = b.Bytes
		}
	}
	if certDER == nil || keyDER == nil {
		return nil, errors.New("needs a CERTIFICATE and a PRIVATE KEY block")
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return nil, err
	}
	key, ok := k.(crypto.Signer)
	if !ok || !publicKeysEqual(key.Public(), cert.PublicKey) {
		return nil, errors.New("the private key does not belong to the certificate")
	}
	if !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("the certificate is not a CA")
	}
	return &CA{
		Cert: cert,
		PEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		key:  key,
	}, nil
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	ka, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && ka.Equal(b)
}

func checkPrivate(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s can be read by other users (mode %v); run chmod 600 on it", path, info.Mode().Perm())
	}
	return nil
}

func writePublic(path string, data []byte) error {
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, data) {
		return nil
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".ca-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil && runtime.GOOS != "windows" {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Fingerprint is the SHA-256 of the certificate, in the colon-separated form
// that certificate viewers show.
func (ca *CA) Fingerprint() string {
	sum := sha256.Sum256(ca.Cert.Raw)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

func (ca *CA) permitsName(name string) bool {
	return len(ca.Cert.PermittedDNSDomains) == 0 || matchesDomain(name, ca.Cert.PermittedDNSDomains)
}

func (ca *CA) permitsIP(ip net.IP) bool {
	if len(ca.Cert.PermittedIPRanges) == 0 {
		return true
	}
	for _, n := range ca.Cert.PermittedIPRanges {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func matchesDomain(name string, domains []string) bool {
	for _, d := range domains {
		if name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
}

// issue signs a server certificate for names and ips, which must be within
// the CA's constraints: one name outside them invalidates the whole
// certificate for clients.
func (ca *CA) issue(names []string, ips []net.IP, now time.Time, lifetime time.Duration) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	notBefore := now.Add(-backdate)
	if notBefore.Before(ca.Cert.NotBefore) {
		notBefore = ca.Cert.NotBefore
	}
	notAfter := now.Add(lifetime)
	if notAfter.After(ca.Cert.NotAfter) {
		notAfter = ca.Cert.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		// No common name: some verifiers check one that looks like a host
		// name against the name constraints.
		Subject:               pkix.Name{Organization: []string{"gocalbox"}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              names,
		IPAddresses:           ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, key.Public(), ca.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now}); err != nil {
		return nil, fmt.Errorf("issued certificate does not verify: %w", err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

func randomSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

// normalizeName returns host as a certificate DNS name, or "" if it cannot
// be one.
func normalizeName(host string) string {
	h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if h == "" || len(h) > 253 || net.ParseIP(h) != nil {
		return ""
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return ""
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return ""
			}
		}
	}
	return h
}
