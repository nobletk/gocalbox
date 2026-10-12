package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nobletk/gocalbox/internal/certs"
)

func TestCheckTLSFlags(t *testing.T) {
	for _, tc := range []struct {
		host, cert, key, dir string
		insecureHTTP         bool
		wantErr              string
	}{
		{"localhost", "", "", "tls", false, ""},
		{"0.0.0.0", "", "", "tls", false, ""},
		{"0.0.0.0", "c.pem", "k.pem", "", false, ""},
		{"localhost", "", "", "tls", true, ""},
		{"127.0.0.1", "", "", "", true, ""},
		{"localhost", "c.pem", "", "tls", false, "together"},
		{"localhost", "", "k.pem", "tls", false, "together"},
		{"localhost", "c.pem", "k.pem", "tls", true, "cannot be combined"},
		{"0.0.0.0", "", "", "tls", true, "loopback"},
		{"192.168.1.5", "", "", "tls", true, "loopback"},
		{"0.0.0.0", "", "", "", false, "-tls-dir is empty"},
		{"localhost", "", "", "", false, "-tls-dir is empty"},
	} {
		err := checkTLSFlags(tc.host, tc.cert, tc.key, tc.dir, tc.insecureHTTP)
		if tc.wantErr == "" && err != nil || tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
			t.Errorf("%+v: %v", tc, err)
		}
	}
}

func withLocalCA(dir string, hosts ...string) func(*config) {
	return func(c *config) {
		c.TLSDir = dir
		c.AllowedHosts = hosts
	}
}

func TestAppWithLocalCA(t *testing.T) {
	tlsDir := filepath.Join(t.TempDir(), "tls")
	a, _ := newTestApp(t, withLocalCA(tlsDir, "localhost", "127.0.0.1", "192.168.1.20", "files.example.com"))
	defer closeApp(t, a)

	if a.TLS == nil || a.TLS.CA == nil || !a.TLS.CACreated || a.TLS.CAPath != filepath.Join(tlsDir, certs.CAFile) {
		t.Fatalf("TLS setup = %+v", a.TLS)
	}
	if !slices.Equal(a.TLS.skipped, []string{"files.example.com"}) {
		t.Errorf("skipped = %v", a.TLS.skipped)
	}
	cert, err := a.TLS.Config.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(a.TLS.CA.Cert)
	if _, err := cert.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "192.168.1.20"}); err != nil {
		t.Errorf("certificate not valid for the LAN address: %v", err)
	}
	if a.TLS.Config.MinVersion != tls.VersionTLS12 || !slices.Contains(a.TLS.Config.NextProtos, "h2") {
		t.Errorf("TLS config: min %x, protocols %v", a.TLS.Config.MinVersion, a.TLS.Config.NextProtos)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/files", nil)
	req.Host = "localhost"
	rec := httptest.NewRecorder()
	a.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTemporaryRedirect || rec.Header().Get("Location") != "https://localhost:80/api/files" {
		t.Errorf("plain request: %d to %q", rec.Code, rec.Header().Get("Location"))
	}
	req = httptest.NewRequest(http.MethodGet, "/ca.crt", nil)
	req.Host, req.TLS = "localhost", &tls.ConnectionState{}
	rec = httptest.NewRecorder()
	a.Handler.ServeHTTP(rec, req)
	if rec.Code != 200 || rec.Body.String() != string(a.TLS.CA.PEM) {
		t.Errorf("GET /ca.crt = %d", rec.Code)
	}

	again, _ := newTestApp(t, withLocalCA(tlsDir, "localhost"))
	defer closeApp(t, again)
	if again.TLS.CACreated || again.TLS.CA.Fingerprint() != a.TLS.CA.Fingerprint() {
		t.Error("a second start did not reuse the CA")
	}
}

func TestPlainHTTPAppHasNoTLS(t *testing.T) {
	a, _ := newTestApp(t)
	defer closeApp(t, a)
	if a.TLS != nil {
		t.Fatal("TLS set up without -tls-dir or -tls-cert")
	}
	if code, _ := get(t, a.Handler, "/ca.crt"); code != 404 {
		t.Errorf("GET /ca.crt over plain HTTP = %d", code)
	}
}

func TestTLSSecretsInsideTheServedDirectoryAreRefused(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	os.Mkdir(root, 0o755)
	auditLog := filepath.Join(base, "audit.jsonl")

	inside := filepath.Join(root, "tls")
	if _, err := newApp(config{RootDir: root, AuditLog: auditLog, TLSDir: inside}); err == nil || !strings.Contains(err.Error(), "-tls-dir") {
		t.Errorf("-tls-dir inside the root: %v", err)
	}
	if _, err := os.Stat(inside); err == nil {
		t.Error("the refused start created the folder in the served directory")
	}

	link := filepath.Join(base, "link")
	if err := os.Symlink(root, link); err == nil {
		if _, err := newApp(config{RootDir: root, AuditLog: auditLog, TLSDir: filepath.Join(link, "tls")}); err == nil {
			t.Error("-tls-dir reaching the root through a symlink was accepted")
		}
	}

	certPath, keyPath := writeCertFiles(t, base, "localhost")
	keyInside := filepath.Join(root, "key.pem")
	os.Rename(keyPath, keyInside)
	if _, err := newApp(config{RootDir: root, AuditLog: auditLog, TLSCert: certPath, TLSKey: keyInside}); err == nil || !strings.Contains(err.Error(), "-tls-key") {
		t.Errorf("-tls-key inside the root: %v", err)
	}
}

func writeCertFiles(t *testing.T, dir string, names ...string) (string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     names,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(key)
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), 0o600)
	return certPath, keyPath
}

func TestAppWithCertificateFile(t *testing.T) {
	certPath, keyPath := writeCertFiles(t, t.TempDir(), "files.example.com")
	a, _ := newTestApp(t, func(c *config) {
		c.TLSCert, c.TLSKey = certPath, keyPath
		c.TLSDir = filepath.Join(t.TempDir(), "unused")
		c.AllowedHosts = []string{"files.example.com", "127.0.0.1", "box.lan"}
	})
	defer closeApp(t, a)
	if a.TLS == nil || a.TLS.CA != nil {
		t.Fatalf("TLS setup = %+v", a.TLS)
	}
	if !slices.Equal(a.TLS.skipped, []string{"box.lan"}) {
		t.Errorf("not covered = %v", a.TLS.skipped)
	}
	if _, err := os.Stat(a.TLS.CAPath); a.TLS.CAPath != "" || err == nil {
		t.Error("a local CA was created although a certificate was given")
	}
	if code, _ := get(t, a.Handler, "/ca.crt"); code == 200 {
		t.Error("/ca.crt served without a local CA")
	}
}

func TestCAURL(t *testing.T) {
	for _, tc := range []struct {
		host    string
		allowed []string
		want    string
	}{
		{"localhost", nil, "https://localhost:8080/ca.crt"},
		{"127.0.0.1", nil, "https://localhost:8080/ca.crt"},
		{"192.168.1.5", nil, "https://192.168.1.5:8080/ca.crt"},
		{"box.lan", nil, "https://box.lan:8080/ca.crt"},
		{"0.0.0.0", []string{"localhost", "127.0.0.1", "::1", "fe80::1", "192.168.1.5", "10.0.0.2"}, "https://192.168.1.5:8080/ca.crt"},
		{"", []string{"localhost", "127.0.0.1"}, "https://localhost:8080/ca.crt"},
		{"::", []string{"fd00::5"}, "https://localhost:8080/ca.crt"},
	} {
		if got := caURL(tc.host, "8080", tc.allowed); got != tc.want {
			t.Errorf("caURL(%q, %v) = %s, want %s", tc.host, tc.allowed, got, tc.want)
		}
	}
}
