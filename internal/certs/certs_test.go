package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func newCA(t *testing.T) (*CA, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "tls")
	ca, created, err := LoadOrCreateCA(dir, t0)
	if err != nil || !created {
		t.Fatalf("LoadOrCreateCA = %v, created %v", err, created)
	}
	return ca, dir
}

func TestCAIsCreatedOnceAndReloaded(t *testing.T) {
	ca, dir := newCA(t)

	again, created, err := LoadOrCreateCA(dir, t0.Add(time.Hour))
	if err != nil || created {
		t.Fatalf("second load: %v, created %v", err, created)
	}
	if again.Fingerprint() != ca.Fingerprint() {
		t.Error("the CA changed between starts")
	}
	pub, err := os.ReadFile(filepath.Join(dir, CAFile))
	if err != nil || string(pub) != string(ca.PEM) || strings.Contains(string(pub), "PRIVATE") {
		t.Errorf("%s holds %q, %v", CAFile, pub, err)
	}
	if runtime.GOOS != "windows" {
		for name, mode := range map[string]os.FileMode{CAKeyFile: 0o600, CAFile: 0o644, ".": 0o700} {
			if info, err := os.Stat(filepath.Join(dir, name)); err != nil || info.Mode().Perm() != mode {
				t.Errorf("%s: mode %v, %v; want %v", name, info.Mode().Perm(), err, mode)
			}
		}
	}

	os.Remove(filepath.Join(dir, CAFile))
	if _, _, err := LoadOrCreateCA(dir, t0); err != nil {
		t.Fatal(err)
	}
	if pub, _ := os.ReadFile(filepath.Join(dir, CAFile)); string(pub) != string(ca.PEM) {
		t.Errorf("deleted %s was not written again", CAFile)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".*.tmp")); len(left) > 0 {
		t.Errorf("temporary files left: %v", left)
	}
}

func TestCAIsConstrainedToTheLAN(t *testing.T) {
	ca, _ := newCA(t)
	c := ca.Cert
	if !c.IsCA || !c.MaxPathLenZero || c.MaxPathLen != 0 || !c.PermittedDNSDomainsCritical {
		t.Errorf("CA flags: IsCA %v, MaxPathLenZero %v, MaxPathLen %d, critical constraints %v",
			c.IsCA, c.MaxPathLenZero, c.MaxPathLen, c.PermittedDNSDomainsCritical)
	}
	if !slices.Equal(c.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) {
		t.Errorf("CA usable for %v", c.ExtKeyUsage)
	}
	if !c.NotAfter.Equal(t0.Add(caLifetime)) {
		t.Errorf("CA valid until %v", c.NotAfter)
	}
	for _, d := range lanDomains {
		if !slices.Contains(c.PermittedDNSDomains, d) {
			t.Errorf("%s not permitted", d)
		}
	}
	if !slices.Equal(c.PermittedDNSDomains, lanDomains) {
		t.Errorf("permitted names %v, want only %v", c.PermittedDNSDomains, lanDomains)
	}

	for host, want := range map[string]bool{
		"localhost": true, "box.local": true, "nas.lan": true, "a.b.home.arpa": true, "x.internal": true,
		"example.com": false, "local.example.com": false, "notlocal": false, "dev": false, "pkg.go.dev": false,
	} {
		if got := ca.permitsName(host); got != want {
			t.Errorf("permitsName(%s) = %v, want %v", host, got, want)
		}
	}
	for ip, want := range map[string]bool{
		"127.0.0.1": true, "10.1.2.3": true, "172.31.255.1": true, "192.168.1.20": true, "169.254.3.4": true,
		"100.100.1.1": true, "::1": true, "fd12::1": true, "fe80::1": true, "::ffff:192.168.1.20": true,
		"8.8.8.8": false, "172.32.0.1": false, "192.0.2.2": false, "2001:db8::1": false, "::": false,
	} {
		if got := ca.permitsIP(net.ParseIP(ip)); got != want {
			t.Errorf("permitsIP(%s) = %v, want %v", ip, got, want)
		}
	}
}

// Clients enforce the constraints, not only this package: a certificate that
// the CA key signs for a public name does not verify.
func TestCertificatesOutsideTheConstraintsDoNotVerify(t *testing.T) {
	ca, _ := newCA(t)
	if _, err := ca.issue([]string{"example.com"}, nil, t0, leafLifetime); err == nil {
		t.Fatal("issued a certificate for example.com")
	}

	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	for name, tmpl := range map[string]*x509.Certificate{
		"public name":            {DNSNames: []string{"bank.example"}},
		"public address":         {IPAddresses: []net.IP{net.ParseIP("8.8.8.8")}},
		"LAN and public name":    {DNSNames: []string{"box.lan", "bank.example"}},
		"LAN name (the control)": {DNSNames: []string{"box.lan"}},
	} {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl.SerialNumber, tmpl.NotBefore, tmpl.NotAfter = randomSerialOrFail(t), t0, t0.Add(time.Hour)
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, key.Public(), ca.key)
		if err != nil {
			t.Fatal(err)
		}
		leaf, _ := x509.ParseCertificate(der)
		_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: t0.Add(time.Minute)})
		var invalid x509.CertificateInvalidError
		if control := strings.Contains(name, "control"); control != (err == nil) ||
			!control && (!errors.As(err, &invalid) || invalid.Reason != x509.CANotAuthorizedForThisName) {
			t.Errorf("%s: Verify = %v", name, err)
		}
	}
}

func randomSerialOrFail(t *testing.T) *big.Int {
	t.Helper()
	s, err := randomSerial()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestCAFileProblemsStopTheStart(t *testing.T) {
	t.Run("expired", func(t *testing.T) {
		_, dir := newCA(t)
		if _, _, err := LoadOrCreateCA(dir, t0.Add(caLifetime+time.Hour)); err == nil || !strings.Contains(err.Error(), "expired") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("corrupt", func(t *testing.T) {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, CAKeyFile), []byte("not a key"), 0o600)
		if _, _, err := LoadOrCreateCA(dir, t0); err == nil {
			t.Error("loaded a corrupt CA file")
		}
	})
	t.Run("key of another certificate", func(t *testing.T) {
		_, dir := newCA(t)
		other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		pkcs8, _ := x509.MarshalPKCS8PrivateKey(other)
		data, _ := os.ReadFile(filepath.Join(dir, CAKeyFile))
		block, _ := pem.Decode(data)
		mixed := append(pem.EncodeToMemory(block), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})...)
		os.WriteFile(filepath.Join(dir, CAKeyFile), mixed, 0o600)
		if _, _, err := LoadOrCreateCA(dir, t0); err == nil || !strings.Contains(err.Error(), "does not belong") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("readable by others", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("POSIX permissions")
		}
		_, dir := newCA(t)
		os.Chmod(filepath.Join(dir, CAKeyFile), 0o644)
		if _, _, err := LoadOrCreateCA(dir, t0); err == nil || !strings.Contains(err.Error(), "chmod 600") {
			t.Errorf("err = %v", err)
		}
	})
}

func TestConcurrentFirstStartsShareOneCA(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tls")
	const n = 8
	prints := make([]string, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ca, _, err := LoadOrCreateCA(dir, t0)
			if err != nil {
				t.Error(err)
				return
			}
			prints[i] = ca.Fingerprint()
		}()
	}
	wg.Wait()
	for _, p := range prints[1:] {
		if p != prints[0] {
			t.Fatalf("starts ended up with different CAs: %v", prints)
		}
	}
}

type addrConn struct {
	net.Conn
	local net.Addr
}

func (c addrConn) LocalAddr() net.Addr { return c.local }

func helloOn(ip string) *tls.ClientHelloInfo {
	return &tls.ClientHelloInfo{Conn: addrConn{local: &net.TCPAddr{IP: net.ParseIP(ip), Port: 8080}}}
}

func sans(c *x509.Certificate) []string {
	out := append([]string{}, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		out = append(out, ip.String())
	}
	return out
}

func TestLocalCoversTheLANHostsOnly(t *testing.T) {
	ca, _ := newCA(t)
	clk := &clock{now: t0}
	hosts := []string{"localhost", "127.0.0.1", "::1", "[fe80::1]", "192.168.1.20", "BOX.lan.", "files.example.com",
		"8.8.8.8", "2001:db8::1", "bad_name", "", "192.168.1.20"}
	l, skipped, err := NewLocal(ca, hosts, clk.Now)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"files.example.com", "8.8.8.8", "2001:db8::1", "bad_name"}; !slices.Equal(skipped, want) {
		t.Errorf("skipped = %v, want %v", skipped, want)
	}
	leaf := l.Leaf()
	if got, want := sans(leaf), []string{"localhost", "box.lan", "127.0.0.1", "::1", "fe80::1", "192.168.1.20"}; !slices.Equal(got, want) {
		t.Errorf("certificate names = %v, want %v", got, want)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	for _, h := range []string{"localhost", "box.lan", "192.168.1.20", "::1"} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: h, CurrentTime: t0, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
			t.Errorf("not valid for %s: %v", h, err)
		}
	}
	if leaf.Subject.CommonName != "" || !leaf.NotAfter.Equal(t0.Add(leafLifetime)) || leaf.IsCA {
		t.Errorf("leaf: CN %q, NotAfter %v, IsCA %v", leaf.Subject.CommonName, leaf.NotAfter, leaf.IsCA)
	}
}

func TestRenewalFollowsTheCalendar(t *testing.T) {
	ca, _ := newCA(t)
	l, _, err := NewLocal(ca, []string{"localhost"}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if l.renewAt != l.renewAt.Round(0) {
		t.Errorf("renewal time %v keeps a monotonic clock reading, which stops while the machine sleeps", l.renewAt)
	}
}

func TestLocalRenewsBeforeExpiry(t *testing.T) {
	ca, _ := newCA(t)
	clk := &clock{now: t0}
	l, _, err := NewLocal(ca, []string{"localhost"}, clk.Now)
	if err != nil {
		t.Fatal(err)
	}
	first, _ := l.GetCertificate(helloOn("127.0.0.1"))

	clk.add(leafLifetime - renewBefore - time.Minute)
	if c, _ := l.GetCertificate(helloOn("127.0.0.1")); c != first {
		t.Error("renewed too early")
	}
	clk.add(2 * time.Minute)
	renewed, _ := l.GetCertificate(helloOn("127.0.0.1"))
	if renewed == first || !renewed.Leaf.NotAfter.Equal(clk.Now().Add(leafLifetime)) {
		t.Errorf("not renewed %v before expiry", renewBefore)
	}
}

func TestLocalAddsAddressesTheMachineGetsLater(t *testing.T) {
	ca, _ := newCA(t)
	clk := &clock{now: t0}
	l, _, err := NewLocal(ca, []string{"localhost", "127.0.0.1"}, clk.Now)
	if err != nil {
		t.Fatal(err)
	}
	l.isInterface = func(ip net.IP) bool { return !ip.IsLoopback() }
	first, _ := l.GetCertificate(helloOn("127.0.0.1"))
	if c, _ := l.GetCertificate(helloOn("127.0.0.2")); c != first {
		t.Error("an address that is not the machine's own changed the certificate")
	}

	c, _ := l.GetCertificate(helloOn("10.0.0.7"))
	if c == first || !slices.Contains(sans(c.Leaf), "10.0.0.7") {
		t.Fatalf("new LAN address not added: %v", sans(c.Leaf))
	}
	if again, _ := l.GetCertificate(helloOn("10.0.0.7")); again != c {
		t.Error("issued again for an address already covered")
	}
	if pub, _ := l.GetCertificate(helloOn("203.0.113.9")); pub != c {
		t.Error("a public address changed the certificate")
	}
	v4mapped, _ := l.GetCertificate(helloOn("::ffff:10.0.0.7"))
	if v4mapped != c {
		t.Error("an IPv4-mapped address was treated as new")
	}

	for i := range maxExtraIPs + 4 {
		c, _ = l.GetCertificate(helloOn(net.IPv4(10, 1, 0, byte(i)).String()))
	}
	got := sans(c.Leaf)
	if len(got) != 2+maxExtraIPs || !slices.Contains(got, "127.0.0.1") || slices.Contains(got, "10.0.0.7") {
		t.Errorf("after many new addresses: %v", got)
	}
}

func writePair(t *testing.T, ca *CA, dir string, names ...string) (string, string) {
	t.Helper()
	c, err := ca.issue(names, nil, time.Now(), leafLifetime)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(c.PrivateKey)
	cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Certificate[0]}), 0o644)
	os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), 0o600)
	return cert, key
}

func TestFileIsReloadedWhenItChanges(t *testing.T) {
	ca, _ := newCA(t)
	dir := t.TempDir()
	certPath, keyPath := writePair(t, ca, dir, "one.lan")
	clk := &clock{now: time.Now()}
	f, err := NewFile(certPath, keyPath, clk.Now)
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := f.GetCertificate(nil); c.Leaf.DNSNames[0] != "one.lan" {
		t.Fatalf("serving %v", c.Leaf.DNSNames)
	}

	bump := func(paths ...string) {
		t.Helper()
		clk.add(reloadCheck)
		stamp := clk.Now().Add(time.Hour)
		for _, p := range paths {
			if err := os.Chtimes(p, stamp, stamp); err != nil {
				t.Fatal(err)
			}
		}
	}
	served := func() string {
		c, err := f.GetCertificate(nil)
		if err != nil {
			t.Fatal(err)
		}
		return c.Leaf.DNSNames[0]
	}

	writePair(t, ca, dir, "two.lan")
	os.Chtimes(certPath, clk.Now().Add(time.Hour), clk.Now().Add(time.Hour))
	if got := served(); got != "one.lan" {
		t.Errorf("files checked again within a minute: serving %s", got)
	}
	bump(certPath, keyPath)
	if got := served(); got != "two.lan" {
		t.Fatalf("changed files not loaded: serving %s", got)
	}

	// Halfway through a renewal: the new key is in place, its certificate is not.
	nextCert, nextKey := writePair(t, ca, t.TempDir(), "three.lan")
	copyFile(t, nextKey, keyPath)
	bump(keyPath)
	if got := served(); got != "two.lan" {
		t.Errorf("a mismatched pair replaced the working one: serving %s", got)
	}
	copyFile(t, nextCert, certPath)
	bump(certPath)
	if got := served(); got != "three.lan" {
		t.Errorf("completed renewal not loaded: serving %s", got)
	}
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	data, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestFileRefusesAnExpiredCertificate(t *testing.T) {
	ca, _ := newCA(t)
	certPath, keyPath := writePair(t, ca, t.TempDir(), "box.lan")
	if _, err := NewFile(certPath, keyPath, func() time.Time { return time.Now().Add(2 * leafLifetime) }); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("err = %v", err)
	}
	if _, err := NewFile(certPath, filepath.Join(t.TempDir(), "missing.pem"), time.Now); err == nil {
		t.Error("loaded without a key")
	}
}

func TestUncovered(t *testing.T) {
	ca, _ := newCA(t)
	c, err := ca.issue([]string{"box.lan"}, []net.IP{net.ParseIP("192.168.1.2")}, t0, leafLifetime)
	if err != nil {
		t.Fatal(err)
	}
	got := Uncovered(c.Leaf, []string{"box.lan", "192.168.1.2", "[::1]", "other.lan", " "})
	if want := []string{"::1", "other.lan"}; !slices.Equal(got, want) {
		t.Errorf("Uncovered = %v, want %v", got, want)
	}
}

func TestNormalizeName(t *testing.T) {
	for in, want := range map[string]string{
		"Box.LAN.": "box.lan", "my-host": "my-host", "-bad": "", "bad-": "", "under_score": "", "a..b": "",
		"192.168.1.1": "", "": "", strings.Repeat("a", 64): "", "*.lan": "",
	} {
		if got := normalizeName(in); got != want {
			t.Errorf("normalizeName(%q) = %q, want %q", in, got, want)
		}
	}
}
