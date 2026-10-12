package httpapi

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/nobletk/gocalbox/internal/fsops"
	"github.com/nobletk/gocalbox/internal/sandbox"
)

func testCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

type tlsEnv struct {
	addr string
	srv  *http.Server
	done chan error
	pool *x509.CertPool
	rec  *recorder
	root string
}

func newTLSEnv(t *testing.T, opts Options, sniffTimeout time.Duration) *tlsEnv {
	t.Helper()
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "a.txt"), []byte("hello"), 0o644)
	sb, err := sandbox.New(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sb.Close() })
	rec := &recorder{}
	opts.RequireTLS = true
	if opts.AllowedHosts == nil {
		opts.AllowedHosts = []string{"127.0.0.1"}
	}
	handler := New(fsops.New(sb, rec), fstest.MapFS{"index.html": {Data: []byte("<html></html>")}}, opts)

	cert, pool := testCert(t)
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}, MinVersion: tls.VersionTLS12}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	e := &tlsEnv{addr: ln.Addr().String(), srv: &http.Server{Handler: handler}, done: make(chan error, 1), pool: pool, rec: rec, root: sb.Root()}
	go func() { e.done <- e.srv.Serve(SplitTLS(ln, cfg, sniffTimeout)) }()
	t.Cleanup(func() { e.srv.Close() })
	return e
}

func (e *tlsEnv) client(h2 bool) *http.Client {
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: e.pool}, ForceAttemptHTTP2: h2}
	if !h2 {
		tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	return &http.Client{
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func TestHTTPSAndRedirectShareOnePort(t *testing.T) {
	e := newTLSEnv(t, Options{}, time.Second)

	for _, tc := range []struct {
		h2    bool
		proto string
	}{{true, "HTTP/2.0"}, {false, "HTTP/1.1"}} {
		resp, err := e.client(tc.h2).Get("https://" + e.addr + "/files/a.txt")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || string(body) != "hello" || resp.Proto != tc.proto {
			t.Errorf("HTTPS GET: %d %q over %s, want 200 over %s", resp.StatusCode, body, resp.Proto, tc.proto)
		}
	}

	plain := e.client(false)
	resp, err := plain.Get("http://" + e.addr + "/files/a.txt?x=1")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTemporaryRedirect || resp.Header.Get("Location") != "https://"+e.addr+"/files/a.txt?x=1" || !resp.Close {
		t.Errorf("plain GET: %d to %q (close %v)", resp.StatusCode, resp.Header.Get("Location"), resp.Close)
	}

	resp, err = plain.Post("http://"+e.addr+"/api/fs/delete", "application/json", strings.NewReader(`{"path":"a.txt"}`))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 400 || !strings.Contains(string(body), "https_required") {
		t.Errorf("plain POST: %d %s", resp.StatusCode, body)
	}
	if _, err := os.Stat(filepath.Join(e.root, "a.txt")); err != nil {
		t.Error("a plain-HTTP request deleted the file")
	}

	req, _ := http.NewRequest(http.MethodGet, "http://"+e.addr+"/", nil)
	req.Host = "attacker.example"
	if resp, err := plain.Do(req); err != nil || resp.StatusCode != http.StatusMisdirectedRequest {
		t.Errorf("plain GET for an unknown host: %v, %v (no redirect to a foreign host)", resp, err)
	} else {
		resp.Body.Close()
	}
}

func TestSilentConnectionsAreClosed(t *testing.T) {
	e := newTLSEnv(t, Options{}, 2*time.Second)
	conn, err := net.Dial("tcp", e.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	start := time.Now()

	client := e.client(true)
	client.Timeout = time.Second
	if resp, err := client.Get("https://" + e.addr + "/files/a.txt"); err != nil {
		t.Errorf("a silent connection held up the next one: %v", err)
	} else {
		resp.Body.Close()
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) || time.Since(start) > 4*time.Second {
		t.Errorf("silent connection: %v after %v, want EOF after the sniff timeout", err, time.Since(start))
	}
}

func TestShutdownClosesTheSplitListener(t *testing.T) {
	e := newTLSEnv(t, Options{}, time.Second)
	idle, err := net.Dial("tcp", e.addr) // still being sniffed at shutdown
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := e.srv.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-e.done:
		if !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("Serve = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after Shutdown")
	}
	if c, err := net.DialTimeout("tcp", e.addr, time.Second); err == nil {
		c.Close()
		t.Error("port still accepts connections")
	}
	fmt.Fprintf(idle, "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
	idle.SetReadDeadline(time.Now().Add(3 * time.Second))
	line, err := bufio.NewReader(idle).ReadString('\n')
	var ne net.Error
	if err == nil || errors.As(err, &ne) && ne.Timeout() {
		t.Errorf("connection accepted before shutdown: read %q, %v; want it closed", line, err)
	}
}

func TestStalledUploadIsAbortedOverHTTP2(t *testing.T) {
	e := newTLSEnv(t, Options{BodyTimeout: 300 * time.Millisecond}, time.Second)
	pr, pw := io.Pipe()
	defer pw.Close()
	go func() {
		io.WriteString(pw, "--B\r\nContent-Disposition: form-data; name=\"myFile\"; filename=\"slow.bin\"\r\n\r\nxxxx")
	}()
	req, _ := http.NewRequest(http.MethodPost, "https://"+e.addr+"/api/upload", pr)
	req.Header.Set("Content-Type", "multipart/form-data; boundary=B")
	req.ContentLength = 1 << 20

	start := time.Now()
	done := make(chan *http.Response, 1)
	go func() {
		resp, _ := e.client(true).Do(req)
		done <- resp
	}()
	select {
	case resp := <-done:
		if resp != nil {
			if resp.ProtoMajor != 2 {
				t.Errorf("served over %s", resp.Proto)
			}
			resp.Body.Close()
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stalled HTTP/2 upload was not aborted")
	}
	if waited := time.Since(start); waited > 3*time.Second {
		t.Errorf("stalled upload held the stream for %v", waited)
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(e.rec.all()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if evs := e.rec.all(); len(evs) != 1 || evs[0].Outcome != "error" || !strings.Contains(evs[0].Detail, "timeout") {
		t.Errorf("events = %+v, want one upload error from the read timeout", evs)
	}
	if _, err := os.Stat(filepath.Join(e.root, "slow.bin")); err == nil {
		t.Error("partial upload left behind")
	}
}

func TestHostCheckAcceptsTheAddressTheRequestArrivedOn(t *testing.T) {
	h := checkHost([]string{"localhost"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	for _, tc := range []struct {
		host, local string
		want        int
	}{
		{"10.0.0.7:8080", "10.0.0.7", 200},
		{"[fd00::7]:8080", "fd00::7", 200},
		{"10.0.0.8:8080", "10.0.0.7", http.StatusMisdirectedRequest},
		{"rebind.example:8080", "10.0.0.7", http.StatusMisdirectedRequest},
		{"localhost:8080", "10.0.0.7", 200},
	} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = tc.host
		req = req.WithContext(context.WithValue(req.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP(tc.local), Port: 8080}))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Errorf("Host %s arriving on %s = %d, want %d", tc.host, tc.local, rec.Code, tc.want)
		}
	}
}

func TestCACertificateDownload(t *testing.T) {
	pemData := []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
	e := newEnvOpts(t, Options{CACert: pemData})

	resp, err := http.Get(e.srv.URL + "/ca.crt")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != string(pemData) ||
		resp.Header.Get("Content-Type") != "application/x-x509-ca-cert" ||
		!strings.Contains(resp.Header.Get("Content-Disposition"), "gocalbox-ca.crt") {
		t.Errorf("GET /ca.crt: %d %v %q", resp.StatusCode, resp.Header, body)
	}
	if code, _ := e.do(http.MethodPost, "/ca.crt", strings.NewReader(""), "text/plain"); code != 405 {
		t.Errorf("POST /ca.crt = %d", code)
	}

	without := newEnv(t, 0)
	if code, _ := without.do(http.MethodGet, "/ca.crt", nil, ""); code != 404 {
		t.Errorf("GET /ca.crt without a local CA = %d", code)
	}
}

func TestRedirectKeepsThePortTheClientUsed(t *testing.T) {
	h := redirectPlain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	for host, want := range map[string]string{
		"localhost:8443": "https://localhost:8443/x?y=1",
		"localhost":      "https://localhost:80/x?y=1",
		"[::1]:8443":     "https://[::1]:8443/x?y=1",
		"[::1]":          "https://[::1]:80/x?y=1",
	} {
		req := httptest.NewRequest(http.MethodGet, "/x?y=1", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if got := rec.Header().Get("Location"); rec.Code != http.StatusTemporaryRedirect || got != want {
			t.Errorf("Host %s: %d to %q, want %q", host, rec.Code, got, want)
		}
	}
}
