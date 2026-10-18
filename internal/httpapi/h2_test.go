package httpapi

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/nobletk/gocalbox/internal/fsops"
	"github.com/nobletk/gocalbox/internal/sandbox"
	"github.com/nobletk/gocalbox/internal/transfer"
)

const h2Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// countingConn is a client's connection that counts, from the frames it
// writes, the DATA bytes sent on each stream.
type countingConn struct {
	net.Conn
	mu      sync.Mutex
	preface int
	hdr     []byte
	left    int    // payload bytes of the current frame still to come
	stream  uint32 // the current frame's stream if it is DATA, else 0
	data    map[uint32]int
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.count(p[:n])
	return n, err
}

func (c *countingConn) count(p []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if k := min(len(h2Preface)-c.preface, len(p)); k > 0 {
		c.preface += k
		p = p[k:]
	}
	for len(p) > 0 {
		if c.left > 0 {
			k := min(c.left, len(p))
			if c.stream != 0 {
				c.data[c.stream] += k
			}
			c.left -= k
			p = p[k:]
			continue
		}
		k := min(9-len(c.hdr), len(p))
		c.hdr = append(c.hdr, p[:k]...)
		p = p[k:]
		if len(c.hdr) < 9 {
			continue
		}
		c.left = int(c.hdr[0])<<16 | int(c.hdr[1])<<8 | int(c.hdr[2])
		c.stream = 0
		if c.hdr[3] == 0 {
			c.stream = binary.BigEndian.Uint32(c.hdr[5:9]) & (1<<31 - 1)
		}
		c.hdr = c.hdr[:0]
	}
}

// sent returns how many streams sent at least min bytes, and the bytes all
// streams sent.
func (c *countingConn) sent(atLeast int) (streams, total int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, n := range c.data {
		if n >= atLeast {
			streams++
		}
		total += n
	}
	return streams, total
}

// stallingUploads is an engine whose parts with an ID starting with "stall"
// read nothing until released, as a part whose writes block does; other
// parts are read whole.
type stallingUploads struct {
	release <-chan struct{}
	entered chan<- string
}

func (u *stallingUploads) Ready() error { return nil }

func (u *stallingUploads) Create(context.Context, transfer.CreateRequest) (transfer.Created, error) {
	return transfer.Created{}, transfer.ErrUnavailable
}

func (u *stallingUploads) Part(_ context.Context, req transfer.PartRequest) (transfer.PartResult, error) {
	if strings.HasPrefix(req.ID, "stall") {
		u.entered <- req.ID
		<-u.release
		return transfer.PartResult{}, transfer.ErrPartAborted
	}
	n, err := io.Copy(io.Discard, req.Body)
	if err != nil {
		return transfer.PartResult{}, fmt.Errorf("%w: %v", transfer.ErrPartAborted, err)
	}
	return transfer.PartResult{Part: req.N, Size: n}, nil
}

func (u *stallingUploads) Status(context.Context, string, []int) (transfer.Status, error) {
	return transfer.Status{}, transfer.ErrUnavailable
}

func (u *stallingUploads) Complete(context.Context, string, string) (transfer.Result, error) {
	return transfer.Result{}, transfer.ErrUnavailable
}

func (u *stallingUploads) Abort(context.Context, string) (transfer.AbortResult, error) {
	return transfer.AbortResult{}, transfer.ErrUnavailable
}

func (u *stallingUploads) List(context.Context, bool) ([]transfer.Status, error) {
	return nil, transfer.ErrUnavailable
}

// stallingFiles stops single-request uploads of files named "stall…" in
// the same way.
type stallingFiles struct {
	FileService
	release <-chan struct{}
	entered chan<- string
}

func (f stallingFiles) Create(ctx context.Context, dir, name string, r io.Reader, sizeHint int64) (string, int64, error) {
	if strings.HasPrefix(name, "stall") {
		f.entered <- name
		<-f.release
		return "", 0, fsops.ErrForbidden
	}
	return f.FileService.Create(ctx, dir, name, r, sizeHint)
}

// h2Env serves the API with NewServer over HTTP/2 without TLS, so that the
// test can read the frames its client sends on the one connection it uses.
type h2Env struct {
	t       *testing.T
	url     string
	root    string
	client  *http.Client
	release chan struct{}
	entered chan string
	dials   atomic.Int32
	conn    atomic.Pointer[countingConn]
	wg      sync.WaitGroup
}

const (
	h2BodyTimeout = 200 * time.Millisecond
	streamWindow  = 256 << 10
	connWindow    = 4<<20 - 1
)

func newH2Env(t *testing.T, bodyTimeout time.Duration) *h2Env {
	t.Helper()
	root := t.TempDir()
	sb, err := sandbox.New(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sb.Close() })
	e := &h2Env{t: t, root: root, release: make(chan struct{}), entered: make(chan string, 64)}
	files := stallingFiles{FileService: adminFiles(sb, &recorder{}), release: e.release, entered: e.entered}
	h := newTestHandler(files, fstest.MapFS{"index.html": {Data: []byte("<html></html>")}}, Options{
		Uploads:      &stallingUploads{release: e.release, entered: e.entered},
		BodyTimeout:  bodyTimeout,
		AllowedHosts: []string{"127.0.0.1"},
	})
	srv := NewServer(h)
	srv.Protocols = new(http.Protocols)
	srv.Protocols.SetHTTP1(true)
	srv.Protocols.SetUnencryptedHTTP2(true)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	e.url = "http://" + ln.Addr().String()

	tr := &http.Transport{Protocols: new(http.Protocols)}
	tr.Protocols.SetUnencryptedHTTP2(true)
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		e.dials.Add(1)
		cc := &countingConn{Conn: c, data: map[uint32]int{}}
		e.conn.Store(cc)
		return cc, nil
	}
	e.client = &http.Client{Transport: tr}
	t.Cleanup(func() {
		e.unstall()
		e.wg.Wait()
		tr.CloseIdleConnections()
		srv.Close()
	})
	return e
}

func (e *h2Env) unstall() {
	select {
	case <-e.release:
	default:
		close(e.release)
	}
}

// send starts a request whose answer the test doesn't wait for.
func (e *h2Env) send(req *http.Request) {
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		if resp, err := e.client.Do(req); err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}()
}

func (e *h2Env) partRequest(id string, body []byte) *http.Request {
	req, _ := http.NewRequest(http.MethodPost, e.url+"/api/upload/part?id="+id+"&n=1", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set(PartChecksumHeader, strings.Repeat("0", 64))
	return req
}

func (e *h2Env) uploadRequest(name string, content []byte) *http.Request {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("myFile", name)
	fw.Write(content)
	mw.Close()
	req, _ := http.NewRequest(http.MethodPost, e.url+"/api/upload", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	return req
}

// open makes the client's connection with a request that sends no body,
// which would count against the connection's window.
func (e *h2Env) open() {
	e.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, e.url+"/api/files?path=", nil)
	if code, _ := e.within(5*time.Second, req); code != http.StatusOK {
		e.t.Fatalf("listing the root = %d", code)
	}
}

func (e *h2Env) mkdirRequest(name string) *http.Request {
	req, _ := http.NewRequest(http.MethodPost, e.url+"/api/fs/mkdir", strings.NewReader(`{"name":"`+name+`","targetPath":""}`))
	req.Header.Set("Content-Type", "application/json")
	return req
}

// within sends req and returns its status, or 0 if it got no answer
// within d.
func (e *h2Env) within(d time.Duration, req *http.Request) (int, time.Duration) {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	start := time.Now()
	resp, err := e.client.Do(req.WithContext(ctx))
	if err != nil {
		return 0, time.Since(start)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.ProtoMajor != 2 {
		e.t.Errorf("%s answered over %s", req.URL.Path, resp.Proto)
	}
	return resp.StatusCode, time.Since(start)
}

// waitStalled waits until n requests stopped in a handler and their bodies
// sent what their windows allow: done reports it from the streams' counts.
func (e *h2Env) waitStalled(n int, done func(streams, total int) bool) {
	e.t.Helper()
	deadline := time.After(10 * time.Second)
	for range n {
		select {
		case <-e.entered:
		case <-deadline:
			e.t.Fatalf("fewer than %d requests reached their handlers", n)
		}
	}
	for {
		c := e.conn.Load()
		if c != nil && done(c.sent(streamWindow)) {
			return
		}
		select {
		case <-deadline:
			if c == nil {
				e.t.Fatal("the client made no connection")
			}
			s, total := c.sent(streamWindow)
			e.t.Fatalf("the stalled bodies sent %d bytes, %d streams their whole window", total, s)
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func TestFifteenStalledBodiesHoldUpNoOtherRequest(t *testing.T) {
	// The probes' bodies have the same timeout, and must never reach it
	// however long a busy machine takes to create their files.
	const bodyTimeout = time.Second
	e := newH2Env(t, bodyTimeout)
	body := bytes.Repeat([]byte("x"), 1<<20)
	e.open()
	for i := range 8 {
		e.send(e.partRequest(fmt.Sprintf("stall%d", i), body))
	}
	for i := range 7 {
		e.send(e.uploadRequest(fmt.Sprintf("stall%d.bin", i), body))
	}
	e.waitStalled(15, func(streams, _ int) bool { return streams >= 15 })
	// Past the stalled bodies' timeouts: their handlers, blocked, still
	// hold what they received.
	time.Sleep(bodyTimeout + 100*time.Millisecond)

	if code, took := e.within(5*time.Second, e.mkdirRequest("probe")); code != http.StatusCreated {
		t.Errorf("a small POST behind 15 stalled bodies = %d after %v", code, took)
	}
	if code, took := e.within(5*time.Second, e.partRequest("read", body)); code != http.StatusOK {
		t.Errorf("a part behind 15 stalled bodies = %d after %v", code, took)
	}
	if code, took := e.within(5*time.Second, e.uploadRequest("probe.bin", body)); code != http.StatusCreated {
		t.Errorf("a single-request upload behind 15 stalled bodies = %d after %v", code, took)
	}
	if got, err := os.ReadFile(filepath.Join(e.root, "probe.bin")); err != nil || !bytes.Equal(got, body) {
		t.Errorf("the probe's upload: %d bytes, %v", len(got), err)
	}
	if n := e.dials.Load(); n != 1 {
		t.Errorf("the client opened %d connections, want 1", n)
	}
}

func TestSixteenStalledBodiesFillTheConnectionsWindow(t *testing.T) {
	e := newH2Env(t, h2BodyTimeout)
	body := bytes.Repeat([]byte("x"), 1<<20)
	e.open()
	for i := range 16 {
		e.send(e.partRequest(fmt.Sprintf("stall%d", i), body))
	}
	e.waitStalled(16, func(_, total int) bool { return total >= connWindow })

	if code, took := e.within(5*time.Second, e.mkdirRequest("probe")); code == http.StatusCreated || took < h2BodyTimeout {
		t.Errorf("a small POST behind 16 stalled bodies = %d after %v, want it held up until its body timed out", code, took)
	}
	if _, err := os.Stat(filepath.Join(e.root, "probe")); err == nil {
		t.Error("the held-up mkdir made its folder")
	}
	e.unstall()
	if code, took := e.within(5*time.Second, e.mkdirRequest("after")); code != http.StatusCreated {
		t.Errorf("a small POST once the bodies are released = %d after %v", code, took)
	}
	if n := e.dials.Load(); n != 1 {
		t.Errorf("the client opened %d connections, want 1", n)
	}
}
