package httpapi

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/nobletk/gocalbox/internal/transfer"
)

// waitServer serves e's engine with a body timeout over HTTP/1.1, or over
// HTTP/2 when h2 is set, and counts the client connections it accepts.
type waitServer struct {
	t     *testing.T
	e     *uploadEnv
	srv   *httptest.Server
	h2    bool
	dials atomic.Int32
}

func serveWaiting(t *testing.T, e *uploadEnv, h2 bool, bodyTimeout time.Duration) *waitServer {
	t.Helper()
	srv := httptest.NewUnstartedServer(New(e.files, fstest.MapFS{"index.html": {Data: []byte("<html></html>")}},
		Options{Accounts: e.acc, Uploads: e.eng, BodyTimeout: bodyTimeout}))
	srv.Config.HTTP2 = NewServer(nil).HTTP2
	srv.EnableHTTP2 = h2
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return &waitServer{t: t, e: e, srv: srv, h2: h2}
}

// client is a browser of user, logged in already: the session cookie is
// the host's, whatever its port.
func (w *waitServer) client(user string) *http.Client {
	tr := w.srv.Client().Transport.(*http.Transport).Clone()
	tr.ForceAttemptHTTP2 = w.h2
	dial := tr.DialContext
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		w.dials.Add(1)
		return dial(ctx, network, addr)
	}
	w.t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Jar: w.e.users[user].Jar}
}

func (w *waitServer) partRequest(id string, n int, body io.Reader, length int64, sum string) *http.Request {
	req, _ := http.NewRequest("POST", w.srv.URL+"/api/upload/part?id="+id+"&n="+fmt.Sprint(n), body)
	req.ContentLength = length
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set(PartChecksumHeader, sum)
	return req
}

// answer is a response's status, error code and protocol.
type answer struct {
	status int
	code   string
	proto  int
	err    error
}

func (w *waitServer) sendAsync(c *http.Client, req *http.Request) <-chan answer {
	out := make(chan answer, 1)
	go func() {
		resp, err := c.Do(req)
		if err != nil {
			out <- answer{err: err}
			return
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		out <- answer{status: resp.StatusCode, code: errorCode(string(b)), proto: resp.ProtoMajor}
	}()
	return out
}

// hold sends part n of p as user, 64 KiB at a time every 50 ms, which keeps
// it within any body timeout of the tests, and returns once the server is
// receiving it. finish sends the rest at once; cut breaks the body off.
func (w *waitServer) hold(user, id string, p payload, n int) (finish, cut func()) {
	w.t.Helper()
	before := w.e.eng.Stats().PartsInFlight
	pr, pw := io.Pipe()
	stop := make(chan bool, 1)
	part := p.part(n)
	go func() {
		off := 0
		tick := time.NewTicker(50 * time.Millisecond)
		defer tick.Stop()
		for off < len(part) {
			select {
			case whole := <-stop:
				if !whole {
					pw.CloseWithError(errors.New("cut"))
					return
				}
				pw.Write(part[off:])
				off = len(part)
			case <-tick.C:
				end := min(off+64<<10, len(part)-1)
				pw.Write(part[off:end])
				off = end
			}
		}
		pw.Close()
	}()
	res := w.sendAsync(w.client(user), w.partRequest(id, n, pr, int64(len(part)), p.sum(n)))
	w.until(func() bool { return w.e.eng.Stats().PartsInFlight > before }, "the held part to start")
	end := func(whole bool, want int) {
		w.t.Helper()
		stop <- whole
		select {
		case a := <-res:
			// A body the client breaks off ends its request on the client.
			if a.status != want && (whole || a.err == nil) {
				w.t.Errorf("the held part: %+v, want %d", a, want)
			}
		case <-time.After(10 * time.Second):
			w.t.Fatal("the held part never ended")
		}
	}
	return func() { end(true, 200) }, func() { end(false, 400) }
}

func (w *waitServer) until(cond func() bool, what string) {
	w.t.Helper()
	for deadline := time.Now().Add(10 * time.Second); !cond(); time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			w.t.Fatalf("waited ten seconds for %s", what)
		}
	}
}

func (w *waitServer) waiting(n int) {
	w.t.Helper()
	w.until(func() bool { return w.e.eng.Stats().Waiting == n }, fmt.Sprintf("%d parts to wait", n))
}

func receive(t *testing.T, ch <-chan answer) answer {
	t.Helper()
	select {
	case a := <-ch:
		return a
	case <-time.After(15 * time.Second):
		t.Fatal("no answer within 15 seconds")
	}
	panic("unreachable")
}

func oneSlot(c *transfer.Config) {
	c.Limits.MaxInflight, c.Limits.MaxInflightUser = 1, 8
	c.AdmitWait = 10 * time.Second
}

func bothProtocols(t *testing.T, test func(t *testing.T, h2 bool)) {
	for _, h2 := range []bool{false, true} {
		t.Run(map[bool]string{false: "HTTP/1.1", true: "HTTP/2"}[h2], func(t *testing.T) { test(t, h2) })
	}
}

// A part waits for a slot longer than the body timeout, and is accepted:
// the wait doesn't count against its body.
func TestAPartThatWaitsPastTheStallLimitIsAccepted(t *testing.T) {
	bothProtocols(t, func(t *testing.T, h2 bool) {
		e := newUploadEnv(t, oneSlot)
		w := serveWaiting(t, e, h2, 200*time.Millisecond)
		big := newPayload(1<<20, 3)
		finish, _ := w.hold("bob", e.create("bob", "users/bob", "hold.bin", big, "").UploadID, big, 1)
		p := newPayload(1000, 9)
		c := e.create("alice", "public", "a.bin", p, "")
		res := w.sendAsync(w.client("alice"), w.partRequest(c.UploadID, 1, bytes.NewReader(p.data), int64(len(p.data)), p.sum(1)))
		w.waiting(1)
		time.Sleep(600 * time.Millisecond)
		finish()
		if a := receive(t, res); a.status != 200 || a.proto != map[bool]int{false: 1, true: 2}[h2] {
			t.Errorf("a part that waited 600 ms with a 200 ms body timeout: %+v", a)
		}
		if s := e.eng.Stats(); s.Waited != 1 || s.WaitTime < 600*time.Millisecond {
			t.Errorf("stats: %+v", s)
		}
	})
}

// A part whose body is sent only after a wait longer than the body timeout
// is accepted: the clock was paused while the part waited, not merely fed by
// a body already buffered.
func TestABodySentOnlyAfterALongWaitIsAccepted(t *testing.T) {
	bothProtocols(t, func(t *testing.T, h2 bool) {
		e := newUploadEnv(t, oneSlot)
		w := serveWaiting(t, e, h2, 200*time.Millisecond)
		big := newPayload(1<<20, 3)
		finish, _ := w.hold("bob", e.create("bob", "users/bob", "hold.bin", big, "").UploadID, big, 1)
		p := newPayload(1000, 9)
		c := e.create("alice", "public", "a.bin", p, "")
		pr, pw := io.Pipe()
		t.Cleanup(func() { pw.CloseWithError(errors.New("the test ended")) })
		res := w.sendAsync(w.client("alice"), w.partRequest(c.UploadID, 1, pr, int64(len(p.data)), p.sum(1)))
		w.waiting(1)
		time.Sleep(600 * time.Millisecond)
		finish()
		w.waiting(0)
		go func() { pw.Write(p.data); pw.Close() }()
		if a := receive(t, res); a.status != 200 {
			t.Errorf("a part whose body came after a 600 ms wait, with a 200 ms body timeout: %+v", a)
		}
	})
}

// A body whose stall limit ran out before its handler paused the clock is
// still cut at its next read over HTTP/1.1.
func TestAPauseDoesNotReviveAStallLimitThatRanOut(t *testing.T) {
	for _, pause := range []bool{false, true} {
		got := make(chan error, 1)
		srv := httptest.NewServer(limitBodyStalls(200*time.Millisecond, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(300 * time.Millisecond)
			if p := pauseStalls(r); pause && p != nil {
				p(true)
				p(false)
			}
			_, err := io.ReadAll(r.Body)
			got <- err
		})))
		c, err := net.Dial("tcp", srv.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		io.WriteString(c, "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\n")
		time.Sleep(400 * time.Millisecond)
		io.WriteString(c, "abcd")
		go bufio.NewReader(c).ReadString('\n')
		if err := <-got; err == nil {
			t.Errorf("paused %v: the body was read whole, though its stall limit ran out first", pause)
		}
		c.Close()
		srv.Close()
	}
}

// A part that stalls once it is read, after its wait, is still cut off.
func TestAPartThatStallsAfterItsWaitIsAborted(t *testing.T) {
	bothProtocols(t, func(t *testing.T, h2 bool) {
		e := newUploadEnv(t, oneSlot)
		w := serveWaiting(t, e, h2, 200*time.Millisecond)
		big := newPayload(1<<20, 3)
		finish, _ := w.hold("bob", e.create("bob", "users/bob", "hold.bin", big, "").UploadID, big, 1)
		p := newPayload(1000, 9)
		c := e.create("alice", "public", "a.bin", p, "")
		pr, pw := io.Pipe()
		t.Cleanup(func() { pw.CloseWithError(errors.New("the test ended")) })
		go pw.Write(p.data[:10])
		res := w.sendAsync(w.client("alice"), w.partRequest(c.UploadID, 1, pr, int64(len(p.data)), p.sum(1)))
		w.waiting(1)
		time.Sleep(400 * time.Millisecond)
		finish()
		start := time.Now()
		if a := receive(t, res); a.status != 400 || a.code != "part_aborted" {
			t.Errorf("a part that stalled after its wait: %+v", a)
		}
		if took := time.Since(start); took > 5*time.Second {
			t.Errorf("answered %v after its wait", took)
		}
	})
}

// rawRequest sends a request over a connection of its own with HTTP/1.1,
// with user's cookies, the given headers and the start of a body that then
// stalls. It returns the status line and how long the server took to close
// the connection after it.
func (w *waitServer) rawRequest(user, path string, headers []string, start string) (status string, closedAfter time.Duration) {
	w.t.Helper()
	u, _ := url.Parse(w.srv.URL)
	cfg := w.srv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	cfg.NextProtos = []string{"http/1.1"}
	conn, err := tls.Dial("tcp", u.Host, cfg)
	if err != nil {
		w.t.Fatal(err)
	}
	defer conn.Close()
	var cookies []string
	for _, c := range w.e.users[user].Jar.Cookies(u) {
		cookies = append(cookies, c.Name+"="+c.Value)
	}
	fmt.Fprintf(conn, "POST %s HTTP/1.1\r\nHost: %s\r\nCookie: %s\r\n%s\r\n%s", path, u.Host, strings.Join(cookies, "; "),
		strings.Join(headers, "\r\n")+"\r\n", start)
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if err != nil {
		w.t.Fatalf("no status line: %v", err)
	}
	answered := time.Now()
	io.Copy(io.Discard, r)
	return strings.TrimSpace(line), time.Since(answered)
}

// A part refused without its body being read, before a wait or after one,
// has its stalled body cut off at the stall limit over HTTP/1.1, as every
// other route's.
func TestARefusedPartsStalledBodyIsCut(t *testing.T) {
	const timeout = 200 * time.Millisecond
	e := newUploadEnv(t, oneSlot)
	w := serveWaiting(t, e, false, timeout)
	headers := func(sum string) []string {
		return []string{"Content-Type: application/octet-stream", PartChecksumHeader + ": " + sum}
	}
	unknown := "/api/upload/part?id=" + strings.Repeat("0", 32) + "&n=1"
	sum := strings.Repeat("0", 64)
	for _, tc := range []struct {
		name  string
		hdrs  []string
		start string
	}{
		{"plain", append(headers(sum), "Content-Length: 100000"), "0123456789"},
		{"chunked", append(headers(sum), "Transfer-Encoding: chunked"), "a\r\n0123456789\r\n"},
	} {
		status, after := w.rawRequest("alice", unknown, tc.hdrs, tc.start)
		if !strings.Contains(status, " 404 ") {
			t.Errorf("%s: an unknown upload: %s", tc.name, status)
		}
		if after > 5*time.Second {
			t.Errorf("%s: the connection was held %v after the answer", tc.name, after)
		}
	}

	big := newPayload(1<<20, 3)
	finish, _ := w.hold("bob", e.create("bob", "users/bob", "hold.bin", big, "").UploadID, big, 1)
	p := newPayload(1000, 9)
	c := e.create("alice", "public", "a.bin", p, "")
	type raw struct {
		status string
		after  time.Duration
	}
	res := make(chan raw, 1)
	go func() {
		s, a := w.rawRequest("alice", "/api/upload/part?id="+c.UploadID+"&n=1", append(headers(p.sum(1)), "Content-Length: 1000"), "0123456789")
		res <- raw{s, a}
	}()
	w.waiting(1)
	if resp, body := e.as("alice", "POST", "/api/upload/abort", UploadAbortRequest{UploadID: c.UploadID}); resp.StatusCode != 200 {
		t.Fatalf("abort: %d %s", resp.StatusCode, body)
	}
	time.Sleep(3 * timeout)
	finish()
	select {
	case r := <-res:
		if !strings.Contains(r.status, " 409 ") {
			t.Errorf("a part whose upload ended while it waited: %s", r.status)
		}
		if r.after > 5*time.Second {
			t.Errorf("the connection was held %v after the answer", r.after)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("no answer")
	}
}

// Eight parts of one user waiting on one HTTP/2 connection hold up nothing
// else on it.
func TestEightWaitingPartsLeaveRoomOnTheirConnection(t *testing.T) {
	e := newUploadEnv(t, func(c *transfer.Config) {
		c.Limits.MaxInflight, c.Limits.MaxInflightUser = 8, 8
		c.AdmitWait = 10 * time.Second
	})
	w := serveWaiting(t, e, true, 2*time.Second)
	big := newPayload(8*8<<20, 3)
	bc := e.create("bob", "users/bob", "hold.bin", big, "")
	var cuts []func()
	for n := 1; n <= 8; n++ {
		_, cut := w.hold("bob", bc.UploadID, big, n)
		cuts = append(cuts, cut)
	}
	p := newPayload(8*8<<20, 9)
	c := e.create("alice", "users/alice", "a.bin", p, "")
	alice := w.client("alice")
	before := w.dials.Load()
	var answers []<-chan answer
	for n := 1; n <= 8; n++ {
		answers = append(answers, w.sendAsync(alice, w.partRequest(c.UploadID, n, bytes.NewReader(p.part(n)), int64(len(p.part(n))), p.sum(n))))
	}
	w.waiting(8)
	time.Sleep(200 * time.Millisecond)

	req, _ := http.NewRequest("POST", w.srv.URL+"/api/fs/mkdir", strings.NewReader(`{"name":"probe","targetPath":"users/alice"}`))
	req.Header.Set("Content-Type", "application/json")
	start := time.Now()
	if a := receive(t, w.sendAsync(alice, req)); a.status != http.StatusCreated || a.proto != 2 {
		t.Errorf("a small POST behind 8 waiting parts: %+v", a)
	}
	if took := time.Since(start); took > time.Second {
		t.Errorf("the small POST took %v", took)
	}
	if n := w.dials.Load() - before; n != 1 {
		t.Errorf("alice's requests used %d connections, want 1", n)
	}

	var wg sync.WaitGroup
	for _, cut := range cuts {
		wg.Add(1)
		go func() { defer wg.Done(); cut() }()
	}
	wg.Wait()
	for n, ch := range answers {
		if a := receive(t, ch); a.status != 200 {
			t.Errorf("alice's part %d: %+v", n+1, a)
		}
	}
}

// Over HTTP/1.1 a client that leaves a waiting part goes unnoticed until a
// slot reaches the part, which then passes it on at once.
func TestAClientThatLeavesAWaitingPartOverHTTP1FreesItsPlace(t *testing.T) {
	e := newUploadEnv(t, func(c *transfer.Config) {
		c.Limits.MaxInflight, c.Limits.MaxInflightUser = 2, 8
		c.AdmitWait = 10 * time.Second
	})
	w := serveWaiting(t, e, false, time.Second)
	big := newPayload(3*8<<20, 3)
	bc := e.create("bob", "users/bob", "hold.bin", big, "")
	finish1, _ := w.hold("bob", bc.UploadID, big, 1)
	finish2, _ := w.hold("bob", bc.UploadID, big, 2)

	p := newPayload(1000, 9)
	c := e.create("alice", "public", "a.bin", p, "")
	ctx, cancel := context.WithCancel(context.Background())
	pr, pw := io.Pipe()
	t.Cleanup(func() { pw.CloseWithError(errors.New("the test ended")) })
	left := w.sendAsync(w.client("alice"), w.partRequest(c.UploadID, 1, pr, int64(len(p.data)), p.sum(1)).WithContext(ctx))
	w.waiting(1)
	cancel()
	// The client's transport is reading the body; this lets it go.
	pw.CloseWithError(errors.New("left"))
	if a := receive(t, left); a.err == nil {
		t.Errorf("the request its client left: %+v", a)
	}

	third := big.part(3)
	next := w.sendAsync(w.client("bob"), w.partRequest(bc.UploadID, 3, bytes.NewReader(third), int64(len(third)), big.sum(3)))
	w.waiting(2)
	finish1()
	start := time.Now()
	if a := receive(t, next); a.status != 200 {
		t.Errorf("the part behind the one its client left: %+v", a)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Errorf("the part behind waited %v once a slot came free", took)
	}
	finish2()
	if s := e.eng.Stats(); s.PartsInFlight != 0 || s.Waiting != 0 {
		t.Errorf("stats at the end: %+v", s)
	}
}
