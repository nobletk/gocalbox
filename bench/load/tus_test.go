package load

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeTus is a tus server as tusd behaves: it keeps the bytes of a PATCH as
// they arrive, those of one cut off too, and refuses a PATCH at another
// offset than the upload's.
type fakeTus struct {
	t   *testing.T
	srv *httptest.Server
	ca  []byte

	mu       sync.Mutex
	uploads  map[string]*bytes.Buffer
	length   map[string]int64
	names    map[string]string
	requests []string // method, protocol, offset and length of each request
	// cutAt cuts the next PATCH off once the upload holds that many bytes,
	// and keeps them; -1 doesn't.
	cutAt    int64
	refuse   map[string]int // the status to answer the next request of a method with, once
	absolute bool           // answer the creation with an absolute URL
	// ahead, on the next PATCH, takes that many of its bytes as if an earlier
	// try had brought them, and answers 409 for the offset it was sent at.
	ahead int
	// noLocation answers the creation without the upload's URL, and
	// headOffset answers HEAD with this offset, when set.
	noLocation bool
	headOffset string
	// breakNext breaks the answer to the next request of a method after its
	// headers, or before them for HEAD, whose answer has no body.
	breakNext map[string]bool
}

func newFakeTus(t *testing.T) *fakeTus {
	t.Helper()
	f := &fakeTus{t: t, uploads: map[string]*bytes.Buffer{}, length: map[string]int64{}, names: map[string]string{},
		cutAt: -1, refuse: map[string]int{}, breakNext: map[string]bool{}}
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	f.srv.EnableHTTP2 = true
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	f.ca = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw})
	return f
}

func (f *fakeTus) endpoint() string { return f.srv.URL + "/files/" }

func (f *fakeTus) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests = append(f.requests, fmt.Sprintf("%s %s %s %d", r.Method, r.Proto, r.Header.Get("Upload-Offset"), r.ContentLength))
	code, refused := f.refuse[r.Method]
	delete(f.refuse, r.Method)
	broken := f.breakNext[r.Method]
	delete(f.breakNext, r.Method)
	f.mu.Unlock()
	if refused {
		http.Error(w, "refused", code)
		return
	}
	if broken && r.Method == http.MethodHead {
		panic(http.ErrAbortHandler)
	}
	if broken {
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(http.StatusTeapot)
		w.Write([]byte("cut"))
		w.(http.Flusher).Flush()
		panic(http.ErrAbortHandler)
	}
	if r.Method == http.MethodOptions {
		w.Header().Set("Tus-Version", TusVersion)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Header.Get("Tus-Resumable") != TusVersion {
		w.WriteHeader(http.StatusPreconditionFailed)
		return
	}
	w.Header().Set("Tus-Resumable", TusVersion)
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/files/":
		n, err := strconv.ParseInt(r.Header.Get("Upload-Length"), 10, 64)
		if err != nil || n < 0 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		name := ""
		if k, v, ok := strings.Cut(r.Header.Get("Upload-Metadata"), " "); ok && k == "filename" {
			b, _ := base64.StdEncoding.DecodeString(v)
			name = string(b)
		}
		id := rand.Text()
		f.mu.Lock()
		f.uploads[id], f.length[id], f.names[id] = &bytes.Buffer{}, n, name
		abs := f.absolute
		f.mu.Unlock()
		loc := "/files/" + id
		if abs {
			loc = f.srv.URL + loc
		}
		if !f.noLocation {
			w.Header().Set("Location", loc)
		}
		w.WriteHeader(http.StatusCreated)
	case r.Method == http.MethodHead:
		f.mu.Lock()
		b, ok := f.uploads[strings.TrimPrefix(r.URL.Path, "/files/")]
		n := 0
		if ok {
			n = b.Len()
		}
		f.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Upload-Offset", strconv.Itoa(n))
		if f.headOffset != "" {
			w.Header().Set("Upload-Offset", f.headOffset)
		}
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodPatch:
		id := strings.TrimPrefix(r.URL.Path, "/files/")
		f.mu.Lock()
		b, ok := f.uploads[id]
		length := f.length[id]
		cut := f.cutAt
		f.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Header.Get("Content-Type") != "application/offset+octet-stream" {
			w.WriteHeader(http.StatusUnsupportedMediaType)
			return
		}
		f.mu.Lock()
		if f.ahead > 0 {
			chunk, _ := io.ReadAll(io.LimitReader(r.Body, int64(f.ahead)))
			b.Write(chunk)
			f.ahead = 0
			f.mu.Unlock()
			w.WriteHeader(http.StatusConflict)
			return
		}
		have := int64(b.Len())
		f.mu.Unlock()
		if r.Header.Get("Upload-Offset") != strconv.FormatInt(have, 10) {
			w.WriteHeader(http.StatusConflict)
			return
		}
		buf := make([]byte, 32<<10)
		for {
			n, err := r.Body.Read(buf)
			f.mu.Lock()
			if have+int64(n) > length {
				f.mu.Unlock()
				w.WriteHeader(http.StatusRequestEntityTooLarge)
				return
			}
			if cut >= 0 && have+int64(n) >= cut {
				b.Write(buf[:cut-have])
				f.cutAt = -1
				f.mu.Unlock()
				panic(http.ErrAbortHandler)
			}
			b.Write(buf[:n])
			have += int64(n)
			f.mu.Unlock()
			if err == io.EOF {
				break
			}
			if err != nil {
				return
			}
		}
		w.Header().Set("Upload-Offset", strconv.FormatInt(have, 10))
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// only returns the one upload the server holds, and its file name.
func (f *fakeTus) only() ([]byte, string) {
	f.t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.uploads) != 1 {
		f.t.Fatalf("%d uploads, want 1", len(f.uploads))
	}
	for id, b := range f.uploads {
		return b.Bytes(), f.names[id]
	}
	return nil, ""
}

func (f *fakeTus) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.requests...)
}

// tusFile writes a file of n random bytes.
func tusFile(t *testing.T, n int) (string, []byte) {
	t.Helper()
	b := make([]byte, n)
	rand.Read(b)
	p := filepath.Join(t.TempDir(), "source.bin")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p, b
}

func (f *fakeTus) config(file string, chunk int64, http1 bool) TusConfig {
	return TusConfig{Server: Tus{Endpoint: f.endpoint(), CA: f.ca, HTTP1: http1}, File: file, Chunk: chunk}
}

// An upload is created with its length and name, then sent in PATCHes of a
// chunk each, one after another from offset 0, over the protocol asked for.
func TestTusUploadsAFileInChunks(t *testing.T) {
	for _, http1 := range []bool{false, true} {
		f := newFakeTus(t)
		p, want := tusFile(t, 1000)
		res, err := TusRun(context.Background(), f.config(p, 300, http1))
		if err != nil {
			t.Fatal(err)
		}
		got, name := f.only()
		if !bytes.Equal(got, want) || name != "source.bin" {
			t.Fatalf("the server holds %d bytes named %q", len(got), name)
		}
		proto := "HTTP/2.0"
		if http1 {
			proto = "HTTP/1.1"
		}
		wantCalls := []string{"OPTIONS " + proto + "  0", "POST " + proto + "  0", "PATCH " + proto + " 0 300", "PATCH " + proto + " 300 300",
			"PATCH " + proto + " 600 300", "PATCH " + proto + " 900 100"}
		if fmt.Sprint(f.calls()) != fmt.Sprint(wantCalls) {
			t.Errorf("requests %q, want %q", f.calls(), wantCalls)
		}
		if res.CodeColumn() != "201" || res.Files != 1 || res.Bytes != 1000 || len(res.Parts) != 4 || res.Resent != 0 ||
			len(res.Resumes) != 0 || len(res.Retried) != 0 || res.Duration <= 0 || res.UserRates[0] <= 0 {
			t.Errorf("result %+v", res)
		}
	}
}

// Without chunks the file goes in one PATCH; an empty file needs none.
func TestTusSendsTheFileInOnePatchWithoutChunks(t *testing.T) {
	f := newFakeTus(t)
	p, want := tusFile(t, 5000)
	res, err := TusRun(context.Background(), f.config(p, 0, false))
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := f.only(); !bytes.Equal(got, want) || len(res.Parts) != 1 || res.CodeColumn() != "201" {
		t.Errorf("%d bytes, result %+v", len(got), res)
	}
	f = newFakeTus(t)
	p, _ = tusFile(t, 0)
	res, err = TusRun(context.Background(), f.config(p, 300, false))
	if err != nil {
		t.Fatal(err)
	}
	if calls := f.calls(); len(calls) != 2 || !strings.HasPrefix(calls[1], "POST") || res.CodeColumn() != "201" || len(res.Parts) != 0 {
		t.Errorf("requests %q, result %+v", calls, res)
	}
}

// An absolute upload URL is followed as it is.
func TestTusFollowsAnAbsoluteUploadURL(t *testing.T) {
	f := newFakeTus(t)
	f.absolute = true
	p, want := tusFile(t, 700)
	res, err := TusRun(context.Background(), f.config(p, 300, false))
	if got, _ := f.only(); err != nil || !bytes.Equal(got, want) || res.CodeColumn() != "201" {
		t.Errorf("%v, %d bytes, %s", err, len(got), res.CodeColumn())
	}
}

// With ResumeAt the upload stops after the chunk that reaches the share, asks
// the server for its offset, and goes on from there.
func TestTusResumesFromTheOffsetAfterAStop(t *testing.T) {
	f := newFakeTus(t)
	p, want := tusFile(t, 1000)
	cfg := f.config(p, 300, false)
	cfg.ResumeAt = 0.5
	res, err := TusRun(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := f.only()
	wantCalls := []string{"OPTIONS HTTP/2.0  0", "POST HTTP/2.0  0", "PATCH HTTP/2.0 0 300", "PATCH HTTP/2.0 300 300", "HEAD HTTP/2.0  0",
		"PATCH HTTP/2.0 600 300", "PATCH HTTP/2.0 900 100"}
	if !bytes.Equal(got, want) || fmt.Sprint(f.calls()) != fmt.Sprint(wantCalls) {
		t.Errorf("%d bytes; requests %q, want %q", len(got), f.calls(), wantCalls)
	}
	if res.CodeColumn() != "201" || len(res.Resumes) != 1 || res.Resumes[0] <= 0 || res.Resumes[0] > res.Duration || res.Resent != 0 {
		t.Errorf("result %+v", res)
	}
}

// A PATCH cut off is sent again, with RetryFor, from the offset the server
// kept, which a HEAD finds; the bytes it carried beyond that count as sent
// twice.
func TestTusGoesOnFromWhatTheServerKeptAfterACut(t *testing.T) {
	f := newFakeTus(t)
	f.cutAt = 450
	p, want := tusFile(t, 1000)
	cfg := f.config(p, 300, true)
	cfg.RetryFor = 10 * time.Second
	res, err := TusRun(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := f.only()
	if !bytes.Equal(got, want) {
		t.Fatalf("the server holds %d bytes, not the file's", len(got))
	}
	wantCalls := []string{"OPTIONS HTTP/1.1  0", "POST HTTP/1.1  0", "PATCH HTTP/1.1 0 300", "PATCH HTTP/1.1 300 300", "HEAD HTTP/1.1  0",
		"PATCH HTTP/1.1 450 300", "PATCH HTTP/1.1 750 250"}
	if fmt.Sprint(f.calls()) != fmt.Sprint(wantCalls) {
		t.Errorf("requests %q, want %q", f.calls(), wantCalls)
	}
	if res.CodeColumn() != "201" || res.Resent != 150 || res.Retried["000"] != 1 || len(res.Parts) != 3 || res.Stalled <= 0 {
		t.Errorf("result %+v", res)
	}
}

// Without RetryFor a PATCH cut off ends the upload, with no answer.
func TestTusEndsAtACutWithoutRetrying(t *testing.T) {
	f := newFakeTus(t)
	f.cutAt = 450
	p, _ := tusFile(t, 1000)
	res, err := TusRun(context.Background(), f.config(p, 300, false))
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := f.only(); len(got) != 450 || res.CodeColumn() != "000x1" || res.UserRates[0] != 0 || len(res.Resumes) != 0 {
		t.Errorf("%d bytes, result %+v", len(got), res)
	}
}

// A PATCH refused for its offset goes on from the server's; any other
// refusal ends the upload with its status.
func TestTusRefusals(t *testing.T) {
	f := newFakeTus(t)
	f.ahead = 100
	p, want := tusFile(t, 1000)
	res, err := TusRun(context.Background(), f.config(p, 300, false))
	if got, _ := f.only(); err != nil || !bytes.Equal(got, want) || res.CodeColumn() != "201" || res.Retried["409"] != 1 || res.Resent != 0 {
		t.Errorf("%v, %d bytes, result %+v", err, len(got), res)
	}
	if calls := f.calls(); len(calls) != 7 || calls[4] != "PATCH HTTP/2.0 100 300" {
		t.Errorf("requests %q", calls)
	}
	// A 409 at the offset the server has just given ends the upload, rather than asking forever.
	f = newFakeTus(t)
	f.refuse[http.MethodPatch] = http.StatusConflict
	res, err = TusRun(context.Background(), f.config(p, 300, false))
	if err != nil || res.CodeColumn() != "409x1" || len(f.calls()) != 4 {
		t.Errorf("%v, %s, requests %q", err, res.CodeColumn(), f.calls())
	}
	for method, code := range map[string]int{http.MethodPatch: 404, http.MethodPost: 413} {
		f := newFakeTus(t)
		f.refuse[method] = code
		res, err := TusRun(context.Background(), f.config(p, 300, false))
		if want := fmt.Sprintf("%dx1", code); err != nil || res.CodeColumn() != want {
			t.Errorf("%s refused: %v, %s, want %s", method, err, res.CodeColumn(), want)
		}
	}
}

// A server that answers a PATCH with another offset than the bytes sent
// ends the upload.
func TestTusChecksTheOffsetAnswered(t *testing.T) {
	var patches int
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			w.Header().Set("Location", "/files/x")
			w.WriteHeader(http.StatusCreated)
		case http.MethodPatch:
			patches++
			io.Copy(io.Discard, r.Body)
			w.Header().Set("Upload-Offset", "1")
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	p, _ := tusFile(t, 100)
	res, err := TusRun(context.Background(), TusConfig{Server: Tus{Endpoint: srv.URL + "/files/", CA: ca}, File: p})
	if err != nil || res.CodeColumn() != "500x1" || patches != 1 {
		t.Errorf("%v, %s after %d PATCHes", err, res.CodeColumn(), patches)
	}
}

// With RetryFor, requests that can't connect are tried again for that long,
// and then the upload ends with no answer.
func TestTusTriesAServerThatIsGoneForRetryFor(t *testing.T) {
	f := newFakeTus(t)
	p, _ := tusFile(t, 100)
	cfg := f.config(p, 0, false)
	f.srv.Close()
	cfg.RetryFor = 500 * time.Millisecond
	start := time.Now()
	res, err := TusRun(context.Background(), cfg)
	// One try every 100 ms, and the time unanswered, to the end.
	if took := time.Since(start); err != nil || res.CodeColumn() != "000x1" || took < cfg.RetryFor || took > 10*time.Second ||
		res.Retried["000"] < 2 || res.Retried["000"] > 6 || res.Stalled < cfg.RetryFor {
		t.Errorf("%v, %s after %v, tried again %v, stalled %v", err, res.CodeColumn(), took, res.Retried, res.Stalled)
	}
}

func TestTusRefusesAConfigurationThatCantRun(t *testing.T) {
	f := newFakeTus(t)
	p, _ := tusFile(t, 10)
	for _, c := range []struct {
		change func(*TusConfig)
		want   string
	}{
		{func(c *TusConfig) { c.Server.Endpoint = "http://localhost/files/" }, "https://host:port/path"},
		{func(c *TusConfig) { c.Server.Endpoint = "https:///files/" }, "https://host:port/path"},
		{func(c *TusConfig) { c.Server.Endpoint = f.srv.URL + "?x=1" }, "https://host:port/path"},
		{func(c *TusConfig) { c.Server.Endpoint = strings.Replace(f.endpoint(), "https://", "https://user@", 1) }, "https://host:port/path"},
		{func(c *TusConfig) { c.ResumeAt = 0.95 }, "falls in the last chunk"},
		{func(c *TusConfig) { c.ResumeAt = 0.5; c.Chunk = 10 }, "falls in the last chunk"},
		{func(c *TusConfig) { c.Chunk = -1 }, "negative"},
		{func(c *TusConfig) { c.ResumeAt = 1 }, "below 1"},
		{func(c *TusConfig) { c.ResumeAt = 0.5; c.Chunk = 0 }, "needs chunks"},
		{func(c *TusConfig) { c.RetryFor = -time.Second }, "negative"},
		{func(c *TusConfig) { c.Server.CA = []byte("no pem") }, "no certificate"},
		{func(c *TusConfig) { c.File = filepath.Dir(p) }, "no regular file"},
		{func(c *TusConfig) { c.File += ".missing" }, "no such file"},
	} {
		cfg := f.config(p, 5, false)
		c.change(&cfg)
		if _, err := TusRun(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v, want %q", err, c.want)
		}
	}
	if calls := f.calls(); len(calls) != 0 {
		t.Errorf("a refused configuration sent %q", calls)
	}
}

// A stop whose chunk ends just before the file's end still stops.
func TestTusStopsInTheChunkBeforeTheLast(t *testing.T) {
	f := newFakeTus(t)
	p, want := tusFile(t, 1000)
	cfg := f.config(p, 300, false)
	cfg.ResumeAt = 0.85
	res, err := TusRun(context.Background(), cfg)
	if got, _ := f.only(); err != nil || !bytes.Equal(got, want) || len(res.Resumes) != 1 || !slices.Contains(f.calls(), "HEAD HTTP/2.0  0") {
		t.Errorf("%v, %d bytes, requests %q, resumes %v", err, len(got), f.calls(), res.Resumes)
	}
}

// The creation must give the upload's URL, and HEAD an offset within the
// file.
func TestTusChecksTheServersAnswers(t *testing.T) {
	p, _ := tusFile(t, 1000)
	f := newFakeTus(t)
	f.noLocation = true
	res, err := TusRun(context.Background(), f.config(p, 300, false))
	if err != nil || res.CodeColumn() == "201" || slices.ContainsFunc(f.calls(), func(c string) bool { return strings.HasPrefix(c, "PATCH") }) {
		t.Errorf("no upload URL: %v, %s, requests %q", err, res.CodeColumn(), f.calls())
	}
	for _, off := range []string{"1001", "-1", "x"} {
		f := newFakeTus(t)
		f.headOffset = off
		cfg := f.config(p, 300, false)
		cfg.ResumeAt = 0.5
		res, err := TusRun(context.Background(), cfg)
		if err != nil || res.CodeColumn() == "201" {
			t.Errorf("HEAD's offset %s: %v, %s", off, err, res.CodeColumn())
		}
	}
}

// A HEAD that loses its answer is tried again within RetryFor, and an
// answer cut off after its headers is no answer.
func TestTusTriesAHeadAgain(t *testing.T) {
	f := newFakeTus(t)
	f.cutAt = 450
	f.breakNext[http.MethodHead] = true
	p, want := tusFile(t, 1000)
	cfg := f.config(p, 300, true)
	cfg.RetryFor = 10 * time.Second
	res, err := TusRun(context.Background(), cfg)
	got, _ := f.only()
	if err != nil || !bytes.Equal(got, want) || res.CodeColumn() != "201" || res.Retried["000"] != 2 || res.Stalled <= 0 {
		t.Errorf("%v, %d bytes, result %+v", err, len(got), res)
	}
	f = newFakeTus(t)
	f.breakNext[http.MethodPost] = true
	res, err = TusRun(context.Background(), f.config(p, 300, true))
	if err != nil || res.CodeColumn() != "000x1" || res.Stalled <= 0 {
		t.Errorf("a creation's answer cut off: %v, %+v", err, res)
	}
}

// A PATCH that couldn't connect sent nothing, so nothing counts as sent
// twice when it is tried again.
func TestTusCountsNothingResentForAConnectionNotMade(t *testing.T) {
	f := newFakeTus(t)
	p, want := tusFile(t, 1000)
	addr := f.srv.Listener.Addr().String()
	cfg := f.config(p, 300, true)
	cfg.RetryFor = 20 * time.Second
	// The server stops listening as it answers the creation, which closes its connection, and
	// listens again on the same address a little later.
	var once sync.Once
	f.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			once.Do(func() {
				f.srv.Listener.Close()
				go func() {
					time.Sleep(300 * time.Millisecond)
					l, err := net.Listen("tcp", addr)
					if err != nil {
						t.Error(err)
						return
					}
					go http.Serve(tls.NewListener(l, f.srv.TLS), http.HandlerFunc(f.serve))
				}()
			})
			w.Header().Set("Connection", "close")
		}
		f.serve(w, r)
	})
	res, err := TusRun(context.Background(), cfg)
	got, _ := f.only()
	if err != nil || !bytes.Equal(got, want) || res.CodeColumn() != "201" || res.Resent != 0 || res.Retried["000"] == 0 {
		t.Errorf("%v, %d bytes, result %+v", err, len(got), res)
	}
}

// A stop whose chunk, shifted by a HEAD after a cut, ends the file isn't a
// resume: nothing was left to send.
func TestTusDoesntStopAtTheEnd(t *testing.T) {
	f := newFakeTus(t)
	f.cutAt = 150
	p, want := tusFile(t, 1000)
	cfg := f.config(p, 300, true)
	cfg.ResumeAt = 0.85
	cfg.RetryFor = 10 * time.Second
	res, err := TusRun(context.Background(), cfg)
	got, _ := f.only()
	calls := f.calls()
	if err != nil || !bytes.Equal(got, want) || res.CodeColumn() != "201" || len(res.Resumes) != 0 || calls[len(calls)-1] != "PATCH HTTP/1.1 750 250" {
		t.Errorf("%v, %d bytes, requests %q, resumes %v", err, len(got), calls, res.Resumes)
	}
}

// A server that goes back behind an offset it had acknowledged gets the
// bytes from there again, but only those of the PATCH that got no answer
// count as sent twice.
func TestTusCountsAsResentOnlyTheLostPatch(t *testing.T) {
	f := newFakeTus(t)
	f.cutAt = 450
	f.headOffset = "200"
	p, _ := tusFile(t, 1000)
	cfg := f.config(p, 300, true)
	cfg.RetryFor = 10 * time.Second
	res, err := TusRun(context.Background(), cfg)
	if err != nil || res.Resent != 300 || res.CodeColumn() == "201" {
		t.Errorf("%v, %s, resent %d, want 300", err, res.CodeColumn(), res.Resent)
	}
}
