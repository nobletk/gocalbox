//go:build bench

package httpapi

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nobletk/gocalbox/internal/benchmode"
)

// benchSettings sets the benchmark settings for one test, and clears them
// after it.
func benchSettings(t *testing.T, kv ...string) {
	t.Helper()
	t.Cleanup(func() {
		for i := 0; i < len(kv); i += 2 {
			os.Unsetenv(kv[i])
		}
		benchmode.Init()
	})
	for i := 0; i < len(kv); i += 2 {
		t.Setenv(kv[i], kv[i+1])
	}
	if err := benchmode.Init(); err != nil {
		t.Fatal(err)
	}
}

func TestABenchmarkBuildSetsTheWindows(t *testing.T) {
	t.Run("both", func(t *testing.T) {
		benchSettings(t, benchmode.EnvConnWindow, "16M", benchmode.EnvStreamWindow, "1M")
		srv := NewServer(http.NotFoundHandler())
		if srv.HTTP2.MaxReceiveBufferPerConnection != 16<<20 || srv.HTTP2.MaxReceiveBufferPerStream != 1<<20 {
			t.Errorf("windows %d, %d", srv.HTTP2.MaxReceiveBufferPerConnection, srv.HTTP2.MaxReceiveBufferPerStream)
		}
	})
	t.Run("one", func(t *testing.T) {
		benchSettings(t, benchmode.EnvStreamWindow, "128K")
		srv := NewServer(http.NotFoundHandler())
		if srv.HTTP2.MaxReceiveBufferPerConnection != receiveWindowPerConnection || srv.HTTP2.MaxReceiveBufferPerStream != 128<<10 {
			t.Errorf("one window set: %d, %d", srv.HTTP2.MaxReceiveBufferPerConnection, srv.HTTP2.MaxReceiveBufferPerStream)
		}
	})
	t.Run("none", func(t *testing.T) {
		benchSettings(t)
		srv := NewServer(http.NotFoundHandler())
		if srv.HTTP2.MaxReceiveBufferPerConnection != receiveWindowPerConnection || srv.HTTP2.MaxReceiveBufferPerStream != receiveWindowPerStream {
			t.Errorf("none set: %d, %d", srv.HTTP2.MaxReceiveBufferPerConnection, srv.HTTP2.MaxReceiveBufferPerStream)
		}
	})
}

func readEntries(t *testing.T, path string, n int) []requestEntry {
	t.Helper()
	var es []requestEntry
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		b, _ := os.ReadFile(path)
		es = nil
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			var e requestEntry
			if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
				t.Fatalf("line %q: %v", sc.Text(), err)
			}
			es = append(es, e)
		}
		if len(es) >= n {
			break
		}
	}
	if len(es) != n {
		t.Fatalf("%d entries, want %d", len(es), n)
	}
	return es
}

// The request log says what each request received and sent, its status,
// when its first byte left and how long it took, over HTTP/1.1 and HTTP/2,
// for a body written in pieces, one copied by ServeContent, and a stream
// flushed through http.ResponseController.
func TestTheRequestLogSaysWhatARequestDid(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "requests.jsonl")
	benchSettings(t, benchmode.EnvRequestLog, logPath)
	content := bytes.Repeat([]byte("0123456789"), 500)
	mux := http.NewServeMux()
	mux.HandleFunc("/up", func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		time.Sleep(20 * time.Millisecond)
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(strings.Repeat("x", 100)))
		w.Write([]byte(strings.Repeat("y", 200)))
	})
	mux.HandleFunc("/file", func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "f.bin", time.Unix(0, 0), bytes.NewReader(content))
	})
	mux.HandleFunc("/stream", func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)
		if err := rc.Flush(); err != nil {
			t.Errorf("flush: %v", err)
		}
		time.Sleep(30 * time.Millisecond)
		w.Write([]byte("late"))
	})
	h := NewServer(mux).Handler

	for _, h2 := range []bool{false, true} {
		srv := httptest.NewUnstartedServer(h)
		srv.EnableHTTP2 = h2
		srv.StartTLS()
		c := srv.Client()
		c.Transport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		c.Transport.(*http.Transport).ForceAttemptHTTP2 = h2
		os.Truncate(logPath, 0)

		resp, err := c.Post(srv.URL+"/up?id=abc&n=3", "application/octet-stream", bytes.NewReader(make([]byte, 1000)))
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/file", nil)
		req.Header.Set("Range", "bytes=100-1099")
		resp, err = c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		resp, err = c.Get(srv.URL + "/file")
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		resp, err = c.Get(srv.URL + "/stream")
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		srv.Close()

		es := readEntries(t, logPath, 4)
		proto := "HTTP/1.1"
		if h2 {
			proto = "HTTP/2.0"
		}
		up, part, whole, stream := es[0], es[1], es[2], es[3]
		if up.Method != "POST" || up.Path != "/up" || up.Query != "id=abc&n=3" || up.Status != 201 || up.In != 1000 || up.Out != 300 || up.Proto != proto {
			t.Errorf("%s upload: %+v", proto, up)
		}
		if up.FirstMS < 20 || up.TotalMS < up.FirstMS || up.Remote == "" || up.Start.IsZero() {
			t.Errorf("%s upload times: %+v", proto, up)
		}
		if part.Status != http.StatusPartialContent || part.Out != 1000 || part.In != 0 {
			t.Errorf("%s range: %+v", proto, part)
		}
		if whole.Status != 200 || whole.Out != int64(len(content)) {
			t.Errorf("%s download: %+v", proto, whole)
		}
		if stream.Status != 200 || stream.Out != 4 || stream.FirstMS > 25 || stream.TotalMS < 30 {
			t.Errorf("%s flushed stream: %+v", proto, stream)
		}
	}
}

// A request the client gives up on is logged as cut short.
func TestTheRequestLogMarksACanceledRequest(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "requests.jsonl")
	benchSettings(t, benchmode.EnvRequestLog, logPath)
	got := make(chan bool)
	h := NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(got)
		<-r.Context().Done()
	})).Handler
	srv := httptest.NewServer(h)
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/slow", nil)
	go func() {
		<-got
		srv.CloseClientConnections()
	}()
	http.DefaultClient.Do(req)
	es := readEntries(t, logPath, 1)
	if !es[0].Canceled || es[0].Path != "/slow" {
		t.Errorf("%+v", es[0])
	}
}

// The log changes nothing the server does: a request without a body keeps
// http.NoBody, so the stall limit leaves a slow download alone, and the limit
// still reaches the connection through the log's writer to cut a stalled body.
func TestTheRequestLogLeavesTheStallLimitAlone(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "requests.jsonl")
	benchSettings(t, benchmode.EnvRequestLog, logPath)
	slowErr, bodyErr := make(chan error, 1), make(chan error, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		if r.Body != http.NoBody {
			t.Errorf("a GET's body is %T", r.Body)
		}
		time.Sleep(300 * time.Millisecond)
		slowErr <- r.Context().Err()
		w.Write([]byte("done"))
	})
	mux.HandleFunc("/body", func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		bodyErr <- err
	})
	srv := httptest.NewServer(NewServer(limitBodyStalls(100*time.Millisecond, mux)).Handler)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/slow")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if err := <-slowErr; err != nil {
		t.Errorf("the slow download's request ended: %v", err)
	}

	pr, pw := io.Pipe()
	go func() {
		pw.Write([]byte("start"))
		time.Sleep(time.Second)
		pw.Close()
	}()
	if resp, err := http.Post(srv.URL+"/body", "application/octet-stream", pr); err == nil {
		resp.Body.Close()
	}
	select {
	case err := <-bodyErr:
		if err == nil {
			t.Error("a stalled body was read to its end: the stall limit didn't reach the connection")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the stalled body's handler never returned")
	}
	es := readEntries(t, logPath, 2)
	if es[0].Path != "/slow" || es[0].Canceled || es[0].Status != 200 || es[0].Out != 4 {
		t.Errorf("the slow download's entry: %+v", es[0])
	}
}

// A handler that writes nothing answers 200; one that writes without
// WriteHeader sends its header with its first byte.
func TestTheRequestLogsStatusAndFirstByteWithoutWriteHeader(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "requests.jsonl")
	benchSettings(t, benchmode.EnvRequestLog, logPath)
	mux := http.NewServeMux()
	mux.HandleFunc("/nothing", func(w http.ResponseWriter, r *http.Request) {})
	mux.HandleFunc("/hints", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", "</x.css>; rel=preload")
		w.WriteHeader(http.StatusEarlyHints)
		w.WriteHeader(http.StatusCreated)
	})
	mux.HandleFunc("/late", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(30 * time.Millisecond)
		w.Write([]byte("x"))
	})
	srv := httptest.NewServer(NewServer(mux).Handler)
	defer srv.Close()
	for _, p := range []string{"/nothing", "/late", "/hints"} {
		resp, err := http.Get(srv.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	es := readEntries(t, logPath, 3)
	if es[2].Status != 201 {
		t.Errorf("an informational answer before the status: %+v", es[2])
	}
	if es[0].Status != 200 || es[0].Out != 0 {
		t.Errorf("nothing written: %+v", es[0])
	}
	if es[1].Status != 200 || es[1].FirstMS < 30 || es[1].Out != 1 {
		t.Errorf("written without WriteHeader: %+v", es[1])
	}
}

// readFromWriter is a ResponseWriter that copies with ReadFrom, as net/http's
// does for sendfile.
type readFromWriter struct {
	httptest.ResponseRecorder
	readFrom bool
}

func (w *readFromWriter) ReadFrom(r io.Reader) (int64, error) {
	w.readFrom = true
	return io.Copy(&w.ResponseRecorder, r)
}

func TestTheLogsWriterPassesReadFromOn(t *testing.T) {
	inner := &readFromWriter{ResponseRecorder: *httptest.NewRecorder()}
	cw := &countingWriter{ResponseWriter: inner}
	n, err := io.Copy(cw, struct{ io.Reader }{strings.NewReader("twelve bytes")})
	if err != nil || n != 12 || cw.n != 12 || !inner.readFrom || cw.status != 200 || cw.first.IsZero() {
		t.Errorf("copied %d, %v; counted %d, ReadFrom used %v, status %d", n, err, cw.n, inner.readFrom, cw.status)
	}
	plain := &countingWriter{ResponseWriter: httptest.NewRecorder()}
	if n, err := io.Copy(plain, struct{ io.Reader }{strings.NewReader("four")}); err != nil || n != 4 || plain.n != 4 {
		t.Errorf("without ReadFrom: %d, %v, counted %d", n, err, plain.n)
	}
}
