package load

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nobletk/gocalbox/internal/auth"
	"github.com/nobletk/gocalbox/internal/transfer"
)

// Remote is a server reached over HTTPS.
type Remote struct {
	URL string // https://host:port
	// CA is the PEM certificate of the server's CA, or nil to trust the
	// system's.
	CA    []byte
	HTTP1 bool // HTTP/1.1 rather than HTTP/2
}

// ErrNoAnswer is a request that got no answer from the server: the
// connection failed, or broke before the answer came.
var ErrNoAnswer = errors.New("no answer from the server")

// ErrNotConnected is a request that got no answer because no connection to
// the server could be made, so nothing of it was sent. It is an ErrNoAnswer.
var ErrNotConnected = errors.New("no connection to the server")

// Refused is an error answer of the server.
type Refused struct {
	Status  int
	Code    string
	Message string
	// RetryAfter is the wait the answer's Retry-After header asks for.
	RetryAfter time.Duration
}

func (r *Refused) Error() string { return fmt.Sprintf("%d %s: %s", r.Status, r.Code, r.Message) }

// Is matches the engine's error of the same status and code.
func (r *Refused) Is(target error) bool {
	te, ok := target.(*transfer.Error)
	return ok && te.Status == r.Status && te.Code == r.Code
}

// LogIn logs each user in with password, each over a connection of its own
// as a browser would be, and returns them, each uploading into its home.
func LogIn(ctx context.Context, r Remote, names []string, password string) ([]User, error) {
	base, err := url.Parse(r.URL)
	if err != nil || base.Scheme != "https" || base.Host == "" || strings.TrimSuffix(base.Path, "/") != "" ||
		base.User != nil || base.RawQuery != "" || base.ForceQuery || base.Fragment != "" {
		return nil, fmt.Errorf("the server's URL must be https://host:port, not %q", r.URL)
	}
	roots, err := rootsOf(r.CA)
	if err != nil {
		return nil, err
	}
	var users []User
	for _, typed := range names {
		name, err := auth.NormalizeUsername(typed)
		if err != nil {
			return nil, fmt.Errorf("user %q: %w", typed, err)
		}
		jar, _ := cookiejar.New(nil)
		a := &remote{url: "https://" + base.Host, client: &http.Client{Transport: newTransport(roots, r.HTTP1), Jar: jar}, open: map[string]bool{}}
		body, _ := json.Marshal(map[string]string{"username": name, "password": password})
		if err := a.post(ctx, "/api/auth/login", body, nil); err != nil {
			return nil, fmt.Errorf("log in as %s: %w", name, err)
		}
		users = append(users, User{API: a, Dir: auth.HomeOf(name)})
	}
	return users, nil
}

// rootsOf parses the PEM certificates of a server's CA, or returns nil, to
// trust the system's, for none.
func rootsOf(ca []byte) (*x509.CertPool, error) {
	if ca == nil {
		return nil, nil
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, errors.New("no certificate in the CA file")
	}
	return roots, nil
}

// newTransport is one user's way to the server, over HTTP/2, or HTTP/1.1
// with http1.
func newTransport(roots *x509.CertPool, http1 bool) *http.Transport {
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{RootCAs: roots},
		Protocols:           new(http.Protocols),
		TLSHandshakeTimeout: 10 * time.Second,
		// Long enough for a completion that waits for the audit log.
		ResponseHeaderTimeout: 5 * time.Minute,
		// Go keeps 2 idle connections per host by default: over HTTP/1.1,
		// more parts in flight would open a new connection for most parts.
		MaxIdleConnsPerHost: 64,
		HTTP2:               &http.HTTP2Config{SendPingTimeout: 30 * time.Second, PingTimeout: 15 * time.Second},
	}
	if http1 {
		tr.Protocols.SetHTTP1(true)
	} else {
		tr.Protocols.SetHTTP2(true)
	}
	return tr
}

// Clean deletes the files the users uploaded over HTTPS, those whose
// completion lost its answer included, and aborts every upload they have
// open, so that a repetition starts where the last one did: the load users
// are the benchmark's own. Users of the in-process stack are left alone.
func Clean(ctx context.Context, users []User) error {
	var errs []error
	for _, u := range users {
		if a, ok := u.API.(*remote); ok {
			errs = append(errs, a.clean(ctx))
		}
	}
	return errors.Join(errs...)
}

// remote is the upload protocol of one user over HTTPS.
type remote struct {
	url    string
	client *http.Client

	mu     sync.Mutex
	placed []string
	open   map[string]bool // uploads created whose completion wasn't answered
}

func (a *remote) Create(ctx context.Context, req transfer.CreateRequest) (transfer.Created, error) {
	body, _ := json.Marshal(map[string]any{"dir": req.Dir, "name": req.Name, "size": req.Size, "clientKey": req.ClientKey})
	var c transfer.Created
	if err := a.post(ctx, "/api/upload/create", body, &c); err != nil {
		return transfer.Created{}, err
	}
	a.mu.Lock()
	a.open[c.UploadID] = true
	a.mu.Unlock()
	return c, nil
}

func (a *remote) Part(ctx context.Context, req transfer.PartRequest) (transfer.PartResult, error) {
	q := url.Values{"id": {req.ID}, "n": {strconv.Itoa(req.N)}}
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, a.url+"/api/upload/part?"+q.Encode(), req.Body)
	if err != nil {
		return transfer.PartResult{}, err
	}
	hr.ContentLength = req.Length
	hr.Header.Set("Content-Type", "application/octet-stream")
	hr.Header.Set("Upload-Part-SHA256", req.SHA256)
	var res transfer.PartResult
	err = a.do(hr, &res)
	return res, err
}

func (a *remote) Complete(ctx context.Context, id, composite string) (transfer.Result, error) {
	body, _ := json.Marshal(map[string]string{"uploadId": id, "compositeSha256": composite})
	var res transfer.Result
	err := a.post(ctx, "/api/upload/complete", body, &res)
	var rf *Refused
	if err == nil || errors.As(err, &rf) && res.Path != "" {
		a.mu.Lock()
		delete(a.open, id)
		a.placed = append(a.placed, res.Path)
		a.mu.Unlock()
	}
	return res, err
}

func (a *remote) clean(ctx context.Context) error {
	a.mu.Lock()
	placed, open := a.placed, a.open
	a.placed, a.open = nil, map[string]bool{}
	a.mu.Unlock()
	var errs []error
	remove := func(p string) {
		body, _ := json.Marshal(map[string]string{"path": p})
		if err := a.post(ctx, "/api/fs/delete", body, nil); err != nil {
			errs = append(errs, fmt.Errorf("delete %s: %w", p, err))
		}
	}
	for _, p := range placed {
		remove(p)
	}
	var list struct {
		Uploads []transfer.Status `json:"uploads"`
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.url+"/api/upload/list", nil)
	if err == nil {
		err = a.do(req, &list)
	}
	if err != nil {
		return errors.Join(append(errs, fmt.Errorf("list the uploads: %w", err))...)
	}
	for _, st := range list.Uploads {
		switch {
		case st.State == transfer.Receiving:
			body, _ := json.Marshal(map[string]string{"uploadId": st.UploadID})
			if err := a.post(ctx, "/api/upload/abort", body, nil); err != nil && !errors.Is(err, transfer.ErrClosed) {
				errs = append(errs, fmt.Errorf("abort upload %s: %w", st.UploadID, err))
			}
		case st.State == transfer.Completed && open[st.UploadID] && st.Result != nil:
			remove(st.Result.Path)
		}
	}
	return errors.Join(errs...)
}

func (a *remote) post(ctx context.Context, path string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.url+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return a.do(req, out)
}

// do sends req and decodes its answer into out, an error answer's result
// too: the file a completion placed though its records are missing.
func (a *remote) do(req *http.Request, out any) error {
	resp, err := a.client.Do(req)
	if err != nil {
		if op := (*net.OpError)(nil); errors.As(err, &op) && op.Op == "dial" {
			return fmt.Errorf("%w: %w: %v", ErrNoAnswer, ErrNotConnected, err)
		}
		return fmt.Errorf("%w: %v", ErrNoAnswer, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNoAnswer, err)
	}
	if resp.StatusCode >= 300 {
		var e struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
			Result json.RawMessage `json:"result"`
		}
		json.Unmarshal(data, &e)
		if out != nil && len(e.Result) > 0 {
			json.Unmarshal(e.Result, out)
		}
		rf := &Refused{Status: resp.StatusCode, Code: e.Error.Code, Message: e.Error.Message}
		if secs, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && secs > 0 {
			rf.RetryAfter = time.Duration(secs) * time.Second
		}
		return rf
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("the server's answer to %s: %w", req.URL.Path, err)
		}
	}
	return nil
}
