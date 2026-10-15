package httpapi

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/nobletk/gocalbox/internal/fsops"
	"github.com/nobletk/gocalbox/internal/sandbox"
)

type failingService struct {
	FileService
	err      error
	sizeHint int64
}

func (f *failingService) Create(_ context.Context, _, _ string, r io.Reader, sizeHint int64) (string, int64, error) {
	f.sizeHint = sizeHint
	return "", 0, f.err
}

func (f *failingService) Move(context.Context, string, string) (string, error) { return "", f.err }

func newFailingServer(t *testing.T, err error, opts ...Options) (*httptest.Server, *failingService) {
	t.Helper()
	var o Options
	if len(opts) > 0 {
		o = opts[0]
	}
	sb, serr := sandbox.New(t.TempDir())
	if serr != nil {
		t.Fatal(serr)
	}
	t.Cleanup(func() { sb.Close() })
	svc := &failingService{FileService: adminFiles(sb, nil), err: err}
	srv := httptest.NewServer(newTestHandler(svc, fstest.MapFS{}, o))
	t.Cleanup(srv.Close)
	return srv, svc
}

func multipartBody(name, content string) (*bytes.Buffer, string) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	w, _ := mw.CreateFormFile("myFile", name)
	io.WriteString(w, content)
	mw.Close()
	return &buf, mw.FormDataContentType()
}

func TestLackOfSpaceIs507(t *testing.T) {
	srv, svc := newFailingServer(t, fmt.Errorf("write file: %w", fsops.ErrInsufficientStorage))
	body, ctype := multipartBody("big.bin", strings.Repeat("x", 1000))
	length := int64(body.Len())

	resp, err := http.Post(srv.URL+"/api/upload", ctype, body)
	if err != nil {
		t.Fatal(err)
	}
	want(t, resp.StatusCode, http.StatusInsufficientStorage, "upload without room")
	if er := readErr(t, resp); er.Error.Code != "insufficient_storage" {
		t.Errorf("code %q", er.Error.Code)
	}
	if svc.sizeHint != length {
		t.Errorf("size hint %d, want the request length %d", svc.sizeHint, length)
	}
}

func TestChunkedUploadHasNoSizeHint(t *testing.T) {
	srv, svc := newFailingServer(t, fsops.ErrInsufficientStorage)
	body, ctype := multipartBody("a.bin", "abc")
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/upload", io.NopCloser(body))
	req.Header.Set("Content-Type", ctype)
	req.ContentLength = -1
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if svc.sizeHint != -1 {
		t.Errorf("size hint %d for a chunked body, want -1", svc.sizeHint)
	}
}

func TestMoveAcrossFileSystemsIs409(t *testing.T) {
	srv, _ := newFailingServer(t, fmt.Errorf("rename: %w", fsops.ErrCrossDevice))
	resp, err := http.Post(srv.URL+"/api/fs/move", "application/json", strings.NewReader(`{"oldPath":"a","newPath":"mnt/a"}`))
	if err != nil {
		t.Fatal(err)
	}
	want(t, resp.StatusCode, http.StatusConflict, "move across file systems")
	if er := readErr(t, resp); er.Error.Code != "cross_device" {
		t.Errorf("code %q", er.Error.Code)
	}
}

func TestSizeHintNeverExceedsTheUploadLimit(t *testing.T) {
	srv, svc := newFailingServer(t, fsops.ErrInsufficientStorage, Options{MaxUploadBytes: 1000})
	body, ctype := multipartBody("big.bin", strings.Repeat("x", 5000))
	resp, err := http.Post(srv.URL+"/api/upload", ctype, body)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if svc.sizeHint != 1000 {
		t.Errorf("size hint %d, want the 1000-byte upload limit", svc.sizeHint)
	}
}

func TestReadOnlyFileSystemIs403(t *testing.T) {
	srv, _ := newFailingServer(t, fmt.Errorf("create file: %w", fsops.ErrReadOnly))
	body, ctype := multipartBody("a.bin", "abc")
	resp, err := http.Post(srv.URL+"/api/upload", ctype, body)
	if err != nil {
		t.Fatal(err)
	}
	want(t, resp.StatusCode, http.StatusForbidden, "upload into a read-only folder")
	er := readErr(t, resp)
	if er.Error.Code != "permission_denied" || !strings.Contains(er.Error.Message, "read-only") {
		t.Errorf("error %+v", er.Error)
	}
}
