package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"unicode"
	"unicode/utf8"

	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/transfer"
)

// UploadService is the resumable upload engine. transfer.Engine implements
// it.
type UploadService interface {
	// Ready refuses calls before their request is read, while the engine is
	// off or closing.
	Ready() error
	Create(ctx context.Context, req transfer.CreateRequest) (transfer.Created, error)
	Part(ctx context.Context, req transfer.PartRequest) (transfer.PartResult, error)
	Status(ctx context.Context, id string, hashes []int) (transfer.Status, error)
	Complete(ctx context.Context, id, composite string) (transfer.Result, error)
	Abort(ctx context.Context, id string) (transfer.AbortResult, error)
	List(ctx context.Context, all bool) ([]transfer.Status, error)
}

// PartChecksumHeader carries the SHA-256 of a part's body, as 64 lowercase
// hex characters.
const PartChecksumHeader = "Upload-Part-SHA256"

// uploadCreateRequest is transfer.CreateRequest with its size required: a
// client that left it out would otherwise upload an empty file.
type uploadCreateRequest struct {
	Dir       string `json:"dir"`
	Name      string `json:"name"`
	Size      *int64 `json:"size"`
	ClientKey string `json:"clientKey,omitempty"`
}

type UploadStatusRequest struct {
	UploadID string `json:"uploadId"`
	Hashes   []int  `json:"hashes"`
}

type UploadCompleteRequest struct {
	UploadID        string `json:"uploadId"`
	CompositeSHA256 string `json:"compositeSha256"`
}

type UploadAbortRequest struct {
	UploadID string `json:"uploadId"`
}

type UploadListResponse struct {
	Uploads []transfer.Status `json:"uploads"`
}

// uploadErrorResponse is the error envelope with what a client needs to go
// on: the parts still missing, or the state an upload ended in.
type uploadErrorResponse struct {
	ErrorResponse
	Missing []transfer.Range `json:"missing,omitempty"`
	State   transfer.State   `json:"state,omitempty"`
}

func (a *api) uploadRoutes() []route {
	return []route{
		{"/api/upload/create", accessUploads, a.track(http.HandlerFunc(a.handleUploadCreate))},
		{"/api/upload/part", accessUploads, a.track(http.HandlerFunc(a.handleUploadPart))},
		{"/api/upload/status", accessUploads, a.track(http.HandlerFunc(a.handleUploadStatus))},
		{"/api/upload/complete", accessUploads, a.track(http.HandlerFunc(a.handleUploadComplete))},
		{"/api/upload/abort", accessUploads, a.track(http.HandlerFunc(a.handleUploadAbort))},
		{"/api/upload/list", accessUploads, a.track(http.HandlerFunc(a.handleUploadList))},
	}
}

// engineOn answers 503 when the server runs without the upload engine, or
// with one that is off or closing.
func (a *api) engineOn(w http.ResponseWriter, r *http.Request) bool {
	var err error = transfer.ErrUnavailable
	if a.uploads != nil {
		err = a.uploads.Ready()
	}
	if err != nil {
		writeUploadError(w, r, err)
		return false
	}
	return true
}

func (a *api) handleUploadCreate(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) || !a.engineOn(w, r) {
		return
	}
	var req uploadCreateRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Size == nil {
		writeErrorJSON(w, r, http.StatusBadRequest, "invalid_body", "The request gives no size")
		return
	}
	c, err := a.uploads.Create(r.Context(), transfer.CreateRequest{Dir: req.Dir, Name: req.Name, Size: *req.Size, ClientKey: req.ClientKey})
	if err != nil {
		writeUploadError(w, r, err)
		return
	}
	status := http.StatusCreated
	if c.Resumed {
		status = http.StatusOK
	}
	writeJSON(w, status, c)
}

func (a *api) handleUploadPart(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) || !a.engineOn(w, r) ||
		!requireContentType(w, r, "application/octet-stream") {
		return
	}
	q := r.URL.Query()
	// A number that doesn't parse reaches the engine as -1, which it refuses
	// and records, so the record tells it from a part 0 that was sent.
	n, err := strconv.Atoi(q.Get("n"))
	if err != nil {
		n = -1
	}
	res, err := a.uploads.Part(r.Context(), transfer.PartRequest{
		ID:     q.Get("id"),
		N:      n,
		SHA256: r.Header.Get(PartChecksumHeader),
		Length: r.ContentLength,
		Body:   r.Body,
	})
	if err != nil {
		writeUploadError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (a *api) handleUploadStatus(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) || !a.engineOn(w, r) {
		return
	}
	var req UploadStatusRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	st, err := a.uploads.Status(r.Context(), req.UploadID, req.Hashes)
	if err != nil {
		writeUploadError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (a *api) handleUploadComplete(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) || !a.engineOn(w, r) {
		return
	}
	var req UploadCompleteRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	res, err := a.uploads.Complete(r.Context(), req.UploadID, req.CompositeSHA256)
	if err != nil && !events.IsUnrecorded(err) {
		writeUploadError(w, r, err)
		return
	}
	reply(w, r, http.StatusCreated, res, err)
}

func (a *api) handleUploadAbort(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) || !a.engineOn(w, r) {
		return
	}
	var req UploadAbortRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	res, err := a.uploads.Abort(r.Context(), req.UploadID)
	if err != nil {
		writeUploadError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (a *api) handleUploadList(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) || !a.engineOn(w, r) {
		return
	}
	list, err := a.uploads.List(r.Context(), r.URL.Query().Get("all") == "1")
	if err != nil {
		writeUploadError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, UploadListResponse{Uploads: list})
}

// writeUploadError answers an error of the engine with the status and code
// it carries; refusals of the file service and the ledger, which the engine
// passes on, are answered as for any other file operation.
func writeUploadError(w http.ResponseWriter, r *http.Request, err error) {
	var missing *transfer.MissingError
	var closed *transfer.ClosedError
	var te *transfer.Error
	switch {
	case errors.As(err, &missing):
		writeErrorBody(w, transfer.ErrPartsMissing.Status, uploadErrorResponse{
			ErrorResponse: envelope(r, transfer.ErrPartsMissing.Code, upperFirst(missing.Error())),
			Missing:       missing.Missing,
		})
	case errors.As(err, &closed):
		writeErrorBody(w, transfer.ErrClosed.Status, uploadErrorResponse{
			ErrorResponse: envelope(r, transfer.ErrClosed.Code, fmt.Sprintf("The upload has ended: %s", closed.State)),
			State:         closed.State,
		})
	case errors.As(err, &te):
		if te == transfer.ErrBusy || te == transfer.ErrTooManyRequests {
			w.Header().Set("Retry-After", "1")
		}
		// The engine's own message, not err's, which may name staging files.
		writeErrorJSON(w, r, te.Status, te.Code, upperFirst(te.Error()))
	default:
		writeError(w, r, err)
	}
}

func envelope(r *http.Request, code, message string) ErrorResponse {
	return ErrorResponse{Error: ErrorBody{Code: code, Message: message}, RequestID: events.RequestIDFrom(r.Context())}
}

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	c, n := utf8.DecodeRuneInString(s)
	return string(unicode.ToUpper(c)) + s[n:]
}
