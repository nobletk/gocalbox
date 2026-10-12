package httpapi

import (
	"fmt"
	"io"
	"mime"
	"net/http"
	"path"
	"strings"

	"github.com/nobletk/gocalbox/internal/fsops"
)

// Without "allow-scripts" the sandbox keeps any script in a file from
// running. Types shown inline keep their origin: a browser's media player
// fetches the file again, and from an opaque origin that request would be
// cross-site and refused by CORP and isolateResources.
const (
	fileCSPRules  = "default-src 'none'; img-src 'self' data:; media-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'self'"
	fileCSP       = "sandbox; " + fileCSPRules
	inlineFileCSP = "sandbox allow-same-origin; " + fileCSPRules
)

func (a *api) handleFile(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet, http.MethodHead) {
		return
	}

	f, err := a.files.Open(r.Context(), r.URL.Path)
	if err != nil {
		writeError(w, r, err)
		return
	}
	defer f.Close()

	info := f.Info()
	h := w.Header()
	setContentHeaders(h, info.Name(), r.URL.Query().Has("download"))
	h.Set("ETag", f.ETag())
	h.Set("Cache-Control", "private, no-cache")
	// ServeContent compares an If-Range date to the second, which cannot prove
	// the client holds this version, so the whole file is sent instead.
	if ir := r.Header.Get("If-Range"); ir != "" && !isEntityTag(ir) {
		r.Header.Del("Range")
	}

	tw := &transferWriter{ResponseWriter: w, r: r}
	http.ServeContent(tw, r, info.Name(), info.ModTime(), f.Content())
	f.Finish(tw.result(r))
}

func isEntityTag(v string) bool {
	return strings.HasPrefix(v, `"`) || strings.HasPrefix(v, `W/"`)
}

type fileType struct {
	ctype  string
	inline bool
}

var (
	plainText = fileType{"text/plain; charset=utf-8", true}
	unknown   = fileType{"application/octet-stream", false}
)

var fileTypes = map[string]fileType{
	".jpg": {"image/jpeg", true}, ".jpeg": {"image/jpeg", true}, ".png": {"image/png", true},
	".gif": {"image/gif", true}, ".webp": {"image/webp", true}, ".avif": {"image/avif", true},
	".bmp": {"image/bmp", true}, ".ico": {"image/x-icon", true},
	".heic": {"image/heic", true}, ".heif": {"image/heif", true},
	".svg": {"image/svg+xml", false},

	".mp3": {"audio/mpeg", true}, ".m4a": {"audio/mp4", true}, ".aac": {"audio/aac", true},
	".wav": {"audio/wav", true}, ".flac": {"audio/flac", true}, ".ogg": {"audio/ogg", true},
	".oga": {"audio/ogg", true}, ".opus": {"audio/ogg", true}, ".weba": {"audio/webm", true},

	".mp4": {"video/mp4", true}, ".m4v": {"video/mp4", true}, ".webm": {"video/webm", true},
	".ogv": {"video/ogg", true}, ".mov": {"video/quicktime", true}, ".mkv": {"video/x-matroska", true},
	".ts": {"video/mp2t", true}, ".m3u8": {"application/vnd.apple.mpegurl", false},
	".vtt": {"text/vtt; charset=utf-8", false},

	".txt": plainText, ".log": plainText, ".md": plainText, ".csv": plainText, ".tsv": plainText,
	".json": plainText, ".yaml": plainText, ".yml": plainText, ".ini": plainText, ".srt": plainText,

	".pdf": {"application/pdf", true},

	".html": {"text/html; charset=utf-8", false}, ".htm": {"text/html; charset=utf-8", false},
	".xhtml": {"application/xhtml+xml", false}, ".xml": {"application/xml", false},
	".js": {"text/javascript; charset=utf-8", false}, ".mjs": {"text/javascript; charset=utf-8", false},
	".css": {"text/css; charset=utf-8", false},

	".zip": {"application/zip", false}, ".gz": {"application/gzip", false}, ".tar": {"application/x-tar", false},
	".7z": {"application/x-7z-compressed", false}, ".epub": {"application/epub+zip", false},
	".doc": {"application/msword", false}, ".xls": {"application/vnd.ms-excel", false},
	".ppt":  {"application/vnd.ms-powerpoint", false},
	".docx": {"application/vnd.openxmlformats-officedocument.wordprocessingml.document", false},
	".xlsx": {"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", false},
	".pptx": {"application/vnd.openxmlformats-officedocument.presentationml.presentation", false},
	".odt":  {"application/vnd.oasis.opendocument.text", false},
}

func typeOf(name string) fileType {
	if ft, ok := fileTypes[strings.ToLower(path.Ext(name))]; ok {
		return ft
	}
	return unknown
}

func setContentHeaders(h http.Header, name string, forceDownload bool) {
	ft := typeOf(name)
	h.Set("Content-Type", ft.ctype)

	inline := ft.inline && !forceDownload
	disposition := "attachment"
	if inline {
		disposition = "inline"
	}
	if v := mime.FormatMediaType(disposition, map[string]string{"filename": name}); v != "" {
		disposition = v
	}
	h.Set("Content-Disposition", disposition)

	switch {
	case ft.ctype == "application/pdf": // browser PDF viewers refuse to render under a CSP sandbox
	case inline:
		h.Set("Content-Security-Policy", inlineFileCSP)
	default:
		h.Set("Content-Security-Policy", fileCSP)
	}
}

// transferWriter implements io.ReaderFrom so that http.ServeContent keeps
// using sendfile.
type transferWriter struct {
	http.ResponseWriter
	r       *http.Request
	status  int
	sent    int64
	err     error
	swallow bool
}

func (t *transferWriter) WriteHeader(code int) {
	if t.status != 0 {
		return
	}
	t.status = code
	if code >= 400 {
		t.swallow = true
		codeName, msg := "internal", "Internal server error"
		switch code {
		case http.StatusRequestedRangeNotSatisfiable:
			codeName, msg = "range_not_satisfiable", "Requested range not satisfiable"
		case http.StatusPreconditionFailed:
			codeName, msg = "precondition_failed", "Precondition failed"
		}
		writeErrorJSON(t.ResponseWriter, t.r, code, codeName, msg)
		return
	}
	t.ResponseWriter.WriteHeader(code)
}

func (t *transferWriter) Write(p []byte) (int, error) {
	if t.status == 0 {
		t.WriteHeader(http.StatusOK)
	}
	if t.swallow {
		return len(p), nil
	}
	n, err := t.ResponseWriter.Write(p)
	t.count(int64(n), err)
	return n, err
}

func (t *transferWriter) ReadFrom(src io.Reader) (int64, error) {
	if t.status == 0 {
		t.WriteHeader(http.StatusOK)
	}
	if t.swallow {
		return io.Copy(io.Discard, src)
	}
	var n int64
	var err error
	if rf, ok := t.ResponseWriter.(io.ReaderFrom); ok {
		n, err = rf.ReadFrom(src)
	} else {
		n, err = io.Copy(writerOnly{t.ResponseWriter}, src)
	}
	t.count(n, err)
	return n, err
}

func (t *transferWriter) Unwrap() http.ResponseWriter { return t.ResponseWriter }

func (t *transferWriter) count(n int64, err error) {
	t.sent += n
	if err != nil && t.err == nil {
		t.err = err
	}
}

func (t *transferWriter) result(r *http.Request) fsops.Transfer {
	tr := fsops.Transfer{
		Range:        r.Header.Get("Range"),
		MetadataOnly: r.Method == http.MethodHead || t.status == http.StatusNotModified,
	}
	switch {
	case t.status == http.StatusRequestedRangeNotSatisfiable:
		tr.Err = fsops.ErrInvalidRange
	case t.status == http.StatusPreconditionFailed:
		tr.Err = fsops.ErrPreconditionFailed
	case t.status >= 400:
		tr.Err = fmt.Errorf("status %d", t.status)
	case t.err != nil:
		tr.Sent = t.sent
		tr.Err = fmt.Errorf("%w: %v", fsops.ErrAborted, t.err)
	case r.Context().Err() != nil:
		tr.Sent = t.sent
		tr.Err = fmt.Errorf("%w: %v", fsops.ErrAborted, r.Context().Err())
	default:
		tr.Sent = t.sent
	}
	return tr
}

type writerOnly struct{ io.Writer }
