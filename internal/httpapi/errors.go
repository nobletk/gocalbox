package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"mime"
	"net/http"
	"reflect"
	"strings"

	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/fsops"
	"github.com/nobletk/gocalbox/internal/sandbox"
)

const maxJSONBody = 1 << 20

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("Failed to write response: %v", err)
	}
}

func writeErrorJSON(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	for _, h := range []string{"Content-Disposition", "Content-Security-Policy", "Content-Encoding", "Content-Length"} {
		w.Header().Del(h)
	}
	writeJSON(w, status, ErrorResponse{
		Error:     ErrorBody{Code: code, Message: message},
		RequestID: events.RequestIDFrom(r.Context()),
	})
}

func writeError(w http.ResponseWriter, r *http.Request, err error) {
	var tooBig *http.MaxBytesError

	switch {
	case errors.Is(err, sandbox.ErrTraversal):
		log.Printf("SECURITY ALERT: Blocked path outside the sandbox: %v", err)
		writeErrorJSON(w, r, http.StatusForbidden, "path_outside_root", "Invalid path")
	case errors.Is(err, sandbox.ErrRootTarget):
		writeErrorJSON(w, r, http.StatusBadRequest, "root_not_allowed", "Operation not allowed on the root directory")
	case errors.Is(err, sandbox.ErrBrokenLink), errors.Is(err, sandbox.ErrInvalidPath):
		log.Printf("Rejected path: %v", err)
		writeErrorJSON(w, r, http.StatusBadRequest, "invalid_path", "Invalid path")

	case errors.Is(err, fsops.ErrNotFound):
		writeErrorJSON(w, r, http.StatusNotFound, "not_found", "Not found")
	case errors.Is(err, fsops.ErrParentNotFound):
		writeErrorJSON(w, r, http.StatusBadRequest, "parent_not_found", "Target folder does not exist")
	case errors.Is(err, fsops.ErrNotDir):
		writeErrorJSON(w, r, http.StatusBadRequest, "not_a_directory", "Not a directory")
	case errors.Is(err, fsops.ErrInvalidName):
		writeErrorJSON(w, r, http.StatusBadRequest, "invalid_name", "Invalid name")
	case errors.Is(err, fsops.ErrMoveIntoSelf):
		writeErrorJSON(w, r, http.StatusBadRequest, "move_into_self", "Cannot move a folder into itself")
	case errors.Is(err, fsops.ErrExists):
		writeErrorJSON(w, r, http.StatusConflict, "already_exists", "Already exists")

	case errors.As(err, &tooBig):
		log.Printf("Request body rejected: larger than %d bytes", tooBig.Limit)
		writeErrorJSON(w, r, http.StatusRequestEntityTooLarge, "too_large", "Request body too large")
	case errors.Is(err, fs.ErrPermission):
		log.Printf("Permission denied: %v", err)
		writeErrorJSON(w, r, http.StatusForbidden, "permission_denied", "Permission denied")

	default:
		log.Printf("Internal error: %v", err)
		writeErrorJSON(w, r, http.StatusInternalServerError, "internal", "Internal server error")
	}
}

func requireMethod(w http.ResponseWriter, r *http.Request, methods ...string) bool {
	for _, m := range methods {
		if r.Method == m {
			return true
		}
	}
	w.Header().Set("Allow", strings.Join(methods, ", "))
	writeErrorJSON(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
	return false
}

func requireContentType(w http.ResponseWriter, r *http.Request, want string) bool {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err == nil && mt == want {
		return true
	}
	writeErrorJSON(w, r, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be "+want)
	return false
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if !requireContentType(w, r, "application/json") {
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBody)
	data, err := io.ReadAll(r.Body)
	if err == nil {
		err = unmarshalStrict(data, v)
	}
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, r, err)
			return false
		}
		log.Printf("Failed to decode request body: %v", err)
		writeErrorJSON(w, r, http.StatusBadRequest, "invalid_body", "Invalid request body")
		return false
	}
	return true
}

func unmarshalStrict(data []byte, v any) error {
	allowed := jsonFieldNames(reflect.TypeOf(v).Elem())
	dec := json.NewDecoder(bytes.NewReader(data))
	if tok, err := dec.Token(); err != nil {
		return err
	} else if tok != json.Delim('{') {
		return errors.New("body is not a JSON object")
	}
	seen := make(map[string]bool, len(allowed))
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		key, _ := tok.(string)
		switch {
		case !allowed[key]:
			return fmt.Errorf("unknown field %q", key)
		case seen[key]:
			return fmt.Errorf("duplicate field %q", key)
		}
		seen[key] = true
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return err
		}
	}
	if _, err := dec.Token(); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("data after the JSON object")
	}
	return json.Unmarshal(data, v)
}

func jsonFieldNames(t reflect.Type) map[string]bool {
	names := make(map[string]bool, t.NumField())
	for i := range t.NumField() {
		f := t.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if !f.IsExported() || name == "-" {
			continue
		}
		if name == "" {
			name = f.Name
		}
		names[name] = true
	}
	return names
}
