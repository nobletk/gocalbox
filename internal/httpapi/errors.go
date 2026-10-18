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
	"strconv"
	"strings"
	"time"

	"github.com/nobletk/gocalbox/internal/auth"
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
	writeErrorResult(w, r, status, code, message, nil)
}

func writeErrorResult(w http.ResponseWriter, r *http.Request, status int, code, message string, result any) {
	writeErrorBody(w, status, ErrorResponse{
		Error:     ErrorBody{Code: code, Message: message},
		RequestID: events.RequestIDFrom(r.Context()),
		Result:    result,
	})
}

// writeErrorBody answers with an error envelope, or one with more fields.
func writeErrorBody(w http.ResponseWriter, status int, body any) {
	for _, h := range []string{"Content-Disposition", "Content-Security-Policy", "Content-Encoding", "Content-Length"} {
		w.Header().Del(h)
	}
	writeJSON(w, status, body)
}

// reply answers a change with v, or, if the change was made but its record
// is missing (err), with the error and v as its result, so the client knows
// the change exists and doesn't repeat it.
func reply(w http.ResponseWriter, r *http.Request, status int, v any, err error) {
	if err == nil {
		writeJSON(w, status, v)
		return
	}
	log.Printf("AUDIT ERROR: %s %s: %v", r.Method, r.URL.Path, err)
	if errors.Is(err, events.ErrNotConfirmed) {
		writeErrorResult(w, r, http.StatusInternalServerError, "not_confirmed",
			"The change was made, but its record in the audit log was not confirmed in time", v)
		return
	}
	writeErrorResult(w, r, http.StatusInternalServerError, "not_recorded",
		"The change was made, but it could not be recorded in the audit log", v)
}

func writeError(w http.ResponseWriter, r *http.Request, err error) {
	var tooBig *http.MaxBytesError
	var weak *auth.WeakPasswordError
	var layout *auth.LayoutExistsError
	var tooMany *auth.TooManyAttemptsError

	switch {
	case events.IsUnrecorded(err):
		reply(w, r, 0, nil, err)
	case errors.Is(err, events.ErrChangesPaused):
		writeErrorJSON(w, r, http.StatusServiceUnavailable, "changes_paused",
			"Changes are paused because the audit log failed; reading still works. The server's operator has to look at it and restart the server")
	case errors.Is(err, sandbox.ErrReserved):
		writeErrorJSON(w, r, http.StatusForbidden, "reserved_path", "This name is reserved for the server")
	case errors.Is(err, fsops.ErrForbidden):
		writeErrorJSON(w, r, http.StatusForbidden, "forbidden", "You may not do this here")
	case errors.Is(err, fsops.ErrBoundFolder):
		writeErrorJSON(w, r, http.StatusConflict, "bound_folder",
			"This folder is shared with users, or holds one that is, so it can't be moved or deleted")
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
	case errors.Is(err, fsops.ErrUploadMoved):
		writeErrorJSON(w, r, http.StatusConflict, "upload_moved", "The file was moved or deleted while it was uploaded")
	case errors.Is(err, fsops.ErrCrossDevice):
		writeErrorJSON(w, r, http.StatusConflict, "cross_device", "Source and destination are on different file systems")
	case errors.Is(err, fsops.ErrInsufficientStorage):
		log.Printf("Refused for lack of space: %v", err)
		writeErrorJSON(w, r, http.StatusInsufficientStorage, "insufficient_storage", "Not enough free space on the server")

	case errors.Is(err, auth.ErrLinkInvalid):
		log.Printf("SECURITY ALERT: Unknown, used, expired or revoked link token from %s", r.RemoteAddr)
		writeErrorJSON(w, r, http.StatusForbidden, "link_invalid", "This link is unknown, used, expired or revoked; ask an admin for a new one")
	case errors.Is(err, auth.ErrNotAdmin):
		writeErrorJSON(w, r, http.StatusForbidden, "forbidden", "Only admins may do this")
	case errors.Is(err, auth.ErrReauthRequired):
		writeErrorJSON(w, r, http.StatusForbidden, "reauth_required", "Enter your password again to change users and folder access")
	case errors.Is(err, auth.ErrLastAdmin):
		writeErrorJSON(w, r, http.StatusConflict, "last_admin", "The last enabled admin can't be deleted, disabled or demoted")
	case errors.Is(err, auth.ErrTooManyLinks):
		writeErrorJSON(w, r, http.StatusConflict, "too_many_links", "There are 100 unused links; revoke some first")
	case errors.Is(err, auth.ErrUserDisabled):
		writeErrorJSON(w, r, http.StatusConflict, "user_disabled", "The account is disabled; enable it first")
	case errors.Is(err, auth.ErrHomeBinding):
		writeErrorJSON(w, r, http.StatusConflict, "home_binding", "A home's binding goes only with its user")
	case errors.Is(err, auth.ErrCoversHomes):
		writeErrorJSON(w, r, http.StatusConflict, "covers_homes", "A binding may not cover /users, a home or the root")
	case errors.Is(err, auth.ErrBindingExists):
		writeErrorJSON(w, r, http.StatusConflict, "already_exists", "This user already has a binding on this folder")
	case errors.Is(err, auth.ErrNoSuchUser):
		writeErrorJSON(w, r, http.StatusNotFound, "not_found", "No such user")
	case errors.Is(err, auth.ErrNoSuchLink):
		writeErrorJSON(w, r, http.StatusNotFound, "not_found", "No such unused link")
	case errors.Is(err, auth.ErrNoSuchBinding):
		writeErrorJSON(w, r, http.StatusNotFound, "not_found", "No such binding")
	case errors.Is(err, auth.ErrInvalidRole):
		writeErrorJSON(w, r, http.StatusBadRequest, "invalid_role", "The role must be admin, contributor or viewer; a binding's viewer or contributor")
	case errors.Is(err, auth.ErrInvalidNote):
		writeErrorJSON(w, r, http.StatusBadRequest, "invalid_note", "A note has at most 100 characters and no control characters")
	case errors.Is(err, auth.ErrSetupCodeInvalid):
		log.Printf("SECURITY ALERT: Wrong setup code from %s", r.RemoteAddr)
		writeErrorJSON(w, r, http.StatusForbidden, "setup_code_invalid", "Wrong setup code")
	case errors.Is(err, auth.ErrSetupDone):
		writeErrorJSON(w, r, http.StatusConflict, "setup_done", "Setup is already complete")
	case errors.As(err, &layout):
		writeErrorJSON(w, r, http.StatusConflict, "layout_exists", fmt.Sprintf(
			"These folders already exist: %s. Move them aside, or repeat the request with useExisting set to true "+
				"to keep them; /public then becomes readable by every user", strings.Join(layout.Paths, ", ")))
	case errors.Is(err, auth.ErrHomeExists):
		writeErrorJSON(w, r, http.StatusConflict, "home_exists", "A folder with this username already exists in /users; choose another username")
	case errors.Is(err, auth.ErrInvalidUsername):
		writeErrorJSON(w, r, http.StatusBadRequest, "invalid_username",
			"Usernames have 3 to 32 characters from a-z, 0-9, '.', '_' and '-', and start and end with a letter or digit")
	case errors.Is(err, auth.ErrUsernameTaken):
		writeErrorJSON(w, r, http.StatusConflict, "username_taken", "This username is taken")
	case errors.As(err, &weak):
		writeErrorJSON(w, r, http.StatusBadRequest, "weak_password", "Password refused: "+weak.Message)
	case errors.Is(err, auth.ErrInvalidCredentials):
		writeErrorJSON(w, r, http.StatusUnauthorized, "invalid_credentials", "Wrong username or password")
	case errors.Is(err, auth.ErrAccountDisabled):
		writeErrorJSON(w, r, http.StatusForbidden, "account_disabled", "This account is disabled")
	case errors.Is(err, auth.ErrPasswordDisabled):
		writeErrorJSON(w, r, http.StatusForbidden, "password_disabled",
			"The password was disabled after too many failed attempts; ask an admin for a reset link")
	case errors.As(err, &tooMany) && tooMany.RetryAfter > 0:
		secs := int((tooMany.RetryAfter + time.Second - 1) / time.Second)
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		writeErrorJSON(w, r, http.StatusTooManyRequests, "too_many_attempts",
			fmt.Sprintf("Too many failed attempts; try again in %d seconds", secs))
	case errors.As(err, &tooMany):
		writeErrorJSON(w, r, http.StatusTooManyRequests, "too_many_attempts",
			"Too many failed attempts on this account from browsers it was never used in; "+
				"log in from a browser you used before, or ask an admin for a reset link")
	case errors.Is(err, auth.ErrTooManyWrongPasswords):
		writeErrorJSON(w, r, http.StatusUnauthorized, "unauthenticated", "Five wrong passwords in a row ended the session; log in again")
	case errors.Is(err, auth.ErrSessionEnded):
		writeErrorJSON(w, r, http.StatusUnauthorized, "unauthenticated", "The session has ended; log in again")
	case errors.Is(err, auth.ErrNoSuchSession):
		writeErrorJSON(w, r, http.StatusNotFound, "not_found", "No such session")
	case errors.Is(err, auth.ErrBusy):
		writeErrorJSON(w, r, http.StatusServiceUnavailable, "busy", "The server is busy; try again in a moment")

	case errors.As(err, &tooBig):
		log.Printf("Request body rejected: larger than %d bytes", tooBig.Limit)
		writeErrorJSON(w, r, http.StatusRequestEntityTooLarge, "too_large", "Request body too large")
	case errors.Is(err, fsops.ErrReadOnly):
		log.Printf("Refused on a read-only file system: %v", err)
		writeErrorJSON(w, r, http.StatusForbidden, "permission_denied", "The folder is on a read-only file system")
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
