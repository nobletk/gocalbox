package transfer

import (
	"errors"
	"fmt"

	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/space"
)

// Error is a refusal the upload protocol names with a code of its own, and
// the HTTP status it answers with. Refusals from Files and the ledger keep
// their own errors.
type Error struct {
	Status int
	Code   string
	msg    string
}

func (e *Error) Error() string { return e.msg }

var (
	ErrUnavailable       = &Error{503, "uploads_unavailable", "resumable uploads are turned off on this server"}
	ErrShuttingDown      = &Error{503, "unavailable", "the server is shutting down; try again once it is back"}
	ErrInvalidRequest    = &Error{400, "invalid_body", "invalid upload request"}
	ErrInvalidPart       = &Error{400, "invalid_part", "invalid upload ID or part number"}
	ErrMissingChecksum   = &Error{400, "missing_checksum", "the part's SHA-256 is missing or malformed"}
	ErrChecksumMismatch  = &Error{400, "checksum_mismatch", "the data doesn't match its SHA-256"}
	ErrPartSizeMismatch  = &Error{400, "part_size_mismatch", "the part's length is not the one its number calls for"}
	ErrUploadNotFound    = &Error{404, "upload_not_found", "no such upload"}
	ErrNoAccount         = &Error{404, "not_found", "not found"}
	ErrPartInProgress    = &Error{409, "part_in_progress", "this part is being received already"}
	ErrPartConflict      = &Error{409, "part_conflict", "this part was received with another SHA-256; the file changed"}
	ErrPartsMissing      = &Error{409, "parts_missing", "parts are missing"}
	ErrPartsInFlight     = &Error{409, "parts_in_flight", "parts are still being received"}
	ErrCompleting        = &Error{409, "upload_completing", "the upload is being completed"}
	ErrClosed            = &Error{409, "upload_closed", "the upload has ended"}
	ErrTooLarge          = &Error{413, "too_large", "the file is larger than this server accepts"}
	ErrTooLargeForVolume = &Error{413, "too_large_for_volume", "the file is larger than the folder's file system can hold"}
	ErrTooManyUploads    = &Error{429, "too_many_uploads", "too many uploads are open for this user"}
	ErrTooManyRequests   = &Error{429, "too_many_requests", "too many parts are being sent at once"}
	ErrBusy              = &Error{503, "busy", "the server is busy; try again in a moment"}
	ErrPartAborted       = &Error{400, "part_aborted", "the part's body ended early or stalled"}
)

// MissingError is ErrPartsMissing with the parts that are missing.
type MissingError struct {
	Missing []Range
}

func (e *MissingError) Error() string {
	return fmt.Sprintf("%s: %d of them", ErrPartsMissing.msg, countRanges(e.Missing))
}

func (e *MissingError) Unwrap() error { return ErrPartsMissing }

// ClosedError is ErrClosed with the state the upload ended in.
type ClosedError struct {
	State  State
	Reason string
}

func (e *ClosedError) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("the upload is %s (%s)", e.State, e.Reason)
	}
	return fmt.Sprintf("the upload is %s", e.State)
}

func (e *ClosedError) Unwrap() error { return ErrClosed }

func closed(s State, reason string) error { return &ClosedError{State: s, Reason: reason} }

// noSpace marks a write the file system refused for lack of space, so that
// it answers like a refusal of the ledger.
func noSpace(err error) error { return fmt.Errorf("%w: %v", space.ErrInsufficient, err) }

// outcome classifies the engine's own refusals for the audit log; other
// errors are classified by Files.
func (e *Engine) outcome(err error) events.Outcome {
	var te *Error
	switch {
	case err == nil:
		return events.OutcomeOK
	case errors.Is(err, space.ErrInsufficient):
		return events.OutcomeNoSpace
	case errors.Is(err, events.ErrChangesPaused):
		return events.OutcomeDenied
	case errors.Is(err, ErrUploadNotFound), errors.Is(err, ErrNoAccount):
		return events.OutcomeNotFound
	case errors.Is(err, ErrPartAborted):
		return events.OutcomeAborted
	case errors.As(err, &te):
		return events.OutcomeInvalid
	}
	return e.files.Outcome(err)
}
