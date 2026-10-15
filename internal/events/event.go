// Package events defines the events emitted for every file operation and the
// in-process bus that carries them to subscribers such as the audit log.
package events

import "time"

type Type string

const (
	FileListed      Type = "file.listed"
	FileDownloaded  Type = "file.downloaded"
	FileChecked     Type = "file.checked"
	FileUploaded    Type = "file.uploaded"
	FolderCreated   Type = "folder.created"
	FileMoved       Type = "file.moved"
	FileDeleted     Type = "file.deleted"
	FileReadSummary Type = "file.read_summary"

	AuthSetupCompleted   Type = "auth.setup_completed"
	AuthLogin            Type = "auth.login"
	AuthLoginSummary     Type = "auth.login_summary"
	AuthLogout           Type = "auth.logout"
	AuthPasswordChanged  Type = "auth.password_changed"
	AuthPasswordDisabled Type = "auth.password_disabled"
	SessionRevoked       Type = "session.revoked"
	UserCreated          Type = "user.created"
)

type Outcome string

const (
	OutcomeOK       Outcome = "ok"
	OutcomeNotFound Outcome = "not_found"
	OutcomeExists   Outcome = "exists"
	OutcomeInvalid  Outcome = "invalid"
	OutcomeDenied   Outcome = "denied"  // blocked by the sandbox or the OS
	OutcomeAborted  Outcome = "aborted" // a transfer that stopped early
	OutcomeNoSpace  Outcome = "no_space"
	OutcomeError    Outcome = "error"
)

// Actor IDs that are not user IDs. No username may take these names.
const (
	AnonymousID = "anonymous"
	ConsoleID   = "console" // the gocalbox command run from a shell, such as "users add"
	SystemID    = "system"  // the server acting on its own, such as at start-up
)

type Actor struct {
	ID         string `json:"id"`
	Name       string `json:"name,omitempty"` // username at the time of the event
	Role       string `json:"role,omitempty"`
	RemoteAddr string `json:"remote_addr,omitempty"`
	Session    string `json:"session,omitempty"` // the session's ID, which stays the same when its token is renewed
}

type Event struct {
	Seq  uint64    `json:"seq"`
	Time time.Time `json:"time"`

	Type      Type    `json:"type"`
	Actor     Actor   `json:"actor"`
	RequestID string  `json:"request_id,omitempty"`
	Outcome   Outcome `json:"outcome"`

	Path           string `json:"path,omitempty"`
	Target         string `json:"target,omitempty"`
	Resolved       string `json:"resolved,omitempty"`
	ResolvedTarget string `json:"resolved_target,omitempty"`

	Size  int64  `json:"size,omitempty"`
	Range string `json:"range,omitempty"`

	Count   int       `json:"count,omitempty"`
	Aborted int       `json:"aborted,omitempty"`
	Since   time.Time `json:"since,omitzero"`

	Detail string `json:"detail,omitempty"`

	// Ack, when set, is told whether the event's record reached the disk.
	Ack *Ack `json:"-"`
}
