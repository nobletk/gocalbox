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
	UserUpdated          Type = "user.updated"
	UserDeleted          Type = "user.deleted"
	InviteCreated        Type = "invite.created"
	InviteUsed           Type = "invite.used"
	ResetCreated         Type = "reset.created"
	ResetUsed            Type = "reset.used"
	LinkRevoked          Type = "link.revoked"
	BindingCreated       Type = "binding.created"
	BindingDeleted       Type = "binding.deleted"

	UploadCreated      Type = "upload.created"
	UploadPartReceived Type = "upload.part_received"
	UploadRejected     Type = "upload.rejected"
	UploadCompleted    Type = "upload.completed"
	UploadAborted      Type = "upload.aborted"
	UploadExpired      Type = "upload.expired"
	UploadFailed       Type = "upload.failed"
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

	// Upload is shared by every subscriber, so it must not change once the
	// event is published.
	Upload *UploadInfo `json:"upload,omitempty"`

	// Ack, when set, is told whether the event's record reached the disk.
	Ack *Ack `json:"-"`
}

// UploadInfo describes the upload session an upload event is about.
type UploadInfo struct {
	ID         string    `json:"id"`
	Owner      string    `json:"owner"`
	OwnerName  string    `json:"owner_name,omitempty"` // set when the actor is someone else
	Part       int       `json:"part,omitempty"`       // 0 for the session as a whole
	PartSize   int64     `json:"part_size,omitempty"`
	Parts      int       `json:"parts,omitempty"`
	Received   int       `json:"received,omitempty"`
	Retries    int       `json:"retries,omitempty"` // duplicate parts answered again
	Rejected   int       `json:"rejected,omitempty"`
	Clients    []string  `json:"clients,omitempty"` // distinct client addresses, at most 8
	Started    time.Time `json:"started,omitzero"`
	DurationMS int64     `json:"duration_ms,omitempty"`
	SHA256     string    `json:"sha256,omitempty"` // the part's hash, or the composite on a session's last event
}

// Progress reports whether ev only tells of progress, an accepted part,
// which subscribers may miss and which the audit log and the console leave
// out unless asked to keep it.
func (ev Event) Progress() bool { return ev.Type == UploadPartReceived && ev.Outcome == OutcomeOK }
