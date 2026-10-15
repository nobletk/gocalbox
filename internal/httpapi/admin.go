package httpapi

import (
	"net/http"
	"time"

	"github.com/nobletk/gocalbox/internal/auth"
	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/state"
)

// LinkTarget is what a new link's recipient needs besides its token.
type LinkTarget struct {
	// Address is the base URL other devices reach the server at, such as
	// "https://192.168.1.20:8080"; empty when none is known.
	Address string
	// CAFingerprint is the SHA-256 fingerprint of the local CA the recipient
	// installs first; empty with a certificate from -tls-cert.
	CAFingerprint string
}

type TokenRequest struct {
	Token string `json:"token"`
}

type InviteAcceptRequest struct {
	Token    string `json:"token"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type ResetAcceptRequest struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

type InviteCreateRequest struct {
	Role     string `json:"role"`
	Username string `json:"username"`
	Note     string `json:"note"`
}

type UserUpdateRequest struct {
	ID       string  `json:"id"`
	Role     *string `json:"role"`
	Disabled *bool   `json:"disabled"`
}

type IDRequest struct {
	ID string `json:"id"`
}

type BindingCreateRequest struct {
	Subject string `json:"subject"`
	Folder  string `json:"folder"`
	Role    string `json:"role"`
}

// NewLinkResponse carries a new link's token, the only time it is shown.
type NewLinkResponse struct {
	ID       string    `json:"id"`
	Kind     string    `json:"kind"`
	Token    string    `json:"token"`
	Role     string    `json:"role,omitempty"`
	Username string    `json:"username,omitempty"`
	Expires  time.Time `json:"expires"`
	// Address is null when the server knows no address for other devices;
	// the UI then asks the admin for one.
	Address       *string `json:"address"`
	CAFingerprint *string `json:"caFingerprint"`
}

type MeWithRevokedLinks struct {
	auth.Me
	RevokedLinks []auth.RevokedLink `json:"revokedLinks"`
}

type DeletedUserResponse struct {
	ArchivedHome *string `json:"archivedHome"`
}

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func (a *api) newLink(l auth.NewLink) NewLinkResponse {
	var t LinkTarget
	if a.linkTarget != nil {
		t = a.linkTarget()
	}
	return NewLinkResponse{
		ID: l.ID, Kind: string(l.Kind), Token: l.Token, Role: string(l.Role), Username: l.Username, Expires: l.Expires,
		Address: optional(t.Address), CAFingerprint: optional(t.CAFingerprint),
	}
}

func (a *api) handleInviteInspect(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var req TokenRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	info, err := a.accounts.InspectInvite(req.Token, a.client(r))
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func (a *api) handleInviteAccept(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var req InviteAcceptRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	g, err := a.accounts.AcceptInvite(r.Context(), req.Token, req.Username, req.Password, a.client(r))
	if err != nil && !events.IsUnrecorded(err) {
		writeError(w, r, err)
		return
	}
	setSessionCookies(w, g)
	reply(w, r, http.StatusCreated, g.Me, err)
}

func (a *api) handleResetInspect(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var req TokenRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	info, err := a.accounts.InspectReset(req.Token, a.client(r))
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func (a *api) handleResetAccept(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var req ResetAcceptRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	g, links, err := a.accounts.AcceptReset(r.Context(), req.Token, req.Password, a.client(r))
	if err != nil && !events.IsUnrecorded(err) {
		writeError(w, r, err)
		return
	}
	setSessionCookies(w, g)
	reply(w, r, http.StatusOK, MeWithRevokedLinks{Me: g.Me, RevokedLinks: links}, err)
}

func (a *api) handleAdminUsers(w http.ResponseWriter, r *http.Request, id auth.Identity) {
	if !requireMethod(w, r, http.MethodGet, http.MethodHead) {
		return
	}
	users, err := a.accounts.Users(id)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, users)
}

func (a *api) handleAdminInvite(w http.ResponseWriter, r *http.Request, id auth.Identity) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var req InviteCreateRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	l, err := a.accounts.CreateInvite(r.Context(), id, auth.InviteRequest{Role: state.Role(req.Role), Username: req.Username, Note: req.Note})
	if err != nil && !events.IsUnrecorded(err) {
		writeError(w, r, err)
		return
	}
	reply(w, r, http.StatusCreated, a.newLink(l), err)
}

func (a *api) handleAdminUserUpdate(w http.ResponseWriter, r *http.Request, id auth.Identity) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var req UserUpdateRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	var upd auth.UserUpdate
	if req.Role != nil {
		role := state.Role(*req.Role)
		upd.Role = &role
	}
	upd.Disabled = req.Disabled
	info, err := a.accounts.UpdateUser(r.Context(), id, req.ID, upd)
	if err != nil && !events.IsUnrecorded(err) {
		writeError(w, r, err)
		return
	}
	reply(w, r, http.StatusOK, info, err)
}

func (a *api) handleAdminResetLink(w http.ResponseWriter, r *http.Request, id auth.Identity) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var req IDRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	l, err := a.accounts.CreateResetLink(r.Context(), id, req.ID)
	if err != nil && !events.IsUnrecorded(err) {
		writeError(w, r, err)
		return
	}
	reply(w, r, http.StatusCreated, a.newLink(l), err)
}

func (a *api) handleAdminLinks(w http.ResponseWriter, r *http.Request, id auth.Identity) {
	if !requireMethod(w, r, http.MethodGet, http.MethodHead) {
		return
	}
	links, err := a.accounts.Links(id)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, links)
}

func (a *api) handleAdminLinkRevoke(w http.ResponseWriter, r *http.Request, id auth.Identity) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var req IDRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := a.accounts.RevokeLink(r.Context(), id, req.ID); err != nil {
		writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *api) handleAdminUserDelete(w http.ResponseWriter, r *http.Request, id auth.Identity) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var req IDRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	archived, err := a.accounts.DeleteUser(r.Context(), id, req.ID)
	if err != nil && !events.IsUnrecorded(err) {
		writeError(w, r, err)
		return
	}
	reply(w, r, http.StatusOK, DeletedUserResponse{ArchivedHome: optional(archived)}, err)
}

func (a *api) handleAdminBindings(w http.ResponseWriter, r *http.Request, id auth.Identity) {
	if !requireMethod(w, r, http.MethodGet, http.MethodHead) {
		return
	}
	bindings, err := a.accounts.Bindings(id)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, bindings)
}

func (a *api) handleAdminBindingCreate(w http.ResponseWriter, r *http.Request, id auth.Identity) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var req BindingCreateRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	b, err := a.accounts.CreateBinding(r.Context(), id, req.Subject, req.Folder, state.Role(req.Role))
	if err != nil && !events.IsUnrecorded(err) {
		writeError(w, r, err)
		return
	}
	reply(w, r, http.StatusCreated, b, err)
}

func (a *api) handleAdminBindingDelete(w http.ResponseWriter, r *http.Request, id auth.Identity) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var req IDRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := a.accounts.DeleteBinding(r.Context(), id, req.ID); err != nil {
		writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *api) handleAdminSessions(w http.ResponseWriter, r *http.Request, id auth.Identity) {
	if !requireMethod(w, r, http.MethodGet, http.MethodHead) {
		return
	}
	sessions, err := a.accounts.AllSessions(id, r.URL.Query().Get("user"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, sessions)
}

func (a *api) handleAdminSessionRevoke(w http.ResponseWriter, r *http.Request, id auth.Identity) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var req IDRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	err := a.accounts.EndSession(r.Context(), id, req.ID)
	if err != nil && !events.IsUnrecorded(err) {
		writeError(w, r, err)
		return
	}
	if req.ID == id.Session.ID {
		clearSessionCookie(w)
	}
	if err != nil {
		writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
