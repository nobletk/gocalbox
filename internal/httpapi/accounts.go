package httpapi

import (
	"context"
	"net/http"
	"strings"

	"github.com/nobletk/gocalbox/internal/auth"
)

type AccountService interface {
	SetupRequired() bool
	CompleteSetup(ctx context.Context, req auth.SetupRequest, c auth.Client) (auth.Grant, error)

	Login(ctx context.Context, username, password string, c auth.Client) (auth.Grant, error)
	Identify(token string) (auth.Identity, auth.SessionState)
	MeFor(id auth.Identity) auth.Me
	Logout(ctx context.Context, id auth.Identity) error
	Confirm(ctx context.Context, id auth.Identity, password string, c auth.Client) (auth.Grant, error)
	ChangePassword(ctx context.Context, id auth.Identity, current, next string, c auth.Client) (auth.Grant, []auth.RevokedLink, error)

	Sessions(id auth.Identity) []auth.SessionInfo
	RevokeSession(ctx context.Context, id auth.Identity, sessionID string) error
	RevokeOtherSessions(ctx context.Context, id auth.Identity) ([]auth.RevokedLink, error)
}

type SetupRequest struct {
	Code        string `json:"code"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	UseExisting bool   `json:"useExisting"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type ConfirmRequest struct {
	Password string `json:"password"`
}

type PasswordRequest struct {
	Current string `json:"current"`
	New     string `json:"new"`
}

type SessionRequest struct {
	ID string `json:"id"`
}

type RevokedLinksResponse struct {
	RevokedLinks []auth.RevokedLink `json:"revokedLinks"`
}

type StatusResponse struct {
	SetupRequired bool `json:"setupRequired"`
}

// Reachable without a session, and while the server has no admin yet.
var publicRoutes = map[string]bool{"/api/auth/login": true, "/api/setup": true, "/api/status": true}

func isPublic(p string) bool { return !isResourcePath(p) || publicRoutes[p] }

func requireSetupDone(accounts AccountService, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Logins work in setup mode, so the session they start can be used
		// and ended there too.
		if !isPublic(r.URL.Path) && !strings.HasPrefix(r.URL.Path, "/api/auth/") && accounts.SetupRequired() {
			writeErrorJSON(w, r, http.StatusServiceUnavailable, "setup_required",
				"The server has no admin account yet; create one with the setup code printed on the server's console")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *api) client(r *http.Request) auth.Client {
	c := auth.Client{Addr: r.RemoteAddr, UserAgent: r.UserAgent()}
	if ck, err := r.Cookie(auth.DeviceCookie); err == nil {
		c.Device = ck.Value
	}
	if ck, err := r.Cookie(auth.SessionCookie); err == nil {
		c.Token = ck.Value
	}
	return c
}

func (a *api) handleSetup(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var req SetupRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	g, err := a.accounts.CompleteSetup(r.Context(), auth.SetupRequest{
		Code: req.Code, Username: req.Username, Password: req.Password, UseExisting: req.UseExisting,
	}, a.client(r))
	if err != nil {
		writeError(w, r, err)
		return
	}
	setSessionCookies(w, g)
	writeJSON(w, http.StatusCreated, g.Me)
}

func (a *api) handleStatus(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet, http.MethodHead) {
		return
	}
	writeJSON(w, http.StatusOK, StatusResponse{SetupRequired: a.accounts.SetupRequired()})
}

func (a *api) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var req LoginRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	g, err := a.accounts.Login(r.Context(), req.Username, req.Password, a.client(r))
	if err != nil {
		writeError(w, r, err)
		return
	}
	setSessionCookies(w, g)
	writeJSON(w, http.StatusOK, g.Me)
}

func (a *api) handleLogout(w http.ResponseWriter, r *http.Request, id auth.Identity) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	if err := a.accounts.Logout(r.Context(), id); err != nil {
		writeError(w, r, err)
		return
	}
	clearSessionCookie(w)
	w.Header().Set("Clear-Site-Data", `"cache"`)
	w.WriteHeader(http.StatusNoContent)
}

func (a *api) handleMe(w http.ResponseWriter, r *http.Request, id auth.Identity) {
	if !requireMethod(w, r, http.MethodGet, http.MethodHead) {
		return
	}
	writeJSON(w, http.StatusOK, a.accounts.MeFor(id))
}

func (a *api) handleConfirm(w http.ResponseWriter, r *http.Request, id auth.Identity) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var req ConfirmRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	g, err := a.accounts.Confirm(r.Context(), id, req.Password, a.client(r))
	if err != nil {
		writeSessionError(w, r, err)
		return
	}
	setSessionCookies(w, g)
	w.WriteHeader(http.StatusNoContent)
}

func (a *api) handlePassword(w http.ResponseWriter, r *http.Request, id auth.Identity) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var req PasswordRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	g, links, err := a.accounts.ChangePassword(r.Context(), id, req.Current, req.New, a.client(r))
	if err != nil {
		writeSessionError(w, r, err)
		return
	}
	setSessionCookies(w, g)
	writeJSON(w, http.StatusOK, RevokedLinksResponse{RevokedLinks: links})
}

func (a *api) handleSessions(w http.ResponseWriter, r *http.Request, id auth.Identity) {
	if !requireMethod(w, r, http.MethodGet, http.MethodHead) {
		return
	}
	writeJSON(w, http.StatusOK, a.accounts.Sessions(id))
}

func (a *api) handleRevokeSession(w http.ResponseWriter, r *http.Request, id auth.Identity) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var req SessionRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := a.accounts.RevokeSession(r.Context(), id, req.ID); err != nil {
		writeError(w, r, err)
		return
	}
	if req.ID == id.Session.ID {
		clearSessionCookie(w)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *api) handleRevokeOthers(w http.ResponseWriter, r *http.Request, id auth.Identity) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	links, err := a.accounts.RevokeOtherSessions(r.Context(), id)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, RevokedLinksResponse{RevokedLinks: links})
}
