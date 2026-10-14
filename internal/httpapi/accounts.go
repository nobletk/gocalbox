package httpapi

import (
	"context"
	"net/http"

	"github.com/nobletk/gocalbox/internal/auth"
)

type AccountService interface {
	SetupRequired() bool
	CompleteSetup(ctx context.Context, req auth.SetupRequest) (auth.Me, error)
}

type SetupRequest struct {
	Code        string `json:"code"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	UseExisting bool   `json:"useExisting"`
}

type StatusResponse struct {
	SetupRequired bool `json:"setupRequired"`
}

// Reachable while the server has no admin yet; every other API route and
// every file answers 503 until setup is done.
var setupRoutes = map[string]bool{"/api/setup": true, "/api/status": true}

func requireSetupDone(accounts AccountService, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isResourcePath(r.URL.Path) && !setupRoutes[r.URL.Path] && accounts.SetupRequired() {
			writeErrorJSON(w, r, http.StatusServiceUnavailable, "setup_required",
				"The server has no admin account yet; create one with the setup code printed on the server's console")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *api) handleSetup(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var req SetupRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	me, err := a.accounts.CompleteSetup(r.Context(), auth.SetupRequest{
		Code: req.Code, Username: req.Username, Password: req.Password, UseExisting: req.UseExisting,
	})
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, me)
}

func (a *api) handleStatus(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet, http.MethodHead) {
		return
	}
	writeJSON(w, http.StatusOK, StatusResponse{SetupRequired: a.accounts.SetupRequired()})
}
