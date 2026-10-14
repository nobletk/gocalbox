package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/nobletk/gocalbox/internal/auth"
	"github.com/nobletk/gocalbox/internal/events"
)

type identityKey struct{}

func identityFrom(ctx context.Context) (auth.Identity, bool) {
	id, ok := ctx.Value(identityKey{}).(auth.Identity)
	return id, ok
}

// authenticate puts the session the cookie names, and its user as the
// actor, into the request's context. Without a valid session the request
// goes on without one. The cookie is cleared only for a session that has
// just ended: a token that names no session may be one that a renewal or a
// login replaced while this request was on its way, and clearing it would
// delete the browser's new cookie.
func authenticate(accounts AccountService, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ck, err := r.Cookie(auth.SessionCookie)
		if accounts == nil || err != nil {
			next.ServeHTTP(w, r)
			return
		}
		id, status := accounts.Identify(ck.Value)
		if status != auth.ValidSession {
			if status == auth.EndedSession {
				clearSessionCookie(w)
			}
			next.ServeHTTP(w, r)
			return
		}
		ctx := events.WithActor(r.Context(), events.Actor{
			ID: id.User.ID, Name: id.User.Username, Role: string(id.User.Role),
			RemoteAddr: r.RemoteAddr, Session: id.Session.ID,
		})
		next.ServeHTTP(w, r.WithContext(context.WithValue(ctx, identityKey{}, id)))
	})
}

// requireSession refuses every route but the public ones without a session.
// A browser opening a file is sent to the login page, which returns there.
func requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := identityFrom(r.Context()); ok || isPublic(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/files/") && r.Header.Get("Sec-Fetch-Mode") == "navigate" {
			w.Header().Set("Location", "/?next="+url.QueryEscape(r.URL.RequestURI()))
			w.WriteHeader(http.StatusSeeOther)
			return
		}
		writeErrorJSON(w, r, http.StatusUnauthorized, "unauthenticated", "Log in first")
	})
}

func withIdentity(h func(http.ResponseWriter, *http.Request, auth.Identity)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identityFrom(r.Context())
		if !ok {
			writeErrorJSON(w, r, http.StatusUnauthorized, "unauthenticated", "Log in first")
			return
		}
		h(w, r, id)
	}
}

func setSessionCookies(w http.ResponseWriter, g auth.Grant) {
	setCookie(w, &http.Cookie{
		Name: auth.SessionCookie, Value: g.Token, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
		MaxAge: max(int(time.Until(g.Expires)/time.Second), 1),
	})
	if g.Device != "" {
		setCookie(w, &http.Cookie{
			Name: auth.DeviceCookie, Value: g.Device, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
			MaxAge: int(auth.DeviceCookieLifetime / time.Second),
		})
	}
}

func clearSessionCookie(w http.ResponseWriter) {
	setCookie(w, &http.Cookie{
		Name: auth.SessionCookie, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}

// setCookie replaces a cookie of the same name set earlier in the response,
// such as authenticate's clearing of an expired one before a login.
func setCookie(w http.ResponseWriter, c *http.Cookie) {
	h := w.Header()
	kept := slices.DeleteFunc(slices.Clone(h.Values("Set-Cookie")), func(v string) bool {
		return strings.HasPrefix(v, c.Name+"=")
	})
	h.Del("Set-Cookie")
	for _, v := range kept {
		h.Add("Set-Cookie", v)
	}
	h.Add("Set-Cookie", c.String())
}

// writeSessionError also clears the cookie of a session that the failed
// password check ended.
func writeSessionError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, auth.ErrTooManyWrongPasswords) {
		clearSessionCookie(w)
	}
	writeError(w, r, err)
}
