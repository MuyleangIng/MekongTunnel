package handlers

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/MuyleangIng/MekongTunnel/internal/auth"
	"github.com/MuyleangIng/MekongTunnel/internal/models"
)

const (
	refreshCookieName     = "mekong_refresh"
	sessionOnlyCookieName = "mekong_session_only"
	refreshCookiePath     = "/api/auth/refresh"

	// rememberedSessionTTL is how long "Remember me" keeps a user signed in.
	rememberedSessionTTL = 30 * 24 * time.Hour
	// browserSessionTTL caps a non-remembered session; its cookie also
	// disappears when the browser closes.
	browserSessionTTL = 24 * time.Hour
)

// issueSession creates an access token plus a refresh token and sets the
// refresh cookie. remember=false gives a browser-session cookie that also
// expires server-side after browserSessionTTL.
func (h *AuthHandler) issueSession(w http.ResponseWriter, ctx context.Context, user *models.User, remember bool) (string, error) {
	accessToken, err := auth.GenerateAccessToken(user, h.JWTSecret)
	if err != nil {
		return "", err
	}

	rawRefresh, err := auth.GenerateSecureToken()
	if err != nil {
		return "", err
	}
	ttl := rememberedSessionTTL
	if !remember {
		ttl = browserSessionTTL
	}
	if err := h.DB.CreateRefreshToken(ctx, user.ID, auth.HashToken(rawRefresh), time.Now().Add(ttl)); err != nil {
		return "", err
	}

	h.setRefreshCookies(w, rawRefresh, remember)
	return accessToken, nil
}

// setRefreshCookies writes the refresh cookie. A small companion cookie marks
// non-remembered sessions so token rotation in Refresh keeps that choice.
func (h *AuthHandler) setRefreshCookies(w http.ResponseWriter, rawRefresh string, remember bool) {
	secure := strings.HasPrefix(h.FrontendURL, "https")

	refresh := &http.Cookie{
		Name:     refreshCookieName,
		Value:    rawRefresh,
		Path:     refreshCookiePath,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	}
	marker := &http.Cookie{
		Name:     sessionOnlyCookieName,
		Value:    "1",
		Path:     refreshCookiePath,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	}
	if remember {
		refresh.MaxAge = int(rememberedSessionTTL.Seconds())
		marker.Value = ""
		marker.MaxAge = -1 // clear any old marker
	}
	http.SetCookie(w, refresh)
	http.SetCookie(w, marker)
}

// isSessionOnly reports whether the request carries a non-remembered session.
func isSessionOnly(r *http.Request) bool {
	c, err := r.Cookie(sessionOnlyCookieName)
	return err == nil && c.Value == "1"
}
