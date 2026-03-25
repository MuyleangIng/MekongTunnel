package handlers

import (
	"net/http"
	"time"

	"github.com/MuyleangIng/MekongTunnel/internal/api/middleware"
	"github.com/MuyleangIng/MekongTunnel/internal/api/response"
	"github.com/MuyleangIng/MekongTunnel/internal/auth"
	"github.com/MuyleangIng/MekongTunnel/internal/db"
)

var timeNow = time.Now

// CLIDeviceHandler implements the OAuth2-style device flow for `mekong login`.
type CLIDeviceHandler struct {
	DB          *db.DB
	FrontendURL string // e.g. "https://angkorsearch.dev"
}

// CreateSession handles POST /api/cli/device.
// No authentication required — the CLI calls this to start the flow.
// Returns {session_id, login_url, expires_in_seconds}.
func (h *CLIDeviceHandler) CreateSession(w http.ResponseWriter, r *http.Request) {
	sess, err := h.DB.CreateDeviceSession(r.Context())
	if err != nil {
		response.InternalError(w, err)
		return
	}

	loginURL := h.FrontendURL + "/cli-auth?session=" + sess.ID
	response.Success(w, map[string]any{
		"session_id":       sess.ID,
		"login_url":        loginURL,
		"expires_in":       900, // 15 minutes
		"poll_interval":    3,   // seconds
	})
}

// PollSession handles GET /api/cli/device?session_id=<id>.
// Called by the CLI every few seconds.  Returns:
//   - {status:"pending"}            — user has not approved yet
//   - {status:"approved", token:"…"} — approved; token returned exactly once
//   - {status:"expired"}            — session expired
func (h *CLIDeviceHandler) PollSession(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		response.BadRequest(w, "session_id required")
		return
	}

	sess, err := h.DB.GetDeviceSession(r.Context(), sessionID)
	if err != nil {
		response.NotFound(w, "session not found")
		return
	}

	// Expired
	if sess.ExpiresAt.Before(timeNow()) {
		response.Success(w, map[string]any{"status": "expired"})
		return
	}

	// Not yet approved
	if sess.ApprovedAt == nil {
		response.Success(w, map[string]any{"status": "pending"})
		return
	}

	// Approved — try to consume the raw token (readable exactly once)
	if sess.RawToken != "" {
		rawToken, err := h.DB.ConsumeDeviceToken(r.Context(), sessionID)
		if err == nil && rawToken != "" {
			response.Success(w, map[string]any{
				"status": "approved",
				"token":  rawToken,
			})
			return
		}
	}

	// Token already consumed on a previous poll
	response.Success(w, map[string]any{"status": "approved"})
}

// ApproveSession handles POST /api/cli/device/approve.
// Auth required — called by the web dashboard after the user confirms.
// Creates an API token linked to the session and marks it approved.
func (h *CLIDeviceHandler) ApproveSession(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		response.BadRequest(w, "session_id required")
		return
	}

	// Verify the session exists and is still pending
	sess, err := h.DB.GetDeviceSession(r.Context(), sessionID)
	if err != nil {
		response.NotFound(w, "session not found or expired")
		return
	}
	if sess.ApprovedAt != nil {
		response.BadRequest(w, "session already approved")
		return
	}
	if sess.ExpiresAt.Before(timeNow()) {
		response.BadRequest(w, "session expired")
		return
	}

	// Generate a new API token for the user
	fullToken, prefix, hash, err := auth.GenerateAPIToken()
	if err != nil {
		response.InternalError(w, err)
		return
	}

	// Persist the token in api_tokens table
	if _, err := h.DB.CreateAPIToken(r.Context(), claims.UserID, "CLI Login", hash, prefix); err != nil {
		response.InternalError(w, err)
		return
	}

	// Store raw token in the session (CLI will consume it on next poll)
	if err := h.DB.ApproveDeviceSession(r.Context(), sessionID, claims.UserID, fullToken, prefix, hash); err != nil {
		response.InternalError(w, err)
		return
	}

	response.Success(w, map[string]any{"ok": true})
}
