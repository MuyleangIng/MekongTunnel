package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/MuyleangIng/MekongTunnel/internal/api/middleware"
	"github.com/MuyleangIng/MekongTunnel/internal/api/response"
	"github.com/MuyleangIng/MekongTunnel/internal/db"
	"github.com/MuyleangIng/MekongTunnel/internal/telegrambot"
	"github.com/jackc/pgx/v5"
)

// TelegramHandler handles Telegram bot webhook and link-session endpoints.
type TelegramHandler struct {
	DB  *db.DB
	Bot *telegrambot.Service
}

// Webhook handles POST /api/telegram/webhook.
// Telegram delivers updates here; verification is done inside Service.HandleWebhook.
func (h *TelegramHandler) Webhook(w http.ResponseWriter, r *http.Request) {
	h.Bot.HandleWebhook(w, r)
}

// GetLinkSession handles GET /api/telegram/link/session?code=<code>.
// Auth required — the frontend page calls this to display session metadata.
func (h *TelegramHandler) GetLinkSession(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		response.BadRequest(w, "code required")
		return
	}

	sess, err := h.DB.GetTelegramLinkSessionByCode(r.Context(), code)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			response.NotFound(w, "session not found")
			return
		}
		response.InternalError(w, err)
		return
	}

	response.Success(w, sess)
}

// ApproveLink handles POST /api/telegram/link/approve.
// Auth required — binds the Telegram chat to the logged-in user.
func (h *TelegramHandler) ApproveLink(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Code == "" {
		response.BadRequest(w, "code required")
		return
	}

	sess, err := h.DB.GetTelegramLinkSessionByCode(r.Context(), body.Code)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			response.NotFound(w, "session not found")
			return
		}
		response.InternalError(w, err)
		return
	}

	if err := h.DB.ApproveTelegramLinkSession(r.Context(), body.Code, claims.UserID); err != nil {
		response.Error(w, http.StatusBadRequest, err.Error())
		return
	}

	if h.Bot != nil {
		user, err := h.DB.GetUserByID(r.Context(), claims.UserID)
		if err != nil {
			response.InternalError(w, err)
			return
		}
		h.Bot.NotifyLinkApproved(sess.TelegramChatID, user)
	}

	response.Success(w, map[string]any{"ok": true})
}

// CancelLink handles POST /api/telegram/link/cancel.
// Auth required — cancels a pending session.
func (h *TelegramHandler) CancelLink(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Code == "" {
		response.BadRequest(w, "code required")
		return
	}

	sess, err := h.DB.GetTelegramLinkSessionByCode(r.Context(), body.Code)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			response.NotFound(w, "session not found")
			return
		}
		response.InternalError(w, err)
		return
	}

	if err := h.DB.CancelTelegramLinkSession(r.Context(), body.Code); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			response.NotFound(w, "session not found")
			return
		}
		response.InternalError(w, err)
		return
	}

	if h.Bot != nil {
		h.Bot.NotifyLinkCancelled(sess.TelegramChatID)
	}

	response.Success(w, map[string]any{"ok": true})
}

// Unlink handles POST /api/telegram/unlink.
// Auth required — web-side unlink.
func (h *TelegramHandler) Unlink(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	link, err := h.DB.GetTelegramLinkByUserID(r.Context(), claims.UserID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		response.InternalError(w, err)
		return
	}

	if err := h.DB.RevokeTelegramLinkByUserID(r.Context(), claims.UserID); err != nil {
		response.InternalError(w, err)
		return
	}

	if h.Bot != nil && link != nil {
		h.Bot.NotifyUnlinked(link.TelegramChatID)
	}

	response.Success(w, map[string]any{"ok": true})
}

// GetMyLink handles GET /api/telegram/link.
// Auth required — returns the active Telegram link for the logged-in user.
func (h *TelegramHandler) GetMyLink(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	link, err := h.DB.GetTelegramLinkByUserID(r.Context(), claims.UserID)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			response.InternalError(w, err)
			return
		}
		response.Success(w, nil)
		return
	}

	response.Success(w, link)
}
