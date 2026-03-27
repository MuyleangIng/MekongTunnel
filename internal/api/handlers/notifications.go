package handlers

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/MuyleangIng/MekongTunnel/internal/api/middleware"
	"github.com/MuyleangIng/MekongTunnel/internal/api/response"
	"github.com/MuyleangIng/MekongTunnel/internal/auth"
	"github.com/MuyleangIng/MekongTunnel/internal/db"
	"github.com/MuyleangIng/MekongTunnel/internal/hub"
	"github.com/MuyleangIng/MekongTunnel/internal/models"
)

// NotificationsHandler handles /api/notifications/* endpoints.
type NotificationsHandler struct {
	DB        *db.DB
	Hub       *hub.Hub
	JWTSecret string
}

// List handles GET /api/notifications — returns paginated notification list.
func (h *NotificationsHandler) List(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}
	limit := queryInt(r, "limit", 30)
	offset := queryInt(r, "offset", 0)

	notifs, total, unread, err := h.DB.ListNotifications(r.Context(), claims.UserID, limit, offset)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	if notifs == nil {
		notifs = []*models.Notification{}
	}

	response.Success(w, map[string]any{
		"notifications": notifs,
		"total":         total,
		"unread":        unread,
	})
}

// MarkRead handles PATCH /api/notifications/{id}/read.
func (h *NotificationsHandler) MarkRead(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		response.BadRequest(w, "id is required")
		return
	}
	unread, err := h.DB.MarkNotificationRead(r.Context(), id, claims.UserID)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	response.Success(w, map[string]any{"unread": unread})
}

// MarkAllRead handles PATCH /api/notifications/read-all.
func (h *NotificationsHandler) MarkAllRead(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}
	unread, err := h.DB.MarkAllNotificationsRead(r.Context(), claims.UserID)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	response.Success(w, map[string]any{"unread": unread})
}

// DeleteOne handles DELETE /api/notifications/{id} — remove a single notification.
func (h *NotificationsHandler) DeleteOne(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		response.BadRequest(w, "id is required")
		return
	}
	unread, err := h.DB.DeleteNotification(r.Context(), id, claims.UserID)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	response.Success(w, map[string]any{"unread": unread})
}

// ClearAll handles DELETE /api/notifications — delete all notifications for the current user.
func (h *NotificationsHandler) ClearAll(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}
	if err := h.DB.DeleteAllNotifications(r.Context(), claims.UserID); err != nil {
		response.InternalError(w, err)
		return
	}
	response.Success(w, map[string]any{"unread": 0})
}

// Stream handles GET /api/notifications/stream — SSE endpoint.
// EventSource cannot set Authorization headers, so the JWT is read from ?token=.
func (h *NotificationsHandler) Stream(w http.ResponseWriter, r *http.Request) {
	// Read JWT from query param (EventSource limitation) or header fallback.
	token := r.URL.Query().Get("token")
	if token == "" {
		hdr := r.Header.Get("Authorization")
		if strings.HasPrefix(hdr, "Bearer ") {
			token = strings.TrimPrefix(hdr, "Bearer ")
		}
	}
	if token == "" {
		response.Unauthorized(w, "token required")
		return
	}
	claims, err := auth.ValidateToken(token, h.JWTSecret)
	if err != nil || claims.Temp2FA {
		response.Unauthorized(w, "invalid token")
		return
	}

	// SSE headers.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	// CORS for SSE (browsers send Origin even for same-site SSE).
	w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
	w.Header().Set("Access-Control-Allow-Credentials", "true")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	// Send initial unread count.
	unread, _ := h.DB.CountUnreadNotifications(r.Context(), claims.UserID)
	fmt.Fprintf(w, "event: connected\ndata: {\"unread\":%d}\n\n", unread)
	flusher.Flush()

	// Subscribe to hub.
	ch, unsub := h.Hub.Subscribe(claims.UserID)
	defer unsub()

	for {
		select {
		case data, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}
