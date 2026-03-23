package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/MuyleangIng/MekongTunnel/internal/api/middleware"
	"github.com/MuyleangIng/MekongTunnel/internal/api/response"
	"github.com/MuyleangIng/MekongTunnel/internal/db"
	"github.com/MuyleangIng/MekongTunnel/internal/mailer"
)

// NewsletterHandler handles /api/newsletter/* endpoints.
type NewsletterHandler struct {
	DB     *db.DB
	Mailer *mailer.Mailer
}

// Subscribe handles POST /api/newsletter/subscribe (public — marketing footer).
func (h *NewsletterHandler) Subscribe(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid JSON body")
		return
	}
	body.Email = strings.ToLower(strings.TrimSpace(body.Email))
	if !emailRE.MatchString(body.Email) {
		response.BadRequest(w, "invalid email address")
		return
	}
	if err := h.DB.SubscribeNewsletter(r.Context(), body.Email); err != nil {
		response.InternalError(w, err)
		return
	}
	response.Success(w, map[string]any{"message": "subscribed"})
}

// Unsubscribe handles GET /api/newsletter/unsubscribe?token=xxx (one-click from email link).
func (h *NewsletterHandler) Unsubscribe(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		response.BadRequest(w, "missing token")
		return
	}
	user, err := h.DB.GetUserByNewsletterToken(r.Context(), token)
	if err != nil || user == nil {
		response.NotFound(w, "invalid unsubscribe token")
		return
	}
	if err := h.DB.SetNewsletterSubscribed(r.Context(), user.ID, false); err != nil {
		response.InternalError(w, err)
		return
	}
	response.Success(w, map[string]any{"message": "unsubscribed", "email": user.Email})
}

// ResubscribeByToken handles POST /api/newsletter/resubscribe?token=xxx.
func (h *NewsletterHandler) ResubscribeByToken(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		response.BadRequest(w, "missing token")
		return
	}
	user, err := h.DB.GetUserByNewsletterToken(r.Context(), token)
	if err != nil || user == nil {
		response.NotFound(w, "invalid token")
		return
	}
	if err := h.DB.SetNewsletterSubscribed(r.Context(), user.ID, true); err != nil {
		response.InternalError(w, err)
		return
	}
	response.Success(w, map[string]any{"message": "resubscribed", "email": user.Email})
}

// Toggle handles POST /api/newsletter/toggle (authenticated — settings page).
func (h *NewsletterHandler) Toggle(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}
	var body struct {
		Subscribed bool `json:"subscribed"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid JSON body")
		return
	}
	if err := h.DB.SetNewsletterSubscribed(r.Context(), claims.UserID, body.Subscribed); err != nil {
		response.InternalError(w, err)
		return
	}
	response.Success(w, map[string]any{"subscribed": body.Subscribed})
}

// AdminSend handles POST /api/admin/newsletter/send — sends campaign to all subscribed users.
func (h *NewsletterHandler) AdminSend(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}
	var body struct {
		Subject  string `json:"subject"`
		BodyHTML string `json:"body_html"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid JSON body")
		return
	}
	body.Subject = strings.TrimSpace(body.Subject)
	body.BodyHTML = strings.TrimSpace(body.BodyHTML)
	if body.Subject == "" || body.BodyHTML == "" {
		response.BadRequest(w, "subject and body_html are required")
		return
	}

	recipients, err := h.DB.GetNewsletterRecipients(r.Context())
	if err != nil {
		response.InternalError(w, err)
		return
	}

	// Send in background goroutines
	sent := 0
	for _, rec := range recipients {
		go h.Mailer.SendNewsletter(rec.Email, rec.Name, body.Subject, body.BodyHTML)
		sent++
	}

	_ = h.DB.SaveNewsletterCampaign(r.Context(), body.Subject, body.BodyHTML, claims.UserID, sent)
	response.Success(w, map[string]any{"sent": sent})
}

// AdminCampaigns handles GET /api/admin/newsletter/campaigns.
func (h *NewsletterHandler) AdminCampaigns(w http.ResponseWriter, r *http.Request) {
	campaigns, err := h.DB.GetNewsletterCampaigns(r.Context())
	if err != nil {
		response.InternalError(w, err)
		return
	}
	response.Success(w, campaigns)
}

// AdminSubscribers handles GET /api/admin/newsletter/subscribers.
func (h *NewsletterHandler) AdminSubscribers(w http.ResponseWriter, r *http.Request) {
	recipients, err := h.DB.GetNewsletterRecipients(r.Context())
	if err != nil {
		response.InternalError(w, err)
		return
	}
	response.Success(w, map[string]any{"count": len(recipients), "recipients": recipients})
}
