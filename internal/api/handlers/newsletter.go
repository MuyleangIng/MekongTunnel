package handlers

import (
	"encoding/json"
	"net/http"
	"net/url"
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
	// FrontendURL is the web app origin used for unsubscribe links.
	FrontendURL string
}

const (
	defaultNewsletterFrontendURL          = "https://angkorsearch.dev"
	newsletterPlaceholderUnsubscribeToken = "{{unsubscribe_token}}"
	newsletterPlaceholderUnsubscribeURL   = "{{unsubscribe_url}}"
)

func normalizeNewsletterFrontendURL(frontendURL string) string {
	frontendURL = strings.TrimSpace(frontendURL)
	if frontendURL == "" {
		frontendURL = defaultNewsletterFrontendURL
	}
	return strings.TrimRight(frontendURL, "/")
}

func buildNewsletterUnsubscribeURL(frontendURL, token string) string {
	return normalizeNewsletterFrontendURL(frontendURL) + "/unsubscribe?token=" + url.QueryEscape(token)
}

func newsletterHasUnsubscribeMarkup(bodyHTML string) bool {
	bodyHTML = strings.ToLower(bodyHTML)
	return strings.Contains(bodyHTML, strings.ToLower(newsletterPlaceholderUnsubscribeToken)) ||
		strings.Contains(bodyHTML, strings.ToLower(newsletterPlaceholderUnsubscribeURL)) ||
		strings.Contains(bodyHTML, "/unsubscribe?token=")
}

func newsletterAutoFooterHTML(unsubscribeURL string) string {
	return `
<hr style="border:none;border-top:1px solid #e5e7eb;margin:32px 0 16px">
<p style="margin:0;font-size:12px;line-height:1.6;color:#6b7280">
  You're receiving this because you have a Mekong Tunnel account.<br>
  <a href="` + unsubscribeURL + `" style="color:#6b7280">Unsubscribe</a>
</p>`
}

func insertNewsletterFooter(bodyHTML, footerHTML string) string {
	lowerBody := strings.ToLower(bodyHTML)
	if idx := strings.LastIndex(lowerBody, "</body>"); idx >= 0 {
		return bodyHTML[:idx] + footerHTML + bodyHTML[idx:]
	}
	if idx := strings.LastIndex(lowerBody, "</html>"); idx >= 0 {
		return bodyHTML[:idx] + footerHTML + bodyHTML[idx:]
	}
	return bodyHTML + footerHTML
}

func renderNewsletterBodyHTML(frontendURL, bodyHTML, unsubscribeToken string) (string, bool) {
	unsubscribeURL := buildNewsletterUnsubscribeURL(frontendURL, unsubscribeToken)
	rendered := strings.ReplaceAll(bodyHTML, newsletterPlaceholderUnsubscribeToken, unsubscribeToken)
	rendered = strings.ReplaceAll(rendered, newsletterPlaceholderUnsubscribeURL, unsubscribeURL)
	if newsletterHasUnsubscribeMarkup(rendered) {
		return rendered, false
	}
	return insertNewsletterFooter(rendered, newsletterAutoFooterHTML(unsubscribeURL)), true
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

// AdminPreview handles POST /api/admin/newsletter/preview — renders newsletter HTML with a concrete token.
func (h *NewsletterHandler) AdminPreview(w http.ResponseWriter, r *http.Request) {
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
	if body.BodyHTML == "" {
		response.BadRequest(w, "body_html is required")
		return
	}

	unsubscribeToken, err := h.DB.EnsureNewsletterUnsubscribeToken(r.Context(), claims.UserID)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	renderedHTML, autoAppended := renderNewsletterBodyHTML(h.FrontendURL, body.BodyHTML, unsubscribeToken)
	response.Success(w, map[string]any{
		"subject":                   body.Subject,
		"html":                      renderedHTML,
		"unsubscribe_token":         unsubscribeToken,
		"unsubscribe_url":           buildNewsletterUnsubscribeURL(h.FrontendURL, unsubscribeToken),
		"auto_appended_unsubscribe": autoAppended,
	})
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
		renderedHTML, _ := renderNewsletterBodyHTML(h.FrontendURL, body.BodyHTML, rec.UnsubscribeToken)
		go h.Mailer.SendNewsletter(rec.Email, rec.Name, body.Subject, renderedHTML)
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
