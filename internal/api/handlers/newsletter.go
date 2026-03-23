package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/MuyleangIng/MekongTunnel/internal/api/response"
	"github.com/MuyleangIng/MekongTunnel/internal/db"
)

// NewsletterHandler handles /api/newsletter/* endpoints.
type NewsletterHandler struct {
	DB *db.DB
}

// Subscribe handles POST /api/newsletter/subscribe.
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
