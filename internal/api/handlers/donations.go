package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/MuyleangIng/MekongTunnel/internal/api/middleware"
	"github.com/MuyleangIng/MekongTunnel/internal/api/response"
	"github.com/MuyleangIng/MekongTunnel/internal/db"
	"github.com/MuyleangIng/MekongTunnel/internal/models"
	"github.com/MuyleangIng/MekongTunnel/internal/notify"
)

type DonationHandler struct {
	DB     *db.DB
	Notify *notify.Service
}

// Submit handles POST /api/donations/submit — public submission.
func (h *DonationHandler) Submit(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name          string `json:"name"`
		Email         string `json:"email"`
		Amount        string `json:"amount"`
		Currency      string `json:"currency"`
		PaymentMethod string `json:"payment_method"`
		ReceiptURL    string `json:"receipt_url"`
		SocialURL     string `json:"social_url"`
		Message       string `json:"message"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid JSON")
		return
	}
	if body.Name == "" || body.Amount == "" || body.PaymentMethod == "" {
		response.BadRequest(w, "name, amount, and payment_method are required")
		return
	}
	if body.Currency == "" {
		body.Currency = "KHR"
	}
	sub := &models.DonationSubmission{
		Name:          body.Name,
		Email:         body.Email,
		Amount:        body.Amount,
		Currency:      body.Currency,
		PaymentMethod: body.PaymentMethod,
		ReceiptURL:    body.ReceiptURL,
		SocialURL:     body.SocialURL,
		Message:       body.Message,
	}
	created, err := h.DB.CreateDonation(r.Context(), sub)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	// Notify all admins of new donation
	if h.Notify != nil {
		go h.Notify.SendToAdmins(r.Context(), "donation",
			fmt.Sprintf("New donation from %s", created.Name),
			fmt.Sprintf("%s %s via %s", created.Amount, created.Currency, created.PaymentMethod),
			"/admin/donations",
		)
	}
	response.Success(w, created)
}

// PublicList handles GET /api/donations?limit=12&offset=0 — approved donations shown on home.
func (h *DonationHandler) PublicList(w http.ResponseWriter, r *http.Request) {
	limit := 12
	offset := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		fmt.Sscanf(v, "%d", &limit)
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		fmt.Sscanf(v, "%d", &offset)
	}
	list, err := h.DB.ListPublicDonations(r.Context(), limit, offset)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	if list == nil {
		list = []*models.DonationSubmission{}
	}
	total, _ := h.DB.CountPublicDonations(r.Context())
	response.Success(w, map[string]any{
		"donors":   list,
		"total":    total,
		"has_more": offset+len(list) < total,
	})
}

// AdminList handles GET /api/admin/donations.
func (h *DonationHandler) AdminList(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}
	status := r.URL.Query().Get("status")
	list, err := h.DB.ListDonationsAdmin(r.Context(), status)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	if list == nil {
		list = []*models.DonationSubmission{}
	}
	response.Success(w, list)
}

// AdminDelete handles DELETE /api/admin/donations/{id}.
func (h *DonationHandler) AdminDelete(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}
	id := r.PathValue("id")
	if err := h.DB.DeleteDonation(r.Context(), id); err != nil {
		response.InternalError(w, err)
		return
	}
	response.Success(w, map[string]bool{"deleted": true})
}

// AdminUpdate handles PATCH /api/admin/donations/{id}.
func (h *DonationHandler) AdminUpdate(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}
	id := r.PathValue("id")
	var body struct {
		Status     string `json:"status"`
		ShowOnHome bool   `json:"show_on_home"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid JSON")
		return
	}
	if body.Status == "" {
		body.Status = "approved"
	}
	updated, err := h.DB.UpdateDonation(r.Context(), id, body.Status, body.ShowOnHome)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	response.Success(w, updated)
}
