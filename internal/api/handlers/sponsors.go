package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/MuyleangIng/MekongTunnel/internal/api/response"
	"github.com/MuyleangIng/MekongTunnel/internal/db"
	"github.com/MuyleangIng/MekongTunnel/internal/models"
)

type SponsorsHandler struct {
	DB *db.DB
}

// ListPublicSponsors handles GET /api/sponsors — public, active only.
func (h *SponsorsHandler) ListPublicSponsors(w http.ResponseWriter, r *http.Request) {
	sponsors, err := h.DB.ListPublicSponsors(r.Context())
	if err != nil {
		response.InternalError(w, err)
		return
	}
	if sponsors == nil {
		sponsors = []*models.Sponsor{}
	}
	response.Success(w, sponsors)
}

// ListAllSponsors handles GET /api/admin/sponsors — admin, all records.
func (h *SponsorsHandler) ListAllSponsors(w http.ResponseWriter, r *http.Request) {
	sponsors, err := h.DB.ListAllSponsors(r.Context())
	if err != nil {
		response.InternalError(w, err)
		return
	}
	if sponsors == nil {
		sponsors = []*models.Sponsor{}
	}
	response.Success(w, sponsors)
}

// CreateSponsor handles POST /api/admin/sponsors.
func (h *SponsorsHandler) CreateSponsor(w http.ResponseWriter, r *http.Request) {
	var s models.Sponsor
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
		response.BadRequest(w, "invalid JSON body")
		return
	}
	if s.Title == "" {
		response.BadRequest(w, "title is required")
		return
	}
	created, err := h.DB.CreateSponsor(r.Context(), &s)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	response.Success(w, created)
}

// UpdateSponsor handles PATCH /api/admin/sponsors/{id}.
func (h *SponsorsHandler) UpdateSponsor(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		response.BadRequest(w, "id is required")
		return
	}
	var fields map[string]any
	if err := json.NewDecoder(r.Body).Decode(&fields); err != nil {
		response.BadRequest(w, "invalid JSON body")
		return
	}
	updated, err := h.DB.UpdateSponsor(r.Context(), id, fields)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	response.Success(w, updated)
}

// DeleteSponsor handles DELETE /api/admin/sponsors/{id}.
func (h *SponsorsHandler) DeleteSponsor(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		response.BadRequest(w, "id is required")
		return
	}
	if err := h.DB.DeleteSponsor(r.Context(), id); err != nil {
		response.InternalError(w, err)
		return
	}
	response.Success(w, map[string]any{"deleted": id})
}
