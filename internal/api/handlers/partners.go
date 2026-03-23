package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/MuyleangIng/MekongTunnel/internal/api/response"
	"github.com/MuyleangIng/MekongTunnel/internal/db"
	"github.com/MuyleangIng/MekongTunnel/internal/models"
)

type PartnersHandler struct {
	DB *db.DB
}

// ListPublicPartners handles GET /api/partners — public, active+public only.
func (h *PartnersHandler) ListPublicPartners(w http.ResponseWriter, r *http.Request) {
	partners, err := h.DB.ListPublicPartners(r.Context())
	if err != nil {
		response.InternalError(w, err)
		return
	}
	if partners == nil {
		partners = []*models.Partner{}
	}
	response.Success(w, partners)
}

// ListAllPartners handles GET /api/admin/partners — admin, all records.
func (h *PartnersHandler) ListAllPartners(w http.ResponseWriter, r *http.Request) {
	partners, err := h.DB.ListAllPartners(r.Context())
	if err != nil {
		response.InternalError(w, err)
		return
	}
	if partners == nil {
		partners = []*models.Partner{}
	}
	response.Success(w, partners)
}

// CreatePartner handles POST /api/admin/partners.
func (h *PartnersHandler) CreatePartner(w http.ResponseWriter, r *http.Request) {
	var p models.Partner
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		response.BadRequest(w, "invalid JSON body")
		return
	}
	if p.Name == "" {
		response.BadRequest(w, "name is required")
		return
	}
	created, err := h.DB.CreatePartner(r.Context(), &p)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	response.Success(w, created)
}

// UpdatePartner handles PATCH /api/admin/partners/{id}.
func (h *PartnersHandler) UpdatePartner(w http.ResponseWriter, r *http.Request) {
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
	updated, err := h.DB.UpdatePartner(r.Context(), id, fields)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	response.Success(w, updated)
}

// DeletePartner handles DELETE /api/admin/partners/{id}.
func (h *PartnersHandler) DeletePartner(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		response.BadRequest(w, "id is required")
		return
	}
	if err := h.DB.DeletePartner(r.Context(), id); err != nil {
		response.InternalError(w, err)
		return
	}
	response.Success(w, map[string]any{"deleted": id})
}
