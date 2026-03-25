package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/MuyleangIng/MekongTunnel/internal/api/middleware"
	"github.com/MuyleangIng/MekongTunnel/internal/api/response"
	"github.com/MuyleangIng/MekongTunnel/internal/db"
	"github.com/MuyleangIng/MekongTunnel/internal/models"
)

// SubdomainHandler handles reserved subdomains and per-subdomain access-control rules.
type SubdomainHandler struct {
	DB *db.DB
}

func (h *SubdomainHandler) userFromAPIToken(r *http.Request) (*models.User, error) {
	hdr := r.Header.Get("Authorization")
	if len(hdr) < 8 || hdr[:7] != "Bearer " {
		return nil, fmt.Errorf("Bearer token required")
	}
	userID, err := h.DB.ValidateToken(r.Context(), hdr[7:])
	if err != nil {
		return nil, fmt.Errorf("invalid or expired token")
	}
	return h.DB.GetUserByID(r.Context(), userID)
}

// List handles GET /api/subdomains
func (h *SubdomainHandler) List(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}
	list, err := h.DB.ListReservedSubdomains(r.Context(), claims.UserID)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	if list == nil {
		list = []*models.ReservedSubdomain{}
	}

	// Attach plan limit info
	limit, _ := h.DB.GetSubdomainLimit(r.Context(), claims.Plan)
	count := len(list)
	response.Success(w, map[string]any{
		"subdomains": list,
		"count":      count,
		"limit":      limit, // -1 = unlimited
	})
}

// ListCLI handles GET /api/cli/subdomains using an API token.
func (h *SubdomainHandler) ListCLI(w http.ResponseWriter, r *http.Request) {
	user, err := h.userFromAPIToken(r)
	if err != nil {
		response.Unauthorized(w, err.Error())
		return
	}

	list, err := h.DB.ListReservedSubdomains(r.Context(), user.ID)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	if list == nil {
		list = []*models.ReservedSubdomain{}
	}

	limit, _ := h.DB.GetSubdomainLimit(r.Context(), user.Plan)
	response.Success(w, map[string]any{
		"subdomains": list,
		"count":      len(list),
		"limit":      limit,
	})
}

// Create handles POST /api/subdomains
func (h *SubdomainHandler) Create(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	// Check plan limit
	if !claims.IsAdmin {
		limit, err := h.DB.GetSubdomainLimit(r.Context(), claims.Plan)
		if err == nil && limit == 0 {
			response.Error(w, http.StatusPaymentRequired,
				"your plan does not include reserved subdomains — upgrade to Student, Pro, or Org")
			return
		}
		if err == nil && limit > 0 {
			count, _ := h.DB.GetSubdomainCount(r.Context(), claims.UserID)
			if count >= limit {
				response.Error(w, http.StatusPaymentRequired,
					fmt.Sprintf("plan limit reached: your %s plan allows %d reserved subdomain(s)", claims.Plan, limit))
				return
			}
		}
	}

	var body struct {
		Subdomain string `json:"subdomain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid request body")
		return
	}
	subdomain := strings.ToLower(strings.TrimSpace(body.Subdomain))
	if subdomain == "" {
		response.BadRequest(w, "subdomain is required")
		return
	}
	for _, c := range subdomain {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
			response.BadRequest(w, "subdomain may only contain lowercase letters, digits, and hyphens")
			return
		}
	}

	s, err := h.DB.CreateReservedSubdomain(r.Context(), claims.UserID, subdomain)
	if err != nil {
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			response.Conflict(w, "subdomain already reserved")
			return
		}
		response.InternalError(w, err)
		return
	}
	response.Created(w, s)
}

// CreateCLI handles POST /api/cli/subdomains using an API token.
func (h *SubdomainHandler) CreateCLI(w http.ResponseWriter, r *http.Request) {
	user, err := h.userFromAPIToken(r)
	if err != nil {
		response.Unauthorized(w, err.Error())
		return
	}

	if !user.IsAdmin {
		limit, err := h.DB.GetSubdomainLimit(r.Context(), user.Plan)
		if err == nil && limit == 0 {
			response.Error(w, http.StatusPaymentRequired,
				"your plan does not include reserved subdomains — upgrade to Student, Pro, or Org")
			return
		}
		if err == nil && limit > 0 {
			count, _ := h.DB.GetSubdomainCount(r.Context(), user.ID)
			if count >= limit {
				response.Error(w, http.StatusPaymentRequired,
					fmt.Sprintf("plan limit reached: your %s plan allows %d reserved subdomain(s)", user.Plan, limit))
				return
			}
		}
	}

	var body struct {
		Subdomain string `json:"subdomain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid request body")
		return
	}
	subdomain := strings.ToLower(strings.TrimSpace(body.Subdomain))
	if subdomain == "" {
		response.BadRequest(w, "subdomain is required")
		return
	}
	for _, c := range subdomain {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
			response.BadRequest(w, "subdomain may only contain lowercase letters, digits, and hyphens")
			return
		}
	}

	s, err := h.DB.CreateReservedSubdomain(r.Context(), user.ID, subdomain)
	if err != nil {
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			response.Conflict(w, "subdomain already reserved")
			return
		}
		response.InternalError(w, err)
		return
	}
	response.Created(w, s)
}

// DeleteCLI handles DELETE /api/cli/subdomains/{id} using an API token.
func (h *SubdomainHandler) DeleteCLI(w http.ResponseWriter, r *http.Request) {
	user, err := h.userFromAPIToken(r)
	if err != nil {
		response.Unauthorized(w, err.Error())
		return
	}

	id := r.PathValue("id")
	if id == "" {
		response.BadRequest(w, "missing id")
		return
	}

	s, err := h.DB.GetReservedSubdomain(r.Context(), id)
	if err != nil {
		response.NotFound(w, "subdomain not found")
		return
	}
	if s.UserID != user.ID && !user.IsAdmin {
		response.Forbidden(w, "not your subdomain")
		return
	}

	if err := h.DB.DeleteReservedSubdomain(r.Context(), id, user.ID); err != nil {
		response.InternalError(w, err)
		return
	}
	response.NoContent(w)
}

// Delete handles DELETE /api/subdomains/{id}
func (h *SubdomainHandler) Delete(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		response.BadRequest(w, "missing id")
		return
	}
	if err := h.DB.DeleteReservedSubdomain(r.Context(), id, claims.UserID); err != nil {
		response.InternalError(w, err)
		return
	}
	response.NoContent(w)
}

// UpsertRule handles PUT /api/subdomains/{id}/rule
func (h *SubdomainHandler) UpsertRule(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		response.BadRequest(w, "missing id")
		return
	}

	s, err := h.DB.GetReservedSubdomain(r.Context(), id)
	if err != nil {
		response.NotFound(w, "subdomain not found")
		return
	}
	if s.UserID != claims.UserID && !claims.IsAdmin {
		response.Forbidden(w, "not your subdomain")
		return
	}

	var body models.SubdomainRule
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid request body")
		return
	}
	body.SubdomainID = id

	rule, err := h.DB.UpsertSubdomainRule(r.Context(), &body)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	response.Success(w, rule)
}

// Analytics handles GET /api/subdomains/analytics
func (h *SubdomainHandler) Analytics(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}
	data, err := h.DB.GetSubdomainAnalytics(r.Context(), claims.UserID)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	if data == nil {
		data = []*db.SubdomainAnalytics{}
	}
	response.Success(w, data)
}
