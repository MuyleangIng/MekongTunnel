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
	scope, err := resolveResourceScope(r.Context(), h.DB, claims.UserID, requestedTeamID(r))
	if err != nil {
		if err == errResourceTeamNotFound {
			response.NotFound(w, "team not found")
			return
		}
		response.Forbidden(w, "you are not a member of this team")
		return
	}

	list, err := h.DB.ListReservedSubdomainsByScope(r.Context(), claims.UserID, scope.TeamID)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	if list == nil {
		list = []*models.ReservedSubdomain{}
	}

	limit := 0
	if scope.IsTeam() {
		limit = teamRouteLimit(scope.Team.Plan)
	} else {
		limit, _ = h.DB.GetSubdomainLimit(r.Context(), claims.Plan)
	}
	count := len(list)
	response.Success(w, map[string]any{
		"subdomains": list,
		"count":      count,
		"limit":      limit,
	})
}

// ListCLI handles GET /api/cli/subdomains using an API token.
func (h *SubdomainHandler) ListCLI(w http.ResponseWriter, r *http.Request) {
	user, err := h.userFromAPIToken(r)
	if err != nil {
		response.Unauthorized(w, err.Error())
		return
	}

	scope, err := resolveResourceScope(r.Context(), h.DB, user.ID, requestedTeamID(r))
	if err != nil {
		if err == errResourceTeamNotFound {
			response.NotFound(w, "team not found")
			return
		}
		response.Forbidden(w, "you are not a member of this team")
		return
	}

	list, err := h.DB.ListReservedSubdomainsByScope(r.Context(), user.ID, scope.TeamID)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	if list == nil {
		list = []*models.ReservedSubdomain{}
	}

	limit := 0
	if scope.IsTeam() {
		limit = teamRouteLimit(scope.Team.Plan)
	} else {
		limit, _ = h.DB.GetSubdomainLimit(r.Context(), user.Plan)
	}
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

	scope, err := resolveResourceScope(r.Context(), h.DB, claims.UserID, requestedTeamID(r))
	if err != nil {
		if err == errResourceTeamNotFound {
			response.NotFound(w, "team not found")
			return
		}
		response.Forbidden(w, "you are not a member of this team")
		return
	}
	if scope.IsTeam() && !claims.IsAdmin && !scope.CanManage() {
		response.Forbidden(w, "only owner, admin, or teacher can manage team subdomains")
		return
	}

	// Check plan limit
	if !claims.IsAdmin {
		if scope.IsTeam() {
			limit := teamRouteLimit(scope.Team.Plan)
			if limit == 0 {
				response.Error(w, http.StatusPaymentRequired,
					"this team plan does not include reserved subdomains")
				return
			}
			if limit > 0 {
				count, _ := h.DB.GetSubdomainCountByScope(r.Context(), claims.UserID, scope.TeamID)
				if count >= limit {
					response.Error(w, http.StatusPaymentRequired,
						fmt.Sprintf("team plan limit reached: this %s team allows %d reserved subdomain(s)", scope.Team.Plan, limit))
					return
				}
			}
		} else {
			limit, err := h.DB.GetSubdomainLimit(r.Context(), claims.Plan)
			if err == nil && limit == 0 {
				response.Error(w, http.StatusPaymentRequired,
					"your plan does not include reserved subdomains — upgrade to Student, Pro, or Org")
				return
			}
			if err == nil && limit > 0 {
				count, _ := h.DB.GetSubdomainCountByScope(r.Context(), claims.UserID, "")
				if count >= limit {
					response.Error(w, http.StatusPaymentRequired,
						fmt.Sprintf("plan limit reached: your %s plan allows %d reserved subdomain(s)", claims.Plan, limit))
					return
				}
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

	ownerUserID := claims.UserID
	if scope.IsTeam() {
		ownerUserID = ""
	}
	s, err := h.DB.CreateReservedSubdomainByScope(r.Context(), ownerUserID, scope.TeamID, subdomain)
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

	scope, err := resolveResourceScope(r.Context(), h.DB, user.ID, requestedTeamID(r))
	if err != nil {
		if err == errResourceTeamNotFound {
			response.NotFound(w, "team not found")
			return
		}
		response.Forbidden(w, "you are not a member of this team")
		return
	}
	if scope.IsTeam() && !user.IsAdmin && !scope.CanManage() {
		response.Forbidden(w, "only owner, admin, or teacher can manage team subdomains")
		return
	}

	if !user.IsAdmin {
		if scope.IsTeam() {
			limit := teamRouteLimit(scope.Team.Plan)
			if limit == 0 {
				response.Error(w, http.StatusPaymentRequired,
					"this team plan does not include reserved subdomains")
				return
			}
			if limit > 0 {
				count, _ := h.DB.GetSubdomainCountByScope(r.Context(), user.ID, scope.TeamID)
				if count >= limit {
					response.Error(w, http.StatusPaymentRequired,
						fmt.Sprintf("team plan limit reached: this %s team allows %d reserved subdomain(s)", scope.Team.Plan, limit))
					return
				}
			}
		} else {
			limit, err := h.DB.GetSubdomainLimit(r.Context(), user.Plan)
			if err == nil && limit == 0 {
				response.Error(w, http.StatusPaymentRequired,
					"your plan does not include reserved subdomains — upgrade to Student, Pro, or Org")
				return
			}
			if err == nil && limit > 0 {
				count, _ := h.DB.GetSubdomainCountByScope(r.Context(), user.ID, "")
				if count >= limit {
					response.Error(w, http.StatusPaymentRequired,
						fmt.Sprintf("plan limit reached: your %s plan allows %d reserved subdomain(s)", user.Plan, limit))
					return
				}
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

	ownerUserID := user.ID
	if scope.IsTeam() {
		ownerUserID = ""
	}
	s, err := h.DB.CreateReservedSubdomainByScope(r.Context(), ownerUserID, scope.TeamID, subdomain)
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
	scope, err := resolveResourceScope(r.Context(), h.DB, user.ID, requestedTeamID(r))
	if err != nil {
		if err == errResourceTeamNotFound {
			response.NotFound(w, "team not found")
			return
		}
		response.Forbidden(w, "you are not a member of this team")
		return
	}
	if scope.IsTeam() && !user.IsAdmin && !scope.CanManage() {
		response.Forbidden(w, "only owner, admin, or teacher can manage team subdomains")
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
	if scope.IsTeam() {
		if s.TeamID == nil || *s.TeamID != scope.TeamID {
			response.NotFound(w, "subdomain not found")
			return
		}
	} else if s.TeamID != nil || (s.UserID != user.ID && !user.IsAdmin) {
		response.Forbidden(w, "not your subdomain")
		return
	}

	if err := h.DB.DeleteReservedSubdomainByScope(r.Context(), id, user.ID, scope.TeamID); err != nil {
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
	scope, err := resolveResourceScope(r.Context(), h.DB, claims.UserID, requestedTeamID(r))
	if err != nil {
		if err == errResourceTeamNotFound {
			response.NotFound(w, "team not found")
			return
		}
		response.Forbidden(w, "you are not a member of this team")
		return
	}
	if scope.IsTeam() && !claims.IsAdmin && !scope.CanManage() {
		response.Forbidden(w, "only owner, admin, or teacher can manage team subdomains")
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
	if scope.IsTeam() {
		if s.TeamID == nil || *s.TeamID != scope.TeamID {
			response.NotFound(w, "subdomain not found")
			return
		}
	} else if s.TeamID != nil || s.UserID != claims.UserID {
		response.Forbidden(w, "not your subdomain")
		return
	}
	if err := h.DB.DeleteReservedSubdomainByScope(r.Context(), id, claims.UserID, scope.TeamID); err != nil {
		response.InternalError(w, err)
		return
	}
	response.NoContent(w)
}

// UpdateAssignment handles PATCH /api/subdomains/{id}/assignment.
// Team-only endpoint for owner/admin/teacher to assign a reserved subdomain to one member.
func (h *SubdomainHandler) UpdateAssignment(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	scope, err := resolveResourceScope(r.Context(), h.DB, claims.UserID, requestedTeamID(r))
	if err != nil {
		if err == errResourceTeamNotFound {
			response.NotFound(w, "team not found")
			return
		}
		response.Forbidden(w, "you are not a member of this team")
		return
	}
	if !scope.IsTeam() {
		response.BadRequest(w, "team_id is required for subdomain assignment")
		return
	}
	if !claims.IsAdmin && !scope.CanManage() {
		response.Forbidden(w, "only owner, admin, or teacher can assign team subdomains")
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
	if s.TeamID == nil || *s.TeamID != scope.TeamID {
		response.NotFound(w, "subdomain not found")
		return
	}

	var body struct {
		AssignedUserID *string `json:"assigned_user_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid request body")
		return
	}

	assignedUserID := ""
	if body.AssignedUserID != nil {
		assignedUserID = strings.TrimSpace(*body.AssignedUserID)
	}
	if assignedUserID != "" && scope.Team.OwnerID != assignedUserID {
		if _, err := h.DB.GetTeamMembership(r.Context(), scope.TeamID, assignedUserID); err != nil {
			response.BadRequest(w, "assigned_user_id must belong to this team")
			return
		}
	}

	updated, err := h.DB.UpdateReservedSubdomainAssignment(r.Context(), id, scope.TeamID, assignedUserID)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	response.Success(w, updated)
}

// UpsertRule handles PUT /api/subdomains/{id}/rule
func (h *SubdomainHandler) UpsertRule(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}
	scope, err := resolveResourceScope(r.Context(), h.DB, claims.UserID, requestedTeamID(r))
	if err != nil {
		if err == errResourceTeamNotFound {
			response.NotFound(w, "team not found")
			return
		}
		response.Forbidden(w, "you are not a member of this team")
		return
	}
	if scope.IsTeam() && !claims.IsAdmin && !scope.CanManage() {
		response.Forbidden(w, "only owner, admin, or teacher can manage team subdomains")
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
	if scope.IsTeam() {
		if s.TeamID == nil || *s.TeamID != scope.TeamID {
			response.NotFound(w, "subdomain not found")
			return
		}
	} else if s.TeamID != nil || (s.UserID != claims.UserID && !claims.IsAdmin) {
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
	scope, err := resolveResourceScope(r.Context(), h.DB, claims.UserID, requestedTeamID(r))
	if err != nil {
		if err == errResourceTeamNotFound {
			response.NotFound(w, "team not found")
			return
		}
		response.Forbidden(w, "you are not a member of this team")
		return
	}
	data, err := h.DB.GetSubdomainAnalyticsByScope(r.Context(), claims.UserID, scope.TeamID)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	if data == nil {
		data = []*db.SubdomainAnalytics{}
	}
	response.Success(w, data)
}
