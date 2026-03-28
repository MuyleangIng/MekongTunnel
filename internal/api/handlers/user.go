package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/MuyleangIng/MekongTunnel/internal/api/middleware"
	"github.com/MuyleangIng/MekongTunnel/internal/api/response"
	"github.com/MuyleangIng/MekongTunnel/internal/auth"
	"github.com/MuyleangIng/MekongTunnel/internal/db"
	"github.com/MuyleangIng/MekongTunnel/internal/notify"
)

var validVerifyTypes = map[string]bool{
	"student": true,
	"teacher": true,
	"org":     true,
}

// UserHandler handles /api/user/* endpoints.
type UserHandler struct {
	DB     *db.DB
	Notify *notify.Service
}

// UpdateProfile handles PUT /api/user.
func (h *UserHandler) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	var body struct {
		Name      string `json:"name"`
		AvatarURL string `json:"avatar_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid JSON body")
		return
	}

	fields := map[string]any{}
	if body.Name != "" {
		fields["name"] = strings.TrimSpace(body.Name)
	}
	if body.AvatarURL != "" {
		fields["avatar_url"] = body.AvatarURL
	}

	if len(fields) == 0 {
		response.BadRequest(w, "nothing to update")
		return
	}

	user, err := h.DB.UpdateUser(r.Context(), claims.UserID, fields)
	if err != nil {
		response.InternalError(w, err)
		return
	}

	response.Success(w, sanitizeUser(user))
}

// UpdatePassword handles PUT /api/user/password.
func (h *UserHandler) UpdatePassword(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	var body struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid JSON body")
		return
	}

	if body.NewPassword == "" {
		response.BadRequest(w, "new_password is required")
		return
	}
	if len(body.NewPassword) < 8 {
		response.BadRequest(w, "new password must be at least 8 characters")
		return
	}

	user, err := h.DB.GetUserByID(r.Context(), claims.UserID)
	if err != nil {
		response.NotFound(w, "user not found")
		return
	}

	if user.ForcePasswordReset {
		// Provisioned users must be able to set a new password immediately after login
		// without re-entering the temporary password.
	} else {
		if body.CurrentPassword == "" {
			response.BadRequest(w, "current_password is required")
			return
		}
		if user.PasswordHash == nil || !auth.CheckPassword(*user.PasswordHash, body.CurrentPassword) {
			response.Unauthorized(w, "current password is incorrect")
			return
		}
	}

	newHash, err := auth.HashPassword(body.NewPassword)
	if err != nil {
		response.InternalError(w, err)
		return
	}

	if err := h.DB.UpdatePassword(r.Context(), claims.UserID, newHash); err != nil {
		response.InternalError(w, err)
		return
	}
	_ = h.DB.SetForcePasswordReset(r.Context(), claims.UserID, false)

	response.Success(w, map[string]any{"message": "password updated"})
}

// DeleteAccount handles DELETE /api/user.
func (h *UserHandler) DeleteAccount(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid JSON body")
		return
	}

	user, err := h.DB.GetUserByID(r.Context(), claims.UserID)
	if err != nil {
		response.NotFound(w, "user not found")
		return
	}

	// Password users must confirm with password; OAuth users can proceed.
	if user.PasswordHash != nil {
		if body.Password == "" {
			response.BadRequest(w, "password confirmation required")
			return
		}
		if !auth.CheckPassword(*user.PasswordHash, body.Password) {
			response.Unauthorized(w, "password is incorrect")
			return
		}
	}

	if err := h.DB.DeleteUser(r.Context(), claims.UserID); err != nil {
		response.InternalError(w, err)
		return
	}

	// Clear refresh cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     "mekong_refresh",
		Value:    "",
		Path:     "/api/auth/refresh",
		HttpOnly: true,
		MaxAge:   -1,
	})

	response.Success(w, map[string]any{"message": "account deleted"})
}

// SetActivePlan handles PATCH /api/user/plan — switches the user's active plan.
// The user can only activate a plan they're authorized for:
//   - Verified plans (student/teacher): requires an approved verify request of that type.
//   - Paid plans (pro/org): requires subscription_plan to match.
//   - free: always allowed.
func (h *UserHandler) SetActivePlan(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	var body struct {
		Plan string `json:"plan"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid JSON body")
		return
	}
	body.Plan = strings.ToLower(strings.TrimSpace(body.Plan))
	validPlans := map[string]bool{"free": true, "student": true, "teacher": true, "pro": true, "org": true}
	if !validPlans[body.Plan] {
		response.BadRequest(w, "plan must be one of: free, student, teacher, pro, org")
		return
	}

	user, err := h.DB.GetUserByID(r.Context(), claims.UserID)
	if err != nil {
		response.NotFound(w, "user not found")
		return
	}

	// Validate authorization for the requested plan.
	switch body.Plan {
	case "free":
		// always allowed
	case "student", "teacher":
		approvedType, err := h.DB.GetApprovedVerifyType(r.Context(), claims.UserID)
		if err != nil || approvedType != body.Plan {
			response.Error(w, http.StatusForbidden, "no approved verification for plan: "+body.Plan)
			return
		}
	case "pro", "org":
		if user.SubscriptionPlan != body.Plan {
			response.Error(w, http.StatusForbidden, "no active subscription for plan: "+body.Plan)
			return
		}
	}

	updated, err := h.DB.UpdateUser(r.Context(), claims.UserID, map[string]any{"plan": body.Plan})
	if err != nil {
		response.InternalError(w, err)
		return
	}

	if body.Plan == "org" {
		if org, _, err := h.DB.GetMyOrg(r.Context(), claims.UserID); err == nil && org != nil && org.OwnerID != nil && *org.OwnerID == claims.UserID && org.Status == "pending" {
			_ = h.DB.UpdateOrganizationStatus(r.Context(), org.ID, "active")
			if h.Notify != nil {
				go h.Notify.Send(context.Background(), claims.UserID, "org_plan_activated",
					"Organization plan active",
					"Your Organization workspace is now active and ready to manage.",
					"/dashboard/org")
			}
		}
	}

	response.Success(w, sanitizeUser(updated))
}

// GetVerifyRequest handles GET /api/user/verify-request.
func (h *UserHandler) GetVerifyRequest(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	vr, err := h.DB.GetVerifyRequestByUser(r.Context(), claims.UserID)
	if err != nil {
		// No request yet — return null
		response.Success(w, nil)
		return
	}

	response.Success(w, vr)
}

// SubmitVerifyRequest handles POST /api/user/verify-request.
func (h *UserHandler) SubmitVerifyRequest(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	var body struct {
		Type                 string `json:"type"`
		OrgName              string `json:"org_name"`
		Reason               string `json:"reason"`
		DocumentURL          string `json:"document_url"`
		RequestedOrgDomain   string `json:"requested_org_domain"`
		RequestedOrgSeatLimit int   `json:"requested_org_seat_limit"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid JSON body")
		return
	}

	body.Type = strings.ToLower(strings.TrimSpace(body.Type))
	if !validVerifyTypes[body.Type] {
		response.BadRequest(w, "type must be one of: student, teacher, org")
		return
	}
	body.OrgName = strings.TrimSpace(body.OrgName)
	body.Reason = strings.TrimSpace(body.Reason)
	body.DocumentURL = strings.TrimSpace(body.DocumentURL)
	body.RequestedOrgDomain = strings.ToLower(strings.TrimSpace(body.RequestedOrgDomain))
	if body.Type == "org" {
		if body.RequestedOrgSeatLimit < 1 {
			body.RequestedOrgSeatLimit = 25
		}
	} else {
		body.RequestedOrgDomain = ""
		body.RequestedOrgSeatLimit = 0
	}

	vr, err := h.DB.UpsertVerifyRequest(
		r.Context(),
		claims.UserID,
		body.Type,
		body.OrgName,
		body.Reason,
		body.DocumentURL,
		body.RequestedOrgDomain,
		body.RequestedOrgSeatLimit,
	)
	if err != nil {
		response.InternalError(w, err)
		return
	}

	// Notify admins about the new verify request.
	if h.Notify != nil {
		user, _ := h.DB.GetUserByID(r.Context(), claims.UserID)
		name := claims.UserID
		if user != nil {
			name = user.Name + " (" + user.Email + ")"
		}
		if body.Type == "org" && body.RequestedOrgDomain != "" {
			name += " requested org domain " + body.RequestedOrgDomain
		}
		go h.Notify.SendToAdmins(context.Background(), "verify_submitted",
			"New verification request",
			name+" submitted a "+body.Type+" verification request",
			"/admin/verify-requests")
	}

	response.Success(w, vr)
}
