package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/MuyleangIng/MekongTunnel/internal/api/response"
	"github.com/MuyleangIng/MekongTunnel/internal/db"
)

// EdgeAuthHandler exposes internal token/domain lookups for the tunnel edge.
// Every route using this handler must be wrapped by InternalSecretMiddleware.
type EdgeAuthHandler struct {
	DB *db.DB
}

func (h *EdgeAuthHandler) ValidateToken(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid request body")
		return
	}
	if body.Token == "" {
		response.BadRequest(w, "token required")
		return
	}

	userID, err := h.DB.ValidateToken(r.Context(), body.Token)
	if err != nil {
		response.Unauthorized(w, "invalid token")
		return
	}
	response.Success(w, map[string]any{"user_id": userID})
}

func (h *EdgeAuthHandler) GetFirstReservedSubdomain(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		response.BadRequest(w, "user_id required")
		return
	}
	subdomain, err := h.DB.GetFirstReservedSubdomain(r.Context(), userID)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	response.Success(w, map[string]any{"subdomain": subdomain})
}

func (h *EdgeAuthHandler) GetReservedSubdomainForUser(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")
	subdomain := r.URL.Query().Get("subdomain")
	if userID == "" || subdomain == "" {
		response.BadRequest(w, "user_id and subdomain are required")
		return
	}
	reserved, err := h.DB.GetReservedSubdomainForUser(r.Context(), userID, subdomain)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	response.Success(w, map[string]any{"subdomain": reserved})
}

func (h *EdgeAuthHandler) LookupCustomDomainTarget(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		response.BadRequest(w, "host required")
		return
	}
	target, found, err := h.DB.LookupVerifiedCustomDomainTarget(r.Context(), host)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	response.Success(w, map[string]any{
		"target_subdomain": target,
		"found":            found,
	})
}

func (h *EdgeAuthHandler) ReservedSubdomainExists(w http.ResponseWriter, r *http.Request) {
	subdomain := r.URL.Query().Get("subdomain")
	if subdomain == "" {
		response.BadRequest(w, "subdomain required")
		return
	}
	exists, err := h.DB.ReservedSubdomainExists(r.Context(), subdomain)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	response.Success(w, map[string]any{"exists": exists})
}

func (h *EdgeAuthHandler) GetTunnelLastSeen(w http.ResponseWriter, r *http.Request) {
	subdomain := r.URL.Query().Get("subdomain")
	if subdomain == "" {
		response.BadRequest(w, "subdomain required")
		return
	}
	lastSeen, err := h.DB.GetTunnelLastSeen(r.Context(), subdomain)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	response.Success(w, map[string]any{"last_seen_at": lastSeen})
}
