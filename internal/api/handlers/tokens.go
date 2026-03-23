package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/MuyleangIng/MekongTunnel/internal/api/middleware"
	"github.com/MuyleangIng/MekongTunnel/internal/api/response"
	"github.com/MuyleangIng/MekongTunnel/internal/auth"
	"github.com/MuyleangIng/MekongTunnel/internal/db"
)

// TokensHandler manages API tokens.
type TokensHandler struct {
	DB *db.DB
}

// ListTokens handles GET /api/tokens.
func (h *TokensHandler) ListTokens(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	tokens, err := h.DB.ListAPITokens(r.Context(), claims.UserID)
	if err != nil {
		response.InternalError(w, err)
		return
	}

	response.Success(w, tokens)
}

// CreateToken handles POST /api/tokens.
func (h *TokensHandler) CreateToken(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid JSON body")
		return
	}
	if body.Name == "" {
		response.BadRequest(w, "name is required")
		return
	}

	fullToken, prefix, hash, err := auth.GenerateAPIToken()
	if err != nil {
		response.InternalError(w, err)
		return
	}

	token, err := h.DB.CreateAPIToken(r.Context(), claims.UserID, body.Name, hash, prefix)
	if err != nil {
		response.InternalError(w, err)
		return
	}

	// Return the full token value ONCE.
	response.Created(w, map[string]any{
		"token":  fullToken, // shown only at creation time
		"record": token,
	})
}

// RevokeToken handles DELETE /api/tokens/{id}.
func (h *TokensHandler) RevokeToken(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		response.BadRequest(w, "token id required")
		return
	}

	if err := h.DB.RevokeAPIToken(r.Context(), id, claims.UserID); err != nil {
		response.InternalError(w, err)
		return
	}

	response.Success(w, map[string]any{"message": "token revoked"})
}
