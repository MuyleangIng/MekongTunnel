// Package middleware provides HTTP middleware for the MekongTunnel API.
// Author: Ing Muyleang (អុឹង មួយលៀង) — Ing_Muyleang
package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/MuyleangIng/MekongTunnel/internal/api/response"
	"github.com/MuyleangIng/MekongTunnel/internal/auth"
	"github.com/MuyleangIng/MekongTunnel/internal/db"
)

type contextKey string

// UserKey is the context key under which *auth.JWTClaims is stored.
const UserKey contextKey = "user"

// mustResetAllowedPaths lists the only paths accessible when MustReset is true.
var mustResetAllowedPaths = map[string]bool{
	"/api/user/password": true,
	"/api/auth/me":       true,
	"/api/auth/logout":   true,
}

// AuthMiddleware validates the Bearer JWT and rejects requests with no or invalid token.
func AuthMiddleware(jwtSecret string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, err := extractClaims(r, jwtSecret)
			if err != nil {
				response.Unauthorized(w, "authentication required")
				return
			}
			if claims.Temp2FA {
				response.Unauthorized(w, "2fa verification required")
				return
			}
			if claims.MustReset && !mustResetAllowedPaths[r.URL.Path] {
				response.Error(w, http.StatusForbidden, "password_reset_required")
				return
			}
			ctx := context.WithValue(r.Context(), UserKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// AuthOrAPITokenMiddleware accepts either a normal dashboard JWT or a CLI API token.
// API tokens are expanded into JWT-like claims by loading the owning user from the DB.
func AuthOrAPITokenMiddleware(jwtSecret string, database *db.DB) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, err := extractClaimsOrAPIToken(r, jwtSecret, database)
			if err != nil {
				response.Unauthorized(w, "authentication required")
				return
			}
			if claims.Temp2FA {
				response.Unauthorized(w, "2fa verification required")
				return
			}
			if claims.MustReset && !mustResetAllowedPaths[r.URL.Path] {
				response.Error(w, http.StatusForbidden, "password_reset_required")
				return
			}
			ctx := context.WithValue(r.Context(), UserKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// InternalSecretMiddleware restricts an endpoint to callers that supply the correct
// X-Tunnel-Secret header. If secret is empty the check is skipped (single-node dev mode).
func InternalSecretMiddleware(secret string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if secret != "" && r.Header.Get("X-Tunnel-Secret") != secret {
				response.Forbidden(w, "internal endpoint")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// AdminMiddleware rejects requests from non-admin users.
// Must be chained AFTER AuthMiddleware.
func AdminMiddleware() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := GetClaims(r)
			if claims == nil || !claims.IsAdmin {
				response.Forbidden(w, "admin access required")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// OptionalAuthMiddleware extracts claims if a token is present but does NOT
// reject unauthenticated requests — it simply stores nil in the context.
func OptionalAuthMiddleware(jwtSecret string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, _ := extractClaims(r, jwtSecret)
			ctx := context.WithValue(r.Context(), UserKey, claims) // may be nil
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetClaims retrieves the JWT claims from the request context.
// Returns nil if no claims are present (unauthenticated request).
func GetClaims(r *http.Request) *auth.JWTClaims {
	val := r.Context().Value(UserKey)
	if val == nil {
		return nil
	}
	claims, _ := val.(*auth.JWTClaims)
	return claims
}

// ParseTokenString validates a raw JWT string (used for SSE ?token= auth).
func ParseTokenString(token, secret string) *auth.JWTClaims {
	if token == "" {
		return nil
	}
	claims, err := auth.ValidateToken(token, secret)
	if err != nil {
		return nil
	}
	return claims
}

// extractClaims reads the Authorization header and validates the token.
func extractClaims(r *http.Request, secret string) (*auth.JWTClaims, error) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return nil, http.ErrNoCookie // sentinel
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return nil, http.ErrNoCookie
	}
	return auth.ValidateToken(parts[1], secret)
}

func extractClaimsOrAPIToken(r *http.Request, secret string, database *db.DB) (*auth.JWTClaims, error) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return nil, http.ErrNoCookie
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return nil, http.ErrNoCookie
	}

	rawToken := parts[1]
	if claims, err := auth.ValidateToken(rawToken, secret); err == nil {
		return claims, nil
	}
	if database == nil {
		return nil, http.ErrNoCookie
	}

	userID, err := database.ValidateToken(r.Context(), rawToken)
	if err != nil {
		return nil, err
	}
	user, err := database.GetUserByID(r.Context(), userID)
	if err != nil {
		return nil, err
	}

	return &auth.JWTClaims{
		UserID:    user.ID,
		Email:     user.Email,
		Plan:      user.Plan,
		IsAdmin:   user.IsAdmin,
		MustReset: user.ForcePasswordReset,
	}, nil
}
