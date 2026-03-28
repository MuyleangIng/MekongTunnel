package middleware

import (
	"net/http"
	"strings"
)

// isLocalhostOrigin returns true for any http://localhost:* or http://127.0.0.1:* origin.
// These are always allowed so local dev environments can reach the API without
// needing to add entries to the ALLOWED_ORIGINS env var.
func isLocalhostOrigin(origin string) bool {
	return strings.HasPrefix(origin, "http://localhost:") ||
		strings.HasPrefix(origin, "http://127.0.0.1:") ||
		origin == "http://localhost" ||
		origin == "http://127.0.0.1"
}

// CORSMiddleware adds CORS headers and handles preflight OPTIONS requests.
// allowedOrigins is a slice of allowed origin strings; use ["*"] to allow all.
// localhost and 127.0.0.1 origins are always allowed for local development.
func CORSMiddleware(allowedOrigins []string) func(next http.Handler) http.Handler {
	allowed := make(map[string]struct{}, len(allowedOrigins))
	for _, o := range allowedOrigins {
		allowed[o] = struct{}{}
	}
	wildcard := false
	for _, o := range allowedOrigins {
		if o == "*" {
			wildcard = true
			break
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" {
				if wildcard {
					w.Header().Set("Access-Control-Allow-Origin", "*")
				} else if _, ok := allowed[origin]; ok {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					w.Header().Set("Vary", "Origin")
				} else if isLocalhostOrigin(origin) {
					// Always allow localhost origins for local development.
					w.Header().Set("Access-Control-Allow-Origin", origin)
					w.Header().Set("Vary", "Origin")
				}
			}

			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers",
				strings.Join([]string{
					"Authorization",
					"Content-Type",
					"Accept",
					"X-Requested-With",
					"X-Api-Key",
				}, ", "))
			w.Header().Set("Access-Control-Max-Age", "86400")

			// Handle preflight.
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
