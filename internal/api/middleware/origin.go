package middleware

import (
	"net/http"
	"strings"
)

// EnforceOrigin blocks browser-initiated requests whose Origin header is not in
// the allowed list. This is a server-side enforcement layer on top of CORS —
// browsers respect CORS headers, but CORS alone does not prevent a server from
// processing a forbidden-origin request. This middleware rejects it outright.
//
// Requests with no Origin header (CLI tools, API token clients, internal services)
// are allowed through and rely on auth middleware for access control.
func EnforceOrigin(allowedOrigins []string) func(http.Handler) http.Handler {
	allowed := make(map[string]struct{}, len(allowedOrigins))
	for _, o := range allowedOrigins {
		allowed[strings.TrimRight(o, "/")] = struct{}{}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			// No Origin header → not a browser cross-origin request.
			// CLI / API token / server-to-server clients are permitted;
			// they are still gated by AuthMiddleware on protected routes.
			if origin == "" {
				next.ServeHTTP(w, r)
				return
			}

			origin = strings.TrimRight(origin, "/")

			if _, ok := allowed[origin]; ok {
				next.ServeHTTP(w, r)
				return
			}

			// Always permit local development origins regardless of ALLOWED_ORIGINS env.
			if isLocalhostOrigin(origin) {
				next.ServeHTTP(w, r)
				return
			}

			http.Error(w, "Forbidden", http.StatusForbidden)
		})
	}
}
