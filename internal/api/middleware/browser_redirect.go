package middleware

import (
	"net/http"
	"strings"
)

// browserRedirectExcluded are paths that must NOT be redirected even when
// accessed from a browser — OAuth flows and callbacks require browser navigation.
var browserRedirectExcluded = map[string]bool{
	"/api/auth/github":          true,
	"/api/auth/github/callback": true,
	"/api/auth/google":          true,
	"/api/auth/google/callback": true,
	"/api/health":               true,
}

// BrowserRedirect sends any browser that visits the API domain straight to the
// frontend. The API is intended for programmatic access only — CLI tools, SDKs,
// and the Next.js proxy. When a user types api.mekongtunnel.dev in their browser
// they should land on mekongtunnel.dev, not see raw JSON.
//
// Detection: a request is a browser if its Accept header contains "text/html"
// AND its User-Agent contains "Mozilla" (every major browser sends both).
func BrowserRedirect(frontendURL string) func(http.Handler) http.Handler {
	target := strings.TrimRight(frontendURL, "/")

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Exact-path exclusions (OAuth callbacks, health check, etc.)
			if browserRedirectExcluded[r.URL.Path] {
				next.ServeHTTP(w, r)
				return
			}

			// Static file paths must be served directly to browsers and iframes.
			if strings.HasPrefix(r.URL.Path, "/api/uploads/") {
				next.ServeHTTP(w, r)
				return
			}

			accept := r.Header.Get("Accept")
			ua := r.Header.Get("User-Agent")
			isBrowser := strings.Contains(accept, "text/html") && strings.Contains(ua, "Mozilla")

			if isBrowser {
				http.Redirect(w, r, target, http.StatusFound)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
