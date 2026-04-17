package middleware

import "net/http"

// SecurityHeaders adds defensive HTTP response headers to every API response.
// These apply even when the Go server is accessed directly (bypassing the Next.js proxy).
func SecurityHeaders() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			// Prevent MIME-type sniffing
			h.Set("X-Content-Type-Options", "nosniff")
			// Prevent this API being embedded in iframes
			h.Set("X-Frame-Options", "DENY")
			// Legacy XSS filter hint for older browsers
			h.Set("X-XSS-Protection", "1; mode=block")
			// Control referrer information
			h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
			// Force HTTPS for 2 years
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
			// Remove headers that advertise backend tech stack
			h.Del("Server")
			h.Del("X-Powered-By")
			next.ServeHTTP(w, r)
		})
	}
}
