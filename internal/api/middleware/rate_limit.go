package middleware

import (
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/MuyleangIng/MekongTunnel/internal/api/response"
	"github.com/MuyleangIng/MekongTunnel/internal/redisx"
)

// RateLimitIP enforces a Redis-backed per-IP limit for a route group.
func RateLimitIP(redisClient *redisx.Client, bucket string, limit int, window time.Duration) func(http.Handler) http.Handler {
	if redisClient == nil || !redisClient.Enabled() || limit <= 0 || window <= 0 {
		return func(next http.Handler) http.Handler { return next }
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := clientIP(r)
			allowed, remaining, retryAfter, err := redisClient.AllowRateLimit(r.Context(), bucket, ip, limit, window)
			if err != nil {
				log.Printf("[api] redis rate limit %s: %v", bucket, err)
				next.ServeHTTP(w, r)
				return
			}

			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(limit))
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))

			if !allowed {
				if retryAfter > 0 {
					w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Round(time.Second).Seconds())))
				}
				response.Error(w, http.StatusTooManyRequests, "rate limit exceeded")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func clientIP(r *http.Request) string {
	for _, value := range []string{
		r.Header.Get("CF-Connecting-IP"),
		firstForwardedFor(r.Header.Get("X-Forwarded-For")),
	} {
		if ip := strings.TrimSpace(value); ip != "" {
			return ip
		}
	}

	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil && host != "" {
		return host
	}
	if ip := strings.TrimSpace(r.RemoteAddr); ip != "" {
		return ip
	}
	return "unknown"
}

func firstForwardedFor(value string) string {
	if value == "" {
		return ""
	}
	parts := strings.Split(value, ",")
	return strings.TrimSpace(parts[0])
}
