// Token-bucket rate limiter for per-tunnel HTTP request limiting.
// Each tunnel gets its own RateLimiter instance configured at
// 10 requests/second with a burst capacity of 20 tokens.
//
// Author: Ing Muyleang (អុឹង មួយលៀង) — Ing_Muyleang
package tunnel

import (
	"sync"
	"time"
)

// RateLimiter implements a token-bucket algorithm for rate limiting.
//
// Tokens refill at refillRate per second up to maxTokens.
// Each allowed request consumes one token.
// If no token is available the request is denied.
type RateLimiter struct {
	tokens     float64    // current token count
	maxTokens  float64    // maximum (burst) token capacity
	refillRate float64    // tokens added per second
	lastRefill time.Time  // time of last token refill
	mu         sync.Mutex // guards all fields
}

// NewRateLimiter creates a RateLimiter with the given sustained rate (tokens/s)
// and burst capacity. The bucket starts full (burst tokens available immediately).
func NewRateLimiter(rate float64, burst int) *RateLimiter {
	return &RateLimiter{
		tokens:     float64(burst),
		maxTokens:  float64(burst),
		refillRate: rate,
		lastRefill: time.Now(),
	}
}

// Allow returns true if a request is permitted (token available), false otherwise.
// It refills tokens based on elapsed time since the last call before deciding.
// Thread-safe.
func (r *RateLimiter) Allow() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(r.lastRefill).Seconds()
	r.tokens += elapsed * r.refillRate
	if r.tokens > r.maxTokens {
		r.tokens = r.maxTokens
	}
	r.lastRefill = now

	if r.tokens >= 1 {
		r.tokens--
		return true
	}
	return false
}
