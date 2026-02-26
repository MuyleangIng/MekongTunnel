// Tests for the token-bucket rate limiter.
//
// Author: Ing Muyleang (អុឹង មួយលៀង) — Ing_Muyleang
package tunnel

import (
	"testing"
	"time"
)

func TestRateLimiter_BurstCapacity(t *testing.T) {
	rl := NewRateLimiter(10, 5) // 10 tokens/sec, burst of 5

	for i := 0; i < 5; i++ {
		if !rl.Allow() {
			t.Fatalf("Allow() returned false on burst request %d", i+1)
		}
	}
}

func TestRateLimiter_LimitAfterBurst(t *testing.T) {
	rl := NewRateLimiter(10, 5)

	for i := 0; i < 5; i++ {
		rl.Allow()
	}

	if rl.Allow() {
		t.Error("Allow() should return false after burst exhausted")
	}
}

func TestRateLimiter_TokenRefill(t *testing.T) {
	rl := NewRateLimiter(10, 5)

	for i := 0; i < 5; i++ {
		rl.Allow()
	}

	// At 10 tokens/sec, 150ms should yield ~1.5 new tokens
	time.Sleep(150 * time.Millisecond)

	if !rl.Allow() {
		t.Error("Allow() should return true after token refill")
	}
}
