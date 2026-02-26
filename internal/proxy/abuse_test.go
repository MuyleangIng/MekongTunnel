// Tests for the AbuseTracker in the proxy package.
//
// Author: Ing Muyleang (អុឹង មួយលៀង) — Ing_Muyleang
package proxy

import (
	"sync"
	"testing"
	"time"
)

func newTestTracker(t *testing.T) *AbuseTracker {
	t.Helper()
	at := NewAbuseTracker()
	t.Cleanup(func() { at.Stop() })
	return at
}

func TestAbuseTracker_BlockIP(t *testing.T) {
	at := newTestTracker(t)

	expiry := at.GetBlockExpiry("1.2.3.4")
	if !expiry.IsZero() {
		t.Error("unblocked IP should have zero expiry")
	}

	at.BlockIP("1.2.3.4")

	expiry = at.GetBlockExpiry("1.2.3.4")
	if expiry.IsZero() {
		t.Error("blocked IP should have non-zero expiry")
	}
	if time.Until(expiry) <= 0 {
		t.Error("block expiry should be in the future")
	}
}

func TestAbuseTracker_BlockExpiry_Expired(t *testing.T) {
	at := newTestTracker(t)

	at.mu.Lock()
	at.blockedIPs["1.2.3.4"] = time.Now().Add(-1 * time.Hour)
	at.mu.Unlock()

	expiry := at.GetBlockExpiry("1.2.3.4")
	if !expiry.IsZero() {
		t.Error("expired block should return zero expiry")
	}
}

func TestAbuseTracker_CheckConnectionRate_Allowed(t *testing.T) {
	at := newTestTracker(t)

	for i := 0; i < 10; i++ {
		if !at.CheckConnectionRate("1.2.3.4") {
			t.Fatalf("CheckConnectionRate() returned false on connection %d", i+1)
		}
	}
}

func TestAbuseTracker_CheckConnectionRate_Limited(t *testing.T) {
	at := newTestTracker(t)

	for i := 0; i < 10; i++ {
		at.CheckConnectionRate("1.2.3.4")
	}

	if at.CheckConnectionRate("1.2.3.4") {
		t.Error("CheckConnectionRate() should return false when rate limited")
	}
}

func TestAbuseTracker_CheckConnectionRate_AutoBlock(t *testing.T) {
	at := newTestTracker(t)

	for i := 0; i < 10; i++ {
		at.CheckConnectionRate("1.2.3.4")
	}

	for i := 0; i < 10; i++ {
		at.CheckConnectionRate("1.2.3.4")
	}

	expiry := at.GetBlockExpiry("1.2.3.4")
	if expiry.IsZero() {
		t.Error("IP should be auto-blocked after repeated violations")
	}
}

func TestAbuseTracker_OnBlockCallback(t *testing.T) {
	at := newTestTracker(t)

	var mu sync.Mutex
	var blockedIP string
	done := make(chan struct{})

	at.SetOnBlockCallback(func(ip string) {
		mu.Lock()
		blockedIP = ip
		mu.Unlock()
		close(done)
	})

	at.BlockIP("5.6.7.8")

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("onBlock callback not called within timeout")
	}

	mu.Lock()
	if blockedIP != "5.6.7.8" {
		t.Errorf("callback got IP %q, want %q", blockedIP, "5.6.7.8")
	}
	mu.Unlock()
}

func TestAbuseTracker_GetStats(t *testing.T) {
	at := newTestTracker(t)

	blockedIPs, totalBlocked, totalRateLimited := at.GetStats()
	if blockedIPs != 0 || totalBlocked != 0 || totalRateLimited != 0 {
		t.Error("new tracker should have zero stats")
	}

	at.BlockIP("1.2.3.4")

	blockedIPs, totalBlocked, _ = at.GetStats()
	if blockedIPs != 1 {
		t.Errorf("blockedIPs = %d, want 1", blockedIPs)
	}
	if totalBlocked != 1 {
		t.Errorf("totalBlocked = %d, want 1", totalBlocked)
	}
}

func TestAbuseTracker_GetStats_RateLimited(t *testing.T) {
	at := newTestTracker(t)

	for i := 0; i < 10; i++ {
		at.CheckConnectionRate("1.2.3.4")
	}
	at.CheckConnectionRate("1.2.3.4")

	_, _, totalRateLimited := at.GetStats()
	if totalRateLimited != 1 {
		t.Errorf("totalRateLimited = %d, want 1", totalRateLimited)
	}
}

func TestAbuseTracker_Stop(t *testing.T) {
	at := NewAbuseTracker()
	at.Stop()
}

func TestAbuseTracker_DifferentIPs(t *testing.T) {
	at := newTestTracker(t)

	for i := 0; i < 10; i++ {
		at.CheckConnectionRate("1.1.1.1")
	}

	if !at.CheckConnectionRate("2.2.2.2") {
		t.Error("rate limiting one IP should not affect another")
	}
}
