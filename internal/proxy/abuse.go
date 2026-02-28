// Abuse protection for MekongTunnel.
// AbuseTracker tracks per-IP connection rates using a sliding time window,
// counts rate-limit violations, and auto-blocks IPs that abuse the service.
// A background goroutine cleans up stale entries every 5 minutes.
//
// Author: Ing Muyleang (អុឹង មួយលៀង) — Ing_Muyleang
package proxy

import (
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/MuyleangIng/MekongTunnel/internal/config"
)

// BlockCallback is invoked asynchronously whenever an IP is blocked.
// The Server uses this to force-close all SSH connections for that IP.
type BlockCallback func(ip string)

// AbuseTracker tracks connection patterns and blocks IPs that misbehave.
//
// It maintains three per-IP maps:
//   - connectionTimes: timestamps of recent connections (sliding window)
//   - violationCounts: how many times an IP has exceeded the rate limit
//   - blockedIPs:      IPs that are currently blocked and their expiry times
type AbuseTracker struct {
	mu sync.RWMutex

	connectionTimes map[string][]time.Time // recent connection timestamps per IP
	blockedIPs      map[string]time.Time   // blocked IPs → expiry time
	violationCounts map[string]int         // rate-limit violation count per IP

	onBlock BlockCallback // called (in a goroutine) when an IP is blocked

	// Atomic counters (no lock required for reads/writes)
	totalBlocked     atomic.Uint64
	totalRateLimited atomic.Uint64

	// Lifecycle channels for the cleanup goroutine
	stopCleanup chan struct{}
	cleanupDone chan struct{}
}

// NewAbuseTracker creates a new AbuseTracker and starts its background cleanup goroutine.
func NewAbuseTracker() *AbuseTracker {
	at := &AbuseTracker{
		connectionTimes: make(map[string][]time.Time),
		blockedIPs:      make(map[string]time.Time),
		violationCounts: make(map[string]int),
		stopCleanup:     make(chan struct{}),
		cleanupDone:     make(chan struct{}),
	}

	go at.cleanup()

	return at
}

// Stop gracefully stops the cleanup goroutine.
// Call this during application shutdown to ensure clean exit.
func (at *AbuseTracker) Stop() {
	close(at.stopCleanup)
	<-at.cleanupDone
}

// SetOnBlockCallback registers a callback that is invoked (in its own goroutine)
// each time an IP is blocked. Used by the Server to close SSH connections.
func (at *AbuseTracker) SetOnBlockCallback(cb BlockCallback) {
	at.mu.Lock()
	defer at.mu.Unlock()
	at.onBlock = cb
}

// callOnBlock invokes the onBlock callback in a new goroutine, recovering from panics.
// Must be called without the write lock held to prevent deadlocks.
func (at *AbuseTracker) callOnBlock(ip string) {
	at.mu.RLock()
	cb := at.onBlock
	at.mu.RUnlock()

	if cb != nil {
		go func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("Panic in onBlock callback for IP %s: %v", ip, r)
				}
			}()
			cb(ip)
		}()
	}
}

// GetBlockExpiry returns the expiry time for a blocked IP.
// Returns the zero time if the IP is not blocked or if the block has expired.
func (at *AbuseTracker) GetBlockExpiry(ip string) time.Time {
	at.mu.RLock()
	defer at.mu.RUnlock()

	expiry, blocked := at.blockedIPs[ip]
	if !blocked || time.Now().After(expiry) {
		return time.Time{}
	}
	return expiry
}

// BlockIP blocks ip for config.BlockDuration (default 1 hour) and triggers the onBlock callback.
func (at *AbuseTracker) BlockIP(ip string) {
	at.mu.Lock()
	at.blockedIPs[ip] = time.Now().Add(config.BlockDuration)
	at.mu.Unlock()

	at.totalBlocked.Add(1)
	at.callOnBlock(ip)
}

// CheckConnectionRate checks whether a new connection from ip should be allowed.
// Uses a sliding window of config.ConnectionRateWindow (1 minute).
//
// Returns true if allowed.
// Returns false and increments the violation counter if the rate limit is exceeded.
// After config.RateLimitViolationsMax (10) violations, the IP is automatically blocked.
func (at *AbuseTracker) CheckConnectionRate(ip string) bool {
	at.mu.Lock()

	now := time.Now()
	windowStart := now.Add(-config.ConnectionRateWindow)

	// Filter connection timestamps to the current window.
	times := at.connectionTimes[ip]
	validTimes := make([]time.Time, 0, len(times))
	for _, t := range times {
		if t.After(windowStart) {
			validTimes = append(validTimes, t)
		}
	}

	if len(validTimes) >= config.MaxConnectionsPerMinute {
		at.violationCounts[ip]++

		blocked := false
		if at.violationCounts[ip] >= config.RateLimitViolationsMax {
			// Auto-block: too many repeated rate-limit violations.
			at.blockedIPs[ip] = now.Add(config.BlockDuration)
			delete(at.violationCounts, ip)
			blocked = true
		}

		at.mu.Unlock()

		at.totalRateLimited.Add(1)
		if blocked {
			at.totalBlocked.Add(1)
			at.callOnBlock(ip)
		}
		return false
	}

	// Record this connection and allow it.
	validTimes = append(validTimes, now)
	at.connectionTimes[ip] = validTimes

	at.mu.Unlock()
	return true
}

// GetStats returns abuse-protection statistics:
//   - blockedIPs:      number of currently active (non-expired) IP blocks
//   - totalBlocked:    all-time count of IPs blocked
//   - totalRateLimited: all-time count of rate-limit rejections
func (at *AbuseTracker) GetStats() (blockedIPs int, totalBlocked uint64, totalRateLimited uint64) {
	at.mu.RLock()
	defer at.mu.RUnlock()

	now := time.Now()
	activeBlocks := 0
	for _, expiry := range at.blockedIPs {
		if expiry.After(now) {
			activeBlocks++
		}
	}

	return activeBlocks, at.totalBlocked.Load(), at.totalRateLimited.Load()
}

// cleanup runs every 5 minutes and removes stale entries from all three maps:
//   - Expired IP blocks
//   - Connection timestamps outside the rate-limit window
//   - Violation counts for IPs with no recent activity and no active block
func (at *AbuseTracker) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	defer close(at.cleanupDone)

	for {
		select {
		case <-at.stopCleanup:
			return
		case <-ticker.C:
			at.mu.Lock()

			now := time.Now()
			windowStart := now.Add(-config.ConnectionRateWindow)
			staleThreshold := now.Add(-2 * config.ConnectionRateWindow)

			// Remove connection timestamps that are outside the rate-limit window.
			for ip, times := range at.connectionTimes {
				validTimes := make([]time.Time, 0, len(times))
				for _, t := range times {
					if t.After(windowStart) {
						validTimes = append(validTimes, t)
					}
				}
				if len(validTimes) == 0 {
					delete(at.connectionTimes, ip)
				} else {
					mostRecent := validTimes[len(validTimes)-1]
					if mostRecent.Before(staleThreshold) {
						delete(at.connectionTimes, ip)
					} else {
						at.connectionTimes[ip] = validTimes
					}
				}
			}

			// Remove expired IP blocks.
			for ip, expiry := range at.blockedIPs {
				if expiry.Before(now) {
					delete(at.blockedIPs, ip)
				}
			}

			// Remove violation counts for IPs with no recent activity and no active block.
			for ip := range at.violationCounts {
				_, hasActivity := at.connectionTimes[ip]
				_, isBlocked := at.blockedIPs[ip]
				if !hasActivity && !isBlocked {
					delete(at.violationCounts, ip)
				}
			}

			at.mu.Unlock()
		}
	}
}
