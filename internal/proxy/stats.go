// Metrics and statistics endpoint for MekongTunnel.
// The /stats endpoint (port 9090) is localhost-only and returns a JSON
// snapshot of active tunnels, unique IPs, lifetime counters, and abuse stats.
//
// Author: Ing Muyleang (អុឹង មួយលៀង) — Ing_Muyleang
package proxy

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"sync/atomic"
)

// Stats holds a point-in-time snapshot of server metrics.
// It is returned by the /stats HTTP endpoint as JSON.
type Stats struct {
	ActiveTunnels    int      `json:"active_tunnels"`    // number of currently open tunnels
	UniqueIPs        int      `json:"unique_ips"`        // number of unique client IPs with active tunnels
	TotalConnections uint64   `json:"total_connections"` // total SSH connections accepted since start
	TotalRequests    uint64   `json:"total_requests"`    // total HTTP requests proxied since start
	Subdomains       []string `json:"subdomains,omitempty"` // active subdomain list (optional)

	// Abuse protection counters
	BlockedIPs       int    `json:"blocked_ips"`        // currently active IP blocks
	TotalBlocked     uint64 `json:"total_blocked"`      // all-time IPs blocked
	TotalRateLimited uint64 `json:"total_rate_limited"` // all-time rate-limit rejections
}

// IncrementConnections atomically increments the total SSH connection counter.
// Called once per accepted SSH connection.
func (s *Server) IncrementConnections() {
	atomic.AddUint64(&s.totalConnections, 1)
}

// IncrementRequests atomically increments the total HTTP request counter.
// Called once per proxied HTTP request.
func (s *Server) IncrementRequests() {
	atomic.AddUint64(&s.totalRequests, 1)
}

// GetStats returns a Stats snapshot. If includeSubdomains is true,
// the Subdomains field is populated with all currently active subdomain names.
func (s *Server) GetStats(includeSubdomains bool) Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	blockedIPs, totalBlocked, totalRateLimited := s.abuseTracker.GetStats()

	stats := Stats{
		ActiveTunnels:    len(s.tunnels),
		UniqueIPs:        len(s.ipConnections),
		TotalConnections: atomic.LoadUint64(&s.totalConnections),
		TotalRequests:    atomic.LoadUint64(&s.totalRequests),
		BlockedIPs:       blockedIPs,
		TotalBlocked:     totalBlocked,
		TotalRateLimited: totalRateLimited,
	}

	if includeSubdomains {
		stats.Subdomains = make([]string, 0, len(s.tunnels))
		for sub := range s.tunnels {
			stats.Subdomains = append(stats.Subdomains, sub)
		}
	}

	return stats
}

// StatsHandler returns an http.Handler for the stats endpoint.
// Access is restricted to loopback addresses (127.0.0.1 / ::1).
// Query with ?subdomains=true to include the active subdomain list.
//
// Example:
//
//	curl http://127.0.0.1:9090/?subdomains=true
func (s *Server) StatsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reject all non-loopback callers.
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		includeSubdomains := r.URL.Query().Get("subdomains") == "true"
		stats := s.GetStats(includeSubdomains)

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(stats); err != nil {
			log.Printf("Failed to encode stats response: %v", err)
		}
	})
}
