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
	"time"
)

// TunnelDetail holds per-tunnel metrics for the dashboard.
type TunnelDetail struct {
	Subdomain     string `json:"subdomain"`
	ClientIP      string `json:"client_ip"`
	UptimeSecs    int64  `json:"uptime_secs"`
	RequestCount  uint64 `json:"request_count"`
}

// Stats holds a point-in-time snapshot of server metrics.
// It is returned by the /api/stats HTTP endpoint as JSON.
type Stats struct {
	ActiveTunnels    int            `json:"active_tunnels"`    // number of currently open tunnels
	UniqueIPs        int            `json:"unique_ips"`        // number of unique client IPs with active tunnels
	TotalConnections uint64         `json:"total_connections"` // total SSH connections accepted since start
	TotalRequests    uint64         `json:"total_requests"`    // total HTTP requests proxied since start
	Subdomains       []string       `json:"subdomains,omitempty"` // active subdomain list (optional)
	Tunnels          []TunnelDetail `json:"tunnels,omitempty"`    // per-tunnel details (optional)

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

	stats.Tunnels = make([]TunnelDetail, 0, len(s.tunnels))
	for _, t := range s.tunnels {
		stats.Tunnels = append(stats.Tunnels, TunnelDetail{
			Subdomain:    t.Subdomain,
			ClientIP:     t.ClientIP,
			UptimeSecs:   int64(time.Since(t.CreatedAt).Seconds()),
			RequestCount: t.RequestCount(),
		})
	}

	return stats
}

// StatsHandler returns an http.Handler that routes the stats port.
// Access is restricted to loopback addresses (127.0.0.1 / ::1).
//
//   - GET /          → HTML dashboard (auto-refreshes every 3 s)
//   - GET /api/stats → JSON snapshot (query ?subdomains=true to include subdomain list)
func (s *Server) StatsHandler() http.Handler {
	mux := http.NewServeMux()

	// Loopback guard shared by all routes.
	guard := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				host = r.RemoteAddr
			}
			ip := net.ParseIP(host)
			if ip == nil || !ip.IsLoopback() {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			next(w, r)
		}
	}

	// JSON API — kept at /api/stats; old /?subdomains=true still works via dashboard redirect.
	mux.HandleFunc("/api/stats", guard(func(w http.ResponseWriter, r *http.Request) {
		includeSubdomains := r.URL.Query().Get("subdomains") == "true"
		stats := s.GetStats(includeSubdomains)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(stats); err != nil {
			log.Printf("Failed to encode stats response: %v", err)
		}
	}))

	// HTML dashboard.
	mux.HandleFunc("/", guard(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(dashboardHTML))
	}))

	return mux
}

// dashboardHTML is the self-contained admin dashboard served at the stats port root.
// It polls /api/stats every 3 seconds and renders live data with no external dependencies.
const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MekongTunnel Dashboard</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0f1117;color:#e2e8f0;min-height:100vh;padding:2rem}
h1{font-size:1.5rem;font-weight:700;color:#7dd3fc;margin-bottom:.25rem}
.sub{color:#64748b;font-size:.85rem;margin-bottom:2rem}
.cards{display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:2rem}
.card{background:#1e2433;border:1px solid #2d3748;border-radius:.75rem;padding:1.25rem 1.75rem;min-width:160px;flex:1}
.card-label{font-size:.75rem;text-transform:uppercase;letter-spacing:.08em;color:#64748b;margin-bottom:.4rem}
.card-value{font-size:2rem;font-weight:700;color:#f8fafc}
.card-value.green{color:#4ade80}
.card-value.red{color:#f87171}
.card-value.blue{color:#60a5fa}
table{width:100%;border-collapse:collapse;background:#1e2433;border:1px solid #2d3748;border-radius:.75rem;overflow:hidden}
th{background:#16213a;padding:.75rem 1rem;text-align:left;font-size:.75rem;text-transform:uppercase;letter-spacing:.08em;color:#64748b;font-weight:600}
td{padding:.75rem 1rem;border-top:1px solid #2d3748;font-size:.875rem;font-family:'Courier New',monospace}
td.plain{font-family:'Segoe UI',system-ui,sans-serif}
tr:hover td{background:#243049}
.badge{display:inline-block;padding:.15rem .5rem;border-radius:9999px;font-size:.7rem;font-weight:600}
.badge-green{background:#14532d;color:#4ade80}
.empty{padding:2rem;text-align:center;color:#475569}
.footer{margin-top:1.5rem;font-size:.75rem;color:#334155;text-align:right}
#status{display:inline-block;width:8px;height:8px;border-radius:50%;background:#4ade80;margin-right:.4rem;vertical-align:middle}
#status.error{background:#f87171}
</style>
</head>
<body>
<h1>&#9670; MekongTunnel <span style="font-weight:400;color:#64748b">Dashboard</span></h1>
<div class="sub"><span id="status"></span><span id="refresh-info">Loading...</span></div>
<div class="cards">
  <div class="card"><div class="card-label">Active Tunnels</div><div class="card-value green" id="c-tunnels">–</div></div>
  <div class="card"><div class="card-label">Total Requests</div><div class="card-value blue" id="c-requests">–</div></div>
  <div class="card"><div class="card-label">Total Connections</div><div class="card-value" id="c-connections">–</div></div>
  <div class="card"><div class="card-label">Blocked IPs</div><div class="card-value red" id="c-blocked">–</div></div>
</div>
<table>
  <thead><tr><th>Subdomain</th><th>Client IP</th><th>Uptime</th><th>Requests</th><th>Status</th></tr></thead>
  <tbody id="tunnel-tbody"><tr><td colspan="5" class="empty">Loading...</td></tr></tbody>
</table>
<div class="footer">MekongTunnel &mdash; by Ing Muyleang &middot; auto-refresh 3s</div>
<script>
function fmt(n){return n.toLocaleString()}
function uptime(s){if(s<60)return s+'s';if(s<3600)return Math.floor(s/60)+'m '+String(s%60).padStart(2,'0')+'s';return Math.floor(s/3600)+'h '+String(Math.floor((s%3600)/60)).padStart(2,'0')+'m'}
async function refresh(){
  try{
    const r=await fetch('/api/stats');
    if(!r.ok)throw new Error(r.status);
    const d=await r.json();
    document.getElementById('c-tunnels').textContent=fmt(d.active_tunnels||0);
    document.getElementById('c-requests').textContent=fmt(d.total_requests||0);
    document.getElementById('c-connections').textContent=fmt(d.total_connections||0);
    document.getElementById('c-blocked').textContent=fmt(d.blocked_ips||0);
    const tb=document.getElementById('tunnel-tbody');
    const tunnels=d.tunnels||[];
    if(tunnels.length===0){tb.innerHTML='<tr><td colspan="5" class="empty">No active tunnels</td></tr>';}
    else{tb.innerHTML=tunnels.map(t=>'<tr><td>'+t.subdomain+'</td><td class="plain">'+t.client_ip+'</td><td class="plain">'+uptime(t.uptime_secs)+'</td><td class="plain">'+fmt(t.request_count)+'</td><td><span class="badge badge-green">live</span></td></tr>').join('');}
    document.getElementById('status').className='';
    document.getElementById('refresh-info').textContent='Last updated '+new Date().toLocaleTimeString();
  }catch(e){
    document.getElementById('status').className='error';
    document.getElementById('refresh-info').textContent='Connection error — retrying...';
  }
}
refresh();setInterval(refresh,3000);
</script>
</body>
</html>`
