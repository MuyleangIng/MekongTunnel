// Package config holds all compile-time constants and the runtime Config struct
// for the MekongTunnel SSH tunnel service.
// Constants cover limits, timeouts, and default values; Config is populated
// from environment variables at startup.
//
// Author: Ing Muyleang (អុឹង មួយលៀង) — Ing_Muyleang
package config

import (
	"fmt"
	"time"
)

const (
	// Author information
	AuthorName   = "Ing Muyleang"
	AuthorKhName = "អុឹង មួយលៀង"
	AuthorHandle = "Ing_Muyleang"

	DefaultDomain     = "muyleanging.com"
	InactivityTimeout = 2 * time.Hour

	// SSH handshake timeout
	SSHHandshakeTimeout = 30 * time.Second

	// Connection rate limiting (new connections per IP)
	ConnectionRateWindow = 1 * time.Minute // sliding window for connection rate

	// Tunnel lifetime
	DefaultTunnelLifetime = 24 * time.Hour     // default tunnel duration regardless of activity
	MaxTunnelLifetime     = 7 * 24 * time.Hour // maximum user-requested tunnel duration

	// HTTP server timeouts
	HTTPReadTimeout   = 10 * time.Second
	HTTPWriteTimeout  = 10 * time.Second
	HTTPIdleTimeout   = 30 * time.Second
	HTTPSReadTimeout  = 30 * time.Second
	HTTPSWriteTimeout = 30 * time.Second
	HTTPSIdleTimeout  = 120 * time.Second
	StatsReadTimeout  = 5 * time.Second
	StatsWriteTimeout = 5 * time.Second
	ShutdownTimeout   = 10 * time.Second

	// Request logging
	LogBufferSize = 128 // buffered channel size for SSH terminal request logs

	// Interstitial warning cookie
	WarningCookieName   = "mekong_warned"
	WarningCookieMaxAge = 86400 // 1 day
)

var (
	DefaultMaxTunnelsPerIP      = 1000 // 0 means unlimited; override with MAX_TUNNELS_PER_IP
	DefaultMaxTotalTunnels      = 0    // 0 means unlimited; override with MAX_TOTAL_TUNNELS
	DefaultMaxConnectionsPerMin = 0    // 0 means unlimited; override with MAX_CONNECTIONS_PER_MINUTE

	// Per-tunnel HTTP rate limit. Setting either to 0 disables the limiter.
	RequestsPerSecond = 0.0
	BurstSize         = 0

	// Upload/download limits. 0 means unlimited.
	MaxRequestBodySize   int64 = 1024 * 1024 * 1024 // 1GB
	MaxResponseBodySize  int64 = 1024 * 1024 * 1024 // 1GB
	MaxWebSocketTransfer int64 = 0                  // unlimited

	// Blocking controls. 0 disables automatic IP blocking for repeated abuse.
	BlockDuration          = time.Duration(0)
	RateLimitViolationsMax = 0

	// WebSocket idle timeout remains finite so dead peers do not hang forever.
	WebSocketIdleTimeout = 6 * time.Hour
)

// Config holds runtime configuration loaded from environment
type Config struct {
	SSHAddr                 string
	HTTPAddr                string
	HTTPSAddr               string
	StatsAddr               string
	HostKeyPath             string
	TLSCert                 string
	TLSKey                  string
	Domain                  string
	MaxTunnelsPerIP         int
	MaxTotalTunnels         int
	MaxConnectionsPerMinute int
}

// Default returns configuration with default values
func Default() *Config {
	return &Config{
		SSHAddr:                 ":22",
		HTTPAddr:                ":80",
		HTTPSAddr:               ":443",
		StatsAddr:               "127.0.0.1:9090",
		HostKeyPath:             "host_key",
		TLSCert:                 fmt.Sprintf("/etc/letsencrypt/live/%s/fullchain.pem", DefaultDomain),
		TLSKey:                  fmt.Sprintf("/etc/letsencrypt/live/%s/privkey.pem", DefaultDomain),
		Domain:                  DefaultDomain,
		MaxTunnelsPerIP:         DefaultMaxTunnelsPerIP,
		MaxTotalTunnels:         DefaultMaxTotalTunnels,
		MaxConnectionsPerMinute: DefaultMaxConnectionsPerMin,
	}
}
