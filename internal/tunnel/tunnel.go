// Package tunnel provides the Tunnel struct which represents a single active SSH tunnel.
// Each tunnel has its own rate limiter, HTTP transport (for connection reuse),
// and an optional request logger that streams HTTP hits to the SSH terminal.
//
// Author: Ing Muyleang (អុឹង មួយលៀង) — Ing_Muyleang
package tunnel

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/MuyleangIng/MekongTunnel/internal/config"
)

type ExpirationReason int

const (
	NotExpired ExpirationReason = iota
	ExpiredByInactivity
	ExpiredByLifetime
)

// SSHCloser is an interface for closing SSH connections
type SSHCloser interface {
	Close() error
}

// Tunnel represents an active SSH tunnel
type Tunnel struct {
	ID                 string
	Subdomain          string
	Listener           net.Listener
	CreatedAt          time.Time
	LastActive         time.Time
	BindAddr           string
	BindPort           uint32
	localPort          uint32
	ClientIP           string // SSH client IP that created this tunnel
	mu                 sync.Mutex
	rateLimiter        *RateLimiter
	sshConn            SSHCloser       // Reference to SSH connection for forced closure
	rateLimitHits      int             // Count of rate limit violations
	requestCount       uint64          // Total HTTP requests proxied through this tunnel
	transport          *http.Transport // Reusable HTTP transport for proxying
	logger             *RequestLogger  // Async request logger for SSH terminal output
	maxLifetime        time.Duration
	inactivityTTL      time.Duration
	apiToken           string // raw API token sent by the client via MEKONG_API_TOKEN env var
	requestedSubdomain string // requested reserved subdomain sent via MEKONG_SUBDOMAIN
	deploySubdomain    string // trusted deployment subdomain sent by the API via MEKONG_DEPLOY_SUBDOMAIN
	edgeSecret         string // shared tunnel-edge secret sent via MEKONG_TUNNEL_EDGE_SECRET
	upstreamHost       string // local Host header override sent via MEKONG_UPSTREAM_HOST
	skipWarning        bool   // skip phishing-warning interstitial (set via MEKONG_SKIP_WARNING)
	userID             string // validated API-token owner for dashboard/live tunnel APIs
	disableSync        bool   // skip tunnel-session sync for internal deployment tunnels

	statsMu       sync.Mutex
	totalBytes    uint64
	todayKey      string
	todayRequests uint64
	todayBytes    uint64
}

// New creates a new tunnel with the given parameters
func New(subdomain string, listener net.Listener, bindAddr string, bindPort uint32, clientIP string, maxLifetime time.Duration) *Tunnel {
	now := time.Now()
	listenerAddr := listener.Addr().String()
	if maxLifetime <= 0 {
		maxLifetime = config.DefaultTunnelLifetime
	}
	return &Tunnel{
		ID:          newTunnelID(),
		Subdomain:   subdomain,
		Listener:    listener,
		CreatedAt:   now,
		LastActive:  now,
		BindAddr:    bindAddr,
		BindPort:    bindPort,
		ClientIP:    clientIP,
		rateLimiter: NewRateLimiter(config.RequestsPerSecond, config.BurstSize),
		transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.DialTimeout("tcp", listenerAddr, 10*time.Second)
			},
			MaxIdleConns:    10,
			IdleConnTimeout: 90 * time.Second,
		},
		maxLifetime:   maxLifetime,
		inactivityTTL: maxLifetime,
	}
}

func newTunnelID() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return fmt.Sprintf("tun_%d", time.Now().UTC().UnixNano())
	}

	// Format as a UUID-like string without adding a new dependency.
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	hexID := hex.EncodeToString(raw[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", hexID[:8], hexID[8:12], hexID[12:16], hexID[16:20], hexID[20:])
}

// IncrementRequestCount atomically increments the per-tunnel HTTP request counter.
func (t *Tunnel) IncrementRequestCount() {
	atomic.AddUint64(&t.requestCount, 1)
}

// RequestCount returns the total number of HTTP requests proxied through this tunnel.
func (t *Tunnel) RequestCount() uint64 {
	return atomic.LoadUint64(&t.requestCount)
}

// RecordTraffic increments request and byte counters, including the UTC daily bucket.
func (t *Tunnel) RecordTraffic(bytes int64) {
	if bytes < 0 {
		bytes = 0
	}

	t.IncrementRequestCount()

	t.statsMu.Lock()
	defer t.statsMu.Unlock()

	nowKey := time.Now().UTC().Format("2006-01-02")
	if t.todayKey != nowKey {
		t.todayKey = nowKey
		t.todayRequests = 0
		t.todayBytes = 0
	}

	t.todayRequests++
	t.todayBytes += uint64(bytes)
	t.totalBytes += uint64(bytes)
}

// TotalBytes returns the total bytes recorded for this tunnel since it was opened.
func (t *Tunnel) TotalBytes() uint64 {
	t.statsMu.Lock()
	defer t.statsMu.Unlock()
	return t.totalBytes
}

// TodayStats returns the request and byte totals for the current UTC day.
func (t *Tunnel) TodayStats() (uint64, uint64) {
	t.statsMu.Lock()
	defer t.statsMu.Unlock()

	nowKey := time.Now().UTC().Format("2006-01-02")
	if t.todayKey != nowKey {
		return 0, 0
	}
	return t.todayRequests, t.todayBytes
}

// Touch updates the last active timestamp
func (t *Tunnel) Touch() {
	t.mu.Lock()
	t.LastActive = time.Now()
	t.mu.Unlock()
}

// LastActiveAt returns the most recent activity timestamp for the tunnel.
func (t *Tunnel) LastActiveAt() time.Time {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.LastActive
}

// IsExpired returns true if the tunnel has been inactive for too long or exceeded max lifetime
func (t *Tunnel) IsExpired() bool {
	return t.ExpirationReason() != NotExpired
}

// IsMaxLifetimeExceeded returns true if the tunnel has exceeded max lifetime
func (t *Tunnel) IsMaxLifetimeExceeded() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return time.Since(t.CreatedAt) > t.maxLifetime
}

// TimeRemaining returns the time remaining before the tunnel expires (either by inactivity or max lifetime)
func (t *Tunnel) TimeRemaining() time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()

	inactivityRemaining := t.inactivityTTL - time.Since(t.LastActive)
	lifetimeRemaining := t.maxLifetime - time.Since(t.CreatedAt)

	if inactivityRemaining < lifetimeRemaining {
		return inactivityRemaining
	}
	return lifetimeRemaining
}

// ExpiresAt returns the wall-clock time when the tunnel's lifetime limit is reached.
func (t *Tunnel) ExpiresAt() time.Time {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.CreatedAt.Add(t.maxLifetime)
}

// MaxLifetime returns the configured lifetime limit for the tunnel.
func (t *Tunnel) MaxLifetime() time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.maxLifetime
}

// SetMaxLifetime updates the tunnel lifetime limit.
func (t *Tunnel) SetMaxLifetime(d time.Duration) {
	t.mu.Lock()
	t.maxLifetime = d
	t.inactivityTTL = d
	t.mu.Unlock()
}

// InactivityTimeout returns the idle timeout for the tunnel.
func (t *Tunnel) InactivityTimeout() time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.inactivityTTL
}

// ExpirationReason reports why the tunnel has expired, if it has.
func (t *Tunnel) ExpirationReason() ExpirationReason {
	t.mu.Lock()
	defer t.mu.Unlock()

	if time.Since(t.LastActive) > t.inactivityTTL {
		return ExpiredByInactivity
	}
	if time.Since(t.CreatedAt) > t.maxLifetime {
		return ExpiredByLifetime
	}
	return NotExpired
}

// AllowRequest checks if a request is allowed by the rate limiter
func (t *Tunnel) AllowRequest() bool {
	return t.rateLimiter.Allow()
}

// SetSSHConn sets the SSH connection reference for forced closure
func (t *Tunnel) SetSSHConn(conn SSHCloser) {
	t.mu.Lock()
	t.sshConn = conn
	t.mu.Unlock()
}

// RecordRateLimitHit records a rate limit violation and returns true if the tunnel should be killed
func (t *Tunnel) RecordRateLimitHit() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if config.RateLimitViolationsMax <= 0 {
		return false
	}
	t.rateLimitHits++
	return t.rateLimitHits >= config.RateLimitViolationsMax
}

// CloseSSH closes the SSH connection associated with this tunnel
func (t *Tunnel) CloseSSH() {
	t.mu.Lock()
	conn := t.sshConn
	t.sshConn = nil // Prevent redundant close calls
	t.mu.Unlock()

	if conn != nil {
		conn.Close()
	}
}

// SetLogger sets the request logger for SSH terminal output
func (t *Tunnel) SetLogger(l *RequestLogger) {
	t.mu.Lock()
	t.logger = l
	t.mu.Unlock()
}

// Logger returns the request logger, or nil if none is set
func (t *Tunnel) Logger() *RequestLogger {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.logger
}

// SetAPIToken stores the raw API token sent by the client.
func (t *Tunnel) SetAPIToken(token string) {
	t.mu.Lock()
	t.apiToken = token
	t.mu.Unlock()
}

// GetAPIToken returns the raw API token, or "" if none was provided.
func (t *Tunnel) GetAPIToken() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.apiToken
}

// SetUserID stores the validated tunnel owner ID.
func (t *Tunnel) SetUserID(userID string) {
	t.mu.Lock()
	t.userID = userID
	t.mu.Unlock()
}

// UserID returns the validated tunnel owner ID, or "" when unavailable.
func (t *Tunnel) UserID() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.userID
}

// SetRequestedSubdomain stores the requested reserved subdomain sent by the client.
func (t *Tunnel) SetRequestedSubdomain(subdomain string) {
	t.mu.Lock()
	t.requestedSubdomain = subdomain
	t.mu.Unlock()
}

// GetRequestedSubdomain returns the requested reserved subdomain, or "" if none was provided.
func (t *Tunnel) GetRequestedSubdomain() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.requestedSubdomain
}

// SetDeploySubdomain stores the trusted deployment subdomain sent by the API.
func (t *Tunnel) SetDeploySubdomain(subdomain string) {
	t.mu.Lock()
	t.deploySubdomain = subdomain
	t.mu.Unlock()
}

// DeploySubdomain returns the trusted deployment subdomain, or "" if none was provided.
func (t *Tunnel) DeploySubdomain() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.deploySubdomain
}

// SetEdgeSecret stores the shared tunnel-edge secret sent by the API.
func (t *Tunnel) SetEdgeSecret(secret string) {
	t.mu.Lock()
	t.edgeSecret = secret
	t.mu.Unlock()
}

// EdgeSecret returns the shared tunnel-edge secret, or "" if none was provided.
func (t *Tunnel) EdgeSecret() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.edgeSecret
}

// SetUpstreamHost stores the Host header override sent by the client.
func (t *Tunnel) SetUpstreamHost(host string) {
	t.mu.Lock()
	t.upstreamHost = host
	t.mu.Unlock()
}

// SetSkipWarning marks the tunnel to skip the phishing-warning interstitial.
func (t *Tunnel) SetSkipWarning(v bool) {
	t.mu.Lock()
	t.skipWarning = v
	t.mu.Unlock()
}

// SkipWarning returns true when the tunnel owner has opted out of the warning page.
func (t *Tunnel) SkipWarning() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.skipWarning
}

// SetDisableSync marks whether this tunnel should be omitted from tunnel-session sync.
func (t *Tunnel) SetDisableSync(v bool) {
	t.mu.Lock()
	t.disableSync = v
	t.mu.Unlock()
}

// DisableSync returns true when this tunnel should not be synced into tunnel_sessions.
func (t *Tunnel) DisableSync() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.disableSync
}

// SetLocalPort stores the developer's actual local app port sent by the client.
func (t *Tunnel) SetLocalPort(port uint32) {
	t.mu.Lock()
	t.localPort = port
	t.mu.Unlock()
}

// LocalPort returns the developer's actual local app port, or 0 if unknown.
func (t *Tunnel) LocalPort() uint32 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.localPort
}

// UpstreamHost returns the local Host header override, or "" if none was provided.
func (t *Tunnel) UpstreamHost() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.upstreamHost
}

// Transport returns the reusable HTTP transport for this tunnel
func (t *Tunnel) Transport() *http.Transport {
	return t.transport
}

// Close closes the tunnel's listener and cleans up the transport and logger
func (t *Tunnel) Close() {
	t.Listener.Close()
	if t.transport != nil {
		t.transport.CloseIdleConnections()
	}
	t.mu.Lock()
	l := t.logger
	t.logger = nil
	t.mu.Unlock()
	if l != nil {
		l.Close()
	}
}
