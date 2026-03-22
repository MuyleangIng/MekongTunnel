// Package tunnel provides the Tunnel struct which represents a single active SSH tunnel.
// Each tunnel has its own rate limiter, HTTP transport (for connection reuse),
// and an optional request logger that streams HTTP hits to the SSH terminal.
//
// Author: Ing Muyleang (អុឹង មួយលៀង) — Ing_Muyleang
package tunnel

import (
	"context"
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
	Subdomain     string
	Listener      net.Listener
	CreatedAt     time.Time
	LastActive    time.Time
	BindAddr      string
	BindPort      uint32
	ClientIP      string // SSH client IP that created this tunnel
	mu            sync.Mutex
	rateLimiter   *RateLimiter
	sshConn       SSHCloser       // Reference to SSH connection for forced closure
	rateLimitHits int             // Count of rate limit violations
	requestCount  uint64          // Total HTTP requests proxied through this tunnel
	transport     *http.Transport // Reusable HTTP transport for proxying
	logger        *RequestLogger  // Async request logger for SSH terminal output
	maxLifetime   time.Duration
	inactivityTTL time.Duration
	apiToken      string // raw API token sent by the client via MEKONG_API_TOKEN env var
}

// New creates a new tunnel with the given parameters
func New(subdomain string, listener net.Listener, bindAddr string, bindPort uint32, clientIP string, maxLifetime time.Duration) *Tunnel {
	now := time.Now()
	listenerAddr := listener.Addr().String()
	if maxLifetime <= 0 {
		maxLifetime = config.DefaultTunnelLifetime
	}
	return &Tunnel{
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

// IncrementRequestCount atomically increments the per-tunnel HTTP request counter.
func (t *Tunnel) IncrementRequestCount() {
	atomic.AddUint64(&t.requestCount, 1)
}

// RequestCount returns the total number of HTTP requests proxied through this tunnel.
func (t *Tunnel) RequestCount() uint64 {
	return atomic.LoadUint64(&t.requestCount)
}

// Touch updates the last active timestamp
func (t *Tunnel) Touch() {
	t.mu.Lock()
	t.LastActive = time.Now()
	t.mu.Unlock()
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
