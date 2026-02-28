// Package proxy manages the core tunnel registry, SSH host key, and connection lifecycle.
// It coordinates all active tunnels, enforces per-IP limits, and wires together
// the SSH, HTTP, stats, and abuse-protection components.
//
// Author: Ing Muyleang (អុឹង មួយលៀង) — Ing_Muyleang
package proxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/mikesmitty/edkey"
	"golang.org/x/crypto/ssh"

	"github.com/MuyleangIng/MekongTunnel/internal/config"
	"github.com/MuyleangIng/MekongTunnel/internal/domain"
	"github.com/MuyleangIng/MekongTunnel/internal/tunnel"
)

// Server manages SSH tunnels and HTTP proxying.
// It holds the tunnel registry, per-IP connection counts, SSH connections
// (for forced closure on IP block), and the abuse tracker.
type Server struct {
	tunnels         map[string]*tunnel.Tunnel
	ipConnections   map[string]int
	sshConns        map[string][]*ssh.ServerConn // SSH connections per IP for forced closure
	mu              sync.RWMutex
	sshConfig       *ssh.ServerConfig
	domain          string
	maxTunnelsPerIP int

	// Counters for lifetime stats
	totalConnections uint64
	totalRequests    uint64

	// Abuse protection subsystem
	abuseTracker *AbuseTracker
}

// New creates and initialises a Server instance.
// It loads (or auto-generates) the SSH host key from hostKeyPath,
// sets up SSH server config with no client authentication,
// and wires the abuse-tracker callback to force-close SSH connections on IP block.
func New(hostKeyPath string, domain string, maxTunnelsPerIP int) (*Server, error) {
	s := &Server{
		tunnels:         make(map[string]*tunnel.Tunnel),
		ipConnections:   make(map[string]int),
		sshConns:        make(map[string][]*ssh.ServerConn),
		abuseTracker:    NewAbuseTracker(),
		domain:          domain,
		maxTunnelsPerIP: maxTunnelsPerIP,
	}

	// When an IP is blocked, force-close all its SSH connections.
	// Closing SSH connections triggers deferred cleanup in HandleSSHConnection,
	// which removes the associated tunnels from the registry.
	s.abuseTracker.SetOnBlockCallback(func(ip string) {
		connCount := s.CloseAllForIP(ip)
		if connCount > 0 {
			log.Printf("Closed %d SSH connection(s) for blocked IP %s", connCount, ip)
		}
	})

	s.sshConfig = &ssh.ServerConfig{
		NoClientAuth: true, // No authentication required — the tunnel is the auth
	}

	hostKey, err := loadOrGenerateHostKey(hostKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load host key: %w", err)
	}
	s.sshConfig.AddHostKey(hostKey)

	return s, nil
}

// Domain returns the configured domain name (e.g. "muyleanging.com").
func (s *Server) Domain() string {
	return s.domain
}

// SSHConfig returns the SSH server configuration used when accepting new connections.
func (s *Server) SSHConfig() *ssh.ServerConfig {
	return s.sshConfig
}

// loadOrGenerateHostKey loads the SSH host key from path.
// If the file does not exist, it generates a new ED25519 key, saves it, then loads it.
func loadOrGenerateHostKey(path string) (ssh.Signer, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		log.Printf("Generating new host key at %s", path)

		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}

		pemBlock := &pem.Block{
			Type:  "OPENSSH PRIVATE KEY",
			Bytes: edkey.MarshalED25519PrivateKey(priv),
		}

		if err := os.WriteFile(path, pem.EncodeToMemory(pemBlock), 0600); err != nil {
			return nil, err
		}
	}

	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return ssh.ParsePrivateKey(keyBytes)
}

// GenerateUniqueSubdomain generates a memorable subdomain (adjective-noun-hex)
// that does not collide with any currently registered tunnel.
// Retries up to 10 times before returning an error.
func (s *Server) GenerateUniqueSubdomain() (string, error) {
	const maxAttempts = 10
	for i := 0; i < maxAttempts; i++ {
		sub, err := domain.Generate()
		if err != nil {
			return "", err
		}

		s.mu.RLock()
		_, exists := s.tunnels[sub]
		s.mu.RUnlock()

		if !exists {
			return sub, nil
		}
	}
	return "", fmt.Errorf("failed to generate unique subdomain after %d attempts", maxAttempts)
}

// CheckAndReserveConnection checks whether a new connection from clientIP is allowed
// and atomically reserves a slot if it is. Returns nil on success.
// On success the caller MUST call DecrementIPConnection when the connection ends.
//
// Reasons for rejection:
//   - IP is currently blocked by the abuse tracker
//   - IP exceeded the per-minute connection rate limit
//   - IP already has MaxTunnelsPerIP active tunnels
//   - Server reached MaxTotalTunnels
func (s *Server) CheckAndReserveConnection(clientIP string) error {
	// Blocked IP check
	if expiry := s.abuseTracker.GetBlockExpiry(clientIP); !expiry.IsZero() {
		remaining := time.Until(expiry).Round(time.Minute)
		return fmt.Errorf("IP %s is temporarily blocked. Try again in %v", clientIP, remaining)
	}

	// Connection rate limit check (sliding window)
	if !s.abuseTracker.CheckConnectionRate(clientIP) {
		return fmt.Errorf("connection rate limit exceeded: max %d connections per minute. Repeated violations will result in a temporary block", config.MaxConnectionsPerMinute)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.ipConnections[clientIP] >= s.maxTunnelsPerIP {
		return fmt.Errorf("rate limit exceeded: max %d tunnels per IP", s.maxTunnelsPerIP)
	}
	if len(s.tunnels) >= config.MaxTotalTunnels {
		return fmt.Errorf("server capacity reached: max %d total tunnels", config.MaxTotalTunnels)
	}

	s.ipConnections[clientIP]++
	return nil
}

// BlockIP blocks the given IP address via the abuse tracker,
// which triggers forced closure of all its SSH connections.
func (s *Server) BlockIP(ip string) {
	s.abuseTracker.BlockIP(ip)
}

// DecrementIPConnection decrements the active connection count for clientIP.
// Must be called once for every successful CheckAndReserveConnection call.
func (s *Server) DecrementIPConnection(clientIP string) {
	s.mu.Lock()
	s.ipConnections[clientIP]--
	if s.ipConnections[clientIP] <= 0 {
		delete(s.ipConnections, clientIP)
	}
	s.mu.Unlock()
}

// RegisterTunnel creates a new Tunnel and stores it in the registry under sub.
// The returned *tunnel.Tunnel is ready to accept connections.
func (s *Server) RegisterTunnel(sub string, listener net.Listener, bindAddr string, bindPort uint32, clientIP string) *tunnel.Tunnel {
	s.mu.Lock()
	defer s.mu.Unlock()

	t := tunnel.New(sub, listener, bindAddr, bindPort, clientIP)
	s.tunnels[sub] = t
	return t
}

// RemoveTunnel removes the tunnel identified by sub from the registry and closes it.
func (s *Server) RemoveTunnel(sub string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.tunnels[sub]; ok {
		t.Close()
		delete(s.tunnels, sub)
	}
}

// GetTunnel retrieves the active tunnel for a given subdomain.
// Returns nil if no tunnel is registered for sub.
func (s *Server) GetTunnel(sub string) *tunnel.Tunnel {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tunnels[sub]
}

// RegisterSSHConn tracks an SSH connection for clientIP so it can be force-closed when the IP is blocked.
func (s *Server) RegisterSSHConn(clientIP string, conn *ssh.ServerConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sshConns[clientIP] = append(s.sshConns[clientIP], conn)
}

// UnregisterSSHConn removes a specific SSH connection from the per-IP tracking list.
// This is called via defer when a connection ends normally.
func (s *Server) UnregisterSSHConn(clientIP string, conn *ssh.ServerConn) {
	s.mu.Lock()
	defer s.mu.Unlock()

	conns := s.sshConns[clientIP]
	newConns := make([]*ssh.ServerConn, 0, len(conns))
	for _, c := range conns {
		if c != conn {
			newConns = append(newConns, c)
		}
	}

	if len(newConns) == 0 {
		delete(s.sshConns, clientIP)
	} else {
		s.sshConns[clientIP] = newConns
	}
}

// CloseAllForIP force-closes every SSH connection associated with ip.
// It removes the IP from the tracking map first to prevent double-close races.
// Returns the number of connections closed.
func (s *Server) CloseAllForIP(ip string) int {
	s.mu.Lock()
	sshConns := s.sshConns[ip]
	connsCopy := make([]*ssh.ServerConn, len(sshConns))
	copy(connsCopy, sshConns)
	delete(s.sshConns, ip)
	s.mu.Unlock()

	for _, conn := range connsCopy {
		conn.Close()
	}

	return len(connsCopy)
}

// Stop gracefully stops the server's background goroutines (abuse-tracker cleanup).
// Call this during application shutdown after HTTP servers are already stopped.
func (s *Server) Stop() {
	s.abuseTracker.Stop()
}
