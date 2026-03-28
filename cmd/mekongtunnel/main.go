// Command mekongtunnel is the entry point for the MekongTunnel SSH tunnel service.
//
// It reads configuration from environment variables, starts four servers
// (SSH, HTTP redirect, HTTPS proxy, and localhost stats), and waits for
// a shutdown signal (SIGINT/SIGTERM) or a fatal server error before
// gracefully stopping everything.
//
// Author: Ing Muyleang (អុឹង មួយលៀង) — Ing_Muyleang
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/MuyleangIng/MekongTunnel/internal/config"
	"github.com/MuyleangIng/MekongTunnel/internal/db"
	"github.com/MuyleangIng/MekongTunnel/internal/proxy"
	"github.com/MuyleangIng/MekongTunnel/internal/redisx"
)

// version is set at build time via -ldflags "-X main.version=..."
var version = "dev"

func main() {
	if len(os.Args) > 1 {
		switch strings.TrimSpace(os.Args[1]) {
		case "version", "--version", "-v":
			fmt.Printf("mekongtunnel %s\n", version)
			return
		}
	}

	// Load configuration from environment variables, falling back to defaults.
	cfg := config.Default()

	if v := os.Getenv("SSH_ADDR"); v != "" {
		cfg.SSHAddr = v
	}
	if v := os.Getenv("HTTP_ADDR"); v != "" {
		cfg.HTTPAddr = v
	}
	if v := os.Getenv("HTTPS_ADDR"); v != "" {
		cfg.HTTPSAddr = v
	}
	if v := os.Getenv("HOST_KEY_PATH"); v != "" {
		cfg.HostKeyPath = v
	}
	if v := os.Getenv("TLS_CERT"); v != "" {
		cfg.TLSCert = v
	}
	if v := os.Getenv("TLS_KEY"); v != "" {
		cfg.TLSKey = v
	}
	if v := os.Getenv("STATS_ADDR"); v != "" {
		cfg.StatsAddr = v
	}
	if v := os.Getenv("DOMAIN"); v != "" {
		cfg.Domain = v
	}
	if v := os.Getenv("MAX_TUNNELS_PER_IP"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			cfg.MaxTunnelsPerIP = n
		}
	}
	if v := os.Getenv("MAX_TOTAL_TUNNELS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			cfg.MaxTotalTunnels = n
		}
	}
	if v := os.Getenv("MAX_CONNECTIONS_PER_MINUTE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			cfg.MaxConnectionsPerMinute = n
		}
	}
	if v := os.Getenv("REQUESTS_PER_SECOND"); v != "" {
		if n, err := strconv.ParseFloat(v, 64); err == nil && n >= 0 {
			config.RequestsPerSecond = n
		}
	}
	if v := os.Getenv("BURST_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			config.BurstSize = n
		}
	}
	if v := os.Getenv("RATE_LIMIT_VIOLATIONS_MAX"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			config.RateLimitViolationsMax = n
		}
	}
	if v := os.Getenv("BLOCK_DURATION"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d >= 0 {
			config.BlockDuration = d
		}
	}
	if v := os.Getenv("MAX_REQUEST_BODY_MB"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n >= 0 {
			config.MaxRequestBodySize = n * 1024 * 1024
		}
	}
	if v := os.Getenv("MAX_RESPONSE_BODY_MB"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n >= 0 {
			config.MaxResponseBodySize = n * 1024 * 1024
		}
	}
	if v := os.Getenv("MAX_WEBSOCKET_TRANSFER_MB"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n >= 0 {
			config.MaxWebSocketTransfer = n * 1024 * 1024
		}
	}

	// Create the proxy server (loads/generates SSH host key, sets up abuse tracker).
	srv, err := proxy.New(
		cfg.HostKeyPath,
		cfg.Domain,
		cfg.MaxTunnelsPerIP,
		cfg.MaxTotalTunnels,
		cfg.MaxConnectionsPerMinute,
	)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	apiURL := strings.TrimSpace(os.Getenv("API_URL"))
	if apiURL == "" {
		apiURL = deriveAPIBaseURL(cfg.Domain)
	}
	if apiURL != "" {
		srv.SetAPIBaseURL(apiURL)
		log.Printf("Tunnel API sync enabled via %s", apiURL)
	}
	if tunnelSecret := strings.TrimSpace(os.Getenv("TUNNEL_EDGE_SECRET")); tunnelSecret != "" {
		srv.SetAPISecret(tunnelSecret)
		log.Println("Tunnel edge secret configured")
	}

	// Wire token validation when DATABASE_URL is available.
	// Without a DB the server still works — users just get random subdomains.
	if dbURL := os.Getenv("DATABASE_URL"); dbURL != "" {
		database, err := db.Connect(dbURL)
		if err != nil {
			log.Printf("WARNING: could not connect to database (%v) — token validation disabled", err)
		} else {
			redisClient, err := redisx.Connect(context.Background(), redisx.ConfigFromEnv())
			if err != nil {
				log.Fatalf("Failed to connect to Redis: %v", err)
			}
			if redisClient != nil {
				database.SetRedis(redisClient)
				log.Println("Redis cache enabled for domain lookups")
				defer func() {
					if err := redisClient.Close(); err != nil {
						log.Printf("Redis close error: %v", err)
					}
				}()
			}
			srv.SetTokenValidator(database)
			log.Println("Token validation enabled (database connected)")
			defer database.Close()
		}
	}

	// --- SSH Server ---
	// Listens for incoming SSH connections with -R port forwarding.
	sshListener, err := net.Listen("tcp", cfg.SSHAddr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", cfg.SSHAddr, err)
	}
	log.Printf("SSH server listening on %s", cfg.SSHAddr)

	sshShutdown := make(chan struct{})
	sshDone := make(chan struct{})
	go func() {
		defer close(sshDone)
		for {
			conn, err := sshListener.Accept()
			if err != nil {
				select {
				case <-sshShutdown:
					return
				default:
				}
				log.Printf("Failed to accept SSH connection: %v", err)
				continue
			}
			go srv.HandleSSHConnection(conn)
		}
	}()

	// --- HTTP Server (redirect only) ---
	// Redirects all HTTP requests to their HTTPS equivalent (301).
	httpServer := &http.Server{
		Addr:         cfg.HTTPAddr,
		Handler:      srv.HTTPRedirectHandler(),
		ReadTimeout:  config.HTTPReadTimeout,
		WriteTimeout: config.HTTPWriteTimeout,
		IdleTimeout:  config.HTTPIdleTimeout,
	}

	// --- HTTPS Server (main proxy) ---
	// Terminates TLS, validates subdomains, and reverse-proxies to SSH clients.
	httpsServer := &http.Server{
		Addr:           cfg.HTTPSAddr,
		Handler:        srv,
		ReadTimeout:    config.HTTPSReadTimeout,
		WriteTimeout:   config.HTTPSWriteTimeout,
		IdleTimeout:    config.HTTPSIdleTimeout,
		MaxHeaderBytes: 1 << 20,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	// --- Stats Server (localhost only) ---
	// Exposes server metrics as JSON on 127.0.0.1:9090.
	statsServer := &http.Server{
		Addr:         cfg.StatsAddr,
		Handler:      srv.StatsHandler(),
		ReadTimeout:  config.StatsReadTimeout,
		WriteTimeout: config.StatsWriteTimeout,
	}

	// Channel to receive fatal errors from any of the three HTTP servers.
	serverErr := make(chan error, 3)

	log.Printf("HTTP server listening on %s (redirects to HTTPS)", cfg.HTTPAddr)
	go func() {
		if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
			serverErr <- fmt.Errorf("HTTP server error: %w", err)
		}
	}()

	log.Printf("HTTPS server listening on %s", cfg.HTTPSAddr)
	go func() {
		if err := httpsServer.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey); err != http.ErrServerClosed {
			serverErr <- fmt.Errorf("HTTPS server error: %w", err)
		}
	}()

	log.Printf("Stats server listening on %s", cfg.StatsAddr)
	go func() {
		if err := statsServer.ListenAndServe(); err != http.ErrServerClosed {
			serverErr <- fmt.Errorf("stats server error: %w", err)
		}
	}()

	// Block until a signal or fatal error triggers shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		log.Printf("Received signal %v, shutting down...", sig)
	case err := <-serverErr:
		log.Printf("Fatal error: %v, shutting down...", err)
	}

	// Graceful shutdown: give servers up to ShutdownTimeout to finish in-flight requests.
	ctx, cancel := context.WithTimeout(context.Background(), config.ShutdownTimeout)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("HTTP server shutdown error: %v", err)
	}
	if err := httpsServer.Shutdown(ctx); err != nil {
		log.Printf("HTTPS server shutdown error: %v", err)
	}
	if err := statsServer.Shutdown(ctx); err != nil {
		log.Printf("Stats server shutdown error: %v", err)
	}

	// Stop the SSH accept loop and wait for it to exit.
	close(sshShutdown)
	sshListener.Close()
	<-sshDone

	// Stop background goroutines (abuse-tracker cleanup).
	srv.Stop()
	log.Println("Shutdown complete")
}

func deriveAPIBaseURL(domain string) string {
	host := strings.TrimSpace(domain)
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	host = strings.Trim(host, "/")
	if host == "" {
		return ""
	}
	if strings.HasPrefix(host, "api.") {
		return "https://" + host
	}

	parts := strings.Split(host, ".")
	base := host
	if len(parts) > 2 {
		switch parts[0] {
		case "proxy", "tunnel", "edge":
			base = strings.Join(parts[1:], ".")
		}
	}
	return "https://api." + base
}
