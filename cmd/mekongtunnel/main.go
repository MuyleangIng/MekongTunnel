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
	"syscall"

	"github.com/MuyleangIng/MekongTunnel/internal/config"
	"github.com/MuyleangIng/MekongTunnel/internal/proxy"
)

func main() {
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

	// Create the proxy server (loads/generates SSH host key, sets up abuse tracker).
	srv, err := proxy.New(cfg.HostKeyPath, cfg.Domain)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
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
