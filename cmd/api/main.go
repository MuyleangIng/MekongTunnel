// Command api is the MekongTunnel REST API server.
// Author: Ing Muyleang (អុឹង មួយលៀង) — Ing_Muyleang
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/MuyleangIng/MekongTunnel/internal/api"
	"github.com/MuyleangIng/MekongTunnel/internal/db"
	"github.com/MuyleangIng/MekongTunnel/internal/mailer"
)

func main() {
	// ── Environment ─────────────────────────────────────────────
	databaseURL := requireEnv("DATABASE_URL")
	jwtSecret := requireEnv("JWT_SECRET")
	refreshSecret := getEnv("REFRESH_SECRET", jwtSecret)
	addr := getEnv("API_ADDR", ":8080")

	githubClientID := getEnv("GITHUB_CLIENT_ID", "")
	githubClientSecret := getEnv("GITHUB_CLIENT_SECRET", "")
	githubCallbackURL := getEnv("GITHUB_CALLBACK_URL", "http://localhost:8080/api/auth/github/callback")

	googleClientID := getEnv("GOOGLE_CLIENT_ID", "")
	googleClientSecret := getEnv("GOOGLE_CLIENT_SECRET", "")
	googleCallbackURL := getEnv("GOOGLE_CALLBACK_URL", "http://localhost:8080/api/auth/google/callback")

	stripeSecretKey := getEnv("STRIPE_SECRET_KEY", "")
	stripeWebhookSecret := getEnv("STRIPE_WEBHOOK_SECRET", "")

	tunnelServerURL := getEnv("TUNNEL_SERVER_URL", "http://localhost:9090")
	frontendURL := getEnv("FRONTEND_URL", "http://localhost:3000")

	allowedOriginsRaw := getEnv("ALLOWED_ORIGINS", "http://localhost:3000")
	allowedOrigins := splitComma(allowedOriginsRaw)

	adminEmail := getEnv("ADMIN_EMAIL", "")

	planPrices := map[string]string{
		"pro": getEnv("STRIPE_PRICE_PRO", ""),
		"org": getEnv("STRIPE_PRICE_ORG", ""),
	}

	uploadDir := getEnv("UPLOAD_DIR", "./uploads")
	publicURL := getEnv("PUBLIC_URL", "http://localhost:8080")

	// Resend (preferred on cloud — no SMTP port restrictions)
	resendKey  := getEnv("RESEND_API_KEY", "")
	resendFrom := getEnv("RESEND_FROM", "Mekong Tunnel <noreply@angkorsearch.dev>")

	// SMTP fallback
	smtpHost := getEnv("SMTP_HOST", "smtp.gmail.com")
	smtpPort := getEnv("SMTP_PORT", "587")
	smtpUser := getEnv("SMTP_USER", "")
	smtpPass := getEnv("SMTP_PASS", "")
	smtpFrom := getEnv("SMTP_FROM", "")

	// ── Database ─────────────────────────────────────────────────
	log.Println("[api] connecting to database...")
	database, err := db.Connect(databaseURL)
	if err != nil {
		log.Fatalf("[api] db connect: %v", err)
	}
	defer database.Close()
	log.Println("[api] database connected")

	// ── Migrations ───────────────────────────────────────────────
	migrationsDir := migrationsPath()
	log.Printf("[api] running migrations from %s", migrationsDir)
	if err := db.RunMigrations(database, migrationsDir); err != nil {
		log.Fatalf("[api] migrations failed: %v", err)
	}
	log.Println("[api] migrations complete")

	// ── Seed admin ───────────────────────────────────────────────
	if adminEmail != "" {
		seedAdmin(database, adminEmail)
	}

	// ── API Server ───────────────────────────────────────────────
	cfg := api.Config{
		JWTSecret:           jwtSecret,
		RefreshSecret:       refreshSecret,
		GitHubClientID:      githubClientID,
		GitHubClientSecret:  githubClientSecret,
		GitHubCallbackURL:   githubCallbackURL,
		GoogleClientID:      googleClientID,
		GoogleClientSecret:  googleClientSecret,
		GoogleCallbackURL:   googleCallbackURL,
		StripeSecretKey:     stripeSecretKey,
		StripeWebhookSecret: stripeWebhookSecret,
		TunnelServerURL:     tunnelServerURL,
		AllowedOrigins:      allowedOrigins,
		FrontendURL:         frontendURL,
		PlanPrices:          planPrices,
		UploadDir:           uploadDir,
		PublicURL:           publicURL,
		MailConfig: mailer.Config{
			ResendKey:  resendKey,
			ResendFrom: resendFrom,
			Host:       smtpHost,
			Port:       smtpPort,
			User:       smtpUser,
			Pass:       smtpPass,
			From:       smtpFrom,
		},
	}

	srv := api.New(database, cfg)

	httpServer := &http.Server{
		Addr:         addr,
		Handler:      srv,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// ── Start ────────────────────────────────────────────────────
	go func() {
		log.Printf("[api] listening on %s", addr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[api] server error: %v", err)
		}
	}()

	// ── Graceful shutdown ────────────────────────────────────────
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	log.Println("[api] shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("[api] shutdown error: %v", err)
	}
	log.Println("[api] stopped")
}

// seedAdmin sets is_admin=true for the user with ADMIN_EMAIL if they exist.
func seedAdmin(database *db.DB, email string) {
	ctx := context.Background()
	user, err := database.GetUserByEmail(ctx, strings.ToLower(email))
	if err != nil || user == nil {
		log.Printf("[api] admin seed: user %q not found (will be promoted on first registration)", email)
		return
	}
	if user.IsAdmin {
		log.Printf("[api] admin seed: %s is already admin", email)
		return
	}
	if _, err := database.UpdateUser(ctx, user.ID, map[string]any{"is_admin": true}); err != nil {
		log.Printf("[api] admin seed error: %v", err)
		return
	}
	log.Printf("[api] admin seed: %s promoted to admin", email)
}

// migrationsPath returns the path to the migrations directory relative to the binary.
func migrationsPath() string {
	// 1. Environment override.
	if dir := os.Getenv("MIGRATIONS_DIR"); dir != "" {
		return dir
	}
	// 2. Relative to the source file (development).
	_, filename, _, ok := runtime.Caller(0)
	if ok {
		// cmd/api/main.go → ../../migrations
		return filepath.Join(filepath.Dir(filename), "..", "..", "migrations")
	}
	// 3. Relative to working directory (Docker).
	return "migrations"
}

// ─── env helpers ─────────────────────────────────────────────

func requireEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("[api] required environment variable %s is not set", key)
	}
	return v
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func splitComma(s string) []string {
	parts := strings.Split(s, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}
