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
	"github.com/MuyleangIng/MekongTunnel/internal/auth"
	"github.com/MuyleangIng/MekongTunnel/internal/db"
	"github.com/MuyleangIng/MekongTunnel/internal/mailer"
	"github.com/MuyleangIng/MekongTunnel/internal/models"
	"github.com/MuyleangIng/MekongTunnel/internal/redisx"
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

	bootstrapOnly := getEnvBool("API_BOOTSTRAP_ONLY", false)
	adminEmail := getEnv("ADMIN_EMAIL", "")
	adminName := getEnv("ADMIN_NAME", "Mekong Admin")
	adminPassword := getEnv("ADMIN_PASSWORD", "")
	adminPlan := normalizePlan(getEnv("ADMIN_PLAN", string(models.PlanOrg)))

	planPrices := map[string]string{
		"pro": getEnv("STRIPE_PRICE_PRO", ""),
		"org": getEnv("STRIPE_PRICE_ORG", ""),
	}

	uploadDir := getEnv("UPLOAD_DIR", "./uploads")
	publicURL := getEnv("PUBLIC_URL", "http://localhost:8080")

	// Resend (preferred on cloud — no SMTP port restrictions)
	resendKey := getEnv("RESEND_API_KEY", "")
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

	redisClient, err := redisx.Connect(context.Background(), redisx.ConfigFromEnv())
	if err != nil {
		log.Fatalf("[api] redis connect: %v", err)
	}
	if redisClient != nil {
		log.Println("[api] redis connected")
		database.SetRedis(redisClient)
		defer func() {
			if err := redisClient.Close(); err != nil {
				log.Printf("[api] redis close: %v", err)
			}
		}()
	}

	// ── Migrations ───────────────────────────────────────────────
	migrationsDir := migrationsPath()
	log.Printf("[api] running migrations from %s", migrationsDir)
	if err := db.RunMigrations(database, migrationsDir); err != nil {
		log.Fatalf("[api] migrations failed: %v", err)
	}
	log.Println("[api] migrations complete")
	if err := database.EnsureServerConfig(context.Background()); err != nil {
		log.Fatalf("[api] seed server_config: %v", err)
	}

	// ── Seed admin ───────────────────────────────────────────────
	if adminEmail != "" {
		if err := seedAdmin(database, adminEmail, adminName, adminPassword, adminPlan); err != nil {
			log.Fatalf("[api] admin seed failed: %v", err)
		}
	}

	if bootstrapOnly {
		log.Println("[api] bootstrap only mode complete")
		return
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
		Redis: redisClient,
	}

	srv := api.New(database, cfg)
	defer srv.Close()

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

// seedAdmin promotes the configured admin or creates it when ADMIN_PASSWORD is provided.
func seedAdmin(database *db.DB, email, name, password, plan string) error {
	ctx := context.Background()
	email = strings.ToLower(strings.TrimSpace(email))
	name = strings.TrimSpace(name)
	plan = normalizePlan(plan)

	user, err := database.GetUserByEmail(ctx, email)
	if err != nil || user == nil {
		if strings.TrimSpace(password) == "" {
			log.Printf("[api] admin seed: user %q not found (set ADMIN_PASSWORD to create it automatically)", email)
			return nil
		}

		hash, err := auth.HashPassword(password)
		if err != nil {
			return err
		}

		user, err = database.CreateUser(ctx, email, fallbackString(name, "Mekong Admin"), hash)
		if err != nil {
			return err
		}
		log.Printf("[api] admin seed: created %s", email)
	}

	fields := map[string]any{}
	if !user.IsAdmin {
		fields["is_admin"] = true
	}
	if !user.EmailVerified {
		fields["email_verified"] = true
	}
	if plan != "" && user.Plan != plan {
		fields["plan"] = plan
	}
	if name != "" && strings.TrimSpace(user.Name) == "" {
		fields["name"] = name
	}
	if strings.TrimSpace(password) != "" && (user.PasswordHash == nil || *user.PasswordHash == "") {
		hash, err := auth.HashPassword(password)
		if err != nil {
			return err
		}
		fields["password_hash"] = hash
	}

	if len(fields) == 0 {
		log.Printf("[api] admin seed: %s already up to date", email)
		return nil
	}

	if _, err := database.UpdateUser(ctx, user.ID, fields); err != nil {
		return err
	}
	log.Printf("[api] admin seed: %s bootstrapped (admin=%t, plan=%s)", email, true, plan)
	return nil
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

func getEnvBool(key string, fallback bool) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	switch strings.ToLower(raw) {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		return fallback
	}
}

func splitComma(s string) []string {
	parts := strings.Split(s, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func fallbackString(value, fallback string) string {
	if strings.TrimSpace(value) != "" {
		return value
	}
	return fallback
}

func normalizePlan(plan string) string {
	switch strings.ToLower(strings.TrimSpace(plan)) {
	case string(models.PlanFree):
		return string(models.PlanFree)
	case string(models.PlanStudent):
		return string(models.PlanStudent)
	case string(models.PlanPro):
		return string(models.PlanPro)
	case string(models.PlanOrg):
		return string(models.PlanOrg)
	default:
		return string(models.PlanOrg)
	}
}
