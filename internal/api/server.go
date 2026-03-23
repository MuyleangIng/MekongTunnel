// Package api wires together all handlers and middleware into an HTTP server.
// Author: Ing Muyleang (អុឹង មួយលៀង) — Ing_Muyleang
package api

import (
	"log"
	"net/http"

	"github.com/MuyleangIng/MekongTunnel/internal/api/handlers"
	"github.com/MuyleangIng/MekongTunnel/internal/api/middleware"
	"github.com/MuyleangIng/MekongTunnel/internal/api/response"
	"github.com/MuyleangIng/MekongTunnel/internal/config"
	"github.com/MuyleangIng/MekongTunnel/internal/db"
	"github.com/MuyleangIng/MekongTunnel/internal/hub"
	"github.com/MuyleangIng/MekongTunnel/internal/mailer"
	"github.com/MuyleangIng/MekongTunnel/internal/notify"
)

// Config holds all environment-driven configuration for the API server.
type Config struct {
	JWTSecret           string
	RefreshSecret       string
	GitHubClientID      string
	GitHubClientSecret  string
	GitHubCallbackURL   string
	GoogleClientID      string
	GoogleClientSecret  string
	GoogleCallbackURL   string
	StripeSecretKey     string
	StripeWebhookSecret string
	TunnelServerURL     string
	AllowedOrigins      []string
	FrontendURL         string
	PlanPrices          map[string]string
	UploadDir           string
	PublicURL           string
	MailConfig          mailer.Config
}

// Server is the MekongTunnel REST API HTTP server.
type Server struct {
	mux *http.ServeMux
	db  *db.DB
	cfg Config
	hub *hub.Hub
}

// New creates a new Server, wires routes, and returns it.
func New(database *db.DB, cfg Config) *Server {
	s := &Server{
		mux: http.NewServeMux(),
		db:  database,
		cfg: cfg,
		hub: hub.New(),
	}
	s.registerRoutes()
	return s
}

// ServeHTTP implements http.Handler, applying global middleware.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	corsMiddleware := middleware.CORSMiddleware(s.cfg.AllowedOrigins)
	corsMiddleware(s.mux).ServeHTTP(w, r)
}

// ─── Route registration ───────────────────────────────────────

func (s *Server) registerRoutes() {
	authRequired := middleware.AuthMiddleware(s.cfg.JWTSecret)
	adminRequired := middleware.AdminMiddleware()

	// ── Shared notification service ──────────────────────────────
	notifySvc := &notify.Service{DB: s.db, Hub: s.hub}

	// ── Mailer ───────────────────────────────────────────────────
	mailSvc := mailer.New(s.cfg.MailConfig)
	if mailSvc.Enabled() {
		if s.cfg.MailConfig.ResendKey != "" {
			log.Printf("[api] mailer: Resend API enabled (from: %s)", s.cfg.MailConfig.ResendFrom)
		} else {
			log.Printf("[api] mailer: Gmail SMTP enabled (%s)", s.cfg.MailConfig.User)
		}
	} else {
		log.Printf("[api] mailer: not configured — emails will be logged only")
	}

	// ── Handlers ────────────────────────────────────────────────
	authH := &handlers.AuthHandler{
		DB:                 s.db,
		JWTSecret:          s.cfg.JWTSecret,
		RefreshSecret:      s.cfg.RefreshSecret,
		GitHubClientID:     s.cfg.GitHubClientID,
		GitHubClientSecret: s.cfg.GitHubClientSecret,
		GitHubCallbackURL:  s.cfg.GitHubCallbackURL,
		GoogleClientID:     s.cfg.GoogleClientID,
		GoogleClientSecret: s.cfg.GoogleClientSecret,
		GoogleCallbackURL:  s.cfg.GoogleCallbackURL,
		FrontendURL:        s.cfg.FrontendURL,
		Notify:             notifySvc,
		Mailer:             mailSvc,
	}

	tokensH := &handlers.TokensHandler{DB: s.db}

	cliDeviceH := &handlers.CLIDeviceHandler{
		DB:          s.db,
		FrontendURL: s.cfg.FrontendURL,
	}

	tunnelsH := &handlers.TunnelsHandler{
		DB:              s.db,
		TunnelServerURL: s.cfg.TunnelServerURL,
	}

	userH := &handlers.UserHandler{DB: s.db, Notify: notifySvc}

	billingH := &handlers.BillingHandler{
		DB:                  s.db,
		StripeSecretKey:     s.cfg.StripeSecretKey,
		StripeWebhookSecret: s.cfg.StripeWebhookSecret,
		PlanPrices:          s.cfg.PlanPrices,
		FrontendURL:         s.cfg.FrontendURL,
		Notify:              notifySvc,
	}

	teamH := &handlers.TeamHandler{DB: s.db}
	adminH := &handlers.AdminHandler{DB: s.db, Notify: notifySvc, Mailer: mailSvc, FrontendURL: s.cfg.FrontendURL}
	newsletterH := &handlers.NewsletterHandler{DB: s.db}
	partnersH  := &handlers.PartnersHandler{DB: s.db}
	sponsorsH  := &handlers.SponsorsHandler{DB: s.db}
	notifH   := &handlers.NotificationsHandler{DB: s.db, Hub: s.hub, JWTSecret: s.cfg.JWTSecret}
	monitorH    := &handlers.MonitorHandler{}
	subdomainH  := &handlers.SubdomainHandler{DB: s.db}
	domainsH    := &handlers.DomainsHandler{DB: s.db}
	uploadH     := &handlers.UploadHandler{
		UploadDir: s.cfg.UploadDir,
		BaseURL:   s.cfg.PublicURL,
	}

	// ── Health ──────────────────────────────────────────────────
	s.mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		response.Success(w, map[string]any{"ok": true, "service": "mekong-api"})
	})

	// ── Auth ────────────────────────────────────────────────────
	s.mux.HandleFunc("POST /api/auth/register", authH.Register)
	s.mux.HandleFunc("POST /api/auth/login", authH.Login)
	s.mux.HandleFunc("POST /api/auth/logout", authH.Logout)
	s.mux.HandleFunc("GET /api/auth/me", chain(authH.Me, authRequired))
	s.mux.HandleFunc("GET /api/auth/token-info", authH.TokenInfo) // API token (mkt_xxx) — no JWT needed
	s.mux.HandleFunc("POST /api/auth/refresh", authH.Refresh)
	s.mux.HandleFunc("POST /api/auth/forgot-password", authH.ForgotPassword)
	s.mux.HandleFunc("POST /api/auth/reset-password", authH.ResetPassword)
	s.mux.HandleFunc("POST /api/auth/verify-email", authH.VerifyEmail)
	s.mux.HandleFunc("POST /api/auth/resend-verify", authH.ResendVerify)
	s.mux.HandleFunc("POST /api/auth/request-admin-verify", authH.RequestAdminVerify)
	s.mux.HandleFunc("GET /api/auth/github", authH.GitHubOAuth)
	s.mux.HandleFunc("GET /api/auth/github/callback", authH.GitHubCallback)
	s.mux.HandleFunc("GET /api/auth/google", authH.GoogleOAuth)
	s.mux.HandleFunc("GET /api/auth/google/callback", authH.GoogleCallback)
	s.mux.HandleFunc("POST /api/auth/2fa/setup", chain(authH.Setup2FA, authRequired))
	s.mux.HandleFunc("POST /api/auth/2fa/enable", chain(authH.Enable2FA, authRequired))
	s.mux.HandleFunc("POST /api/auth/2fa/disable", chain(authH.Disable2FA, authRequired))
	s.mux.HandleFunc("POST /api/auth/2fa/verify", authH.Verify2FA)

	// ── API Tokens ──────────────────────────────────────────────
	s.mux.HandleFunc("GET /api/tokens", chain(tokensH.ListTokens, authRequired))
	s.mux.HandleFunc("POST /api/tokens", chain(tokensH.CreateToken, authRequired))
	s.mux.HandleFunc("DELETE /api/tokens/{id}", chain(tokensH.RevokeToken, authRequired))

	// ── CLI Device Auth (mekong login) ───────────────────────────
	s.mux.HandleFunc("POST /api/cli/device", cliDeviceH.CreateSession)
	s.mux.HandleFunc("GET /api/cli/device", cliDeviceH.PollSession)
	s.mux.HandleFunc("POST /api/cli/device/approve", chain(cliDeviceH.ApproveSession, authRequired))

	// ── Tunnels ─────────────────────────────────────────────────
	s.mux.HandleFunc("GET /api/tunnels", chain(tunnelsH.ListTunnels, authRequired))
	s.mux.HandleFunc("GET /api/tunnels/stats", tunnelsH.GetStats)
	s.mux.HandleFunc("POST /api/tunnels", tunnelsH.ReportTunnel) // internal, no auth
	s.mux.HandleFunc("PATCH /api/tunnels/{id}", tunnelsH.UpdateTunnelStatus)

	// ── User ────────────────────────────────────────────────────
	s.mux.HandleFunc("PUT /api/user", chain(userH.UpdateProfile, authRequired))
	s.mux.HandleFunc("PUT /api/user/password", chain(userH.UpdatePassword, authRequired))
	s.mux.HandleFunc("DELETE /api/user", chain(userH.DeleteAccount, authRequired))
	s.mux.HandleFunc("GET /api/user/verify-request", chain(userH.GetVerifyRequest, authRequired))
	s.mux.HandleFunc("POST /api/user/verify-request", chain(userH.SubmitVerifyRequest, authRequired))
	s.mux.HandleFunc("PATCH /api/user/plan", chain(userH.SetActivePlan, authRequired))

	// ── Billing ─────────────────────────────────────────────────
	s.mux.HandleFunc("GET /api/billing", chain(billingH.GetBilling, authRequired))
	s.mux.HandleFunc("POST /api/billing/checkout", chain(billingH.CreateCheckout, authRequired))
	s.mux.HandleFunc("POST /api/billing/portal", chain(billingH.CreatePortal, authRequired))
	s.mux.HandleFunc("POST /api/billing/webhook", billingH.WebhookHandler)

	// ── Team ────────────────────────────────────────────────────
	s.mux.HandleFunc("GET /api/team", chain(teamH.GetTeam, authRequired))
	s.mux.HandleFunc("POST /api/team", chain(teamH.CreateTeam, authRequired))
	s.mux.HandleFunc("PATCH /api/team/{id}", chain(teamH.RenameTeam, authRequired))
	s.mux.HandleFunc("DELETE /api/team/{id}", chain(teamH.DeleteTeam, authRequired))
	s.mux.HandleFunc("GET /api/team/members", chain(teamH.ListMembers, authRequired))
	s.mux.HandleFunc("GET /api/team/invitations", chain(teamH.ListInvitations, authRequired))
	s.mux.HandleFunc("DELETE /api/team/members/{userId}", chain(teamH.RemoveMember, authRequired))
	s.mux.HandleFunc("POST /api/team/invite", chain(teamH.Invite, authRequired))
	s.mux.HandleFunc("POST /api/team/invite/code", chain(teamH.GenerateInviteCode, authRequired))
	s.mux.HandleFunc("POST /api/team/invite/accept", chain(teamH.AcceptInvite, authRequired))
	s.mux.HandleFunc("DELETE /api/team/invite/{id}", chain(teamH.RevokeInvite, authRequired))

	// ── Admin ───────────────────────────────────────────────────
	adminChain := func(h http.HandlerFunc) http.HandlerFunc {
		return chain(h, authRequired, adminRequired)
	}

	s.mux.HandleFunc("GET /api/admin/stats", adminChain(adminH.GetStats))
	s.mux.HandleFunc("GET /api/admin/users", adminChain(adminH.ListUsers))
	s.mux.HandleFunc("GET /api/admin/users/{id}", adminChain(adminH.GetUser))
	s.mux.HandleFunc("PATCH /api/admin/users/{id}", adminChain(adminH.UpdateUser))
	s.mux.HandleFunc("POST /api/admin/users/{id}/resend-verify", adminChain(adminH.ResendVerification))
	s.mux.HandleFunc("DELETE /api/admin/users/{id}", adminChain(adminH.DeleteUser))
	s.mux.HandleFunc("GET /api/admin/tunnels", adminChain(adminH.ListTunnels))
	s.mux.HandleFunc("DELETE /api/admin/tunnels/{id}", adminChain(adminH.KillTunnel))
	s.mux.HandleFunc("GET /api/admin/plans", adminChain(adminH.GetPlans))
	s.mux.HandleFunc("PUT /api/admin/plans", adminChain(adminH.UpdatePlans))
	s.mux.HandleFunc("GET /api/admin/organizations", adminChain(adminH.ListOrgs))
	s.mux.HandleFunc("POST /api/admin/organizations", adminChain(adminH.CreateOrg))
	s.mux.HandleFunc("GET /api/admin/organizations/{id}", adminChain(adminH.GetOrg))
	s.mux.HandleFunc("GET /api/admin/organizations/{id}/members", adminChain(adminH.ListOrgMembers))
	s.mux.HandleFunc("PATCH /api/admin/organizations/{id}", adminChain(adminH.UpdateOrg))
	s.mux.HandleFunc("DELETE /api/admin/organizations/{id}", adminChain(adminH.DeleteOrg))
	s.mux.HandleFunc("GET /api/admin/abuse/events", adminChain(adminH.ListAbuseEvents))
	s.mux.HandleFunc("GET /api/admin/abuse/blocked", adminChain(adminH.ListBlockedIPs))
	s.mux.HandleFunc("POST /api/admin/abuse/blocked", adminChain(adminH.BlockIP))
	s.mux.HandleFunc("DELETE /api/admin/abuse/blocked/{id}", adminChain(adminH.UnblockIP))
	s.mux.HandleFunc("GET /api/admin/verify-requests", adminChain(adminH.ListVerifyRequests))
	s.mux.HandleFunc("GET /api/admin/verify-requests/{id}", adminChain(adminH.GetVerifyRequest))
	s.mux.HandleFunc("PATCH /api/admin/verify-requests/{id}", adminChain(adminH.UpdateVerifyRequest))
	s.mux.HandleFunc("DELETE /api/admin/verify-requests/{id}", adminChain(adminH.DeleteVerifyRequest))
	s.mux.HandleFunc("POST /api/admin/verify-requests/{id}/notify", adminChain(adminH.NotifyVerifyRequest))
	s.mux.HandleFunc("POST /api/admin/verify-requests/{id}/reset", adminChain(adminH.ResetVerifyRequest))
	s.mux.HandleFunc("GET /api/admin/revenue", adminChain(billingH.GetRevenue))
	s.mux.HandleFunc("GET /api/admin/billing/subscribers", adminChain(billingH.GetSubscribers))
	s.mux.HandleFunc("POST /api/admin/billing/refund", adminChain(billingH.AdminRefund))
	s.mux.HandleFunc("POST /api/admin/billing/receipt", adminChain(billingH.AdminSendReceipt))

	// ── System monitor (admin only) ─────────────────────────────
	s.mux.HandleFunc("GET /api/admin/system", adminChain(monitorH.GetSnapshot))
	s.mux.HandleFunc("GET /api/admin/system/stream", func(w http.ResponseWriter, r *http.Request) {
		monitorH.Stream(w, r, s.cfg.JWTSecret)
	})

	// ── Public plans (no auth) ──────────────────────────────────
	s.mux.HandleFunc("GET /api/plans", adminH.GetPublicPlans)

	// ── Public server limits (no auth) ───────────────────────────
	s.mux.HandleFunc("GET /api/server-limits", func(w http.ResponseWriter, r *http.Request) {
		cfg, err := s.db.GetServerConfig(r.Context())
		if err != nil {
			// fallback to compiled-in defaults
			response.Success(w, map[string]any{
				"maxTunnelsPerIP":            config.DefaultMaxTunnelsPerIP,
				"maxTotalTunnels":            config.DefaultMaxTotalTunnels,
				"maxConnectionsPerMinute":    config.DefaultMaxConnectionsPerMin,
				"requestsPerSecond":          config.RequestsPerSecond,
				"maxRequestBodyBytes":        config.MaxRequestBodySize,
				"maxWebSocketTransferBytes":  config.MaxWebSocketTransfer,
				"inactivityTimeoutSeconds":   int(config.InactivityTimeout.Seconds()),
				"maxTunnelLifetimeHours":     int(config.MaxTunnelLifetime.Hours()),
				"sshHandshakeTimeoutSeconds": int(config.SSHHandshakeTimeout.Seconds()),
				"blockDurationMinutes":       int(config.BlockDuration.Minutes()),
			})
			return
		}
		response.Success(w, cfg)
	})

	// ── Admin server limits ───────────────────────────────────────
	s.mux.HandleFunc("GET /api/admin/server-limits", adminChain(adminH.GetServerConfig))
	s.mux.HandleFunc("PATCH /api/admin/server-limits", adminChain(adminH.UpdateServerConfig))

	// ── Partners (public read, admin write) ──────────────────────
	s.mux.HandleFunc("GET /api/partners", partnersH.ListPublicPartners)
	s.mux.HandleFunc("GET /api/admin/partners", adminChain(partnersH.ListAllPartners))
	s.mux.HandleFunc("POST /api/admin/partners", adminChain(partnersH.CreatePartner))
	s.mux.HandleFunc("PATCH /api/admin/partners/{id}", adminChain(partnersH.UpdatePartner))
	s.mux.HandleFunc("DELETE /api/admin/partners/{id}", adminChain(partnersH.DeletePartner))

	// ── Sponsors (public read, admin write) ──────────────────────
	s.mux.HandleFunc("GET /api/sponsors", sponsorsH.ListPublicSponsors)
	s.mux.HandleFunc("GET /api/admin/sponsors", adminChain(sponsorsH.ListAllSponsors))
	s.mux.HandleFunc("POST /api/admin/sponsors", adminChain(sponsorsH.CreateSponsor))
	s.mux.HandleFunc("PATCH /api/admin/sponsors/{id}", adminChain(sponsorsH.UpdateSponsor))
	s.mux.HandleFunc("DELETE /api/admin/sponsors/{id}", adminChain(sponsorsH.DeleteSponsor))

	// ── Notifications ────────────────────────────────────────────
	s.mux.HandleFunc("GET /api/notifications", chain(notifH.List, authRequired))
	s.mux.HandleFunc("PATCH /api/notifications/read-all", chain(notifH.MarkAllRead, authRequired))
	s.mux.HandleFunc("PATCH /api/notifications/{id}/read", chain(notifH.MarkRead, authRequired))
	s.mux.HandleFunc("DELETE /api/notifications", chain(notifH.ClearAll, authRequired))
	s.mux.HandleFunc("DELETE /api/notifications/{id}", chain(notifH.DeleteOne, authRequired))
	s.mux.HandleFunc("GET /api/notifications/stream", notifH.Stream) // auth via ?token=

	// ── Reserved Subdomains ─────────────────────────────────────
	s.mux.HandleFunc("GET /api/subdomains", chain(subdomainH.List, authRequired))
	s.mux.HandleFunc("GET /api/subdomains/analytics", chain(subdomainH.Analytics, authRequired))
	s.mux.HandleFunc("POST /api/subdomains", chain(subdomainH.Create, authRequired))
	s.mux.HandleFunc("DELETE /api/subdomains/{id}", chain(subdomainH.Delete, authRequired))
	s.mux.HandleFunc("PUT /api/subdomains/{id}/rule", chain(subdomainH.UpsertRule, authRequired))

	// ── Custom Domains ───────────────────────────────────────────
	s.mux.HandleFunc("GET /api/domains", chain(domainsH.List, authRequired))
	s.mux.HandleFunc("POST /api/domains", chain(domainsH.Create, authRequired))
	s.mux.HandleFunc("DELETE /api/domains/{id}", chain(domainsH.Delete, authRequired))
	s.mux.HandleFunc("POST /api/domains/{id}/verify", chain(domainsH.Verify, authRequired))
	s.mux.HandleFunc("PATCH /api/domains/{id}/target", chain(domainsH.SetTarget, authRequired))

	// ── Newsletter ──────────────────────────────────────────────
	s.mux.HandleFunc("POST /api/newsletter/subscribe", newsletterH.Subscribe)

	// ── File uploads ─────────────────────────────────────────────
	s.mux.HandleFunc("POST /api/upload", chain(uploadH.Upload, authRequired))
	s.mux.HandleFunc("GET /api/uploads/{filename}", uploadH.ServeFile)
}

// ─── Middleware chain helper ──────────────────────────────────

// chain applies middleware in order: last middleware wraps outermost.
// chain(handler, mw1, mw2) → mw1(mw2(handler))
func chain(h http.HandlerFunc, middlewares ...func(http.Handler) http.Handler) http.HandlerFunc {
	var handler http.Handler = h
	for i := len(middlewares) - 1; i >= 0; i-- {
		handler = middlewares[i](handler)
	}
	return handler.ServeHTTP
}

