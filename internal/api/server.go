// Package api wires together all handlers and middleware into an HTTP server.
// Author: Ing Muyleang (អុឹង មួយលៀង) — Ing_Muyleang
package api

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/MuyleangIng/MekongTunnel/internal/api/handlers"
	"github.com/MuyleangIng/MekongTunnel/internal/api/middleware"
	"github.com/MuyleangIng/MekongTunnel/internal/api/response"
	"github.com/MuyleangIng/MekongTunnel/internal/config"
	"github.com/MuyleangIng/MekongTunnel/internal/db"
	"github.com/MuyleangIng/MekongTunnel/internal/hub"
	"github.com/MuyleangIng/MekongTunnel/internal/mailer"
	"github.com/MuyleangIng/MekongTunnel/internal/notify"
	"github.com/MuyleangIng/MekongTunnel/internal/redisx"
	"github.com/MuyleangIng/MekongTunnel/internal/telegrambot"
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
	// TunnelEdgeSecret is a shared secret required on internal tunnel-edge write endpoints.
	// Set TUNNEL_EDGE_SECRET in env. If empty, the check is skipped (dev/single-node only).
	TunnelEdgeSecret string
	AllowedOrigins   []string
	FrontendURL      string
	PlanPrices       map[string]string
	UploadDir        string
	PublicURL        string
	MailConfig       mailer.Config
	Redis            *redisx.Client
	Telegram         telegrambot.Config
}

// Server is the MekongTunnel REST API HTTP server.
type Server struct {
	mux         *http.ServeMux
	handler     http.Handler
	db          *db.DB
	cfg         Config
	hub         *hub.Hub
	redisCancel context.CancelFunc
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
	s.handler = middleware.CORSMiddleware(cfg.AllowedOrigins)(s.mux)
	s.startNotificationRelay()
	return s
}

// ServeHTTP implements http.Handler, applying global middleware.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

// Close stops background Redis subscribers.
func (s *Server) Close() {
	if s.redisCancel != nil {
		s.redisCancel()
	}
}

// ─── Route registration ───────────────────────────────────────

func (s *Server) registerRoutes() {
	authRequired := middleware.AuthMiddleware(s.cfg.JWTSecret)
	adminRequired := middleware.AdminMiddleware()
	internalOnly := middleware.InternalSecretMiddleware(s.cfg.TunnelEdgeSecret)
	registerRate := middleware.RateLimitIP(s.cfg.Redis, "auth-register", 10, time.Minute)
	loginRate := middleware.RateLimitIP(s.cfg.Redis, "auth-login", 20, time.Minute)
	forgotPasswordRate := middleware.RateLimitIP(s.cfg.Redis, "auth-forgot-password", 8, time.Minute)
	verifyEmailRate := middleware.RateLimitIP(s.cfg.Redis, "auth-verify-email", 20, time.Minute)
	resendVerifyRate := middleware.RateLimitIP(s.cfg.Redis, "auth-resend-verify", 8, time.Minute)
	adminVerifyRequestRate := middleware.RateLimitIP(s.cfg.Redis, "auth-request-admin-verify", 6, time.Minute)
	emailOTPRate := middleware.RateLimitIP(s.cfg.Redis, "auth-email-otp", 20, time.Minute)
	tokenInfoRate := middleware.RateLimitIP(s.cfg.Redis, "auth-token-info", 60, time.Minute)
	cliDeviceCreateRate := middleware.RateLimitIP(s.cfg.Redis, "cli-device-create", 20, time.Minute)
	cliDevicePollRate := middleware.RateLimitIP(s.cfg.Redis, "cli-device-poll", 120, time.Minute)
	refreshRate := middleware.RateLimitIP(s.cfg.Redis, "auth-refresh", 30, time.Minute)
	twoFAVerifyRate := middleware.RateLimitIP(s.cfg.Redis, "auth-2fa-verify", 10, time.Minute)
	donationSubmitRate := middleware.RateLimitIP(s.cfg.Redis, "donation-submit", 5, time.Minute)

	// ── Shared notification service ──────────────────────────────
	notifySvc := &notify.Service{DB: s.db, Hub: s.hub, Redis: s.cfg.Redis}

	var botSvc *telegrambot.Service
	if s.cfg.Telegram.Enabled {
		botSvc = telegrambot.New(s.cfg.Telegram, s.db)
	}

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
		StatsClient: &http.Client{
			Timeout: 5 * time.Second,
		},
		StreamClient: &http.Client{},
		JWTSecret:    s.cfg.JWTSecret,
		Telegram:     botSvc,
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

	receiptH := &handlers.ReceiptHandler{
		DB:     s.db,
		Notify: notifySvc,
		Mailer: mailSvc,
	}

	teamH := &handlers.TeamHandler{DB: s.db, Mailer: mailSvc, Notify: notifySvc, FrontendURL: s.cfg.FrontendURL}
	adminH := &handlers.AdminHandler{DB: s.db, Notify: notifySvc, Mailer: mailSvc, FrontendURL: s.cfg.FrontendURL, Telegram: botSvc}
	newsletterH := &handlers.NewsletterHandler{DB: s.db, Mailer: mailSvc, FrontendURL: s.cfg.FrontendURL}
	partnersH := &handlers.PartnersHandler{DB: s.db}
	sponsorsH := &handlers.SponsorsHandler{DB: s.db}
	notifH := &handlers.NotificationsHandler{DB: s.db, Hub: s.hub, JWTSecret: s.cfg.JWTSecret}
	monitorH := &handlers.MonitorHandler{}
	subdomainH := &handlers.SubdomainHandler{DB: s.db}
	domainsH := &handlers.DomainsHandler{DB: s.db, Telegram: botSvc}
	uploadH := &handlers.UploadHandler{
		UploadDir: s.cfg.UploadDir,
		BaseURL:   s.cfg.PublicURL,
	}

	// ── Health ──────────────────────────────────────────────────
	s.mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		response.Success(w, map[string]any{"ok": true, "service": "mekong-api"})
	})

	// ── Public announcement ──────────────────────────────────────
	s.mux.HandleFunc("GET /api/announcement", func(w http.ResponseWriter, r *http.Request) {
		cfg, err := s.db.GetServerConfig(r.Context())
		if err != nil || !cfg.AnnouncementEnabled || cfg.AnnouncementText == "" {
			response.Success(w, nil)
			return
		}
		response.Success(w, map[string]any{
			"text":       cfg.AnnouncementText,
			"color":      cfg.AnnouncementColor,
			"link":       cfg.AnnouncementLink,
			"link_label": cfg.AnnouncementLinkLabel,
		})
	})

	// ── Auth ────────────────────────────────────────────────────
	s.mux.HandleFunc("POST /api/auth/register", chain(authH.Register, registerRate))
	s.mux.HandleFunc("POST /api/auth/login", chain(authH.Login, loginRate))
	s.mux.HandleFunc("POST /api/auth/logout", authH.Logout)
	s.mux.HandleFunc("GET /api/auth/me", chain(authH.Me, authRequired))
	s.mux.HandleFunc("GET /api/auth/token-info", chain(authH.TokenInfo, tokenInfoRate)) // API token (mkt_xxx) — no JWT needed
	s.mux.HandleFunc("POST /api/auth/refresh", chain(authH.Refresh, refreshRate))
	s.mux.HandleFunc("POST /api/auth/forgot-password", chain(authH.ForgotPassword, forgotPasswordRate))
	s.mux.HandleFunc("POST /api/auth/reset-password", authH.ResetPassword)
	s.mux.HandleFunc("POST /api/auth/verify-email", chain(authH.VerifyEmail, verifyEmailRate))
	s.mux.HandleFunc("POST /api/auth/resend-verify", chain(authH.ResendVerify, resendVerifyRate))
	s.mux.HandleFunc("POST /api/auth/request-admin-verify", chain(authH.RequestAdminVerify, adminVerifyRequestRate))
	s.mux.HandleFunc("POST /api/auth/email-otp/verify", chain(authH.VerifyEmailOTP, emailOTPRate))
	s.mux.HandleFunc("POST /api/auth/2fa/email/enable", chain(authH.EnableEmailOTP, authRequired))
	s.mux.HandleFunc("POST /api/auth/2fa/email/disable", chain(authH.DisableEmailOTP, authRequired))
	s.mux.HandleFunc("GET /api/auth/github", authH.GitHubOAuth)
	s.mux.HandleFunc("GET /api/auth/github/callback", authH.GitHubCallback)
	s.mux.HandleFunc("GET /api/auth/google", authH.GoogleOAuth)
	s.mux.HandleFunc("GET /api/auth/google/callback", authH.GoogleCallback)
	s.mux.HandleFunc("POST /api/auth/2fa/setup", chain(authH.Setup2FA, authRequired))
	s.mux.HandleFunc("POST /api/auth/2fa/enable", chain(authH.Enable2FA, authRequired))
	s.mux.HandleFunc("POST /api/auth/2fa/disable", chain(authH.Disable2FA, authRequired))
	s.mux.HandleFunc("POST /api/auth/2fa/verify", chain(authH.Verify2FA, twoFAVerifyRate))

	// ── API Tokens ──────────────────────────────────────────────
	s.mux.HandleFunc("GET /api/tokens", chain(tokensH.ListTokens, authRequired))
	s.mux.HandleFunc("POST /api/tokens", chain(tokensH.CreateToken, authRequired))
	s.mux.HandleFunc("DELETE /api/tokens/{id}", chain(tokensH.RevokeToken, authRequired))

	// ── CLI Device Auth (mekong login) ───────────────────────────
	s.mux.HandleFunc("POST /api/cli/device", chain(cliDeviceH.CreateSession, cliDeviceCreateRate))
	s.mux.HandleFunc("GET /api/cli/device", chain(cliDeviceH.PollSession, cliDevicePollRate))
	s.mux.HandleFunc("POST /api/cli/device/approve", chain(cliDeviceH.ApproveSession, authRequired))
	s.mux.HandleFunc("GET /api/cli/subdomains", subdomainH.ListCLI)
	s.mux.HandleFunc("POST /api/cli/subdomains", subdomainH.CreateCLI)
	s.mux.HandleFunc("DELETE /api/cli/subdomains/{id}", subdomainH.DeleteCLI)
	s.mux.HandleFunc("GET /api/cli/domains", domainsH.ListCLI)
	s.mux.HandleFunc("POST /api/cli/domains", domainsH.CreateCLI)
	s.mux.HandleFunc("DELETE /api/cli/domains/{id}", domainsH.DeleteCLI)
	s.mux.HandleFunc("POST /api/cli/domains/{id}/verify", domainsH.VerifyCLI)
	s.mux.HandleFunc("PATCH /api/cli/domains/{id}/target", domainsH.SetTargetCLI)

	// ── Tunnels ─────────────────────────────────────────────────
	s.mux.HandleFunc("GET /api/tunnels", chain(tunnelsH.ListTunnels, authRequired))
	s.mux.HandleFunc("GET /api/tunnels/live", chain(tunnelsH.ListLiveTunnels, authRequired))
	s.mux.HandleFunc("GET /api/tunnels/overview", chain(tunnelsH.GetOverview, authRequired))
	s.mux.HandleFunc("GET /api/tunnels/stats", tunnelsH.GetStats)
	s.mux.HandleFunc("DELETE /api/tunnels/history", chain(tunnelsH.ClearHistory, authRequired))
	s.mux.HandleFunc("POST /api/tunnels/{id}/log-token", chain(tunnelsH.CreateLogToken, authRequired))
	s.mux.HandleFunc("GET /api/tunnels/{id}/logs", tunnelsH.GetLogs)
	s.mux.HandleFunc("POST /api/tunnels", chain(tunnelsH.ReportTunnel, internalOnly))             // tunnel edge only
	s.mux.HandleFunc("PATCH /api/tunnels/{id}", chain(tunnelsH.UpdateTunnelStatus, internalOnly)) // tunnel edge only

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
	s.mux.HandleFunc("POST /api/billing/manual-payment", chain(receiptH.SubmitReceipt, authRequired))
	s.mux.HandleFunc("GET /api/billing/manual-payment", chain(receiptH.ListMyReceipts, authRequired))
	s.mux.HandleFunc("GET /api/billing/manual-payment/count", chain(receiptH.UserReceiptPendingCount, authRequired))

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
	s.mux.HandleFunc("POST /api/team/invite/accept-by-id", chain(teamH.AcceptInviteByID, authRequired))
	s.mux.HandleFunc("DELETE /api/team/invite/{id}", chain(teamH.RevokeInvite, authRequired))
	s.mux.HandleFunc("POST /api/team/invite/{id}/resend", chain(teamH.ResendInvite, authRequired))
	s.mux.HandleFunc("GET /api/team/joined", chain(teamH.GetJoinedTeams, authRequired))
	s.mux.HandleFunc("GET /api/team/{id}/detail", chain(teamH.GetTeamDetail, authRequired))
	s.mux.HandleFunc("GET /api/team/{id}/stats", chain(teamH.GetTeamStats, authRequired))
	s.mux.HandleFunc("GET /api/team/{id}/my-tunnels", chain(teamH.GetMyTunnels, authRequired))
	s.mux.HandleFunc("GET /api/team/{id}/members/{userId}/tunnels", chain(teamH.GetMemberTunnels, authRequired))
	s.mux.HandleFunc("PATCH /api/team/members/{userId}/role", chain(teamH.ChangeRole, authRequired))
	s.mux.HandleFunc("GET /api/team/my-invitations", chain(teamH.GetMyInvitations, authRequired))
	s.mux.HandleFunc("POST /api/team/{id}/leave", chain(teamH.LeaveTeam, authRequired))

	// ── Org ─────────────────────────────────────────────────────
	orgH := &handlers.OrgHandler{DB: s.db, Mailer: mailSvc, Notify: notifySvc, FrontendURL: s.cfg.FrontendURL}
	s.mux.HandleFunc("POST /api/org/create", chain(orgH.CreateMyOrg, authRequired))
	s.mux.HandleFunc("GET /api/org/mine", chain(orgH.GetMine, authRequired))
	s.mux.HandleFunc("GET /api/org/{id}", chain(orgH.GetOrg, authRequired))
	s.mux.HandleFunc("GET /api/org/{id}/members", chain(orgH.ListMembers, authRequired))
	s.mux.HandleFunc("DELETE /api/org/{id}/members/{userId}", chain(orgH.RemoveMember, authRequired))
	s.mux.HandleFunc("PATCH /api/org/{id}/members/{userId}/allocation", chain(orgH.SetAllocation, authRequired))
	s.mux.HandleFunc("GET /api/org/{id}/teams", chain(orgH.ListTeams, authRequired))
	s.mux.HandleFunc("POST /api/org/{id}/teams", chain(orgH.CreateTeam, authRequired))
	s.mux.HandleFunc("DELETE /api/org/{id}/teams/{teamId}", chain(orgH.DeleteTeam, authRequired))
	s.mux.HandleFunc("GET /api/org/{id}/requests", chain(orgH.ListRequests, authRequired))
	s.mux.HandleFunc("PATCH /api/org/{id}/requests/{reqId}", chain(orgH.ReviewRequest, authRequired))
	s.mux.HandleFunc("POST /api/org/{id}/requests/{reqId}/comments", chain(orgH.AddRequestComment, authRequired))
	s.mux.HandleFunc("POST /api/org/request", chain(orgH.SubmitRequest, authRequired))
	s.mux.HandleFunc("POST /api/org/{id}/import/preview", chain(orgH.PreviewImport, authRequired))
	s.mux.HandleFunc("POST /api/org/{id}/import", chain(orgH.BulkImport, authRequired))

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
	s.mux.HandleFunc("GET /api/admin/domains", adminChain(adminH.ListDomains))
	s.mux.HandleFunc("GET /api/admin/domains/{id}", adminChain(adminH.GetDomain))
	s.mux.HandleFunc("POST /api/admin/domains/{id}/verify", adminChain(adminH.VerifyDomain))
	s.mux.HandleFunc("PATCH /api/admin/domains/{id}/target", adminChain(adminH.SetDomainTarget))
	s.mux.HandleFunc("DELETE /api/admin/domains/{id}", adminChain(adminH.DeleteDomain))
	s.mux.HandleFunc("GET /api/admin/plans", adminChain(adminH.GetPlans))
	s.mux.HandleFunc("PUT /api/admin/plans", adminChain(adminH.UpdatePlans))
	s.mux.HandleFunc("GET /api/admin/organizations", adminChain(adminH.ListOrgs))
	s.mux.HandleFunc("POST /api/admin/organizations", adminChain(adminH.CreateOrg))
	s.mux.HandleFunc("GET /api/admin/organizations/{id}", adminChain(adminH.GetOrg))
	s.mux.HandleFunc("GET /api/admin/organizations/{id}/members", adminChain(adminH.ListOrgMembers))
	s.mux.HandleFunc("POST /api/admin/organizations/{id}/import/preview", adminChain(orgH.PreviewImport))
	s.mux.HandleFunc("POST /api/admin/organizations/{id}/import", adminChain(orgH.BulkImport))
	s.mux.HandleFunc("PATCH /api/admin/organizations/{id}", adminChain(adminH.UpdateOrg))
	s.mux.HandleFunc("DELETE /api/admin/organizations/{id}", adminChain(adminH.DeleteOrg))
	s.mux.HandleFunc("PATCH /api/admin/org/{id}/seat-limit", adminChain(orgH.SetSeatLimit))
	s.mux.HandleFunc("PATCH /api/admin/org/{id}/plan", adminChain(orgH.SetPlan))
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
	s.mux.HandleFunc("GET /api/admin/billing/receipts", adminChain(receiptH.AdminListReceipts))
	s.mux.HandleFunc("GET /api/admin/billing/receipts/count", adminChain(receiptH.AdminReceiptCount))
	s.mux.HandleFunc("POST /api/admin/billing/receipts/{id}/review", adminChain(receiptH.AdminReviewReceipt))
	s.mux.HandleFunc("DELETE /api/admin/billing/receipts/{id}", adminChain(receiptH.AdminDeleteReceipt))

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
	s.mux.HandleFunc("PATCH /api/subdomains/{id}/assignment", chain(subdomainH.UpdateAssignment, authRequired))
	s.mux.HandleFunc("PUT /api/subdomains/{id}/rule", chain(subdomainH.UpsertRule, authRequired))

	// ── Custom Domains ───────────────────────────────────────────
	s.mux.HandleFunc("GET /api/domains", chain(domainsH.List, authRequired))
	s.mux.HandleFunc("POST /api/domains", chain(domainsH.Create, authRequired))
	s.mux.HandleFunc("DELETE /api/domains/{id}", chain(domainsH.Delete, authRequired))
	s.mux.HandleFunc("POST /api/domains/{id}/verify", chain(domainsH.Verify, authRequired))
	s.mux.HandleFunc("PATCH /api/domains/{id}/target", chain(domainsH.SetTarget, authRequired))

	// ── Newsletter ──────────────────────────────────────────────
	s.mux.HandleFunc("POST /api/newsletter/subscribe", newsletterH.Subscribe)
	s.mux.HandleFunc("GET /api/newsletter/unsubscribe", newsletterH.Unsubscribe)
	s.mux.HandleFunc("POST /api/newsletter/resubscribe", newsletterH.ResubscribeByToken)
	s.mux.HandleFunc("POST /api/newsletter/toggle", chain(newsletterH.Toggle, authRequired))
	s.mux.HandleFunc("POST /api/admin/newsletter/preview", chain(newsletterH.AdminPreview, authRequired, adminRequired))
	s.mux.HandleFunc("POST /api/admin/newsletter/send", chain(newsletterH.AdminSend, authRequired, adminRequired))
	s.mux.HandleFunc("GET /api/admin/newsletter/campaigns", chain(newsletterH.AdminCampaigns, authRequired, adminRequired))
	s.mux.HandleFunc("GET /api/admin/newsletter/subscribers", chain(newsletterH.AdminSubscribers, authRequired, adminRequired))

	// ── Donations ─────────────────────────────────────────────────
	donationH := &handlers.DonationHandler{DB: s.db, Notify: notifySvc}
	s.mux.HandleFunc("POST /api/donations/submit", chain(donationH.Submit, donationSubmitRate))
	s.mux.HandleFunc("GET /api/donations", donationH.PublicList)
	s.mux.HandleFunc("GET /api/admin/donations", adminChain(donationH.AdminList))
	s.mux.HandleFunc("PATCH /api/admin/donations/{id}", adminChain(donationH.AdminUpdate))
	s.mux.HandleFunc("DELETE /api/admin/donations/{id}", adminChain(donationH.AdminDelete))

	// ── Trial ────────────────────────────────────────────────────
	s.mux.HandleFunc("POST /api/admin/users/{id}/trial", chain(adminH.SetUserTrial, authRequired, adminRequired))

	// ── File uploads ─────────────────────────────────────────────
	s.mux.HandleFunc("POST /api/upload", chain(uploadH.Upload, authRequired))
	s.mux.HandleFunc("GET /api/uploads/{filename}", uploadH.ServeFile)

	// ── Telegram bot ─────────────────────────────────────────────
	if s.cfg.Telegram.Enabled {
		telegramRate := middleware.RateLimitIP(s.cfg.Redis, "telegram-link", 10, time.Minute)
		telegramH := &handlers.TelegramHandler{DB: s.db, Bot: botSvc}
		log.Printf("[api] telegram bot enabled (@%s)", s.cfg.Telegram.BotUsername)
		s.mux.HandleFunc("POST /api/telegram/webhook", telegramH.Webhook)
		s.mux.HandleFunc("GET /api/telegram/link", chain(telegramH.GetMyLink, authRequired))
		s.mux.HandleFunc("GET /api/telegram/link/session", chain(telegramH.GetLinkSession, authRequired, telegramRate))
		s.mux.HandleFunc("POST /api/telegram/link/approve", chain(telegramH.ApproveLink, authRequired))
		s.mux.HandleFunc("POST /api/telegram/link/cancel", chain(telegramH.CancelLink, authRequired))
		s.mux.HandleFunc("POST /api/telegram/unlink", chain(telegramH.Unlink, authRequired))
	}
}

func (s *Server) startNotificationRelay() {
	if s.cfg.Redis == nil || !s.cfg.Redis.Enabled() {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	s.redisCancel = cancel

	go func() {
		err := s.cfg.Redis.SubscribeNotifications(ctx, func(userID string, payload []byte) {
			s.hub.Push(userID, payload)
		})
		if err != nil && ctx.Err() == nil {
			log.Printf("[api] notification relay: %v", err)
		}
	}()
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
