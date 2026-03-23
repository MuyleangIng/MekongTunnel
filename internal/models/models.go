// Package models defines all data models for MekongTunnel.
// Author: Ing Muyleang (អុឹង មួយលៀង) — Ing_Muyleang
package models

import (
	"encoding/json"
	"time"
)

// ─── Typed constants ──────────────────────────────────────────

type Plan string

const (
	PlanFree    Plan = "free"
	PlanStudent Plan = "student"
	PlanPro     Plan = "pro"
	PlanOrg     Plan = "org"
)

type AccountType string

const (
	AccountPersonal AccountType = "personal"
	AccountTeam     AccountType = "team"
	AccountOrg      AccountType = "org"
)

type TunnelStatus string

const (
	TunnelActive  TunnelStatus = "active"
	TunnelStopped TunnelStatus = "stopped"
)

type TeamRole string

const (
	RoleOwner  TeamRole = "owner"
	RoleMember TeamRole = "member"
	RoleAdmin  TeamRole = "admin"
)

type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// ─── User ─────────────────────────────────────────────────────

type User struct {
	ID            string      `json:"id"`
	Email         string      `json:"email"`
	Name          string      `json:"name"`
	PasswordHash  *string     `json:"-"`
	AvatarURL     string      `json:"avatar_url"`
	Plan          string      `json:"plan"`
	AccountType   string      `json:"account_type"`
	EmailVerified bool        `json:"email_verified"`
	TOTPSecret      *string     `json:"-"`
	TOTPEnabled     bool        `json:"totp_enabled"`
	EmailOTPEnabled bool        `json:"email_otp_enabled"`
	IsAdmin       bool        `json:"is_admin"`
	Suspended     bool        `json:"suspended"`
	GithubID             *string    `json:"github_id,omitempty"`
	GithubLogin          string     `json:"github_login,omitempty"`
	GoogleID             *string    `json:"google_id,omitempty"`
	StripeCustomerID     *string    `json:"-"`
	StripeSubscriptionID *string    `json:"-"`
	SubscriptionPlan     string     `json:"subscription_plan,omitempty"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
	LastSeenAt           *time.Time `json:"last_seen_at,omitempty"`
	// Trial & newsletter
	TrialEndsAt                *time.Time `json:"trial_ends_at,omitempty"`
	NewsletterSubscribed       bool       `json:"newsletter_subscribed"`
	NewsletterUnsubscribeToken string     `json:"-"`
}

// IsAdmin returns whether the user has admin privileges.
func (u *User) IsAdminUser() bool {
	return u.IsAdmin
}

// ─── ApiToken ─────────────────────────────────────────────────

type ApiToken struct {
	ID         string     `json:"id"`
	UserID     string     `json:"user_id"`
	Name       string     `json:"name"`
	TokenHash  string     `json:"-"`
	Prefix     string     `json:"prefix"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

// ─── RefreshToken ─────────────────────────────────────────────

type RefreshToken struct {
	ID        string     `json:"id"`
	UserID    string     `json:"user_id"`
	TokenHash string     `json:"-"`
	ExpiresAt time.Time  `json:"expires_at"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// ─── PasswordResetToken ───────────────────────────────────────

type PasswordResetToken struct {
	ID        string     `json:"id"`
	UserID    string     `json:"user_id"`
	TokenHash string     `json:"-"`
	ExpiresAt time.Time  `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// ─── EmailVerifyToken ─────────────────────────────────────────

type EmailVerifyToken struct {
	ID        string     `json:"id"`
	UserID    string     `json:"user_id"`
	TokenHash string     `json:"-"`
	ExpiresAt time.Time  `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// ─── Tunnel ───────────────────────────────────────────────────

type Tunnel struct {
	ID            string     `json:"id"`
	UserID        *string    `json:"user_id,omitempty"`
	Subdomain     string     `json:"subdomain"`
	LocalPort     int        `json:"local_port"`
	RemoteIP      string     `json:"remote_ip"`
	Status        string     `json:"status"`
	StartedAt     time.Time  `json:"started_at"`
	EndedAt       *time.Time `json:"ended_at,omitempty"`
	TotalRequests int64      `json:"total_requests"`
	TotalBytes    int64      `json:"total_bytes"`
}

// ─── Team ─────────────────────────────────────────────────────

type Team struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	Plan      string    `json:"plan"`
	OwnerID   string    `json:"owner_id"`
	CreatedAt time.Time `json:"created_at"`
}

// ─── TeamMember ───────────────────────────────────────────────

type TeamMember struct {
	ID       string    `json:"id"`
	TeamID   string    `json:"team_id"`
	UserID   string    `json:"user_id"`
	Role     string    `json:"role"`
	JoinedAt time.Time `json:"joined_at"`
	// Populated via JOIN
	User *User `json:"user,omitempty"`
}

// ─── Invitation ───────────────────────────────────────────────

type Invitation struct {
	ID         string     `json:"id"`
	TeamID     string     `json:"team_id"`
	Email      string     `json:"email"`
	Role       string     `json:"role"`
	TokenHash  string     `json:"-"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	AcceptedAt *time.Time `json:"accepted_at,omitempty"`
}

// ─── Organization ─────────────────────────────────────────────

type Organization struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Domain        string    `json:"domain"`
	Plan          string    `json:"plan"`
	OwnerID       *string   `json:"owner_id,omitempty"`
	Status        string    `json:"status"`
	MemberCount   int       `json:"member_count"`
	ActiveTunnels int       `json:"active_tunnels"`
	CreatedAt     time.Time `json:"created_at"`
}

// ─── BlockedIP ────────────────────────────────────────────────

type BlockedIP struct {
	ID            string     `json:"id"`
	IP            string     `json:"ip"`
	Reason        string     `json:"reason"`
	BlockedBy     *string    `json:"blocked_by,omitempty"`
	Violations    int        `json:"violations"`
	TunnelsKilled int        `json:"tunnels_killed"`
	AutoBlock     bool       `json:"auto_block"`
	BlockedAt     time.Time  `json:"blocked_at"`
	UnblockedAt   *time.Time `json:"unblocked_at,omitempty"`
}

// ─── AbuseEvent ───────────────────────────────────────────────

type AbuseEvent struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	IP        string    `json:"ip"`
	Subdomain *string   `json:"subdomain,omitempty"`
	Detail    string    `json:"detail"`
	Severity  string    `json:"severity"`
	CreatedAt time.Time `json:"created_at"`
}

// ─── NewsletterSubscriber ─────────────────────────────────────

type NewsletterSubscriber struct {
	ID             string     `json:"id"`
	Email          string     `json:"email"`
	SubscribedAt   time.Time  `json:"subscribed_at"`
	UnsubscribedAt *time.Time `json:"unsubscribed_at,omitempty"`
}

// ─── PlanConfig ───────────────────────────────────────────────

type PlanLimits struct {
	MaxTunnels        int     `json:"max_tunnels"`
	MaxRequestsPerMin int     `json:"max_requests_per_min"`
	MaxBandwidthGB    int     `json:"max_bandwidth_gb"`
	CustomSubdomain   bool    `json:"custom_subdomain"`
	TeamMembers       int     `json:"team_members"`
	PriceMonthly      float64 `json:"price_monthly"`
	PriceYearly       float64 `json:"price_yearly"`
}

type PlanConfig struct {
	PlanID    string          `json:"plan_id"`
	Config    json.RawMessage `json:"config"`
	UpdatedAt time.Time       `json:"updated_at"`
	UpdatedBy *string         `json:"updated_by,omitempty"`
}

// ─── VerifyRequest ────────────────────────────────────────────

type VerifyRequest struct {
	ID           string    `json:"id"`
	UserID       string    `json:"user_id"`
	Type         string    `json:"type"`
	Status       string    `json:"status"`
	OrgName      string    `json:"org_name,omitempty"`
	RejectReason string    `json:"reject_reason,omitempty"`
	Reason       string    `json:"reason,omitempty"`
	DocumentURL  string    `json:"document_url,omitempty"`
	AdminNote    string    `json:"admin_note,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	// Populated via JOIN for admin views
	UserName            string `json:"user_name,omitempty"`
	UserEmail           string `json:"user_email,omitempty"`
	UserPlan            string `json:"user_plan,omitempty"`
	UserHasSubscription bool   `json:"user_has_subscription,omitempty"`
}

// ─── Notification ─────────────────────────────────────────────

type Notification struct {
	ID        string     `json:"id"`
	UserID    string     `json:"user_id"`
	Type      string     `json:"type"`
	Title     string     `json:"title"`
	Body      string     `json:"body"`
	Link      string     `json:"link"`
	ReadAt    *time.Time `json:"read_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// ─── Partner ──────────────────────────────────────────────────

type Partner struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Slogan       string    `json:"slogan"`
	Description  string    `json:"description"`
	LogoURL      string    `json:"logo_url"`
	WebsiteURL   string    `json:"website_url"`
	Badge        string    `json:"badge,omitempty"`
	FacebookURL  string    `json:"facebook_url,omitempty"`
	TwitterURL   string    `json:"twitter_url,omitempty"`
	InstagramURL string    `json:"instagram_url,omitempty"`
	LinkedinURL  string    `json:"linkedin_url,omitempty"`
	GithubURL    string    `json:"github_url,omitempty"`
	YoutubeURL   string    `json:"youtube_url,omitempty"`
	IsActive     bool      `json:"is_active"`
	IsPublic     bool      `json:"is_public"`
	SortOrder    int       `json:"sort_order"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// ─── CustomDomain ─────────────────────────────────────────────

type CustomDomain struct {
	ID                string     `json:"id"`
	UserID            string     `json:"user_id"`
	Domain            string     `json:"domain"`
	Status            string     `json:"status"` // pending | verified | failed
	VerificationToken string     `json:"verification_token"`
	TargetSubdomain   *string    `json:"target_subdomain,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	VerifiedAt        *time.Time `json:"verified_at,omitempty"`
	LastCheckedAt     *time.Time `json:"last_checked_at,omitempty"`
	// Derived for UI
	CNAMETarget string `json:"cname_target,omitempty"`
	TXTRecord   string `json:"txt_record,omitempty"`
}

// ─── ReservedSubdomain ────────────────────────────────────────

type ReservedSubdomain struct {
	ID        string       `json:"id"`
	UserID    string       `json:"user_id"`
	Subdomain string       `json:"subdomain"`
	CreatedAt time.Time    `json:"created_at"`
	Rule      *SubdomainRule `json:"rule,omitempty"`
}

// ─── SubdomainRule ────────────────────────────────────────────

type SubdomainRule struct {
	ID             string            `json:"id"`
	SubdomainID    string            `json:"subdomain_id"`
	AllowedIPs     []string          `json:"allowed_ips"`
	AllowedAgents  []string          `json:"allowed_agents"`
	RateLimitRPM   int               `json:"rate_limit_rpm"`
	MaxConnections int               `json:"max_connections"`
	BlockTor       bool              `json:"block_tor"`
	ForceHTTPS     bool              `json:"force_https"`
	CustomHeaders  map[string]string `json:"custom_headers"`
	Enabled        bool              `json:"enabled"`
	UpdatedAt      time.Time         `json:"updated_at"`
}

// ─── AdminStats ───────────────────────────────────────────────

type AdminStats struct {
	TotalUsers        int `json:"total_users"`
	VerifiedUsers     int `json:"verified_users"`
	AdminUsers        int `json:"admin_users"`
	SuspendedUsers    int `json:"suspended_users"`
	TotalTunnels      int `json:"total_tunnels"`
	ActiveTunnels     int `json:"active_tunnels"`
	TotalOrgs         int `json:"total_orgs"`
	TotalAPITokens    int `json:"total_api_tokens"`
	TotalBlockedIPs   int `json:"total_blocked_ips"`
	TotalAbuseEvents  int `json:"total_abuse_events"`
	NewsletterSubs    int `json:"newsletter_subs"`
	UsersByPlan       map[string]int `json:"users_by_plan"`
}

// ─── Sponsor ──────────────────────────────────────────────────

type Sponsor struct {
	ID            string    `json:"id"`
	Type          string    `json:"type"` // github | coffee | bank | referral | other
	Title         string    `json:"title"`
	Description   string    `json:"description"`
	URL           string    `json:"url"`
	ButtonText    string    `json:"button_text"`
	Icon          string    `json:"icon"`
	Badge         string    `json:"badge"`
	BankName      string    `json:"bank_name"`
	AccountName   string    `json:"account_name"`
	AccountNumber string    `json:"account_number"`
	Currency      string    `json:"currency"`
	Note          string    `json:"note"`
	IsActive      bool      `json:"is_active"`
	SortOrder     int       `json:"sort_order"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// ServerConfig holds admin-editable server limit values stored in the DB.
type ServerConfig struct {
	MaxTunnelsPerIP            int     `json:"maxTunnelsPerIP"`
	MaxTotalTunnels            int     `json:"maxTotalTunnels"`
	MaxConnectionsPerMinute    int     `json:"maxConnectionsPerMinute"`
	RequestsPerSecond          float64 `json:"requestsPerSecond"`
	MaxRequestBodyBytes        int64   `json:"maxRequestBodyBytes"`
	MaxWebSocketTransferBytes  int64   `json:"maxWebSocketTransferBytes"`
	InactivityTimeoutSeconds   int     `json:"inactivityTimeoutSeconds"`
	MaxTunnelLifetimeHours     int     `json:"maxTunnelLifetimeHours"`
	SSHHandshakeTimeoutSeconds int     `json:"sshHandshakeTimeoutSeconds"`
	BlockDurationMinutes       int     `json:"blockDurationMinutes"`
	// Trial & payments
	FreeTrialEnabled     bool `json:"freeTrialEnabled"`
	TrialDurationDays    int  `json:"trialDurationDays"`
	BakongDiscountPercent int `json:"bakongDiscountPercent"`
	UpdatedAt            time.Time `json:"updatedAt"`
}

// NewsletterCampaign is an admin-sent newsletter broadcast.
type NewsletterCampaign struct {
	ID             string    `json:"id"`
	Subject        string    `json:"subject"`
	BodyHTML       string    `json:"body_html"`
	SentBy         string    `json:"sent_by"`
	SentAt         time.Time `json:"sent_at"`
	RecipientCount int       `json:"recipient_count"`
}

// ─── DonationSubmission ───────────────────────────────────────

type DonationSubmission struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Email         string    `json:"email"`
	Amount        string    `json:"amount"`
	Currency      string    `json:"currency"`
	PaymentMethod string    `json:"payment_method"`
	ReceiptURL    string    `json:"receipt_url"`
	SocialURL     string    `json:"social_url"`
	Message       string    `json:"message"`
	Status        string    `json:"status"`
	ShowOnHome    bool      `json:"show_on_home"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// ─── CLIDeviceSession ─────────────────────────────────────────

// CLIDeviceSession implements the OAuth2-style device flow for `mekong login`.
// The CLI creates a session, the user approves via the web dashboard, and the
// CLI polls until the token is ready.
type CLIDeviceSession struct {
	ID          string     `json:"id"`
	UserID      string     `json:"user_id,omitempty"`
	TokenHash   string     `json:"-"`
	TokenPrefix string     `json:"token_prefix,omitempty"`
	RawToken    string     `json:"raw_token,omitempty"` // returned exactly once, then cleared
	ApprovedAt  *time.Time `json:"approved_at,omitempty"`
	ExpiresAt   time.Time  `json:"expires_at"`
	CreatedAt   time.Time  `json:"created_at"`
}
