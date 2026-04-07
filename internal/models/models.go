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
	ID                   string     `json:"id"`
	Email                string     `json:"email"`
	Name                 string     `json:"name"`
	PasswordHash         *string    `json:"-"`
	AvatarURL            string     `json:"avatar_url"`
	Plan                 string     `json:"plan"`
	AccountType          string     `json:"account_type"`
	EmailVerified        bool       `json:"email_verified"`
	TOTPSecret           *string    `json:"-"`
	TOTPEnabled          bool       `json:"totp_enabled"`
	EmailOTPEnabled      bool       `json:"email_otp_enabled"`
	IsAdmin              bool       `json:"is_admin"`
	Suspended            bool       `json:"suspended"`
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
	// Org provisioning fields
	ProvisionedByOrgID *string `json:"provisioned_by_org_id,omitempty"`
	ForcePasswordReset bool    `json:"force_password_reset,omitempty"`
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
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Type        string    `json:"type"`
	Plan        string    `json:"plan"`
	OwnerID     string    `json:"owner_id"`
	OrgID       *string   `json:"org_id,omitempty"`
	CreatedBy   *string   `json:"created_by,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	MemberCount int       `json:"member_count,omitempty"`
	Owner       *User     `json:"owner,omitempty"`
	// Role is populated only for membership queries (non-owner view).
	Role string `json:"role,omitempty"`
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
	// TeamName is populated only for my-invitations queries.
	TeamName string `json:"team_name,omitempty"`
}

// ─── Organization ─────────────────────────────────────────────

type Organization struct {
	ID                      string     `json:"id"`
	Name                    string     `json:"name"`
	Domain                  string     `json:"domain"`
	Plan                    string     `json:"plan"`
	OwnerID                 *string    `json:"owner_id,omitempty"`
	Status                  string     `json:"status"`
	MemberCount             int        `json:"member_count"`
	ActiveTunnels           int        `json:"active_tunnels"`
	CreatedAt               time.Time  `json:"created_at"`
	Slug                    string     `json:"slug,omitempty"`
	Type                    string     `json:"type,omitempty"`
	SeatLimit               int        `json:"seat_limit"`
	CreatedBy               *string    `json:"created_by,omitempty"`
	AdminNote               string     `json:"admin_note,omitempty"`
	StatusChangedAt         time.Time  `json:"status_changed_at"`
	ArchivedAt              *time.Time `json:"archived_at,omitempty"`
	ApprovedVerifyRequestID *string    `json:"approved_verify_request_id,omitempty"`
	BillingDiscountPercent  int        `json:"billing_discount_percent,omitempty"`
	BillingDiscountNote     string     `json:"billing_discount_note,omitempty"`
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
	ID                      string    `json:"id"`
	UserID                  string    `json:"user_id"`
	Type                    string    `json:"type"`
	Status                  string    `json:"status"`
	OrgName                 string    `json:"org_name,omitempty"`
	RejectReason            string    `json:"reject_reason,omitempty"`
	Reason                  string    `json:"reason,omitempty"`
	DocumentURL             string    `json:"document_url,omitempty"`
	AdminNote               string    `json:"admin_note,omitempty"`
	RequestedOrgDomain      string    `json:"requested_org_domain,omitempty"`
	RequestedOrgSeatLimit   int       `json:"requested_org_seat_limit,omitempty"`
	ApprovedOrgID           *string   `json:"approved_org_id,omitempty"`
	ApprovalNote            string    `json:"approval_note,omitempty"`
	ApprovedDiscountPercent int       `json:"approved_discount_percent,omitempty"`
	CreatedAt               time.Time `json:"created_at"`
	UpdatedAt               time.Time `json:"updated_at"`
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
	UserID            string     `json:"user_id,omitempty"`
	TeamID            *string    `json:"team_id,omitempty"`
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
	ID             string         `json:"id"`
	UserID         string         `json:"user_id,omitempty"`
	TeamID         *string        `json:"team_id,omitempty"`
	AssignedUserID *string        `json:"assigned_user_id,omitempty"`
	Subdomain      string         `json:"subdomain"`
	CreatedAt      time.Time      `json:"created_at"`
	Rule           *SubdomainRule `json:"rule,omitempty"`
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
	TotalUsers       int            `json:"total_users"`
	VerifiedUsers    int            `json:"verified_users"`
	AdminUsers       int            `json:"admin_users"`
	SuspendedUsers   int            `json:"suspended_users"`
	TotalTunnels     int            `json:"total_tunnels"`
	ActiveTunnels    int            `json:"active_tunnels"`
	TotalOrgs        int            `json:"total_orgs"`
	TotalAPITokens   int            `json:"total_api_tokens"`
	TotalBlockedIPs  int            `json:"total_blocked_ips"`
	TotalAbuseEvents int            `json:"total_abuse_events"`
	NewsletterSubs   int            `json:"newsletter_subs"`
	UsersByPlan      map[string]int `json:"users_by_plan"`
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
	FreeTrialEnabled      bool `json:"freeTrialEnabled"`
	TrialDurationDays     int  `json:"trialDurationDays"`
	BakongDiscountPercent int  `json:"bakongDiscountPercent"`
	// Announcement banner
	AnnouncementEnabled   bool      `json:"announcementEnabled"`
	AnnouncementText      string    `json:"announcementText"`
	AnnouncementColor     string    `json:"announcementColor"` // gold | rose | blue | green
	AnnouncementLink      string    `json:"announcementLink"`
	AnnouncementLinkLabel string    `json:"announcementLinkLabel"`
	UpdatedAt             time.Time `json:"updatedAt"`
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

// ─── OrgMember ────────────────────────────────────────────────

type OrgMember struct {
	ID       string    `json:"id"`
	OrgID    string    `json:"org_id"`
	UserID   string    `json:"user_id"`
	Role     string    `json:"role"`
	JoinedAt time.Time `json:"joined_at"`
	// Populated via JOIN
	User       *User          `json:"user,omitempty"`
	Allocation *OrgAllocation `json:"allocation,omitempty"`
}

// ─── OrgAllocation ────────────────────────────────────────────

type OrgAllocation struct {
	ID                  string    `json:"id"`
	OrgID               string    `json:"org_id"`
	UserID              string    `json:"user_id"`
	TunnelLimit         int       `json:"tunnel_limit"`
	TeamLimit           int       `json:"team_limit"`
	SubdomainLimit      int       `json:"subdomain_limit"`
	CustomDomainAllowed bool      `json:"custom_domain_allowed"`
	BandwidthGB         int       `json:"bandwidth_gb"`
	UpdatedBy           *string   `json:"updated_by,omitempty"`
	UpdatedAt           time.Time `json:"updated_at"`
}

// ─── ResourceRequest ──────────────────────────────────────────

type ResourceRequest struct {
	ID              string     `json:"id"`
	OrgID           string     `json:"org_id"`
	UserID          string     `json:"user_id"`
	Type            string     `json:"type"`
	AmountRequested int        `json:"amount_requested"`
	AmountApproved  int        `json:"amount_approved,omitempty"`
	Reason          string     `json:"reason"`
	Status          string     `json:"status"`
	ReviewerNote    string     `json:"reviewer_note,omitempty"`
	ReviewedBy      *string    `json:"reviewed_by,omitempty"`
	ReviewedAt      *time.Time `json:"reviewed_at,omitempty"`
	ResolvedBy      *string    `json:"resolved_by,omitempty"`
	ResolvedAt      *time.Time `json:"resolved_at,omitempty"`
	LastCommentAt   *time.Time `json:"last_commented_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	// Populated via JOIN for admin views
	UserName  string                    `json:"user_name,omitempty"`
	UserEmail string                    `json:"user_email,omitempty"`
	Comments  []*ResourceRequestComment `json:"comments,omitempty"`
}

type ResourceRequestComment struct {
	ID          string    `json:"id"`
	RequestID   string    `json:"request_id"`
	UserID      *string   `json:"user_id,omitempty"`
	AuthorRole  string    `json:"author_role"`
	Kind        string    `json:"kind"`
	Body        string    `json:"body"`
	CreatedAt   time.Time `json:"created_at"`
	AuthorName  string    `json:"author_name,omitempty"`
	AuthorEmail string    `json:"author_email,omitempty"`
}

// ─── ImportResult ─────────────────────────────────────────────

type ImportResult struct {
	Total     int                   `json:"total"`
	Created   int                   `json:"created"`
	Added     int                   `json:"added"`
	Skipped   int                   `json:"skipped"`
	Errors    []string              `json:"errors"`
	FailedCSV string                `json:"failed_csv,omitempty"`
	Summary   *ImportPreviewSummary `json:"summary,omitempty"`
}

type ImportPreview struct {
	FileName       string                `json:"file_name,omitempty"`
	Format         string                `json:"format,omitempty"`
	Headers        []string              `json:"headers,omitempty"`
	MissingHeaders []string              `json:"missing_headers,omitempty"`
	FileErrors     []string              `json:"file_errors,omitempty"`
	Rows           []*ImportPreviewRow   `json:"rows"`
	Summary        *ImportPreviewSummary `json:"summary,omitempty"`
	FailedCSV      string                `json:"failed_csv,omitempty"`
}

type ImportPreviewSummary struct {
	TotalRows       int `json:"total_rows"`
	ValidRows       int `json:"valid_rows"`
	WarningRows     int `json:"warning_rows"`
	ErrorRows       int `json:"error_rows"`
	CreateUsers     int `json:"create_users"`
	AddMembers      int `json:"add_members"`
	UpdateUsers     int `json:"update_users"`
	ExistingMembers int `json:"existing_members"`
	CurrentSeats    int `json:"current_seats"`
	ProjectedSeats  int `json:"projected_seats"`
	SeatLimit       int `json:"seat_limit"`
}

// ─── Telegram ─────────────────────────────────────────────────

// TelegramLink is a durable mapping between a Telegram private chat and a Mekong user.
type TelegramLink struct {
	ID                string     `json:"id"`
	UserID            string     `json:"user_id"`
	TelegramChatID    int64      `json:"telegram_chat_id"`
	TelegramUserID    int64      `json:"telegram_user_id"`
	TelegramUsername  string     `json:"telegram_username,omitempty"`
	TelegramFirstName string     `json:"telegram_first_name,omitempty"`
	TelegramLastName  string     `json:"telegram_last_name,omitempty"`
	Status            string     `json:"status"`
	LinkedAt          time.Time  `json:"linked_at"`
	LastSeenAt        *time.Time `json:"last_seen_at,omitempty"`
	UnlinkedAt        *time.Time `json:"unlinked_at,omitempty"`
}

// TelegramLinkSession is a short-lived browser approval session for linking Telegram.
type TelegramLinkSession struct {
	ID                string     `json:"id"`
	Code              string     `json:"code"`
	TelegramChatID    int64      `json:"telegram_chat_id"`
	TelegramUserID    int64      `json:"telegram_user_id"`
	TelegramUsername  string     `json:"telegram_username,omitempty"`
	TelegramFirstName string     `json:"telegram_first_name,omitempty"`
	TelegramLastName  string     `json:"telegram_last_name,omitempty"`
	Status            string     `json:"status"`
	ApprovedUserID    *string    `json:"approved_user_id,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	ExpiresAt         time.Time  `json:"expires_at"`
	ApprovedAt        *time.Time `json:"approved_at,omitempty"`
	CancelledAt       *time.Time `json:"cancelled_at,omitempty"`
}

type ImportPreviewRow struct {
	Row            int      `json:"row"`
	Email          string   `json:"email"`
	Name           string   `json:"name,omitempty"`
	Role           string   `json:"role,omitempty"`
	Plan           string   `json:"plan,omitempty"`
	Status         string   `json:"status"`
	Action         string   `json:"action"`
	Message        string   `json:"message,omitempty"`
	ExistingUser   bool     `json:"existing_user,omitempty"`
	ExistingMember bool     `json:"existing_member,omitempty"`
	ConsumesSeat   bool     `json:"consumes_seat,omitempty"`
	Errors         []string `json:"errors,omitempty"`
	Warnings       []string `json:"warnings,omitempty"`
}
