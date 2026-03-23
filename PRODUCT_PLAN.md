# Mekong Tunnel — Product Plan: Auth, Pricing & Dashboard

> **Status:** Draft for review — Ing Muyleang
> **Date:** 2026-03-21
> **Scope:** Full-stack product expansion: user accounts, OAuth2, 2FA, pricing tiers, team workspaces, user dashboard, admin dashboard

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [How ngrok Does It (Benchmark)](#2-how-ngrok-does-it-benchmark)
3. [Pricing Plan Design](#3-pricing-plan-design)
4. [Authentication System](#4-authentication-system)
5. [User Roles & Account Types](#5-user-roles--account-types)
6. [Team & Organization Features](#6-team--organization-features)
7. [User Dashboard](#7-user-dashboard)
8. [Admin Dashboard](#8-admin-dashboard)
9. [Architecture Changes to Go Server](#9-architecture-changes-to-go-server)
10. [Database Schema (Overview)](#10-database-schema-overview)
11. [Tech Stack Recommendation](#11-tech-stack-recommendation)
12. [Implementation Phases](#12-implementation-phases)
13. [Risk & Open Questions](#13-risk--open-questions)

---

## 1. Executive Summary

Right now Mekong Tunnel is a **fully anonymous** service — anyone runs `mekong 3000` and gets a tunnel, no account needed. That is the free baseline.

The expansion adds:
- **Accounts** (optional for free, required for paid) with GitHub/Google OAuth2 + email/password
- **2FA** via TOTP QR code (Google Authenticator, Authy, etc.)
- **Three pricing tiers**: Free · Student · Pro (organization / team)
- **Team workspaces** with invitation flow
- **User dashboard** — manage tunnels, tokens, billing, team
- **Admin dashboard** — see all users, tunnels, abuse flags, billing, plan management

The core tunnel engine (SSH + HTTP proxy in Go) stays the same. Auth and billing sit **in front of it** as a new web service layer.

---

## 2. How ngrok Does It (Benchmark)

Understanding ngrok's model helps us design Mekong correctly.

### How ngrok enforces plans via the CLI

```
ngrok authtoken <YOUR_TOKEN>           # stored in ~/.ngrok2/ngrok.yml
ngrok http 3000                        # CLI sends authtoken over SSH / API
```

1. User registers on dashboard → gets a **personal auth token**
2. CLI sends the token when opening a tunnel connection
3. Server validates token → looks up user → applies plan limits
4. If no token → anonymous free tier (severely limited or blocked on paid plans)

### What ngrok limits per plan

| Feature | Free | Pro | Enterprise |
|---------|------|-----|-----------|
| Active tunnels | 1 | 3+ | Unlimited |
| Custom domains | ❌ | ✅ | ✅ |
| Bandwidth | 1 GB/mo | Unlimited | Unlimited |
| Tunnel lifetime | Session-only | Persistent | Persistent |
| Team members | 1 | 5 | Unlimited |
| Request inspection | ❌ | ✅ | ✅ |
| Reserved subdomains | ❌ | ✅ | ✅ |
| Auth on tunnels (OAuth) | ❌ | ✅ | ✅ |

### Mekong's current state vs ngrok

| Feature | Mekong Today | After This Plan |
|---------|-------------|-----------------|
| Anonymous tunnels | ✅ Fully open | ✅ Still available (Free plan) |
| Auth token | ❌ None | ✅ JWT / API token |
| Custom subdomain | ❌ Removed | ✅ Pro plan only |
| Tunnel limits | Global config only | ✅ Per-plan per-user |
| Dashboard | Stats only (port 9090) | ✅ Full user + admin UI |
| Team | ❌ | ✅ Pro/Org plan |

---

## 3. Pricing Plan Design

### Plan Tiers

#### 🆓 Free Plan
- No account required (anonymous use)
- Optional login — if logged in, gets slightly better limits
- **Limits (anonymous):**
  - 1 active tunnel
  - Random subdomain only
  - 1 hour tunnel lifetime (session ends = tunnel gone)
  - 1 GB/month bandwidth
  - No request inspection
  - No team
- **Limits (logged-in free):**
  - 2 active tunnels
  - 24-hour tunnel lifetime
  - 5 GB/month bandwidth
  - Basic tunnel history (last 7 days)

#### 🎓 Student Plan — *Discounted*
- Requires account with student verification
- Verification methods:
  - `.edu` email address (auto-approve)
  - School email domain (configured per organization)
  - Manual review by admin (upload student ID — optional)
  - Invited by a Teacher or Organization account
- **Limits:**
  - 3 active tunnels
  - Reserved subdomain (1 fixed subdomain)
  - 7-day tunnel lifetime
  - 20 GB/month bandwidth
  - Request inspection in dashboard
  - Can join 1 team (their school/class team)
  - No custom domain
- **Price:** Free or heavily discounted (e.g., $1–2/month or free via school license)

#### 💼 Pro Plan — *Individual Professional*
- Full-featured individual account
- **Limits:**
  - 10 active tunnels
  - 3 reserved subdomains
  - Persistent tunnels (survive CLI disconnect, reconnect on next login)
  - Unlimited bandwidth (fair use)
  - Request inspection + traffic logs (30 days)
  - 1 team (up to 5 members)
  - 1 custom domain (CNAME → mekongtunnel.dev)
- **Price:** ~$8–12/month

#### 🏢 Organization Plan — *Teams & Schools*
- Account owned by a school, company, or group
- **Limits:**
  - Unlimited tunnels (fair use)
  - Unlimited reserved subdomains
  - Unlimited bandwidth
  - Full traffic logs (90 days)
  - Up to 3 teams, unlimited members per team
  - Multiple custom domains
  - Admin can manage all member tunnels
  - Bulk student/teacher invitation
  - SSO support (future)
- **Price:** ~$25–50/month (per organization, not per seat)

### Plan Comparison Table

| Feature | Free (anon) | Free (logged in) | Student | Pro | Organization |
|---------|------------|-----------------|---------|-----|-------------|
| Account required | ❌ | ✅ | ✅ | ✅ | ✅ |
| Active tunnels | 1 | 2 | 3 | 10 | Unlimited |
| Reserved subdomain | ❌ | ❌ | 1 | 3 | Unlimited |
| Custom domain | ❌ | ❌ | ❌ | 1 | Multiple |
| Tunnel lifetime | 1 hr | 24 hr | 7 days | Persistent | Persistent |
| Bandwidth | 1 GB/mo | 5 GB/mo | 20 GB/mo | Unlimited | Unlimited |
| Request logs | ❌ | ❌ | ✅ 7 days | ✅ 30 days | ✅ 90 days |
| Team members | ❌ | ❌ | 1 team (join) | 5 | Unlimited |
| 2FA | ❌ | ✅ optional | ✅ optional | ✅ optional | ✅ enforced |
| Priority support | ❌ | ❌ | ❌ | ✅ | ✅ |
| **Price** | Free | Free | Free–$2/mo | $8–12/mo | $25–50/mo |

---

## 4. Authentication System

### 4.1 Login Methods

#### GitHub OAuth2
```
User clicks "Login with GitHub"
→ Redirect to github.com/login/oauth/authorize
→ GitHub callback → /auth/github/callback
→ Exchange code for access_token
→ GET api.github.com/user → get id, login, email, avatar
→ Upsert user in DB → create session/JWT
→ Redirect to /dashboard
```

#### Google OAuth2
```
User clicks "Login with Google"
→ Redirect to accounts.google.com/o/oauth2/auth
→ Google callback → /auth/google/callback
→ Exchange code for id_token
→ Verify id_token → get sub, email, name, picture
→ Upsert user in DB → create session/JWT
→ Redirect to /dashboard
```

#### Email + Password
```
Register: POST /auth/register
  { email, password, name }
  → validate email format
  → check email not taken
  → bcrypt hash password (cost 12)
  → insert user (unverified)
  → send verification email
  → return "check your email"

Verify email: GET /auth/verify?token=<uuid>
  → mark user verified
  → auto-login → /dashboard

Login: POST /auth/login
  { email, password }
  → lookup user by email
  → bcrypt compare
  → if 2FA enabled → redirect to /auth/2fa
  → else → issue JWT + refresh token
```

### 4.2 Forgot Password / Reset Password

```
Forgot: POST /auth/forgot-password
  { email }
  → generate secure token (crypto/rand, 32 bytes, hex)
  → store in db: reset_tokens(token, user_id, expires_at = now+1h)
  → send email: "Reset your password" with link
  → always return 200 (don't reveal if email exists)

Reset: POST /auth/reset-password
  { token, new_password }
  → lookup token in DB
  → check not expired
  → check not used
  → bcrypt hash new_password
  → update user password
  → mark token used
  → invalidate all existing sessions for user
  → return success
```

### 4.3 Two-Factor Authentication (2FA / TOTP)

**Standard TOTP flow (RFC 6238) — works with Google Authenticator, Authy, 1Password, etc.**

```
Setup (first time):
  POST /auth/2fa/setup
  → generate TOTP secret (base32, 20 bytes)
  → store secret in DB (unconfirmed)
  → return: { qr_url, secret, backup_codes[8] }
  → frontend shows QR code image (otpauth://totp/...)

Confirm setup:
  POST /auth/2fa/confirm
  { code: "123456" }
  → verify TOTP code against secret
  → mark 2FA as active
  → store backup_codes (hashed)
  → show "2FA is now enabled"

Login flow with 2FA:
  1. User logs in with email+password (or OAuth)
  2. Server sees 2FA is enabled
  3. Issue short-lived "pre-2fa" token (5 min TTL)
  4. Redirect to /auth/2fa/verify
  5. User enters 6-digit code from app
     POST /auth/2fa/verify { code }
  6. Server validates TOTP → issue full JWT
  7. Redirect to /dashboard

Backup codes:
  - 8 single-use codes shown at setup
  - User can use one if they lose phone
  - Each use marks that code as used
  - User can regenerate backup codes (invalidates old ones)

Disable 2FA:
  POST /auth/2fa/disable
  { password, code }  ← require both for security
  → verify password + current TOTP code
  → remove 2FA from account
```

### 4.4 Session / JWT Design

```
Access token:  JWT, 15 min TTL
  payload: { user_id, plan, team_id, 2fa_verified }

Refresh token: opaque token, 30 days TTL, stored in httpOnly cookie
  → POST /auth/refresh → issue new access token

Auth token (CLI): long-lived API token, never expires unless revoked
  → stored in ~/.mekong/config.yml (like ngrok)
  → user can revoke from dashboard
  → multiple tokens allowed (one per device/project)
```

---

## 5. User Roles & Account Types

### Role Hierarchy

```
SuperAdmin          ← you (Ing Muyleang) — full system access
    │
    ├── Admin       ← staff accounts — manage users, see all tunnels
    │
    └── User
         ├── Free (anonymous or logged in)
         ├── Student
         │     └── verified by: .edu email / org invite / manual
         ├── Teacher
         │     └── can create org teams, invite students
         ├── Pro
         └── Org Admin
               └── manages org members, billing, tunnels
```

### Account Type Field on User

```go
type AccountType string

const (
    AccountFree     AccountType = "free"
    AccountStudent  AccountType = "student"
    AccountTeacher  AccountType = "teacher"
    AccountPro      AccountType = "pro"
    AccountOrg      AccountType = "org"
)
```

### Student / Teacher Verification

| Path | How it works |
|------|-------------|
| `.edu` email | Auto-approve on registration |
| School domain | Org admin registers `@school.edu.kh` → all users with that email auto-qualify |
| Manual | User submits student ID → admin reviews in dashboard |
| Invitation | Teacher/Org admin invites by email → user registers → auto-gets Student plan |

---

## 6. Team & Organization Features

### Team Structure

```
Organization Account
    └── Team (can have multiple)
          ├── Org Admin (owner)
          ├── Teacher (can manage students)
          └── Member (student / developer)
```

### Invitation Flow

```
Org Admin clicks "Invite Member"
→ enters email(s) — single or bulk CSV upload
→ chooses role: Member / Teacher
→ system sends invitation email
  "You've been invited to join [School Name] on Mekong Tunnel"
  → link: /invite/accept?token=<uuid>
→ recipient clicks link
  → if no account: goes to register page (email pre-filled)
  → if has account: confirm join
→ user joins org team
→ plan auto-upgrades to org's plan level
```

### Team Permissions

| Action | Member | Teacher | Org Admin |
|--------|--------|---------|-----------|
| Create tunnels | ✅ | ✅ | ✅ |
| See own tunnels | ✅ | ✅ | ✅ |
| See all team tunnels | ❌ | ✅ | ✅ |
| Stop member tunnels | ❌ | ✅ | ✅ |
| Invite members | ❌ | ✅ (students only) | ✅ |
| Remove members | ❌ | ❌ | ✅ |
| Manage billing | ❌ | ❌ | ✅ |
| View audit logs | ❌ | ❌ | ✅ |

---

## 7. User Dashboard

The user dashboard is a web app at `https://dashboard.mekongtunnel.dev` (or `/dashboard` on same domain).

### Pages & Features

#### 7.1 Overview Page `/dashboard`
- Welcome header: "Hello, Ing 👋"
- **Plan badge**: Free / Student / Pro / Org
- **Quick stats cards**:
  - Active tunnels (e.g., `2 / 10`)
  - Bandwidth used this month (e.g., `1.2 GB / Unlimited`)
  - Total requests today
  - Account status (Verified ✅ / 2FA enabled ✅)
- **Active tunnels list** — real-time table:
  - URL, port, started at, requests, bandwidth
  - Kill button per tunnel
- **Recent activity feed** — last 10 tunnel events

#### 7.2 Tunnels Page `/dashboard/tunnels`
- List of all tunnels (active + history)
- Filter: active / stopped / all
- Per tunnel: subdomain, port, created, duration, requests, bandwidth
- Click tunnel → detail view with request log (if plan allows)
- Reserved subdomains management (Pro/Org)
- CLI token copy:
  ```
  mekong auth <YOUR_TOKEN>
  ```

#### 7.3 API Tokens Page `/dashboard/tokens`
- List of API tokens (name, created, last used, scopes)
- Create new token (name it: e.g., "MacBook Pro", "CI/CD")
- Revoke individual tokens
- Copy token (shown once at creation, masked after)

#### 7.4 Security Page `/dashboard/security`
- Change password
- Enable / disable 2FA
  - Shows QR code during setup
  - Shows backup codes (can regenerate)
- Active sessions list (device, location, last seen)
- Revoke session button
- "Log out all devices" button
- Connected OAuth accounts (GitHub / Google linked/unlinked)
- Login history (last 20 logins with IP and device)

#### 7.5 Team Page `/dashboard/team` *(Pro/Org)*
- Team name and avatar
- Members list: name, role, joined date, status
- Invite by email (single or bulk CSV)
- Change member role
- Remove member
- Pending invitations list (resend / cancel)

#### 7.6 Billing Page `/dashboard/billing`
- Current plan with features summary
- Next billing date and amount
- Payment method (credit card / PayPal)
- Invoice history (downloadable PDF)
- Upgrade / Downgrade plan buttons
- Cancel subscription (with confirmation + reason)
- Student plan: verification status + how to verify

#### 7.7 Settings Page `/dashboard/settings`
- Display name, avatar
- Notification preferences (email: tunnel created, abuse warning, billing)
- Account type (Student / Teacher — for verification purposes)
- Delete account (with confirmation + data export)

---

## 8. Admin Dashboard

The admin dashboard is at `https://dashboard.mekongtunnel.dev/admin` — only accessible to admin/superadmin roles.

### Pages & Features

#### 8.1 Admin Overview `/admin`
- **System health cards**:
  - Total active tunnels (live count)
  - Total users (registered / anonymous sessions)
  - Bandwidth used today / this month
  - SSH connections open right now
  - Server CPU / memory (if Go expvar/pprof exposed)
- **Recent sign-ups** (last 10, with plan)
- **Abuse alerts** (flagged IPs, rate-limited users)
- **Revenue summary** (this month)

#### 8.2 Users `/admin/users`
- Search by email, name, GitHub login
- Filter by plan, role, status (active / suspended / banned)
- Per user row: name, email, plan, tunnels active, joined date, last seen
- Click user → User Detail page:
  - All their info
  - All tunnels (history)
  - Login history
  - Manual plan override
  - Suspend / ban account
  - Send email
  - Verify student manually
  - Impersonate (view as user — for support)

#### 8.3 Tunnels `/admin/tunnels`
- All active tunnels across all users
- Search by subdomain, user, port
- Sort by started time, requests, bandwidth
- Force-kill any tunnel
- See which IP / user owns each tunnel
- Export as CSV

#### 8.4 Organizations `/admin/organizations`
- List of all org accounts
- Members count, plan, billing status
- Approve / reject organization registration
- Manage school domain whitelists (e.g., add `@rupp.edu.kh`)
- View all org teams and tunnels

#### 8.5 Abuse & Security `/admin/abuse`
- Currently blocked IPs (with reason, blocked at, auto/manual)
- Rate limit violations log
- Manually block / unblock IP
- Suspicious activity feed (many tunnels from same IP, etc.)
- Abuse reports from users

#### 8.6 Billing & Revenue `/admin/billing`
- Monthly recurring revenue (MRR)
- New subscriptions, cancellations, upgrades this month
- Failed payments
- Plan distribution pie chart (Free / Student / Pro / Org)
- Individual subscription list (search, filter by status)
- Manual subscription adjustments (add free months, etc.)

#### 8.7 System Config `/admin/config`
- Live editable limits (max tunnels per plan, bandwidth caps)
- Email templates (invitation, reset password, verification)
- Announcement banner (shown on dashboard to all users)
- Maintenance mode toggle
- Feature flags (enable/disable features per plan)

---

## 9. Architecture Changes to Go Server

### Current Architecture

```
mekongtunnel.dev
    ├── :22    SSH server   (proxy.go → ssh.go)
    ├── :80    HTTP redirect
    ├── :443   HTTPS proxy  (http.go)
    └── :9090  Admin stats  (stats.go — localhost only)
```

### New Architecture

```
mekongtunnel.dev
    ├── :22    SSH server   (MODIFIED: validate auth token on connect)
    ├── :80    HTTP redirect
    ├── :443   HTTPS proxy + dashboard  (MODIFIED: route /dashboard, /auth, /api)
    └── :9090  Internal stats (unchanged, localhost only)

dashboard.mekongtunnel.dev  (or same domain /dashboard)
    └── Next.js / React web app  (separate service, calls API)

api.mekongtunnel.dev  (or /api)
    └── REST API  (Go — new service, talks to DB + tunnel server)
```

### Changes to SSH Server (`internal/proxy/ssh.go`)

**Today:** SSH accepts any connection, generates random subdomain.

**After:** SSH reads an auth token from the SSH request metadata:
```
ssh -t -R 80:localhost:3000 -o "SendEnv MEKONG_TOKEN" mekongtunnel.dev
```
Or via mekong CLI: token stored in `~/.mekong/config.yml`, sent in SSH handshake.

**Logic:**
```
On SSH connect:
  1. Extract token from SSH env var or SSH request payload
  2. If no token:
     → anonymous free tier (1 tunnel, 1hr lifetime, random subdomain)
  3. If token provided:
     → validate against DB (token_hash, not expired, not revoked)
     → load user + plan
     → check: does user already have max_tunnels for their plan?
     → apply plan limits (lifetime, bandwidth, subdomain)
     → if Pro/Org: allow custom subdomain request
     → record tunnel in DB (tunnel_id, user_id, subdomain, port, started_at)
  4. On tunnel close:
     → update DB: ended_at, total_requests, total_bytes
```

### New Internal Packages Needed

```
internal/
  auth/
    token.go        — API token validation (lookup hash in DB)
    jwt.go          — JWT issue/verify for web sessions
    totp.go         — TOTP verify for 2FA
  user/
    user.go         — User struct, plan limits lookup
    plan.go         — PlanLimits struct per plan type
  db/
    db.go           — DB connection (PostgreSQL via pgx)
    migrate.go      — Schema migrations
  billing/
    billing.go      — Plan check, bandwidth tracking
```

---

## 10. Database Schema (Overview)

```sql
-- Users
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email           TEXT UNIQUE,
    email_verified  BOOLEAN DEFAULT false,
    password_hash   TEXT,                    -- NULL if OAuth-only
    name            TEXT,
    avatar_url      TEXT,
    account_type    TEXT DEFAULT 'free',     -- free/student/teacher/pro/org
    plan            TEXT DEFAULT 'free',     -- free/student/pro/org
    plan_expires_at TIMESTAMPTZ,
    totp_secret     TEXT,                    -- encrypted at rest
    totp_enabled    BOOLEAN DEFAULT false,
    created_at      TIMESTAMPTZ DEFAULT now(),
    last_seen_at    TIMESTAMPTZ,
    suspended_at    TIMESTAMPTZ,
    suspended_reason TEXT
);

-- OAuth providers linked to users
CREATE TABLE oauth_accounts (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID REFERENCES users(id) ON DELETE CASCADE,
    provider    TEXT,                        -- 'github' | 'google'
    provider_id TEXT,
    username    TEXT,
    UNIQUE(provider, provider_id)
);

-- API tokens (for CLI auth)
CREATE TABLE api_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID REFERENCES users(id) ON DELETE CASCADE,
    name        TEXT,
    token_hash  TEXT UNIQUE,                 -- SHA-256 of actual token
    last_used_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ DEFAULT now(),
    revoked_at  TIMESTAMPTZ
);

-- Tunnel records (persisted, not just in-memory)
CREATE TABLE tunnels (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID REFERENCES users(id),   -- NULL = anonymous
    subdomain   TEXT NOT NULL,
    local_port  INTEGER,
    remote_ip   TEXT,
    started_at  TIMESTAMPTZ DEFAULT now(),
    ended_at    TIMESTAMPTZ,
    total_requests BIGINT DEFAULT 0,
    total_bytes    BIGINT DEFAULT 0
);

-- Reserved subdomains (Pro/Org)
CREATE TABLE reserved_subdomains (
    subdomain   TEXT PRIMARY KEY,
    user_id     UUID REFERENCES users(id) ON DELETE CASCADE,
    team_id     UUID REFERENCES teams(id),
    created_at  TIMESTAMPTZ DEFAULT now()
);

-- Teams
CREATE TABLE teams (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id    UUID REFERENCES users(id),
    name        TEXT,
    type        TEXT,                        -- 'class' | 'company' | 'project'
    plan        TEXT DEFAULT 'org',
    created_at  TIMESTAMPTZ DEFAULT now()
);

-- Team memberships
CREATE TABLE team_members (
    team_id     UUID REFERENCES teams(id) ON DELETE CASCADE,
    user_id     UUID REFERENCES users(id) ON DELETE CASCADE,
    role        TEXT DEFAULT 'member',       -- 'admin' | 'teacher' | 'member'
    joined_at   TIMESTAMPTZ DEFAULT now(),
    PRIMARY KEY (team_id, user_id)
);

-- Invitations
CREATE TABLE invitations (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id     UUID REFERENCES teams(id),
    inviter_id  UUID REFERENCES users(id),
    email       TEXT,
    role        TEXT DEFAULT 'member',
    token       TEXT UNIQUE,
    accepted_at TIMESTAMPTZ,
    expires_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ DEFAULT now()
);

-- Password reset tokens
CREATE TABLE password_reset_tokens (
    token       TEXT PRIMARY KEY,
    user_id     UUID REFERENCES users(id) ON DELETE CASCADE,
    used_at     TIMESTAMPTZ,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ DEFAULT now()
);

-- 2FA backup codes
CREATE TABLE totp_backup_codes (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID REFERENCES users(id) ON DELETE CASCADE,
    code_hash   TEXT,
    used_at     TIMESTAMPTZ
);

-- Audit log
CREATE TABLE audit_log (
    id          BIGSERIAL PRIMARY KEY,
    user_id     UUID REFERENCES users(id),
    action      TEXT,                        -- 'login' | 'tunnel.create' | 'plan.upgrade' | etc.
    meta        JSONB,
    ip          TEXT,
    created_at  TIMESTAMPTZ DEFAULT now()
);
```

---

## 11. Tech Stack Recommendation

### Option A — Full Go (Minimal new tech)
- **Backend**: Go — new `cmd/api/main.go` HTTP API server
- **Frontend**: Go HTML templates + HTMX (no JS framework)
- **Database**: PostgreSQL (add `pgx` driver)
- **Email**: SMTP via `net/smtp` or Resend/Postmark API
- **Sessions**: JWT (Go `golang-jwt/jwt`)
- **2FA**: `github.com/pquerna/otp` (TOTP)
- **OAuth**: `golang.org/x/oauth2`
- **Payments**: Stripe Go SDK

**Pros**: Consistent with existing codebase, single language, easy deployment
**Cons**: Dashboard UI will be simpler unless using a JS framework

### Option B — Go API + Next.js Dashboard *(Recommended)*
- **Backend API**: Go — REST API (or tRPC-style)
- **Frontend**: Next.js 14 (App Router) + Tailwind CSS + shadcn/ui
- **Database**: PostgreSQL (Neon serverless or self-hosted)
- **Auth**: Custom Go auth (not NextAuth — you control everything)
- **Email**: Resend (simple API, generous free tier)
- **Payments**: Stripe
- **Deployment**: API on same VPS → Next.js on Vercel or same VPS

**Pros**: Beautiful dashboard, easy to build modern UI, shadcn components ready
**Cons**: Two languages, slightly more complex deployment

### Option C — Go API + React SPA
- Same as Option B but React without Next.js (Vite)
- Simpler frontend deployment (just static files)
- Good if you want everything on one VPS

**My recommendation: Option B** — Next.js gives you a professional dashboard quickly with shadcn/ui components. The Go API handles auth + tunnel integration. This is exactly how ngrok works (Go backend, React/Next dashboard).

---

## 12. Implementation Phases

### Phase 1 — Foundation (Database + Auth API)
*Goal: Users can register, login, get an API token, connect mekong CLI with that token*

- [ ] PostgreSQL setup (schema: users, api_tokens, tunnels)
- [ ] Go API: `POST /auth/register`, `POST /auth/login`, `POST /auth/logout`
- [ ] Go API: GitHub OAuth2 flow
- [ ] Go API: Google OAuth2 flow
- [ ] Go API: JWT issue + refresh token
- [ ] Go API: `POST /auth/forgot-password`, `POST /auth/reset-password`
- [ ] Go API: Email verification on register
- [ ] Go API: `GET/POST /tokens` — create/list/revoke API tokens
- [ ] SSH server: read MEKONG_TOKEN from env, validate against DB
- [ ] mekong CLI: `mekong auth <token>` — stores in `~/.mekong/config.yml`
- [ ] Plan limits: apply free plan limits on SSH connect

### Phase 2 — 2FA + Security
*Goal: Users can enable TOTP 2FA, security settings work*

- [ ] Go API: `POST /auth/2fa/setup` — generate TOTP secret + QR URI
- [ ] Go API: `POST /auth/2fa/confirm` — verify code + activate
- [ ] Go API: `POST /auth/2fa/verify` — verify during login
- [ ] Go API: `POST /auth/2fa/disable`
- [ ] Go API: Backup codes (generate, store hashed, verify one-time use)
- [ ] Go API: Session list + revoke
- [ ] Go API: Login history

### Phase 3 — User Dashboard (Frontend)
*Goal: Users have a dashboard they can log into*

- [ ] Next.js project setup, auth flow (login page, OAuth buttons)
- [ ] Dashboard: Overview page with live tunnel stats
- [ ] Dashboard: Tunnels page (active + history)
- [ ] Dashboard: API Tokens page
- [ ] Dashboard: Security page (2FA setup with QR code)
- [ ] Dashboard: Settings page

### Phase 4 — Plans & Billing
*Goal: Plans enforced, payment works*

- [ ] Stripe integration (checkout, webhooks)
- [ ] Plan enforcement on SSH connect (check plan limits)
- [ ] Bandwidth tracking (update tunnels table during session)
- [ ] Dashboard: Billing page
- [ ] Student verification flow (`.edu` email auto-approve)
- [ ] Admin: manual student approval

### Phase 5 — Teams & Organizations
*Goal: Schools and companies can create teams*

- [ ] Go API: `POST /teams`, `GET /teams/:id`, team CRUD
- [ ] Go API: `POST /teams/:id/invite`, `GET /invite/accept?token=`
- [ ] Go API: Role management (member/teacher/admin)
- [ ] Dashboard: Team page (invite, manage members)
- [ ] School domain whitelist (admin configures, auto-approves student accounts)

### Phase 6 — Admin Dashboard
*Goal: You (and staff) can manage everything*

- [ ] Admin middleware (role check)
- [ ] Admin: Users list + user detail + suspend/ban
- [ ] Admin: All tunnels + force-kill
- [ ] Admin: Abuse panel (blocked IPs, rate limits)
- [ ] Admin: Organizations management
- [ ] Admin: Billing overview + revenue stats
- [ ] Admin: Student verification review queue

---

## 13. Risk & Open Questions

### Questions to Decide Before Building

| Question | Options |
|----------|---------|
| Should free anonymous users be allowed indefinitely? | Yes (current behavior) / Time-limit anonymous sessions |
| Student verification — require `.edu` or accept manual? | Auto + manual fallback |
| How to handle Cambodia schools (no `.edu` domains)? | Org admin registers school domain + bulk invite |
| Reserved subdomains — random or user-chosen? | User-chosen (Pro/Org), with availability check |
| Where to deploy the dashboard? | Same VPS / Vercel (Next.js) |
| Payment — Stripe only or also local payment (ABA, WING)? | Start Stripe only, add local later |
| Should Student plan be completely free? | Suggest: free if org-sponsored, $1/mo direct |

### Risks

| Risk | Mitigation |
|------|-----------|
| Auth bugs exposing tunnels cross-user | Token scoped to user, validated on every SSH connect |
| 2FA lockout (lost phone) | Backup codes + admin reset via email verification |
| Bandwidth abuse on free tier | Rate limit + cap at 1 GB/month, disconnect and warn |
| Student plan abuse (fake `.edu`) | Disposable `.edu` addresses are rare; add manual review trigger |
| Database becomes bottleneck on SSH connect | Cache token validation in memory (Redis or sync.Map, 60s TTL) |
| Breaking existing anonymous users | Never remove anonymous access — just add auth on top |

---

## Summary

This is a significant but well-structured expansion. The Go tunnel engine needs minimal changes — mainly token validation on SSH connect and plan limit enforcement. All the new complexity is in the auth service, dashboard, and billing layer which can be built independently without breaking anything that works today.

**Suggested starting point:** Phase 1 (auth + API tokens + mekong auth command) — this gives you the foundation for everything else and is something you can ship and test with real users quickly before building the full dashboard.

---

*Document by Ing Muyleang (អុឹង មួយលៀង) — Mekong Tunnel product plan*
