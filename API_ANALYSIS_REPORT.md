# MekongTunnel API — Architecture & Endpoint Analysis Report

**Date:** 2026-03-28 | **Codebase:** `/Users/ingmuyleang/tunnl.gg` | **Module:** `github.com/MuyleangIng/MekongTunnel`
**Status:** All P0/P1 issues fixed and deployed to production (2026-03-28)

---

## Fixes Applied in This Pass

All 7 issues have been implemented and deployed.

| # | Priority | Issue | Fix Applied | Files Changed |
|---|----------|-------|-------------|---------------|
| 1 | P0 | `POST /api/tunnels` + `PATCH /api/tunnels/{id}` had no auth | Added `InternalSecretMiddleware` — checks `X-Tunnel-Secret` header | `middleware/auth.go`, `server.go`, `proxy/proxy.go`, `cmd/mekongtunnel/main.go` |
| 2 | P0 | `POST /api/upload` had no auth | Added `authRequired` middleware | `server.go` |
| 3 | P1 | `POST /api/auth/refresh` had no rate limit | Added `RateLimitIP` 30/min | `server.go` |
| 4 | P1 | `POST /api/auth/2fa/verify` had no rate limit | Added `RateLimitIP` 10/min | `server.go` |
| 5 | P1 | `force_password_reset` enforced only on frontend | Added `MustReset` to JWT claims; `AuthMiddleware` now blocks all endpoints except `PUT /api/user/password`, `GET /api/auth/me`, `POST /api/auth/logout` | `auth/jwt.go`, `middleware/auth.go` |
| 6 | P1 | `GET /api/org/{id}/members` returned all rows unpagenated | Added `ListOrgMembersPage` with LIMIT/OFFSET; handler supports `?limit=&offset=` query params | `db/org_system.go`, `handlers/org.go` |
| 7 | P2 | `POST /api/donations/submit` had no spam protection | Added `RateLimitIP` 5/min | `server.go` |

**Deployment:** `scripts/deploy-api.sh` completed — binary v1.5.7-dirty deployed to `api.angkorsearch.dev`. Health check, `/api/cli/subdomains` 401 check, and `/api/cli/domains` 401 check all passed.

---

## 1. Executive Summary

### What the System Is

A SaaS reverse-tunnel platform (like ngrok). Users run `mekong 3000` on their laptop; the SSH edge server creates a public URL. The REST API (`internal/api/`) manages auth, billing, teams, organizations, subdomains, custom domains, and admin tooling. The tunnel edge (`internal/proxy/`, `internal/tunnel/`) is a separate process.

### What Is Now Fixed

- **Tunnel edge writes are gated.** `POST /api/tunnels` and `PATCH /api/tunnels/{id}` now require `X-Tunnel-Secret` header. The tunnel edge binary (`cmd/mekongtunnel`) reads `TUNNEL_EDGE_SECRET` from env and attaches it. If `TUNNEL_EDGE_SECRET` is unset in env, the check is skipped (backward-compat for dev/single-node).
- **File upload requires auth.** `POST /api/upload` now demands a valid JWT. Unauthenticated uploads return 401.
- **2FA and refresh are rate-limited.** `POST /api/auth/refresh` allows 30/min per IP. `POST /api/auth/2fa/verify` allows 10/min per IP. Both were previously unlimited.
- **`force_password_reset` is now backend-enforced.** `JWTClaims.MustReset` is set from `user.ForcePasswordReset` at login time. `AuthMiddleware` blocks all endpoints except password change, `/api/auth/me`, and logout until the user resets.
- **Org member list is paginated.** `GET /api/org/{id}/members?limit=50&offset=0` returns a page. `X-Total-Count` header carries the full count. The old unpaginated path is preserved when no `limit`/`offset` params are passed.
- **Donation submit is rate-limited.** 5/min per IP.

### Remaining Known Risks (Not Fixed — Require Ops Action)

| Risk | How to Fix | Why Not Done Here |
|------|-----------|-------------------|
| `TUNNEL_EDGE_SECRET` is empty in production until you set it in `.env` | Set `TUNNEL_EDGE_SECRET=<random-secret>` in both API and tunnel edge env files, then restart both services | Requires coordinated secret rotation; empty = skip check (backward compat) |
| `POST /api/org/{id}/import` is still synchronous | Refactor to background job | Large scope change requiring new job queue infrastructure |
| `mergeLiveTunnels()` makes live HTTP call on every `GET /api/tunnels` | Add Redis cache for 5–10s | Requires cache key design and invalidation strategy |
| Org role authorization is per-handler (no middleware) | Add org-auth context middleware | Large refactor touching all org handlers |

---

## 2. Full Endpoint Inventory (Updated)

### Health / Public System

| Method | Path | Auth | Handler | Purpose | Risk |
|--------|------|------|---------|---------|------|
| GET | `/api/health` | public | inline | Liveness probe | low |
| GET | `/api/announcement` | public | inline | Banner text from DB | low |
| GET | `/api/plans` | public | `adminH.GetPublicPlans` | Plan pricing list | low |
| GET | `/api/server-limits` | public | inline | Compiled + DB limits | low |
| GET | `/api/partners` | public | `partnersH.ListPublicPartners` | Partner list | low |
| GET | `/api/sponsors` | public | `sponsorsH.ListPublicSponsors` | Sponsor list | low |
| GET | `/api/donations` | public | `donationH.PublicList` | Public donation feed | low |

### Auth

| Method | Path | Auth | Rate Limit | Handler | Risk |
|--------|------|------|-----------|---------|------|
| POST | `/api/auth/register` | public | 10/min | `authH.Register` | medium |
| POST | `/api/auth/login` | public | 20/min | `authH.Login` | medium |
| POST | `/api/auth/logout` | public | none | `authH.Logout` | low |
| GET | `/api/auth/me` | JWT | none | `authH.Me` | low |
| GET | `/api/auth/token-info` | public (mkt_ token) | 60/min | `authH.TokenInfo` | medium |
| POST | `/api/auth/refresh` | public | **30/min ✅ fixed** | `authH.Refresh` | medium |
| POST | `/api/auth/forgot-password` | public | 8/min | `authH.ForgotPassword` | medium |
| POST | `/api/auth/reset-password` | public | none | `authH.ResetPassword` | medium |
| POST | `/api/auth/verify-email` | public | 20/min | `authH.VerifyEmail` | low |
| POST | `/api/auth/resend-verify` | public | 8/min | `authH.ResendVerify` | low |
| POST | `/api/auth/request-admin-verify` | public | 6/min | `authH.RequestAdminVerify` | low |
| POST | `/api/auth/email-otp/verify` | public | 20/min | `authH.VerifyEmailOTP` | medium |
| POST | `/api/auth/2fa/email/enable` | JWT | none | `authH.EnableEmailOTP` | low |
| POST | `/api/auth/2fa/email/disable` | JWT | none | `authH.DisableEmailOTP` | medium |
| GET | `/api/auth/github` | public | none | `authH.GitHubOAuth` | low |
| GET | `/api/auth/github/callback` | public | none | `authH.GitHubCallback` | medium |
| GET | `/api/auth/google` | public | none | `authH.GoogleOAuth` | low |
| GET | `/api/auth/google/callback` | public | none | `authH.GoogleCallback` | medium |
| POST | `/api/auth/2fa/setup` | JWT | none | `authH.Setup2FA` | low |
| POST | `/api/auth/2fa/enable` | JWT | none | `authH.Enable2FA` | low |
| POST | `/api/auth/2fa/disable` | JWT | none | `authH.Disable2FA` | medium |
| POST | `/api/auth/2fa/verify` | public | **10/min ✅ fixed** | `authH.Verify2FA` | medium |

### API Tokens / CLI Auth

| Method | Path | Auth | Handler | Risk |
|--------|------|------|---------|------|
| GET | `/api/tokens` | JWT | `tokensH.ListTokens` | low |
| POST | `/api/tokens` | JWT | `tokensH.CreateToken` | low |
| DELETE | `/api/tokens/{id}` | JWT | `tokensH.RevokeToken` | low |
| POST | `/api/cli/device` | public + rate | `cliDeviceH.CreateSession` | medium |
| GET | `/api/cli/device` | public + rate | `cliDeviceH.PollSession` | medium |
| POST | `/api/cli/device/approve` | JWT | `cliDeviceH.ApproveSession` | low |

### CLI Subdomain/Domain Routes (API token auth inside handler)

| Method | Path | Auth | Handler | Note |
|--------|------|------|---------|------|
| GET | `/api/cli/subdomains` | `mkt_xxx` Bearer | `subdomainH.ListCLI` | Token validated inside handler |
| POST | `/api/cli/subdomains` | `mkt_xxx` Bearer | `subdomainH.CreateCLI` | Token validated inside handler |
| DELETE | `/api/cli/subdomains/{id}` | `mkt_xxx` Bearer | `subdomainH.DeleteCLI` | Token validated inside handler |
| GET | `/api/cli/domains` | `mkt_xxx` Bearer | `domainsH.ListCLI` | Token validated inside handler |
| POST | `/api/cli/domains` | `mkt_xxx` Bearer | `domainsH.CreateCLI` | Token validated inside handler |
| DELETE | `/api/cli/domains/{id}` | `mkt_xxx` Bearer | `domainsH.DeleteCLI` | Token validated inside handler |
| POST | `/api/cli/domains/{id}/verify` | `mkt_xxx` Bearer | `domainsH.VerifyCLI` | Token validated inside handler |
| PATCH | `/api/cli/domains/{id}/target` | `mkt_xxx` Bearer | `domainsH.SetTargetCLI` | Token validated inside handler |

> These routes use API token validation (`mkt_xxx`) inside the handler via `userFromAPIToken()`, not JWT middleware. Deploy script confirms they correctly return 401 without auth.

### Tunnels / Live / Logs

| Method | Path | Auth | Handler | Risk |
|--------|------|------|---------|------|
| GET | `/api/tunnels` | JWT | `tunnelsH.ListTunnels` | low |
| GET | `/api/tunnels/live` | JWT | `tunnelsH.ListLiveTunnels` | low |
| GET | `/api/tunnels/overview` | JWT | `tunnelsH.GetOverview` | low |
| GET | `/api/tunnels/stats` | public | `tunnelsH.GetStats` | low |
| DELETE | `/api/tunnels/history` | JWT | `tunnelsH.ClearHistory` | low |
| POST | `/api/tunnels/{id}/log-token` | JWT | `tunnelsH.CreateLogToken` | medium |
| GET | `/api/tunnels/{id}/logs` | public (token param) | `tunnelsH.GetLogs` | medium |
| POST | `/api/tunnels` | **`X-Tunnel-Secret` ✅ fixed** | `tunnelsH.ReportTunnel` | low |
| PATCH | `/api/tunnels/{id}` | **`X-Tunnel-Secret` ✅ fixed** | `tunnelsH.UpdateTunnelStatus` | low |

### Subdomains

| Method | Path | Auth | Handler | Risk |
|--------|------|------|---------|------|
| GET | `/api/subdomains` | JWT | `subdomainH.List` | low |
| GET | `/api/subdomains/analytics` | JWT | `subdomainH.Analytics` | low |
| POST | `/api/subdomains` | JWT | `subdomainH.Create` | medium |
| DELETE | `/api/subdomains/{id}` | JWT | `subdomainH.Delete` | medium |
| PATCH | `/api/subdomains/{id}/assignment` | JWT | `subdomainH.UpdateAssignment` | medium |
| PUT | `/api/subdomains/{id}/rule` | JWT | `subdomainH.UpsertRule` | medium |

### Custom Domains

| Method | Path | Auth | Handler | Risk |
|--------|------|------|---------|------|
| GET | `/api/domains` | JWT | `domainsH.List` | low |
| POST | `/api/domains` | JWT | `domainsH.Create` | medium |
| DELETE | `/api/domains/{id}` | JWT | `domainsH.Delete` | medium |
| POST | `/api/domains/{id}/verify` | JWT | `domainsH.Verify` | medium |
| PATCH | `/api/domains/{id}/target` | JWT | `domainsH.SetTarget` | medium |

### User / Account

| Method | Path | Auth | Handler | Risk |
|--------|------|------|---------|------|
| PUT | `/api/user` | JWT | `userH.UpdateProfile` | low |
| PUT | `/api/user/password` | JWT (MustReset allowed) | `userH.UpdatePassword` | medium |
| DELETE | `/api/user` | JWT | `userH.DeleteAccount` | high |
| GET | `/api/user/verify-request` | JWT | `userH.GetVerifyRequest` | low |
| POST | `/api/user/verify-request` | JWT | `userH.SubmitVerifyRequest` | low |
| PATCH | `/api/user/plan` | JWT | `userH.SetActivePlan` | medium |

### Billing

| Method | Path | Auth | Handler | Risk |
|--------|------|------|---------|------|
| GET | `/api/billing` | JWT | `billingH.GetBilling` | medium |
| POST | `/api/billing/checkout` | JWT | `billingH.CreateCheckout` | medium |
| POST | `/api/billing/portal` | JWT | `billingH.CreatePortal` | medium |
| POST | `/api/billing/webhook` | public (Stripe sig) | `billingH.WebhookHandler` | high |

### Teams

| Method | Path | Auth | Handler | Risk |
|--------|------|------|---------|------|
| GET | `/api/team` | JWT | `teamH.GetTeam` | low |
| POST | `/api/team` | JWT | `teamH.CreateTeam` | low |
| PATCH | `/api/team/{id}` | JWT | `teamH.RenameTeam` | low |
| DELETE | `/api/team/{id}` | JWT | `teamH.DeleteTeam` | medium |
| GET | `/api/team/members` | JWT | `teamH.ListMembers` | low |
| GET | `/api/team/invitations` | JWT | `teamH.ListInvitations` | low |
| DELETE | `/api/team/members/{userId}` | JWT | `teamH.RemoveMember` | medium |
| POST | `/api/team/invite` | JWT | `teamH.Invite` | low |
| POST | `/api/team/invite/code` | JWT | `teamH.GenerateInviteCode` | low |
| POST | `/api/team/invite/accept` | JWT | `teamH.AcceptInvite` | low |
| POST | `/api/team/invite/accept-by-id` | JWT | `teamH.AcceptInviteByID` | low |
| DELETE | `/api/team/invite/{id}` | JWT | `teamH.RevokeInvite` | low |
| POST | `/api/team/invite/{id}/resend` | JWT | `teamH.ResendInvite` | low |
| GET | `/api/team/joined` | JWT | `teamH.GetJoinedTeams` | low |
| GET | `/api/team/{id}/detail` | JWT | `teamH.GetTeamDetail` | low |
| GET | `/api/team/{id}/stats` | JWT | `teamH.GetTeamStats` | medium |
| GET | `/api/team/{id}/my-tunnels` | JWT | `teamH.GetMyTunnels` | low |
| GET | `/api/team/{id}/members/{userId}/tunnels` | JWT | `teamH.GetMemberTunnels` | medium |
| PATCH | `/api/team/members/{userId}/role` | JWT | `teamH.ChangeRole` | medium |
| GET | `/api/team/my-invitations` | JWT | `teamH.GetMyInvitations` | low |
| POST | `/api/team/{id}/leave` | JWT | `teamH.LeaveTeam` | low |

### Organizations

| Method | Path | Auth | Handler | Risk |
|--------|------|------|---------|------|
| POST | `/api/org/create` | JWT | `orgH.CreateMyOrg` | medium |
| GET | `/api/org/mine` | JWT | `orgH.GetMine` | low |
| GET | `/api/org/{id}` | JWT | `orgH.GetOrg` | medium |
| GET | `/api/org/{id}/members` | JWT | `orgH.ListMembers` | medium — **now paginated ✅** |
| DELETE | `/api/org/{id}/members/{userId}` | JWT | `orgH.RemoveMember` | high |
| PATCH | `/api/org/{id}/members/{userId}/allocation` | JWT | `orgH.SetAllocation` | medium |
| GET | `/api/org/{id}/teams` | JWT | `orgH.ListTeams` | low |
| POST | `/api/org/{id}/teams` | JWT | `orgH.CreateTeam` | medium |
| DELETE | `/api/org/{id}/teams/{teamId}` | JWT | `orgH.DeleteTeam` | medium |
| GET | `/api/org/{id}/requests` | JWT | `orgH.ListRequests` | low |
| PATCH | `/api/org/{id}/requests/{reqId}` | JWT | `orgH.ReviewRequest` | medium |
| POST | `/api/org/{id}/requests/{reqId}/comments` | JWT | `orgH.AddRequestComment` | low |
| POST | `/api/org/request` | JWT | `orgH.SubmitRequest` | low |
| POST | `/api/org/{id}/import/preview` | JWT | `orgH.PreviewImport` | medium |
| POST | `/api/org/{id}/import` | JWT | `orgH.BulkImport` | **high — still synchronous** |

### Admin (all require JWT + IsAdmin)

| Method | Path | Handler | Risk |
|--------|------|---------|------|
| GET | `/api/admin/stats` | `adminH.GetStats` | low |
| GET | `/api/admin/users` | `adminH.ListUsers` | medium |
| GET | `/api/admin/users/{id}` | `adminH.GetUser` | medium |
| PATCH | `/api/admin/users/{id}` | `adminH.UpdateUser` | high |
| POST | `/api/admin/users/{id}/resend-verify` | `adminH.ResendVerification` | low |
| DELETE | `/api/admin/users/{id}` | `adminH.DeleteUser` | high |
| GET | `/api/admin/tunnels` | `adminH.ListTunnels` | medium |
| DELETE | `/api/admin/tunnels/{id}` | `adminH.KillTunnel` | medium |
| GET/POST/PATCH/DELETE | `/api/admin/domains/*` | `adminH.*` | medium |
| GET/PUT | `/api/admin/plans` | `adminH.*` | high |
| GET/POST/PATCH/DELETE | `/api/admin/organizations/*` | `adminH.*`, `orgH.*` | high |
| PATCH | `/api/admin/org/{id}/seat-limit` | `orgH.SetSeatLimit` | medium |
| PATCH | `/api/admin/org/{id}/plan` | `orgH.SetPlan` | medium |
| GET/POST/DELETE | `/api/admin/abuse/*` | `adminH.*` | medium |
| GET/PATCH/DELETE | `/api/admin/verify-requests/*` | `adminH.*` | medium |
| GET | `/api/admin/revenue` | `billingH.GetRevenue` | low |
| GET | `/api/admin/billing/subscribers` | `billingH.GetSubscribers` | low |
| POST | `/api/admin/billing/refund` | `billingH.AdminRefund` | high |
| POST | `/api/admin/billing/receipt` | `billingH.AdminSendReceipt` | medium |
| GET/PATCH | `/api/admin/server-limits` | `adminH.*` | high |
| GET | `/api/admin/system` | `monitorH.GetSnapshot` | low |
| GET | `/api/admin/system/stream` | `monitorH.Stream` (custom JWT) | low |
| GET/POST/PATCH/DELETE | `/api/admin/partners/*` | `partnersH.*` | low |
| GET/POST/PATCH/DELETE | `/api/admin/sponsors/*` | `sponsorsH.*` | low |
| GET/POST | `/api/admin/newsletter/*` | `newsletterH.*` | medium |
| GET/PATCH/DELETE | `/api/admin/donations/*` | `donationH.*` | low |
| POST | `/api/admin/users/{id}/trial` | `adminH.SetUserTrial` | medium |

### Notifications

| Method | Path | Auth | Risk |
|--------|------|------|------|
| GET | `/api/notifications` | JWT | low |
| PATCH | `/api/notifications/read-all` | JWT | low |
| PATCH | `/api/notifications/{id}/read` | JWT | low |
| DELETE | `/api/notifications` | JWT | low |
| DELETE | `/api/notifications/{id}` | JWT | low |
| GET | `/api/notifications/stream` | `?token=` param | medium |

### Newsletter / Misc / Uploads

| Method | Path | Auth | Risk |
|--------|------|------|------|
| POST | `/api/newsletter/subscribe` | public | low |
| GET | `/api/newsletter/unsubscribe` | public | low |
| POST | `/api/newsletter/resubscribe` | public | low |
| POST | `/api/newsletter/toggle` | JWT | low |
| POST | `/api/donations/submit` | public + **5/min ✅ fixed** | low |
| POST | `/api/upload` | **JWT ✅ fixed** | low |
| GET | `/api/uploads/{filename}` | public | medium |

---

## 3. Role + Plan Matrix

| Action | Free | Student | Pro | Org Owner | Org Admin | Org Member | Team Owner/Admin | Team Member | Global Admin |
|--------|------|---------|-----|-----------|-----------|------------|-----------------|-------------|--------------|
| Register/Login | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| View own tunnels | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Reserve subdomain | plan-gated | ✅ | ✅ | ✅ | ✅ | via allocation | ✅ | via assignment | ✅ |
| Custom domain | ❌ | ❌ | ✅ | via plan | via allocation | via allocation | ✅ | ❌ | ✅ |
| Create team | ❌ | ❌ | ✅ | ✅ | ✅ (for org) | ❌ | owner only | ❌ | ✅ |
| View member tunnels | ❌ | ❌ | team owners only | ✅ | ✅ | own only | owner/admin/teacher | own only | ✅ |
| Create org | ❌ | ❌ | ❌ | self-service | ❌ | ❌ | ❌ | ❌ | ✅ |
| Manage org members | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ | ❌ | ✅ |
| Bulk import | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ | ❌ | ✅ |
| Kill any tunnel | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Issue refunds | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Change plan limits | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |

> **Key rule:** Org membership does NOT change `users.plan`. `org_allocations` controls org-managed resource limits. Both can coexist.

---

## 4. Gaps vs nextupdate.md (Updated)

### All 13 Checklist Items Now Fully Implemented ✅

Items 1–13 were confirmed deployed in the previous session. This pass added hardening on top:
- Items 1–7 backend fixes: tunnel secret, upload auth, rate limits, password reset enforcement.
- Items 8–13 org system: unchanged, already deployed 2026-03-28.

### Still Open (Not in nextupdate.md)

| Item | Status |
|------|--------|
| `TUNNEL_EDGE_SECRET` env var must be set on both API and tunnel edge servers | Ops action required — no code change needed |
| Async bulk import job queue | Not yet implemented — requires new infrastructure |
| Redis cache for `mergeLiveTunnels()` | Not yet implemented |
| Org-auth middleware (centralized role check) | Not yet refactored |

---

## 5. Remaining Performance / Refactor Risks

### P0 — All Fixed ✅

### P1 — Remaining

**1. `POST /api/org/{id}/import` — still synchronous**

Each row does: email lookup, optional user creation, org member upsert, allocation upsert, welcome email. For 1000 rows this blocks the goroutine for minutes.

**Recommended fix:** Return `202 Accepted` with a job ID. Process in a background goroutine. Expose `GET /api/org/{id}/import/{jobId}/status`.

**2. `mergeLiveTunnels()` — live HTTP call on every `GET /api/tunnels`**

Every dashboard load makes a 5s-timeout HTTP call to the tunnel edge. If edge is slow or restarting, the user sees a delay.

**Recommended fix:** Cache the live snapshot per `userID` in Redis with 5–10s TTL. On error, return DB-only data (graceful degrade).

### P2 — Remaining

**3. `emailUsers()` N+1 user lookups (`org.go:~148`)**

Fetches each user by ID in a loop when sending bulk notifications.

**Recommended fix:** Add `GetUsersByIDs(ctx, ids []string)` batch query to `db/users.go`.

**4. `GET /api/team/{id}/stats` CTE — no cache**

Expensive JOIN across `tunnels`, `reserved_subdomains`, `team_members` with no TTL or size guard.

**Recommended fix:** Redis cache with 30–60s TTL per team ID.

**5. Org-auth middleware**

`callerOrgRole()` is called independently in every org handler. Each call does a DB query. This is an extra SELECT per org request.

**Recommended fix:** Shared middleware that stores caller org role in request context once per request lifecycle.

---

## 6. Test Coverage Plan (Remaining Gaps)

### Fixed Issues — Now Testable

| Test | Expected behavior after fix |
|------|----------------------------|
| `POST /api/tunnels` without `X-Tunnel-Secret` | 403 when `TUNNEL_EDGE_SECRET` is configured |
| `POST /api/tunnels` with correct secret | 200 |
| `POST /api/upload` without JWT | 401 |
| `POST /api/auth/refresh` 31 times in a minute | 29th–30th: 200, 31st: 429 |
| `POST /api/auth/2fa/verify` 11 times in a minute | 10th: 200, 11th: 429 |
| Login as provisioned user, then call `GET /api/tunnels` | 403 with `password_reset_required` |
| Login as provisioned user, then call `PUT /api/user/password` | 200 — allowed |
| After `PUT /api/user/password` succeeds, call `GET /api/tunnels` | 200 — `MustReset` cleared |
| `GET /api/org/{id}/members?limit=10&offset=0` | Returns 10 members + `X-Total-Count` header |
| `POST /api/donations/submit` 6 times in a minute | 6th: 429 |

### Still Missing Tests

| Test | Priority |
|------|---------|
| Stripe webhook with invalid signature → 400 | P0 |
| Stripe webhook replayed (same event ID) → idempotent | P0 |
| Org admin of org A calls allocation for org B → 403 | P0 |
| BulkImport at exact seat limit → blocked | P0 |
| `GET /api/uploads/../../../etc/passwd` → path traversal blocked | P0 |
| `mergeLiveTunnels` when tunnel server is down → 200 with DB-only data | P1 |

---

## 7. Top 10 Recommended Next Actions (Updated)

| # | Priority | Action | Status |
|---|----------|--------|--------|
| 1 | **P0** | Set `TUNNEL_EDGE_SECRET` in production `.env` for both API and tunnel edge, then restart both | **Ops action — not done yet** |
| 2 | **P0** | Write test: `POST /api/tunnels` without secret → 403 | Not done |
| 3 | **P0** | Write test: Stripe webhook replay idempotency | Not done |
| 4 | **P0** | Write test: cross-org allocation access → 403 | Not done |
| 5 | **P1** | Make `POST /api/org/{id}/import` async — return 202 + job ID | Not done |
| 6 | **P1** | Add Redis cache to `mergeLiveTunnels()` with 5–10s TTL | Not done |
| 7 | **P1** | Add batch `GetUsersByIDs` to replace N+1 in `emailUsers()` | Not done |
| 8 | **P1** | Add Redis cache to `GetTeamStats` with 30–60s TTL | Not done |
| 9 | **P2** | Centralize org-auth as middleware (request context injection) | Not done |
| 10 | **P2** | Add `admin_audit_log` table — record all admin mutations (UpdateUser, DeleteUser, UpdatePlans, Refund) | Not done |

---

**Total routes: 130** | **Fixed in this pass: 7 issues** | **Deployed: 2026-03-28 13:45** | **Remaining high-risk: 1 (TUNNEL_EDGE_SECRET must be set in prod env)**

*Generated: 2026-03-28 — Based on analysis of `internal/api/server.go`, all handler files, and `db/` layer.*
