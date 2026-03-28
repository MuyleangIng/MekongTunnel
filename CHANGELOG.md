# Changelog

## Unreleased

Highlights:

- Split browser error handling for reserved subdomains and custom domains so known-but-offline routes now return a branded `502` tunnel-offline page, while unknown routes return a branded `404` not-found page
- Added last-seen timestamps to offline tunnel pages when the tunnel has historical activity in PostgreSQL
- Added in-memory tunnel log history plus live subscribers on the tunnel edge so active tunnels can expose recent request logs and SSE follow streams
- Added localhost-only tunnel-edge APIs for live active-tunnel snapshots and per-subdomain log streaming
- Added API endpoints for live tunnel data and dashboard summaries: `GET /api/tunnels/live`, `GET /api/tunnels/overview`, `POST /api/tunnels/{id}/log-token`, and `GET /api/tunnels/{id}/logs`
- Merged live tunnel state into `GET /api/tunnels` so active status, today request counts, and live bandwidth counters are fresher for the existing dashboard UI
- Added `GET /api/team/{id}/members/{userId}/tunnels` for teacher/admin/owner read-only member tunnel access
- Restored tunnel lifecycle sync from the tunnel edge into the API so newly opened tunnels are inserted into PostgreSQL and show up in dashboard/user tunnel APIs immediately
- Added tunnel-log SSE retry hints and keepalive heartbeats, and made the dashboard log inspector keep existing lines visible while browser EventSource auto-reconnects after transient drops
- Retired older active tunnel rows when the same subdomain reconnects, and added list-side active de-duplication so dashboards do not show duplicate active entries for one live tunnel
- Deployed the dashboard live-state backend and token-based tunnel log backend to production on `2026-03-27`; public routes remain auth-protected and still need authenticated end-to-end UI validation
- Added frontend tunnel log inspectors for members and team leaders, plus upgraded `/dashboard/tunnels` with log actions and team-member filtering; deployed frontend to production on `2026-03-27`
- Expanded tunnel logger tests to cover retained history and live subscriber delivery
- Added team-route assignment for team-owned reserved subdomains so owner/admin/teacher can assign one member per route, inspect that member from team detail, and keep personal routes separate from team route dashboards
- Split team-owned route quotas from per-member route limits: student teams can manage 3 shared routes while each member stays limited to 1 assigned route, and pro teams can manage 10 shared routes while each member stays limited to 3
- Expanded `/dashboard/team` so route and member actions open a real member-detail view with assigned team routes, route usage snapshots, route filtering, and direct log access without leaving the team page
- Normalized team-member identity fields in the dashboard client so Team route assignment now shows the real member name/email consistently, and added `Delete route` actions to team-owned reserved routes
- Fixed admin organization member listing to read real `org_members` data, made bulk/manual org import update existing user names from CSV when provided, applied the visible import allocation fields, and added an admin-only delete action on `/admin/organizations`
- Added a dedicated admin import route for `/admin/organizations` so global admins can add org members without also being org owners, and expanded the regular `/dashboard/org` page into an org-management view for owners/admins with member import, allocation controls, and request review
- Fixed auth routing so successful sign-in now resolves to `/dashboard/org` for organization users, keeps explicit safe redirect targets for invite/CLI flows, and enforces forced password reset across login, 2FA, email OTP, refresh restore, and protected dashboard/admin routes
- Fixed org member import defaults so organization membership no longer changes a user’s personal plan unless `plan` is set explicitly, while org allocations continue to control org-managed tunnels, subdomains, bandwidth, and custom-domain access
- Updated `/dashboard/org` and `/admin/organizations` member forms and CSV guidance to label personal plan as optional and keep org role separate from the user’s personal subscription plan
- Updated provisioned welcome emails to use `/auth/login` with the invited email prefilled, and added a compatibility `/login` redirect on the frontend for older links
- Added per-member organization `team_limit` allocation support, plus org-managed team creation/deletion endpoints so org owner/admin can create teams for members without depending on the member’s personal paid plan
- Simplified `/dashboard/org` member creation so new people default to `Member of ORG`, moved personal-plan changes into advanced settings, surfaced team limits in org allocation, and added automatic notifications when an org team is created for a member
- Added self-service organization creation on `/dashboard/org` for authenticated ORG-plan users who are not yet in an organization, and removed the manual role/personal-plan controls from the normal add-member UI so manual invites default to standard org membership
- Added import preview endpoints for organization member CSV/JSON uploads, plus preview/confirm UI on `/dashboard/org` and `/admin/organizations` with row-by-row validation, projected seat usage, and failed-row CSV export before final import
- Added shared workspace identity cards across dashboard pages, plus stronger organization summary cards, seat-usage visibility, member lifecycle badges, and clearer empty states on `/dashboard/org` and `/admin/organizations`
- Expanded organization requests with richer request types, threaded comments, reviewer notes, `needs discussion` status, automatic allocation changes on approval, and request-status notifications/emails for requesters and org managers
- Added richer admin organization lifecycle tools with status changes, admin notes, creator/manager/team/request summary fields, and better org detail data on `/admin/organizations`
- Added the ORG verification approval flow end-to-end: requested org domain and seat limits, approval notes, waiting-state UI, admin review details, and org creation/linking/activation when an ORG request is approved
- Added approved ORG contract discount support so admins can set `0`-`100%` during org approval, the billing page surfaces the approved discount, and ORG checkout applies it to Stripe checkout sessions
- Extended organization billing requests so members can request a discount percentage and org managers can approve a specific percentage with notes on the org dashboard

## v1.5.8 - 2026-03-28

Highlights:

- Added manual payment receipt system for PayPal, ABA Pay, and Bakong so users can upload proof of payment and admins can approve, reject, or request resubmission from the admin billing page
- Added duplicate receipt prevention so a user cannot submit a second receipt for the same plan while one is already pending or awaiting resubmission
- Added refund tracking fields on receipt rejection so admins can record the bank account, refund amount, and notes for the user
- Sent admin in-app notification when a new receipt is submitted, and sent approval confirmation email to the user via Resend when a receipt is approved
- Added seven new API endpoints for receipt management: submit, list, count (user + admin), review, delete
- Fixed Google and GitHub OAuth to accept `?redirect_to=<origin>` so the callback token is delivered to the correct frontend origin, enabling `localhost:3000` dev servers to receive the OAuth token without landing on production
- Fixed CORS middleware to always allow `localhost:*` and `127.0.0.1:*` origins regardless of the `ALLOWED_ORIGINS` env var, removing the need for developers to change server config when running locally
- Updated HANDBOOK.md with Manual Payment Receipts API table, updated OAuth endpoint docs with `?redirect_to` param, and corrected `ALLOWED_ORIGINS` example

## v1.5.7 - 2026-03-27

Highlights:

- Added optional Redis integration for the Go API and tunnel edge
- Cached `server_config` reads and verified custom-domain target lookups in Redis
- Added Redis pub/sub fan-out for notifications so multiple API instances can serve SSE correctly
- Added Redis-backed distributed API rate limiting for public auth and CLI device endpoints
- Moved email login OTP codes to Redis when configured, with PostgreSQL fallback kept for single-node or Redis-disabled setups
- Added GitHub Actions workflows for systemd-based dev and production deploys, plus deployment docs for environment secrets, variables, and optional Redis setup
- Added compose base/dev/prod stack files for Postgres + Redis + API + optional tunnel edge
- Added bootstrap-only API mode plus `api-init` workflow for migrations, `server_config`, and admin creation/promotion
- Added `.env.compose.dev.example` and `.env.compose.prod.example` templates
- Added `cmd/apibench` and `scripts/stress-local.sh` for local API stress runs such as 1000 users and 5000 tunnel reports
- Redesigned the shared-tunnel warning page into a simpler one-click flow so the first Continue click sets the warning cookie and opens the site correctly
- Added a cleaner branded Tunnel Status page for unreachable local apps with a 4-step connection flow, active/failed state colors, mobile-safe text wrapping, and automatic retry/reopen when the local app starts responding again
- Improved tunnel browser error pages so they show the real client-reported local port when available and never fake `localhost:80` for raw `ssh -R` sessions
- Expanded the random generated tunnel-name word pool while keeping the stable `word-word-8hex` format
- Added `docs/API_FLOW.md` and `docs/PERFORMANCE.md`
- Replaced the old local `.env` / `.env.api` workflow with explicit `.env.dev` / `.env.prod` templates, cleaned the compose env templates, and updated scripts/docs to match
- Updated the README, CLI contract, and handbook to document the normal `npm run dev` + `mekong 3000` workflow and the new browser tunnel UX
- Built fresh multi-platform client binaries with `main.version=v1.5.7`

## v1.5.1 - 2026-03-25

Highlights:

- Added reserved subdomain and custom-domain management commands to the Go CLI, including clearer `mekong domain add`, `verify`, `connect`, `delete`, `doctor`, and `subdomains` flows
- Added apex-aware DNS guidance so root domains such as `example.com` show `A` / `AAAA` records while subdomains such as `app.example.com` show `CNAME`
- Rejected malformed domains in both the CLI and API, improved custom-domain verification messaging, and made `connect` wait through DNS and HTTPS readiness states
- Added admin custom-domain management endpoints so admins can list, inspect, verify, retarget, and delete user domain mappings
- Added donations API improvements, free-trial and newsletter config updates, public receipt upload support, and stronger OTP enforcement on OAuth sign-in
- Improved QR code reliability and frontend compatibility for auth flows
- Added API and tunnel deploy tooling plus cloud startup planning docs for the ecosystem deployment workflow
- Built fresh multi-platform client binaries with `main.version=v1.5.1`

## v1.5.0 - 2026-03-23

Highlights:

- Added `mekong login`, `mekong logout`, and `mekong whoami` commands for account management
- Added `mekong test` command for connectivity and auth self-diagnostics
- Added `--token` flag and `MEKONG_TOKEN` env var for reserved subdomains without interactive login
- Updated install.sh to install to `/usr/local/bin` on macOS (VS Code and all SDKs find it without PATH tricks); falls back gracefully to `~/.local/bin` when piped without sudo
- Updated install.ps1 to install to `%LOCALAPPDATA%\Programs\mekong\` on Windows (no admin required)
- Added Windows arm64 binary (`mekong-windows-arm64.exe`) to release assets
- VS Code extension v1.5.0: login/account panel, email + plan badge, auto-detects login state
- npm mekong-cli v2.0.0: Node.js SDK with support for Next.js, Vite, Nuxt, Remix, SvelteKit, Astro, Express
- Python mekong-tunnel v2.1.0: pip SDK with support for FastAPI, Flask, Django, uvicorn, gunicorn, Granian, Hypercorn
- All SDKs (VS Code, npm, pip) search `/usr/local/bin` first on macOS, then `~/.local/bin`, with full Windows path coverage

## v1.4.9 - 2026-03-14

Highlights:

- Hardened `mekong update` with checksum verification for release assets
- Added retry logic for transient HTTPS download failures such as `tls: bad record MAC`
- Prevented the updater from replacing the current binary until a full verified download is complete
- Built fresh multi-platform client binaries with `main.version=v1.4.9`

## v1.4.8 - 2026-03-14

Highlights:

- Raised the default per-IP active tunnel limit to `1000`
- Made total tunnel capacity and per-minute connection caps unlimited by default via `0`
- Disabled automatic blocking by default so aggressive reconnect/load testing is not rejected unless explicitly configured
- Raised default request and response body limits to `1 GB` and made WebSocket transfer unlimited by default
- Added runtime env vars for request rate, burst size, block duration, violation threshold, and payload sizes
- Built fresh multi-platform client binaries with `main.version=v1.4.8`

## v1.4.7 - 2026-03-14

Highlights:

- Surfaced the server's real `tcpip-forward` rejection reason in `mekong` instead of a generic `server rejected port-forward request`
- Raised the default per-IP active tunnel limit from `3` to `10`
- Added configurable `MAX_TOTAL_TUNNELS` and `MAX_CONNECTIONS_PER_MINUTE` server env vars for higher-capacity deployments, including 300+ tunnels from one IP when explicitly configured
- Versioned Docker builds now embed `main.version`, publish OCI image version metadata, and support versioned Compose image tags
- Built fresh multi-platform client binaries with `main.version=v1.4.7`

## v1.4.6 - 2026-03-13

Highlights:

- Added `mekong logs` to print daemon logs from `~/.mekong/mekong.log`
- Added `mekong logs -f` / `mekong logs --follow` to stream daemon logs live like `docker logs -f`
- Added optional port filtering so `mekong logs 3000` and `mekong logs -f 3000` show only one local port
- Added `mekong stop 3000` to stop a single daemon tunnel by local port and `mekong stop --all` to stop every daemon tunnel
- Stopping a daemon tunnel now clears that port's old log lines from `~/.mekong/mekong.log`
- Updated daemon mode output and README examples to surface the new log commands
- Built fresh multi-platform client binaries with `main.version=v1.4.6`

## v1.4.5 - 2026-03-13

Highlights:

- Hardened `update.sh` so production deploys fetch tags, reset to a clean ref, clear Go caches, clean old build outputs, rebuild both binaries, and restart from the latest code
- Added `mekongtunnel version` for direct server binary verification after deploys
- Updated install docs to use `sudo xattr` for macOS binaries installed into `/usr/local/bin`
- Built fresh multi-platform client binaries with `main.version=v1.4.5`

## v1.4.4 - 2026-03-13

Highlights:

- Added tunnel expiry support to `mekong` via `-e` / `--expire`
- Added raw SSH expiry support via `--expire=...` and `MEKONG_EXPIRE`
- Added per-tunnel lifetime handling, expiry display, expiry-aware reconnect behavior, and idle timeout that follows the requested expiry
- Built fresh multi-platform client binaries with `main.version=v1.4.4`
- Clarified the client error when expiry is used against an older server that does not support the feature yet

## Tags

| Tag | Date |
| --- | --- |
| `v1.5.7` | 2026-03-27 |
| `v1.5.6` | 2026-03-25 |
| `v1.4.9` | 2026-03-14 |
| `v1.4.8` | 2026-03-14 |
| `v1.4.7` | 2026-03-14 |
| `v1.4.6` | 2026-03-13 |
| `v1.4.5` | 2026-03-13 |
| `v1.4.4` | 2026-03-13 |
| `v1.4.3` | 2026-03-03 |
| `v1.4.2` | 2026-02-28 |
| `v1.4.1` | 2026-02-28 |
| `v1.4.0` | 2026-02-28 |
| `v1.3.0` | 2026-02-28 |
| `v1.2.0` | 2026-02-28 |
| `v1.1.0` | 2026-02-28 |
| `v1.0.0` | 2026-02-27 |

## v1.4.3 - 2026-03-03

Tag commit: `chore: remove multi-port and --server from help text`

Changes since `v1.4.2`:

- `docs: remove unsupported features for v1.4.3`
- `chore: remove multi-port and --server from help text`

## v1.4.2 - 2026-02-28

Tag commit: `fix: write state file immediately when tunnel URL is received`

Changes since `v1.4.1`:

- `feat: remove custom subdomain feature`
- `fix: write state file immediately when tunnel URL is received`

## v1.4.1 - 2026-02-28

Tag commit: `chore: remove subdomain example from help text`

Changes since `v1.4.0`:

- `fix: split platform-specific daemon code for cross-compilation`
- `feat: make MaxTunnelsPerIP configurable via MAX_TUNNELS_PER_IP env var`
- `fix: allow flags after port args (mekong 3000 --subdomain myapp)`
- `feat: add -p/--port flag for local port, fix flag ordering issue`
- `docs: update install links to v1.4.1, add changelog entry`
- `chore: clean old binaries before rebuild in update.sh`
- `debug: log SSH User field and show requested subdomain in banner`
- `chore: clean up usage examples in help text`
- `chore: remove subdomain example from help text`

## v1.4.0 - 2026-02-28

Tag commit: `feat: v1.4.0 - custom subdomain, multi-port, daemon mode, status/stop, web dashboard`

Changes since `v1.3.0`:

- `docs: bump install links to v1.3.0`
- `readme update`
- `feat: v1.4.0 - custom subdomain, multi-port, daemon mode, status/stop, web dashboard`

## v1.3.0 - 2026-02-28

Tag commit: `feat(mekong): add self-update command and version embedding`

Changes since `v1.2.0`:

- `docs: bump install links to v1.2.0`
- `feat(mekong): add self-update command and version embedding`

## v1.2.0 - 2026-02-28

Tag commit: `chore: remove certs and mekong binary from repo, update .gitignore`

Changes since `v1.1.0`:

- `docs: bump install links to v1.1.0`
- `chore: add update.sh script for server deployment`
- `chore: also build mekong client binary in update.sh`
- `docs: add xattr quarantine fix for macOS Gatekeeper`
- `docs: remove xattr note, keep command in install steps`
- `fix(mekong): use half-block chars for smaller QR code in terminal`
- `fix(mekong): use GenerateHalfBlock for smaller QR code`
- `chore: rename module to github.com/MuyleangIng/MekongTunnel`
- `chore: remove certs and mekong binary from repo, update .gitignore`

## v1.1.0 - 2026-02-28

Tag commit: `docs: update README to reflect blocked IP auto-detection in mekong CLI`

Changes since `v1.0.0`:

- `docs: add sudo and test command to install instructions`
- `docs: update project structure and build commands to include mekong CLI`
- `feat: redirect root domain to mekongtunnel-dev.vercel.app`
- `fix: only redirect root domain to Vercel when not a warning page request`
- `fix: redirect to Vercel when warning page has no redirect param`
- `docs: add troubleshooting entry for IP blocked error`
- `docs: add auto-reconnect IP blocking warning to mekong CLI section`
- `config: relax rate limits to reduce accidental blocks`
- `feat(mekong): stop auto-reconnect when server reports IP is blocked`
- `docs: update README to reflect blocked IP auto-detection in mekong CLI`

## v1.0.0 - 2026-02-27

Tag commit: `fix: keep stdin pipe open to prevent immediate server disconnect`

Initial tagged release:

- `first commit`
- `feat: replace tunnel banner with ASCII art logo and author branding`
- `fix: serve warning interstitial page on root domain instead of Bad Request`
- `fix: fix warning cookie domain and redesign page with Khmer theme`
- `feat: add mekong CLI client with auto-reconnect, QR code, and clipboard`
- `docs: add mekong CLI install instructions and usage to README`
- `fix: keep stdin pipe open to prevent immediate server disconnect`
