# MekongTunnel Telegram Bot Integration Plan

Status: Draft for implementation
Date: 2026-04-08
Scope: Add a BotFather-created Telegram bot that links to a user's Mekong account and exposes read-only account, tunnel, log, subdomain, and custom-domain features.

## 1. Summary

The Telegram bot should be a linked-account client for MekongTunnel, not a separate auth system.

Recommended product shape:

- users start with `/start` or `/link` in Telegram
- the bot sends a short-lived browser approval URL
- the user logs into Mekong on the web if needed
- the user approves the Telegram chat link
- the bot can then show active services, recent logs, reserved subdomains, and custom-domain status

This should reuse the same UX pattern as `mekong login`, but it should not reuse the CLI device session table directly. The CLI flow in `internal/api/handlers/cli_device.go` mints a one-time API token for a polling client. Telegram linking needs to bind `telegram_chat_id` to `user_id`, which is a different responsibility.

## 2. Product Decisions

### Do

- treat Telegram as another Mekong client
- require the user to link their Telegram chat to an existing Mekong account
- start with read-only features
- keep the approval step in the browser
- use private chats only for MVP

### Do not

- ask users to type passwords into Telegram
- ask users to paste raw API tokens into Telegram
- try to start `mekong 3000` on the user's local machine from Telegram in v1
- expose streaming live logs in Telegram chat
- allow destructive actions in the first release

## 3. Bot Identity And Naming

The bot should look official, simple, and product-linked.

### Recommended primary name

- Display name: `Mekong Tunnel`
- Username: `MekongTunnelBot`

This is the best default if the username is available.

Why:

- matches the product name used in the repo and README
- easy to understand in Telegram search
- works for both CLI users and dashboard users

### Good fallback names

- Display name: `MekongTunnel`
- Username: `MekongTunnelAppBot`

- Display name: `Mekong Control`
- Username: `MekongControlBot`

- Display name: `Mekong Assistant`
- Username: `MekongAssistantBot`

### Recommendation

Use this if available:

- BotFather name: `Mekong Tunnel`
- BotFather username: `MekongTunnelBot`

If it is already taken, use:

- BotFather name: `Mekong Tunnel`
- BotFather username: `MekongControlBot`

### Bot profile text

Suggested description:

`Link your Mekong account to view active tunnels, recent logs, reserved subdomains, and domain status.`

Suggested about text:

`Official MekongTunnel bot for account linking and service status.`

Suggested short welcome text for `/start`:

`Link your Mekong account to view services, logs, subdomains, and domains from Telegram. Use /link to begin.`

## 4. BotFather Setup

Create the bot in Telegram before backend implementation is wired.

### Step-by-step

1. Open Telegram and message `@BotFather`.
2. Run `/newbot`.
3. Set the bot display name:
   - `Mekong Tunnel`
4. Set the bot username:
   - `MekongTunnelBot`
   - or fallback `MekongControlBot`
5. Save the bot token securely.
6. Run `/setdescription` and use:
   - `Link your Mekong account to view active tunnels, logs, subdomains, and domain status.`
7. Run `/setabouttext` and use:
   - `Official MekongTunnel bot for account linking and service status.`
8. Run `/setuserpic` and upload the MekongTunnel logo if you want the bot to feel official.
9. After backend deploy, run `/setcommands`.
10. After production deploy, set the webhook URL to your API.

### Recommended BotFather commands list

Use this command list:

- `start - Start the bot and see link status`
- `help - Show available commands`
- `link - Link Telegram to your Mekong account`
- `me - Show your Mekong account`
- `services - Show active tunnels`
- `logs - Show recent logs for one service`
- `subdomains - Show reserved subdomains`
- `domains - Show custom domains`
- `domain - Check one custom domain`
- `unlink - Unlink Telegram from your account`

### Webhook target

Recommended production webhook:

- `https://api.angkorsearch.dev/api/telegram/webhook`

Recommended staging webhook:

- `https://<staging-api-host>/api/telegram/webhook`

### Secrets to keep

- Bot token from BotFather
- webhook secret token used by your backend

Never commit the BotFather token to git.

## 5. Existing Backend Surfaces To Reuse

The current repo already has most of the core product data the bot needs.

- CLI-style device approval flow:
  - `internal/api/handlers/cli_device.go`
- API token lifecycle:
  - `internal/api/handlers/tokens.go`
  - `internal/api/handlers/auth.go`
- tunnel listing and overview:
  - `internal/api/handlers/tunnels.go`
- tunnel log token and log proxy:
  - `internal/api/handlers/tunnels.go`
- reserved subdomains:
  - `internal/api/handlers/subdomain.go`
- custom domains and verification:
  - `internal/api/handlers/domains.go`
- route registration:
  - `internal/api/server.go`

Important note:

- `GET /api/tunnels/live` and `GET /api/tunnels/overview` currently assume JWT auth, not API-token auth.
- `GET /api/cli/subdomains` and `GET /api/cli/domains` already support API-token style auth.

Because of that, the Telegram bot should not be built as a thin wrapper around existing public HTTP endpoints alone. It should share internal services and DB access inside the backend.

## 6. Recommended Architecture

For MVP, keep the bot inside the existing Go API deployment.

Why:

- the API already owns auth, DB, Redis, tunnel metadata, and `FRONTEND_URL`
- the repo does not include the full web frontend, so the backend should own the server-side linking logic
- one deployment is simpler than adding a second Go service immediately

Recommended shape:

```text
Telegram
  -> webhook -> Mekong API
                  -> Telegram command router
                  -> internal telegram service
                  -> DB + tunnel edge + existing domain/subdomain logic

User browser
  -> FRONTEND_URL/telegram-link?code=...
  -> Mekong login if needed
  -> approve link
  -> API stores telegram_chat_id -> user_id
```

Suggested packages and files:

- `internal/api/handlers/telegram.go`
- `internal/telegrambot/service.go`
- `internal/telegrambot/router.go`
- `internal/telegrambot/client.go`
- `internal/telegrambot/format.go`
- `internal/telegrambot/redact.go`
- `internal/telegrambot/store.go`
- `internal/tunnelsvc/service.go`
- `migrations/0xx_telegram_bot.sql`

## 7. Auth And Linking Flow

### Goal

Reuse the approval pattern of `mekong login` without forcing Telegram to become a login provider.

### Recommended flow

1. User sends `/link` to the Telegram bot.
2. Bot creates a `telegram_link_session`.
3. Bot replies with an approval URL such as:
   - `https://angkorsearch.dev/telegram-link?code=<opaque-code>`
4. User opens the page.
5. If the user is not logged in, the web app uses the normal Mekong login flow first.
6. After login, the page shows:
   - Telegram account label
   - Mekong account email
   - approve or cancel
7. Approval stores a durable `telegram_link`.
8. Bot confirms the link in Telegram.

### Why not reuse `cli_device_sessions` directly

- CLI device sessions are meant to return a one-time API token to a polling client.
- Telegram linking does not need to return a raw user token to Telegram.
- Telegram linking needs durable identity binding, unlink support, and account ownership checks.

## 8. Data Model

Add two new tables.

### `telegram_links`

Purpose: durable mapping between a Telegram private chat and a Mekong user.

Suggested columns:

- `id uuid primary key`
- `user_id uuid not null references users(id) on delete cascade`
- `telegram_chat_id bigint not null unique`
- `telegram_user_id bigint not null`
- `telegram_username text`
- `telegram_first_name text`
- `telegram_last_name text`
- `status text not null default 'active'`
- `linked_at timestamptz not null default now()`
- `last_seen_at timestamptz`
- `unlinked_at timestamptz`

Suggested rules:

- one Telegram private chat links to one Mekong account
- a user may re-link to a new Telegram chat, but old links should be revoked cleanly
- linked rows should remain auditable after unlink

### `telegram_link_sessions`

Purpose: short-lived browser approval sessions.

Suggested columns:

- `id uuid primary key`
- `code text not null unique`
- `telegram_chat_id bigint not null`
- `telegram_user_id bigint not null`
- `telegram_username text`
- `telegram_first_name text`
- `telegram_last_name text`
- `status text not null default 'pending'`
- `approved_user_id uuid references users(id)`
- `created_at timestamptz not null default now()`
- `expires_at timestamptz not null`
- `approved_at timestamptz`
- `cancelled_at timestamptz`

Suggested TTL:

- 10 to 15 minutes

## 9. API Changes In This Repo

Add new backend endpoints.

### Public Telegram webhook

- `POST /api/telegram/webhook`

Responsibilities:

- verify Telegram secret header
- parse updates
- accept only private chats for MVP
- route commands to the Telegram service

### Link session endpoints

- `POST /api/telegram/link/start`
  - internal use by the bot webhook handler
  - creates a session and returns `approve_url`
- `GET /api/telegram/link/session`
  - auth required
  - frontend page fetches session metadata for display
- `POST /api/telegram/link/approve`
  - auth required
  - binds the Telegram chat to the logged-in user
- `POST /api/telegram/link/cancel`
  - auth required
  - cancels a pending session
- `POST /api/telegram/unlink`
  - auth required
  - optional web-side unlink

### Internal refactor for tunnel access

Extract tunnel read logic out of `internal/api/handlers/tunnels.go` into a reusable package.

Suggested service:

- `internal/tunnelsvc/service.go`

Suggested methods:

- `ListUserTunnels(ctx, userID, status)`
- `ListUserLiveTunnels(ctx, userID)`
- `GetUserTunnelOverview(ctx, userID)`
- `GetRecentTunnelLogs(ctx, userID, tunnelID, teamID, limit)`

This avoids forcing the Telegram bot to fabricate JWT claims or call its own HTTP endpoints.

## 10. User Discovery And Onboarding

The bot should be easy to find from both Telegram and the public internet.

### Primary public entrypoint

Use a public landing URL:

- `https://mekongtunnel.dev/telegram`

That page should:

- explain what the bot does in one short paragraph
- show the bot name and username
- include an `Open in Telegram` button
- include a `Link your account` explanation
- show the main supported commands
- explain that the bot is read-only in v1

Recommended CTA links:

- `https://t.me/MekongTunnelBot`
- `https://t.me/MekongTunnelBot?start=link`

If `MekongTunnelBot` is unavailable, replace the username with the chosen fallback consistently everywhere.

### Make the bot easy to find

Add the bot in these places:

- README
- dashboard account page
- dashboard tunnels page
- dashboard domains page
- login success page
- docs/help pages
- footer or support menu on the website

Recommended labels:

- `Open Telegram Bot`
- `Manage in Telegram`
- `Get tunnel status in Telegram`

### Telegram-side discoverability

Make the Telegram profile easy to recognize:

- use the official MekongTunnel logo as the bot avatar
- keep the display name exactly `Mekong Tunnel`
- keep the username simple, ideally `MekongTunnelBot`
- set a clear description and about text in BotFather
- publish the command list in BotFather

### Suggested website copy

Short headline:

- `Mekong Tunnel on Telegram`

Short body:

- `Link your Mekong account and check active tunnels, recent logs, reserved subdomains, and domain status directly from Telegram.`

Short CTA:

- `Open @MekongTunnelBot`

### Suggested dashboard onboarding flow

Add a card in the dashboard:

- title: `Telegram Bot`
- body: `Link Telegram to check services and logs without opening the dashboard.`
- button: `Open Bot`

Suggested follow-up button after linking:

- `Send me updates in Telegram`

### Suggested CLI discovery later

Not required for MVP, but a future CLI hint would help discoverability:

- `mekong help telegram`

Possible help text:

- `Use the Telegram bot to view active services, recent logs, subdomains, and domains. Open https://mekongtunnel.dev/telegram`

### Deep-link recommendation

Prefer Telegram deep links when opening from the web:

- default open:
  - `https://t.me/MekongTunnelBot`
- start link flow:
  - `https://t.me/MekongTunnelBot?start=link`
- future feature-specific deep links:
  - `https://t.me/MekongTunnelBot?start=services`
  - `https://t.me/MekongTunnelBot?start=domains`

### MVP discoverability checklist

- choose final bot name and username
- create a clean bot avatar
- set BotFather description, about text, and commands
- add `mekongtunnel.dev/telegram`
- add `Open Telegram Bot` button in the dashboard
- add one README section with the public bot link

## 11. Telegram Command Set

### MVP commands

- `/start`
  - short intro + link status
- `/help`
  - show supported commands
- `/link`
  - start browser approval flow
- `/me`
  - show Mekong account email, plan, and linked status
- `/services`
  - list active tunnels
- `/logs <subdomain-or-id>`
  - show recent log lines only
- `/subdomains`
  - list reserved subdomains and limits
- `/domains`
  - list custom domains and status
- `/domain <host>`
  - show one domain's verification and readiness detail
- `/unlink`
  - unlink Telegram from the Mekong account

### Command behavior rules

- only work in private chats for MVP
- require a linked account for all commands except `/start`, `/help`, and `/link`
- use short, readable summaries instead of raw JSON
- use inline buttons for refresh and approve flows where useful

## 12. Log Handling Rules

Telegram is not a terminal. Log support should be limited.

Recommended v1 behavior:

- `/logs <service>` returns the last 20 to 40 lines
- truncate to Telegram message size limits
- redact likely secrets before sending
- never open a continuous stream in chat

Minimum redaction list:

- `Authorization: Bearer ...`
- `mkt_...` API tokens
- cookies
- passwords
- SMTP, GitHub, Google, Stripe, and Resend secrets

## 13. Security And Abuse Controls

### Required controls

- verify Telegram webhook secret token
- accept only private chat updates in MVP
- expire link sessions quickly
- rate-limit link creation by chat and IP
- rate-limit command spam by chat
- confirm account ownership in browser before binding
- reject commands for suspended users
- reject commands when the link is inactive

### Sensitive-action policy

For v1, keep the bot read-only.

Do not implement from Telegram yet:

- create token
- delete domain
- reserve subdomain
- clear history
- stop tunnel
- billing changes

Those can come later with explicit confirmation and browser re-approval.

## 14. Config And Runtime

Add these env vars to the API runtime.

- `TELEGRAM_BOT_TOKEN`
- `TELEGRAM_WEBHOOK_SECRET`
- `TELEGRAM_BOT_USERNAME`
- `TELEGRAM_BOT_NAME`
- `TELEGRAM_BOT_ENABLED`
- `TELEGRAM_APPROVE_PATH`

Suggested defaults:

- `TELEGRAM_BOT_NAME=Mekong Tunnel`
- `TELEGRAM_BOT_USERNAME=MekongTunnelBot`
- `TELEGRAM_BOT_ENABLED=false`
- `TELEGRAM_APPROVE_PATH=/telegram-link`

Wire these through:

- `cmd/api/main.go`
- `internal/api/config.go` or the existing API config struct
- `internal/api/server.go`

## 15. Frontend Dependency

This repo already assumes a web frontend exists outside this codebase for CLI approval via `FRONTEND_URL`.

Telegram should follow the same pattern:

- bot sends `FRONTEND_URL + "/telegram-link?code=<code>"`
- frontend page checks login
- frontend page calls auth-required API endpoints to fetch session and approve it

Required frontend page:

- `/telegram-link`

Required UI states:

- loading
- login required
- expired
- already linked
- approve
- success
- cancelled

## 16. Implementation Phases

### Phase 1: Data and link flow

- add migrations for `telegram_links` and `telegram_link_sessions`
- add link-session DB methods
- add API endpoints for start, session detail, approve, cancel, unlink
- add frontend approval page
- add public landing page or redirect at `mekongtunnel.dev/telegram`

Exit criteria:

- `/link` produces a valid approval URL
- browser approval links the Telegram chat to the right user

### Phase 2: Basic bot command router

- add Telegram webhook handler
- add command parsing for `/start`, `/help`, `/link`, `/me`
- add message send helper
- configure BotFather profile and commands

Exit criteria:

- linked users can verify account identity in Telegram

### Phase 3: Tunnel and domain read features

- extract tunnel read logic into `internal/tunnelsvc`
- add `/services`
- add `/logs <service>`
- add `/subdomains`
- add `/domains`
- add `/domain <host>`
- add dashboard `Open Telegram Bot` entrypoint

Exit criteria:

- a linked user can inspect their active tunnel and domain state without using the dashboard

### Phase 4: Notifications

- notify when a linked user's tunnel goes offline
- notify when a custom domain becomes verified
- notify when domain verification is still pending after a threshold

Exit criteria:

- bot can push useful status changes without user polling

## 17. Testing Plan

### Unit tests

- link session creation, expiry, approval, cancellation
- chat-to-user lookup
- command parsing
- log redaction
- Telegram message formatting and truncation

### Integration tests

- webhook secret verification
- `/link` flow from chat to browser approval
- account mismatch handling
- linked-user tunnel lookup
- linked-user domain lookup

### Manual QA

- create a real BotFather bot in a test Telegram account
- set webhook to staging
- verify private-chat-only behavior
- verify approval with logged-out and logged-in browser sessions
- verify unlink and re-link behavior

## 18. Rollout Plan

Roll out in this order:

1. deploy migrations and disabled code paths
2. enable link flow in staging
3. test with one internal bot
4. enable read-only commands
5. enable notifications later

Recommended production flag order:

- deploy code with `TELEGRAM_BOT_ENABLED=false`
- register webhook only after staging passes
- enable for internal users first

## 19. Open Questions

- Should one user be allowed to link multiple Telegram chats, or only one primary private chat?
- Should team admins be allowed to view team tunnel logs from Telegram, or only their own tunnels in v1?
- Should `/logs` resolve by tunnel ID, subdomain, or both?
- Should notifications be stored as user preferences in a separate table in phase 1 or phase 4?
- Is the Telegram approval page going into the existing external frontend repo or a minimal page in the current frontend app that already handles `cli-auth`?
- Is `MekongTunnelBot` available, or do we need to ship with `MekongControlBot`?

## 20. Recommended First Cut

Build the smallest useful release first:

- `/link`
- `/help`
- `/me`
- `/services`
- `/logs <service>`
- `/domains`
- `/subdomains`
- public landing page at `mekongtunnel.dev/telegram`
- dashboard `Open Telegram Bot` button

That gives the user the value they asked for:

- login with their own Mekong account
- see active services
- inspect recent logs
- check reserved subdomains and custom domains

It also stays aligned with the current Mekong architecture instead of inventing a second auth system.
