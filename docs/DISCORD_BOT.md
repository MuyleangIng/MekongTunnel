# Mekong Tunnel Discord Bot

Status: Draft user documentation for a Discord bot that matches the Telegram bot experience.

Use the Mekong Tunnel Discord Bot to monitor your Mekong account, active tunnels, recent logs, reserved subdomains, and custom domains from Discord.

This bot should stay read-only. It is best used for monitoring and quick checks, not for starting tunnels or making destructive changes.

## What it is for

The Discord bot is a chat-based monitoring companion for Mekong.

Recommended use cases:

- check whether your tunnel is active
- see which subdomain is live
- inspect recent logs when something breaks
- verify custom-domain status
- quickly confirm account and plan details

## Add the bot

1. Open the Discord bot invite link.
2. Add the bot to your Discord server or open a direct message with it.
3. Use slash commands such as `/link` or `/help`.

Recommended behavior:

- personal account data should be shown only in DMs or ephemeral replies
- monitoring commands in shared servers should avoid exposing secrets
- log output should always be redacted before sending replies

## Link your Mekong account

1. Run `/link`.
2. The bot replies with a secure approval link.
3. Open the link and sign in to your Mekong account if needed.
4. Approve the Discord link request.
5. Return to Discord and run `/help`.

Notes:

- The approval link should expire after a short time, such as 10 minutes.
- One Discord user should map to one Mekong account at a time.
- If the account is already linked, the user should unlink first before linking again.
- Suspended Mekong accounts should not receive account data from the bot.

## Commands

The recommended Discord command set should mirror the Telegram bot for consistency.

### `/help`

Shows the command list.

### `/link`

Starts the browser approval flow to connect Discord to your Mekong account.

### `/me`

Shows your Mekong account summary, including:

- email
- email verification status
- plan
- account type

### `/services`

Lists your active tunnels.

Each result should include:

- subdomain
- local port
- request count
- tunnel status

This is the main monitoring command for quickly checking what is live.

### `/logs <subdomain-or-id>`

Shows the most recent logs for one active tunnel.

Examples:

```text
/logs myapp
/logs tun_123
```

Recommended behavior:

- accept either the tunnel subdomain or the tunnel ID
- return only recent lines, not full streaming logs
- limit the response to a small safe window such as the last 20 lines
- redact bearer tokens, cookies, passwords, API keys, and other secrets before sending

This command is useful when the tunnel is up but the local app is failing.

### `/subdomains`

Lists your reserved subdomains.

Useful for checking which names are available for reuse or already assigned to your account.

### `/domains`

Lists your custom domains and their current status.

Recommended statuses:

- `verified`
- `active`
- `pending`
- `failed`

This command is useful for DNS and HTTPS monitoring.

### `/domain <hostname>`

Shows details for one custom domain.

Example:

```text
/domain app.example.com
```

Recommended details:

- current status
- target subdomain
- verification time
- created time

This is the most useful domain monitoring command when a single hostname is failing.

### `/unlink`

Disconnects your Discord account from your Mekong account.

After unlinking, monitoring commands should stop working until the user links again.

## Monitoring flow

A simple Discord monitoring flow should look like this:

1. Run `/services` to see which tunnels are active.
2. If one service looks wrong, run `/logs <subdomain-or-id>`.
3. If the issue is domain-related, run `/domains` or `/domain <hostname>`.
4. If account access looks wrong, run `/me`.

This keeps Discord focused on fast operational checks instead of full dashboard management.

## Quick command list

```text
/link - Link Discord to your Mekong account
/me - Show your account info
/services - List active tunnels
/logs <id> - Show recent logs
/subdomains - List reserved subdomains
/domains - List custom domains
/domain <host> - Check one domain
/unlink - Unlink from your account
/help - Show help
```

## Troubleshooting

### The bot says the account is not linked

Run `/link` and complete the approval step in your browser.

### The bot cannot find a tunnel

Run `/services` first, then use one of the active tunnel subdomains or IDs with `/logs`.

### The logs reply is empty

Logs should only be available for active tunnels, and some tunnels may not have recent lines yet.

### A domain looks broken

Run `/domain <hostname>` to inspect the exact host status, then check DNS and HTTPS in the Mekong dashboard if needed.

## Product note

For users, Discord and Telegram serve the same general purpose: quick monitoring and account lookups from chat.

Recommended positioning:

- Telegram is better for direct personal chat usage
- Discord is better for shared team monitoring in a server
- both should share the same core commands and link flow
