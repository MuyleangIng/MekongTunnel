# Mekong Tunnel Bot

Use the Mekong Tunnel Bot in Telegram to check your Mekong account, active tunnels, recent logs, reserved subdomains, and custom domains.

This bot is read-only. It does not start tunnels, stop tunnels, or change your account from Telegram.

Telegram works best when replies are short, easy to scan, and clearly show whether something is healthy, pending, or broken.

## Add the bot

1. Open Telegram.
2. Search for `@MekongTunnelBot` or open your deployed Mekong bot username.
3. Start a private chat with the bot.
4. Send `/start` or `/link`.

Note: the bot currently works in private chats only.

## Link your Mekong account

1. Send `/link`.
2. The bot replies with a secure approval link.
3. Open the link and sign in to your Mekong account if needed.
4. Approve the Telegram link request.
5. Return to Telegram and use `/help` to see the available commands.

Notes:

- The approval link expires in 10 minutes.
- If your Telegram account is already linked, use `/unlink` first before linking again.
- If your Mekong account is suspended, the bot will not return account data until the account is restored.

## Response design

Recommended response style for Telegram:

- keep the first line status-focused
- use short sections instead of long paragraphs
- show the service or domain name near the top
- highlight the current state with simple icons such as `🟢`, `🟡`, and `🔴`
- end with the next useful command when the user may need to investigate more

Good pattern:

```text
<status icon> <resource name>
Key detail 1
Key detail 2
Key detail 3

Next step: <recommended command>
```

## Commands

### `/start`

Starts the conversation with the bot.

- If your account is not linked yet, the bot asks you to use `/link`.
- If your account is already linked, the bot shows a welcome-back message.

Suggested reply template:

```text
Hi <first_name>!

Link your Mekong account to view active tunnels, logs, subdomains, and domain status.

Use /link to begin.
```

### `/help`

Shows the command list.

Suggested reply template:

```text
Mekong Tunnel Bot

Available commands:
/link
/me
/services
/logs <id>
/subdomains
/domains
/domain <host>
/unlink
/help
```

### `/link`

Starts the browser approval flow to connect Telegram to your Mekong account.

Suggested reply template:

```text
Open the link below to connect your Mekong account:

<approval_url>

This link expires in 10 minutes.
```

### `/me`

Shows your Mekong account summary, including:

- email
- email verification status
- plan
- account type

Suggested reply template:

```text
Your Mekong Account

Email: user@example.com
Status: verified
Plan: PRO
Account: PERSONAL
```

### `/services`

Lists your active tunnels.

Each result includes:

- subdomain
- local port
- request count

Suggested reply template:

```text
Active Tunnels (2)

🟢 myapp
Port: 3000 | Requests: 1284

🟢 admin
Port: 8080 | Requests: 214
```

For monitoring, this should be the easiest command to scan quickly.

Recommended order:

- status icon
- subdomain
- local port
- request count

If you later want a richer version, add:

- last seen time
- current custom domain
- local service health

### `/logs <subdomain-or-id>`

Shows the most recent tunnel logs for one active tunnel.

Examples:

```text
/logs myapp
/logs tun_123
```

Notes:

- You can use either the tunnel subdomain or the tunnel ID.
- Logs are only available for active tunnels.
- The bot returns up to the last 20 log lines.
- Known secrets such as bearer tokens, cookies, API keys, and passwords are redacted before logs are sent to Telegram.

Suggested reply template:

```text
Recent logs: myapp

[2026-04-08 09:12:01] GET / 200
[2026-04-08 09:12:04] GET /api/health 200
[2026-04-08 09:12:10] GET /login 500
[2026-04-08 09:12:10] error=database timeout
```

For Telegram, plain text is better than a very long formatted block. The user should be able to copy, scan, and forward it easily.

### `/subdomains`

Lists your reserved subdomains.

Suggested reply template:

```text
Reserved Subdomains (3)

- myapp
- admin
- preview-team
```

### `/domains`

Lists your custom domains and their current status.

Common statuses include:

- `verified`
- `active`
- `pending`
- `failed`

Suggested reply template:

```text
Custom Domains (3)

✅ app.example.com - active
⏳ api.example.com - pending
❌ admin.example.com - failed
```

This command should feel like a quick health board for domain monitoring.

### `/domain <hostname>`

Shows details for one custom domain.

Example:

```text
/domain app.example.com
```

The bot can show:

- current status
- target subdomain
- verification time
- created time

Suggested reply template:

```text
Domain: app.example.com

Status: ✅ active
Target: myapp
Verified: Tue, 08 Apr 2026 09:20:00 KST
Added: Tue, 01 Apr 2026 14:10:00 KST
```

If the domain is broken, this command should make the problem obvious immediately.

### `/unlink`

Disconnects your Telegram chat from your Mekong account.

After unlinking, account commands such as `/me`, `/services`, `/logs`, `/subdomains`, and `/domains` will stop working until you link again.

Suggested reply template:

```text
Your Telegram account has been unlinked from Mekong.
```

## Automatic alerts

The Telegram bot now sends automatic monitoring alerts to linked Telegram users.

Current alert behavior:

- tunnel status changed to `stopped` or `inactive` -> tunnel down alert
- tunnel status changed to `failed` or `error` -> tunnel issue alert
- tunnel status changed back to `active` -> tunnel recovered alert
- custom domain created -> domain pending alert
- custom domain verification passed but HTTPS is still not ready -> domain pending alert
- custom domain verification failed -> domain failed alert
- custom domain verification passed and HTTPS is ready -> domain ready alert
- custom domain target changed -> domain updated alert

Who receives alerts:

- personal tunnel alerts go to the linked Telegram account for that Mekong user
- personal domain alerts go to the linked Telegram account for that Mekong user
- team-owned domain alerts go to linked Telegram accounts for the team owner, admins, and teachers
- admin-triggered tunnel and domain changes use the same Telegram alert flow

Note: alerts are only delivered when the recipient has already linked Telegram to their Mekong account.

### Tunnel down alert

```text
🔴 Tunnel Down

Service: myapp
Last known port: 3000
Issue: tunnel is no longer active

Check: /services
Then: /logs myapp
```

### Tunnel issue alert

```text
🟡 Tunnel Issue

Service: myapp
Recent symptom: status changed to failed

Check: /services
Then: /logs myapp
```

### Domain pending alert

```text
🟡 Domain Pending

Domain: app.example.com
Status: pending
Reason: DNS or HTTPS setup is not complete yet

Check: /domain app.example.com
```

### Domain failed alert

```text
🔴 Domain Failed

Domain: app.example.com
Status: failed
Reason: verification did not pass

Check: /domain app.example.com
```

### Domain ready alert

```text
✅ Domain Ready

Domain: app.example.com
Target: myapp
Status: verified and HTTPS is ready

Check: /domain app.example.com
```

### Domain updated alert

```text
🟡 Domain Updated

Domain: app.example.com
Target: myapp
Status: route updated

Check: /domain app.example.com
```

### Tunnel recovered alert

```text
🟢 Tunnel Recovered

Service: myapp
Status: active again

Check: /services
```

### Link approved message

```text
✅ Your Telegram account is now linked to <name or email>.

Use /services to check active tunnels or /help to see all commands.
```

### Account suspended message

```text
Your Mekong account is suspended.

Manage your account in the dashboard to restore Telegram access.
```

## Quick command list

```text
/link - Link Telegram to your Mekong account
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

### The bot says my account is not linked

Send `/link` and complete the approval step in your browser.

### The bot says no tunnel was found

Run `/services` first, then use one of the active tunnel subdomains or IDs with `/logs`.

### `/logs` does not return anything

Logs are only available for active tunnels, and some tunnels may not have recent log lines yet.

### I want to connect a different Mekong account

Send `/unlink`, then run `/link` again and approve with the correct Mekong account.
