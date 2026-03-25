# MekongTunnel Production Setup

> Current production layout:
> `angkorsearch.dev` = web UI
> `api.angkorsearch.dev` = REST API
> `proxy.angkorsearch.dev` = tunnel SSH + HTTPS entrypoint
> `*.proxy.angkorsearch.dev` = generated public tunnel URLs
> `*.mekongtunnel.dev` = optional branded custom-domain wildcard

## Docs Map

- [`README.md`](./README.md): quick start and developer-facing overview
- [`HANDBOOK.md`](./HANDBOOK.md): architecture, API surface, and release notes
- [`SETUP.md`](./SETUP.md): production DNS, TLS, deploy, and verification

## Recommended Production Model

Use three separate concerns:

1. UI on `angkorsearch.dev`
2. API on `api.angkorsearch.dev`
3. Tunnel edge on `proxy.angkorsearch.dev`

The repo now supports:

- reserved subdomains: `mekong reserve myapp`
- one-step custom domains: `mekong domain connect app.example.com myapp`
- branded wildcard domains such as `app.mekongtunnel.dev`

The preferred deployment flow is:

```bash
./scripts/deploy-api.sh
./scripts/deploy-tunnel.sh
WILDCARD_DOMAIN=mekongtunnel.dev ./scripts/deploy-tunnel.sh   # optional branded wildcard
```

`update.sh` is still supported, but only for a git checkout that already exists on the proxy host.

---

## 1. DNS

Keep your existing UI/API records if they already work:

| Type | Name | Value |
|------|------|-------|
| A / CNAME | `angkorsearch.dev` | your frontend host |
| A / CNAME | `api.angkorsearch.dev` | your API host |

Point the tunnel edge to the proxy server:

| Type | Name | Value |
|------|------|-------|
| A | `proxy.angkorsearch.dev` | `YOUR_PROXY_SERVER_IP` |
| A | `*.proxy.angkorsearch.dev` | `YOUR_PROXY_SERVER_IP` |

Optional branded wildcard:

| Type | Name | Value |
|------|------|-------|
| CNAME | `*.mekongtunnel.dev` | `proxy.angkorsearch.dev` |

Quick checks:

```bash
dig +short proxy.angkorsearch.dev
dig +short test.proxy.angkorsearch.dev
dig +short app.mekongtunnel.dev
```

---

## 2. Proxy Host Preparation

Run on the tunnel/proxy server:

```bash
apt update && apt upgrade -y
apt install -y nginx certbot ufw openssl
```

Open the required ports:

```bash
ufw allow 2222/tcp   # server admin SSH
ufw allow 22/tcp     # Mekong tunnel SSH
ufw allow 80/tcp
ufw allow 443/tcp
ufw enable
ufw status
```

Move your server's own SSH to `2222` so MekongTunnel can own port `22`:

```bash
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
grep -q '^Port 2222$' /etc/ssh/sshd_config || echo 'Port 2222' >> /etc/ssh/sshd_config
systemctl disable --now ssh.socket || true
systemctl enable ssh.service
systemctl restart ssh.service
```

From a second terminal, verify before closing your original session:

```bash
ssh -p 2222 root@proxy.angkorsearch.dev
```

---

## 3. TLS Certificates

### Tunnel wildcard

Issue the certificate that covers the proxy entrypoint and generated tunnel URLs:

```bash
certbot certonly --manual --preferred-challenges dns \
  -d proxy.angkorsearch.dev \
  -d '*.proxy.angkorsearch.dev'
```

### Optional branded wildcard

If you want browser-secure branded custom domains like `app.mekongtunnel.dev`, issue a second wildcard cert:

```bash
certbot certonly --manual --preferred-challenges dns \
  -d mekongtunnel.dev \
  -d '*.mekongtunnel.dev'
```

Expected certificate paths:

```bash
/etc/letsencrypt/live/proxy.angkorsearch.dev/fullchain.pem
/etc/letsencrypt/live/proxy.angkorsearch.dev/privkey.pem
/etc/letsencrypt/live/mekongtunnel.dev/fullchain.pem
/etc/letsencrypt/live/mekongtunnel.dev/privkey.pem
```

Important:

- manual DNS challenge certs do not auto-renew cleanly by themselves
- if you need unattended renewal, move to a DNS plugin or an ACME edge such as Caddy

---

## 4. Local `.env.prod`

`./scripts/deploy-tunnel.sh` uploads your local [`.env.prod`](./.env.prod) to the proxy host as `/opt/mekongtunnel/.env.prod`.

Minimum tunnel-side values:

```env
DOMAIN=proxy.angkorsearch.dev
SSH_ADDR=:22
HTTP_ADDR=127.0.0.1:8081
HTTPS_ADDR=127.0.0.1:8443
STATS_ADDR=127.0.0.1:9090
HOST_KEY_PATH=/opt/mekongtunnel/host_key
TLS_CERT=/etc/letsencrypt/live/proxy.angkorsearch.dev/fullchain.pem
TLS_KEY=/etc/letsencrypt/live/proxy.angkorsearch.dev/privkey.pem
DATABASE_URL=postgres://USER:PASS@HOST:5432/DB?sslmode=disable
```

Notes:

- `HTTP_ADDR` and `HTTPS_ADDR` stay on loopback because nginx terminates public `80/443`
- `DATABASE_URL` must be valid if you want reserved subdomains and custom domains
- `./scripts/deploy-api.sh` does not manage API secrets; it only updates the API binary and restarts the service

---

## 5. Deploy Commands

Run from your local repo:

```bash
./scripts/deploy-api.sh
./scripts/deploy-tunnel.sh
```

If you also issued the branded wildcard certificate:

```bash
WILDCARD_DOMAIN=mekongtunnel.dev ./scripts/deploy-tunnel.sh
```

What the scripts do:

- `deploy-api.sh`: build `cmd/api`, upload to the API host over SSH `:2222`, restart `mekong-api`, verify `/api/health`, `/api/cli/subdomains`, and `/api/cli/domains`
- `deploy-tunnel.sh`: build `cmd/mekongtunnel`, upload `.env.prod`, install `/etc/systemd/system/mekongtunnel.service`, restart it, verify ports, and optionally install the branded wildcard nginx vhost

Optional server-side git workflow:

```bash
cd /opt/mekongtunnel
./update.sh
```

Use `update.sh` only when `/opt/mekongtunnel` is already a git checkout.

---

## 6. Verify the Proxy Host

On the proxy host:

```bash
ss -tlnp | egrep ':22|:2222|:8081|:8443|:9090'
systemctl status mekongtunnel.service --no-pager
journalctl -u mekongtunnel.service -n 50 --no-pager
```

Expected:

- `sshd` on `:2222`
- `mekongtunnel` on `:22`
- `mekongtunnel` on `127.0.0.1:8081`
- `mekongtunnel` on `127.0.0.1:8443`
- `mekongtunnel` on `127.0.0.1:9090`

---

## 7. Verify the CLI

On your local machine:

```bash
mekong version
mekong doctor
mekong subdomains
```

Expected `mekong doctor` checks:

- DNS resolves `proxy.angkorsearch.dev`
- SSH port `22` reachable
- API health on `https://api.angkorsearch.dev/api/health`
- saved credentials and token validation if logged in

---

## 8. Reserved Subdomain Flow

```bash
mekong login
mekong reserve myapp
mekong 3000 --subdomain myapp
```

Useful commands:

```bash
mekong subdomains
mekong status
mekong delete myapp
```

---

## 9. Custom Domain Flow

### Recommended one-step command

```bash
mekong domain connect app.example.com myapp
```

This command:

1. creates the custom-domain record if needed
2. points the domain at the reserved subdomain
3. keeps checking until DNS verifies
4. waits until HTTPS is ready
5. prints the active error or waiting stage if DNS / HTTPS is still pending

### Manual flow

```bash
mekong domain add app.example.com
mekong domain verify app.example.com
mekong domain target app.example.com myapp
mekong domain wait app.example.com
mekong doctor app.example.com
```

If DNS is not ready, the CLI prints the required records:

- apex/root domains such as `example.com`: `A/AAAA @ -> same IPs as proxy.angkorsearch.dev`
- subdomains such as `app.example.com`: `CNAME app -> proxy.angkorsearch.dev`
- TXT fallback: `_mekongtunnel-verify.app.example.com -> mekong-verify=...`

Rule of thumb:

- if the user enters the main domain, show `A` / `AAAA`
- if the user enters a subdomain, show `CNAME`
- if the DNS provider does not accept short names such as `@` or `app`, enter the full host instead
- invalid names such as `ttt..example.com` are rejected before the record is created

Delete behavior:

- `mekong domain delete app.example.com` removes the MekongTunnel mapping only
- DNS records at the provider are not changed automatically
- if the hostname is covered by a shared wildcard or another existing certificate, TLS may still validate, but the hostname will no longer route to the deleted MekongTunnel app
- to fully disconnect the hostname, remove or change the DNS record at the provider
- the user API and admin API now return the same cleanup guidance on delete so dashboards can explain this clearly

---

## 10. Branded `mekongtunnel.dev` Domains

After the wildcard DNS and wildcard certificate exist, branded domains such as `app.mekongtunnel.dev` work like this:

```bash
mekong reserve myapp
mekong domain connect app.mekongtunnel.dev myapp
mekong 3000 --subdomain myapp
```

Validation:

```bash
mekong doctor app.mekongtunnel.dev
curl -I https://app.mekongtunnel.dev
```

If HTTPS fails with `ERR_CERT_COMMON_NAME_INVALID`, nginx is still serving the wrong certificate on `443`.

---

## 11. Maintenance

API redeploy:

```bash
./scripts/deploy-api.sh
```

Tunnel redeploy:

```bash
./scripts/deploy-tunnel.sh
```

Branded wildcard redeploy:

```bash
WILDCARD_DOMAIN=mekongtunnel.dev ./scripts/deploy-tunnel.sh
```

Server-side update for git checkouts:

```bash
cd /opt/mekongtunnel
./update.sh
```

---

## 12. Troubleshooting

### `ssh: unable to authenticate`

Your proxy host still has normal `sshd` listening on port `22`. Fix the split:

- server admin SSH on `2222`
- MekongTunnel on `22`

### `nothing is listening on localhost:PORT`

Start your local app first, then run:

```bash
mekong 3000
```

### `reserved subdomain "myapp" is already active`

Another tunnel is still using it:

```bash
mekong status
mekong stop 3000
```

### Custom domain stays `pending_dns`

Recheck DNS:

```bash
dig +short app.example.com
dig +short _mekongtunnel-verify.app.example.com TXT
mekong doctor app.example.com
```

For root domains, also compare the proxy IPs directly:

```bash
dig +short proxy.angkorsearch.dev
dig +short app.example.com
```

### Custom domain stays `pending_https`

DNS is correct but the certificate or nginx vhost is wrong. Check:

```bash
openssl s_client -connect app.example.com:443 -servername app.example.com </dev/null 2>/dev/null | openssl x509 -noout -subject -ext subjectAltName
```

The certificate must cover the hostname you are testing.
