# New Server Setup Guide — MekongTunnel

> Open Source by **KhmerStack**
> Author: Ing Muyleang (អុឹង មួយលៀង) — Ing_Muyleang

Complete step-by-step guide to deploy MekongTunnel on a fresh Ubuntu/Debian VPS
with your own domain (e.g. `muyleanging.com`).

---

## What You Need Before Starting

- A VPS or dedicated server (Ubuntu 22.04 LTS recommended) with a public IP
- A domain name that you control (e.g. `muyleanging.com`)
- SSH access to the server as root or a sudo user
- 15–30 minutes

---

## Step 1 — Point DNS to Your Server

In your domain registrar or DNS provider, add two **A records**:

| Type | Name | Value | TTL |
|------|------|-------|-----|
| A | `@` (or `muyleanging.com`) | `YOUR_SERVER_IP` | 300 |
| A | `*` (wildcard) | `YOUR_SERVER_IP` | 300 |

The wildcard record (`*.muyleanging.com`) is required so that
`happy-tiger-a1b2c3d4.muyleanging.com` routes to your server.

> Wait 2–5 minutes for DNS to propagate before the next step.
> Test with: `dig muyleanging.com` and `dig test.muyleanging.com`

---

## Step 2 — Prepare the Server

```bash
# Connect to your server
ssh root@YOUR_SERVER_IP

# Update packages
apt update && apt upgrade -y

# Install required tools
apt install -y docker.io docker-compose-plugin git curl certbot ufw

# Enable Docker
systemctl enable --now docker

# Add your user to docker group (optional, so you don't need sudo)
usermod -aG docker $USER
```

---

## Step 3 — Configure the Firewall

```bash
# Allow SSH on a non-standard port (we'll move sshd off port 22)
ufw allow 2222/tcp   # your server's own SSH (new port)
ufw allow 22/tcp     # MekongTunnel SSH port
ufw allow 80/tcp     # HTTP
ufw allow 443/tcp    # HTTPS
ufw enable

# Verify
ufw status
```

---

## Step 4 — Move Your Server SSH to Port 2222

MekongTunnel needs port 22. Move your server's own `sshd` first.

```bash
nano /etc/ssh/sshd_config
```

Find the line `#Port 22` and change it to:

```
Port 2222
```

Then restart and verify — **open a new terminal on port 2222 BEFORE closing this session**:

```bash
systemctl restart sshd

# In a NEW terminal window:
ssh -p 2222 root@YOUR_SERVER_IP
# If this works, it's safe to close the old terminal
```

---

## Step 5 — Get a Wildcard TLS Certificate

```bash
# Run certbot in manual DNS challenge mode
certbot certonly --manual --preferred-challenges dns \
  -d muyleanging.com \
  -d '*.muyleanging.com'
```

Certbot will pause and ask you to add a TXT DNS record like:

```
_acme-challenge.muyleanging.com   TXT   "some-long-string-here"
```

Add that TXT record in your DNS provider, wait ~60 seconds, then press Enter in certbot.

When done, certbot saves certs to:
```
/etc/letsencrypt/live/muyleanging.com/fullchain.pem
/etc/letsencrypt/live/muyleanging.com/privkey.pem
```

---

## Step 6 — Clone and Configure MekongTunnel

```bash
cd /opt
git clone https://github.com/Ing-Muyleang/MekongTunnel.git
cd MekongTunnel

# Create your .env from the template
cp .env.example .env
nano .env
```

Fill in your `.env`:

```env
DOMAIN=muyleanging.com

SSH_ADDR=:22
HTTP_ADDR=:80
HTTPS_ADDR=:443
STATS_ADDR=127.0.0.1:9090

HOST_KEY_PATH=/host_key

TLS_CERT=/certs/fullchain.pem
TLS_KEY=/certs/privkey.pem
```

Save and exit (`Ctrl+X`, then `Y`, then `Enter`).

---

## Step 7 — Copy TLS Certificates

```bash
mkdir -p /opt/MekongTunnel/data/certs

cp /etc/letsencrypt/live/muyleanging.com/fullchain.pem /opt/MekongTunnel/data/certs/
cp /etc/letsencrypt/live/muyleanging.com/privkey.pem   /opt/MekongTunnel/data/certs/

chown -R $USER:$USER /opt/MekongTunnel/data/certs
chmod 600 /opt/MekongTunnel/data/certs/privkey.pem
```

---

## Step 8 — Start MekongTunnel

```bash
cd /opt/MekongTunnel

# Build and start in background
docker compose up -d

# Check it started correctly
docker compose ps
docker compose logs -f
```

Expected output:
```
mekongtunnel  |  SSH server listening on :22
mekongtunnel  |  HTTP server listening on :80 (redirects to HTTPS)
mekongtunnel  |  HTTPS server listening on :443
mekongtunnel  |  Stats server listening on 127.0.0.1:9090
```

---

## Step 9 — Test the Tunnel

From your **local machine** (not the server):

```bash
# Start a test local server
python3 -m http.server 9000

# Open a tunnel (in a new terminal)
ssh -t -R 80:localhost:9000 muyleanging.com

# You'll see:
# Connected to muyleanging.com.
# Tunnel is live!
# Public URL: https://happy-tiger-a1b2c3d4.muyleanging.com
```

Open `https://happy-tiger-a1b2c3d4.muyleanging.com` in a browser — you should see the Python HTTP server listing.

---

## Step 10 — Auto-Renew TLS Certificates

Create a renewal script:

```bash
nano /opt/MekongTunnel/renew-certs.sh
```

```bash
#!/bin/bash
# Renew Let's Encrypt wildcard certificate and update MekongTunnel

set -e

DOMAIN="muyleanging.com"
CERT_DIR="/opt/MekongTunnel/data/certs"

# Renew (will prompt for DNS challenge again with --manual)
# For fully automated renewal, use a DNS plugin instead:
#   apt install python3-certbot-dns-cloudflare  (if using Cloudflare)
certbot renew --quiet

# Copy renewed certs
cp /etc/letsencrypt/live/$DOMAIN/fullchain.pem $CERT_DIR/
cp /etc/letsencrypt/live/$DOMAIN/privkey.pem   $CERT_DIR/
chmod 600 $CERT_DIR/privkey.pem

# Restart MekongTunnel to pick up new certs
cd /opt/MekongTunnel
docker compose restart

echo "Certificate renewed and MekongTunnel restarted."
```

```bash
chmod +x /opt/MekongTunnel/renew-certs.sh
```

Add to crontab (runs on the 1st of every month at 3am):

```bash
crontab -e
```

```
0 3 1 * * /opt/MekongTunnel/renew-certs.sh >> /var/log/mekongtunnel-cert-renew.log 2>&1
```

---

## Monitoring & Management

### Check server status

```bash
docker compose ps
docker compose logs --tail=50
```

### View live metrics

```bash
curl http://127.0.0.1:9090/
curl "http://127.0.0.1:9090/?subdomains=true"
```

### Restart after config change

```bash
cd /opt/MekongTunnel
docker compose restart
```

### Update to new version

```bash
cd /opt/MekongTunnel
git pull
docker compose down
docker compose up -d --build
```

### Stop the service

```bash
docker compose down
```

---

## Troubleshooting

### "Connection refused" on port 22

```bash
# Check MekongTunnel is running
docker compose ps

# Check port 22 is open
ss -tlnp | grep :22

# Check firewall
ufw status
```

### "Host key verification failed"

First connection always prompts to accept the host key:

```
Are you sure you want to continue connecting (yes/no)? yes
```

### "No tunnel URL shown"

The `-t` flag is required:

```bash
# Wrong
ssh -R 80:localhost:8080 muyleanging.com

# Correct
ssh -t -R 80:localhost:8080 muyleanging.com
```

### TLS certificate errors

```bash
# Check certs are in place
ls -la /opt/MekongTunnel/data/certs/

# Check cert validity
openssl x509 -in /opt/MekongTunnel/data/certs/fullchain.pem -noout -dates
```

### View logs for specific errors

```bash
docker compose logs mekongtunnel | grep -i "error\|fail\|warn"
```

---

## Backup

The only persistent data is:

| Path | What it is | How to backup |
|------|-----------|---------------|
| `/opt/MekongTunnel/data/host_key` | SSH host key | Copy this file. If lost, clients will see a host key mismatch warning on next connect. |
| `/opt/MekongTunnel/data/certs/` | TLS certificates | Back up or just re-run certbot. |
| `/opt/MekongTunnel/.env` | Your config | Back up securely. |

```bash
# Simple backup
tar -czf mekongtunnel-backup-$(date +%Y%m%d).tar.gz \
  /opt/MekongTunnel/data/host_key \
  /opt/MekongTunnel/data/certs/ \
  /opt/MekongTunnel/.env
```

---

## Quick Reference Card

```
Domain:    muyleanging.com
Server:    YOUR_SERVER_IP
SSH port:  22  (MekongTunnel)  /  2222  (your server access)
HTTP:      80
HTTPS:     443
Stats:     127.0.0.1:9090  (localhost only)

Deploy:    cd /opt/MekongTunnel && docker compose up -d
Logs:      docker compose logs -f
Stats:     curl http://127.0.0.1:9090/
Renew:     /opt/MekongTunnel/renew-certs.sh

Connect:   ssh -t -R 80:localhost:PORT muyleanging.com
```
