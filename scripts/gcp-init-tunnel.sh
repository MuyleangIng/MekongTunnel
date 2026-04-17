#!/usr/bin/env bash
# ============================================================
#  scripts/gcp-init-tunnel.sh — First-time setup for VM 1
#  (Tunnel Server) on GCP
#
#  Usage:
#    ./scripts/gcp-init-tunnel.sh
#
#  What it does:
#    1. SSH into tunnel-server VM
#    2. Install Caddy (reverse proxy + auto SSL)
#    3. Create app directories
#    4. Configure Caddy for proxy.mekongtunnel.dev wildcard
#
#  Run this ONCE before first deploy.
# ============================================================
set -euo pipefail

REMOTE_HOST="${REMOTE_HOST:-muyleanging@34.158.38.176}"
REMOTE_SSH_PORT="${REMOTE_SSH_PORT:-2222}"
WILDCARD_DOMAIN="${WILDCARD_DOMAIN:-proxy.mekongtunnel.dev}"
SSH_OPTS=(-p "${REMOTE_SSH_PORT}" -o StrictHostKeyChecking=accept-new)

remote() {
  ssh "${SSH_OPTS[@]}" "${REMOTE_HOST}" "$@"
}

echo ""
echo "  ▶  Initialising tunnel-server (${REMOTE_HOST}) ..."

remote "sudo bash -s" <<'SETUP'
set -euo pipefail

echo "  ▶  Updating system ..."
apt-get update -qq && apt-get upgrade -y -qq

echo "  ▶  Moving sshd to port 2222 (port 22 reserved for tunnel users) ..."
sed -i 's/^#\?Port 22$/Port 2222/' /etc/ssh/sshd_config
grep -q '^Port 2222$' /etc/ssh/sshd_config || echo 'Port 2222' >> /etc/ssh/sshd_config
systemctl restart ssh

echo "  ▶  Installing Caddy ..."
apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https curl
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
apt-get update -qq && apt-get install -y -qq caddy

echo "  ▶  Creating app directories ..."
mkdir -p /opt/mekongtunnel/data/certs
mkdir -p /opt/mekong/uploads

echo "  ▶  Writing Caddyfile ..."
cat > /etc/caddy/Caddyfile <<'EOF'
proxy.mekongtunnel.dev, *.proxy.mekongtunnel.dev {
    reverse_proxy https://127.0.0.1:8443 {
        transport http {
            tls
            tls_insecure_skip_verify
        }
        header_up Host {host}
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-For {remote_host}
        header_up X-Forwarded-Proto https
    }
}
EOF

echo "  ▶  Enabling and starting Caddy ..."
systemctl enable caddy
systemctl restart caddy

echo "  ✅  Tunnel server init complete"
SETUP

echo "  ✅  Done — tunnel-server is ready for deploy"
echo "      Next: ./scripts/gcp-deploy-tunnel.sh"
echo ""
