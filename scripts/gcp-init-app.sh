#!/usr/bin/env bash
# ============================================================
#  scripts/gcp-init-app.sh — First-time setup for VM 2
#  (App Server: API + Postgres + Next.js) on GCP
#
#  Usage:
#    ./scripts/gcp-init-app.sh
#
#  What it does:
#    1. SSH into app-server VM
#    2. Install Postgres 16, Node.js 20, Caddy
#    3. Create database + user
#    4. Configure Caddy for mekongtunnel.dev + api.mekongtunnel.dev
#    5. Create app directories
#
#  Run this ONCE before first deploy.
# ============================================================
set -euo pipefail

REMOTE_HOST="${REMOTE_HOST:-muyleanging@34.21.139.140}"
REMOTE_SSH_PORT="${REMOTE_SSH_PORT:-22}"
DB_NAME="${DB_NAME:-mekongdb}"
DB_USER="${DB_USER:-mekong}"
DB_PASS="${DB_PASS:-mekong2026}"
SSH_OPTS=(-p "${REMOTE_SSH_PORT}" -o StrictHostKeyChecking=accept-new)

remote() {
  ssh "${SSH_OPTS[@]}" "${REMOTE_HOST}" "$@"
}

echo ""
echo "  ▶  Initialising app-server (${REMOTE_HOST}) ..."

remote "sudo bash -s" <<SETUP
set -euo pipefail

echo "  ▶  Updating system ..."
apt-get update -qq && apt-get upgrade -y -qq


echo "  ▶  Installing Postgres 16 ..."
apt-get install -y -qq postgresql postgresql-contrib
systemctl enable postgresql
systemctl start postgresql

echo "  ▶  Creating database and user ..."
sudo -u postgres psql -c "CREATE USER ${DB_USER} WITH PASSWORD '${DB_PASS}';" 2>/dev/null || true
sudo -u postgres psql -c "CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};" 2>/dev/null || true
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER};" 2>/dev/null || true

echo "  ▶  Installing Redis ..."
apt-get install -y -qq redis-server
systemctl enable redis-server
systemctl start redis-server

echo "  ▶  Installing Node.js 20 ..."
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt-get install -y -qq nodejs
npm install -g pm2

echo "  ▶  Installing Caddy ..."
apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https curl
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
apt-get update -qq && apt-get install -y -qq caddy

echo "  ▶  Writing Caddyfile ..."
cat > /etc/caddy/Caddyfile <<'EOF'
mekongtunnel.dev, www.mekongtunnel.dev {
    reverse_proxy localhost:3000
}

api.mekongtunnel.dev {
    reverse_proxy localhost:8080
}
EOF

echo "  ▶  Creating app directories ..."
mkdir -p /opt/mekong/api
mkdir -p /opt/mekong/uploads
mkdir -p /opt/mekong/frontend

echo "  ▶  Enabling and starting Caddy ..."
systemctl enable caddy
systemctl restart caddy

echo "  ✅  App server init complete"
SETUP

echo "  ✅  Done — app-server is ready for deploy"
echo "      Next: ./scripts/gcp-deploy-api.sh"
echo "            ./scripts/gcp-deploy-frontend.sh"
echo ""
