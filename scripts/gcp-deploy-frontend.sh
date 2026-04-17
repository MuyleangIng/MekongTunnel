#!/usr/bin/env bash
# ============================================================
#  scripts/gcp-deploy-frontend.sh — Build and deploy the
#  Next.js frontend to GCP VM 2 (app-server)
#
#  Usage:
#    ./scripts/gcp-deploy-frontend.sh
#    FRONTEND_DIR=/path/to/frontend ./scripts/gcp-deploy-frontend.sh
#
#  What it does:
#    1. Build Next.js app (standalone output)
#    2. Upload standalone build + public/ to app-server
#    3. Start/restart with PM2
# ============================================================
set -euo pipefail

REMOTE_HOST="${REMOTE_HOST:-muyleanging@34.21.139.140}"
REMOTE_SSH_PORT="${REMOTE_SSH_PORT:-22}"
REMOTE_DIR="${REMOTE_DIR:-/opt/mekong/frontend}"
FRONTEND_DIR="${FRONTEND_DIR:-/Users/ingmuyleang/tunnel/mekongtunnel.dev}"
PM2_APP_NAME="${PM2_APP_NAME:-mekongtunnel-web}"
SSH_OPTS=(-p "${REMOTE_SSH_PORT}" -o StrictHostKeyChecking=accept-new)

remote() {
  ssh "${SSH_OPTS[@]}" "${REMOTE_HOST}" "$@"
}

echo ""
echo "  ▶  Building Next.js frontend ..."
cd "${FRONTEND_DIR}"
pnpm build
echo "  ✓  Build complete"

echo "  ▶  Uploading to ${REMOTE_HOST}:${REMOTE_DIR}/ ..."
remote "sudo mkdir -p '${REMOTE_DIR}/public'"
tar -czf - -C "${FRONTEND_DIR}/.next/standalone" . | remote "cat > /tmp/frontend-$$.tar.gz"
remote "sudo bash -c \"tar -xzf /tmp/frontend-$$.tar.gz -C '${REMOTE_DIR}' && rm -f /tmp/frontend-$$.tar.gz\""

echo "  ▶  Uploading public/ assets ..."
tar -czf - -C "${FRONTEND_DIR}" public | remote "cat > /tmp/frontend-public-$$.tar.gz"
remote "sudo bash -c \"tar -xzf /tmp/frontend-public-$$.tar.gz -C '${REMOTE_DIR}' && rm -f /tmp/frontend-public-$$.tar.gz\""

echo "  ▶  Uploading .next/static/ ..."
remote "sudo mkdir -p '${REMOTE_DIR}/.next/static'"
tar -czf - -C "${FRONTEND_DIR}/.next" static | remote "cat > /tmp/frontend-static-$$.tar.gz"
remote "sudo bash -c \"tar -xzf /tmp/frontend-static-$$.tar.gz -C '${REMOTE_DIR}/.next' && rm -f /tmp/frontend-static-$$.tar.gz\""
echo "  ✓  Upload complete"

echo "  ▶  Starting/restarting with PM2 ..."
remote "sudo bash -s" <<PMCMD
set -euo pipefail
cd '${REMOTE_DIR}'
if pm2 describe '${PM2_APP_NAME}' >/dev/null 2>&1; then
  pm2 restart '${PM2_APP_NAME}'
else
  pm2 start node --name '${PM2_APP_NAME}' -- server.js
fi
pm2 save
PMCMD
echo "  ✓  PM2 started"

sleep 3

echo "  ▶  Verifying frontend ..."
STATUS=$(remote "pm2 describe '${PM2_APP_NAME}' 2>/dev/null | grep -c 'online' || echo 0")
if [ "${STATUS}" = "0" ]; then
  echo "  ❌  PM2 process not online"
  echo "      Check logs: ssh ${REMOTE_HOST} pm2 logs ${PM2_APP_NAME} --lines 30"
  exit 1
fi
echo "  ✓  Frontend is online"

echo "  ✅  Frontend deploy complete → https://mekongtunnel.dev"
echo ""
