#!/usr/bin/env bash
# ============================================================
#  scripts/deploy-api.sh — Build and deploy the Go API to production
#  Author: Ing Muyleang (អុឹង មួយលៀង) — Ing_Muyleang
#
#  Usage:
#    ./scripts/deploy-api.sh
#
#  What it does:
#    1. Cross-compile Go API binary for linux/amd64
#    2. Upload binary to server via scp
#    3. Restart the systemd service
#    4. Verify the service is running
# ============================================================
set -euo pipefail

REMOTE_HOST="root@139.59.108.158"
REMOTE_DIR="/opt/mekong/api"
BINARY_NAME="mekong-api"

echo ""
echo "  ▶  Compiling Go API (linux/amd64) ..."
GOOS=linux GOARCH=amd64 go build -o "bin/${BINARY_NAME}" ./cmd/api
echo "  ✓  Binary: bin/${BINARY_NAME}"

echo "  ▶  Uploading to ${REMOTE_HOST}:${REMOTE_DIR}/ ..."
scp "bin/${BINARY_NAME}" "${REMOTE_HOST}:${REMOTE_DIR}/${BINARY_NAME}"
echo "  ✓  Upload complete"

echo "  ▶  Restarting mekong-api service ..."
ssh "${REMOTE_HOST}" "systemctl restart mekong-api"

sleep 3

STATUS=$(ssh "${REMOTE_HOST}" "systemctl is-active mekong-api" 2>/dev/null || echo "unknown")
if [ "$STATUS" = "active" ]; then
  echo "  ✅  API deploy complete — https://api.angkorsearch.dev"
  echo ""
else
  echo "  ❌  Service not running (status: ${STATUS})"
  echo "      Check logs: ssh ${REMOTE_HOST} journalctl -u mekong-api -n 30"
  echo ""
  exit 1
fi
