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
#    2. Upload binary to server via ssh
#    3. Restart the systemd service
#    4. Verify the service is running
# ============================================================
set -euo pipefail

REMOTE_HOST="${REMOTE_HOST:-root@139.59.108.158}"
REMOTE_SSH_PORT="${REMOTE_SSH_PORT:-2222}"
REMOTE_DIR="${REMOTE_DIR:-/opt/mekong/api}"
REMOTE_SERVICE_NAME="${REMOTE_SERVICE_NAME:-mekong-api}"
BINARY_NAME="${BINARY_NAME:-mekong-api}"
PUBLIC_API_BASE="${PUBLIC_API_BASE:-https://api.angkorsearch.dev}"
TMP_REMOTE_BIN="/tmp/${BINARY_NAME}.new.$$"
SSH_OPTS=(-p "${REMOTE_SSH_PORT}")

remote() {
  ssh "${SSH_OPTS[@]}" "${REMOTE_HOST}" "$@"
}

mkdir -p bin
VERSION="$(git describe --tags --always --dirty)"

echo ""
echo "  ▶  Compiling Go API (linux/amd64) ..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -ldflags="-s -w -X main.version=${VERSION}" -trimpath -o "bin/${BINARY_NAME}" ./cmd/api
echo "  ✓  Binary: bin/${BINARY_NAME}"
echo "  ✓  Version: ${VERSION}"

echo "  ▶  Uploading to ${REMOTE_HOST}:${REMOTE_SSH_PORT}:${REMOTE_DIR}/ ..."
remote "mkdir -p '${REMOTE_DIR}' && cat > '${TMP_REMOTE_BIN}'" < "bin/${BINARY_NAME}"
remote "install -m 0755 '${TMP_REMOTE_BIN}' '${REMOTE_DIR}/${BINARY_NAME}' && rm -f '${TMP_REMOTE_BIN}'"
echo "  ✓  Upload complete"

echo "  ▶  Restarting ${REMOTE_SERVICE_NAME} service ..."
remote "systemctl restart '${REMOTE_SERVICE_NAME}'"

sleep 3

STATUS=$(remote "systemctl is-active '${REMOTE_SERVICE_NAME}'" 2>/dev/null || echo "unknown")
if [ "$STATUS" != "active" ]; then
  echo "  ❌  Service not running (status: ${STATUS})"
  echo "      Check logs: ssh -p ${REMOTE_SSH_PORT} ${REMOTE_HOST} journalctl -u ${REMOTE_SERVICE_NAME} -n 30"
  echo ""
  exit 1
fi
echo "  ✓  Service is active"

echo "  ▶  Verifying public health endpoint ..."
curl --retry 3 --retry-delay 1 --retry-connrefused -fsS "${PUBLIC_API_BASE}/api/health" >/dev/null
echo "  ✓  Public health OK"

echo "  ▶  Verifying public route /api/cli/subdomains ..."
PUBLIC_SUBDOMAINS_CODE=$(curl -s -o /dev/null -w '%{http_code}' "${PUBLIC_API_BASE}/api/cli/subdomains")
if [ "${PUBLIC_SUBDOMAINS_CODE}" != "401" ]; then
  echo "  ❌  Public route check failed: ${PUBLIC_API_BASE}/api/cli/subdomains returned ${PUBLIC_SUBDOMAINS_CODE} (expected 401 without auth)"
  echo "      This usually means the public API is still serving an older binary or routing to the wrong place."
  echo ""
  exit 1
fi
echo "  ✓  Public route exists (401 without auth is expected)"

echo "  ▶  Verifying public route /api/cli/domains ..."
PUBLIC_DOMAINS_CODE=$(curl -s -o /dev/null -w '%{http_code}' "${PUBLIC_API_BASE}/api/cli/domains")
if [ "${PUBLIC_DOMAINS_CODE}" != "401" ]; then
  echo "  ❌  Public route check failed: ${PUBLIC_API_BASE}/api/cli/domains returned ${PUBLIC_DOMAINS_CODE} (expected 401 without auth)"
  echo "      This usually means the public API is still serving an older binary or routing to the wrong place."
  echo ""
  exit 1
fi
echo "  ✓  Public custom-domain route exists (401 without auth is expected)"

echo "  ✅  API deploy complete — ${PUBLIC_API_BASE}"
echo ""
