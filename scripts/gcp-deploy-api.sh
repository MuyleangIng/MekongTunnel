#!/usr/bin/env bash
# ============================================================
#  scripts/gcp-deploy-api.sh — Build and deploy the Go API
#  to GCP VM 2 (app-server)
#
#  Usage:
#    ./scripts/gcp-deploy-api.sh
#    LOCAL_ENV_FILE=.env.prod ./scripts/gcp-deploy-api.sh
#
#  What it does:
#    1. Cross-compile Go API binary for linux/amd64
#    2. Upload binary, migrations, and env to app-server
#    3. Install/update systemd unit
#    4. Restart and verify the service + public endpoints
# ============================================================
set -euo pipefail

REMOTE_HOST="${REMOTE_HOST:-muyleanging@34.21.139.140}"
REMOTE_SSH_PORT="${REMOTE_SSH_PORT:-22}"
REMOTE_DIR="${REMOTE_DIR:-/opt/mekong/api}"
REMOTE_SERVICE_NAME="${REMOTE_SERVICE_NAME:-mekong-api}"
BINARY_NAME="${BINARY_NAME:-mekong-api}"
PUBLIC_API_BASE="${PUBLIC_API_BASE:-https://api.mekongtunnel.dev}"
LOCAL_ENV_FILE="${LOCAL_ENV_FILE:-.env.prod}"
REMOTE_ENV_FILE="${REMOTE_ENV_FILE:-${REMOTE_DIR}/.env.prod}"
REMOTE_ENV_LINK="${REMOTE_ENV_LINK:-${REMOTE_DIR}/.env}"
TMP_REMOTE_BIN="/tmp/${BINARY_NAME}.new.$$"
TMP_REMOTE_ENV="/tmp/${BINARY_NAME}.env.$$"
TMP_REMOTE_MIGRATIONS="/tmp/${BINARY_NAME}.migrations.tar.gz.$$"
SSH_OPTS=(-p "${REMOTE_SSH_PORT}" -o StrictHostKeyChecking=accept-new)
TELEGRAM_ENABLED_IN_ENV="false"

remote() {
  ssh "${SSH_OPTS[@]}" "${REMOTE_HOST}" "$@"
}

if [[ -z "${LOCAL_ENV_FILE}" ]]; then
  echo "  !  LOCAL_ENV_FILE is unset — skipping env upload"
else
  if [[ -f "${LOCAL_ENV_FILE}" ]] && \
     grep -Eq '^TELEGRAM_BOT_ENABLED=(1|true|yes|on)$' "${LOCAL_ENV_FILE}" && \
     grep -Eq '^TELEGRAM_BOT_TOKEN=.+$' "${LOCAL_ENV_FILE}"; then
    TELEGRAM_ENABLED_IN_ENV="true"
  fi
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

mkdir -p bin
VERSION="$(git describe --tags --always --dirty)"

echo ""
echo "  ▶  Compiling Go API (linux/amd64) ..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -ldflags="-s -w -X main.version=${VERSION}" -trimpath -o "${REPO_ROOT}/bin/${BINARY_NAME}" ./cmd/api
echo "  ✓  Binary: bin/${BINARY_NAME}"
echo "  ✓  Version: ${VERSION}"

echo "  ▶  Uploading to ${REMOTE_HOST}:${REMOTE_DIR}/ ..."
remote "sudo mkdir -p '${REMOTE_DIR}'"
remote "cat > '${TMP_REMOTE_BIN}'" < "${REPO_ROOT}/bin/${BINARY_NAME}"

echo "  ▶  Uploading migrations/ ..."
tar -C "${REPO_ROOT}" -czf - migrations | remote "cat > '${TMP_REMOTE_MIGRATIONS}'"
remote "sudo bash -c \"rm -rf '${REMOTE_DIR}/migrations' && tar -xzf '${TMP_REMOTE_MIGRATIONS}' -C '${REMOTE_DIR}' && rm -f '${TMP_REMOTE_MIGRATIONS}'\""
echo "  ✓  Migrations uploaded"

if [[ -n "${LOCAL_ENV_FILE}" && -f "${LOCAL_ENV_FILE}" ]]; then
  echo "  ▶  Uploading env file ..."
  remote "cat > '${TMP_REMOTE_ENV}'" < "${LOCAL_ENV_FILE}"
  remote "sudo bash -c \"install -m 0600 '${TMP_REMOTE_ENV}' '${REMOTE_ENV_FILE}' && ln -sfn '${REMOTE_ENV_FILE}' '${REMOTE_ENV_LINK}' && rm -f '${TMP_REMOTE_ENV}'\""
  echo "  ✓  Env installed at ${REMOTE_ENV_FILE}"
fi

echo "  ▶  Installing binary and systemd unit ..."
ssh "${SSH_OPTS[@]}" "${REMOTE_HOST}" sudo bash -s \
  "${REMOTE_DIR}" "${BINARY_NAME}" "${TMP_REMOTE_BIN}" "${REMOTE_SERVICE_NAME}" "${REMOTE_ENV_LINK}" <<'INSTALL'
set -euo pipefail
REMOTE_DIR="$1"
BINARY_NAME="$2"
TMP_REMOTE_BIN="$3"
REMOTE_SERVICE_NAME="$4"
REMOTE_ENV_LINK="$5"

install -m 0755 "${TMP_REMOTE_BIN}" "${REMOTE_DIR}/${BINARY_NAME}"
rm -f "${TMP_REMOTE_BIN}"

cat > "/etc/systemd/system/${REMOTE_SERVICE_NAME}.service" <<EOF
[Unit]
Description=MekongTunnel API
After=network.target postgresql.service

[Service]
Type=simple
User=root
WorkingDirectory=${REMOTE_DIR}
EnvironmentFile=${REMOTE_ENV_LINK}
Environment=MIGRATIONS_DIR=${REMOTE_DIR}/migrations
ExecStart=${REMOTE_DIR}/${BINARY_NAME}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "${REMOTE_SERVICE_NAME}" >/dev/null 2>&1 || true
systemctl restart "${REMOTE_SERVICE_NAME}"
INSTALL
echo "  ✓  Install complete"

sleep 3

echo "  ▶  Verifying ${REMOTE_SERVICE_NAME} ..."
STATUS=$(remote "systemctl is-active '${REMOTE_SERVICE_NAME}'" 2>/dev/null || echo "unknown")
if [ "${STATUS}" != "active" ]; then
  echo "  ❌  Service not running (status: ${STATUS})"
  echo "      Check logs: ssh -p ${REMOTE_SSH_PORT} ${REMOTE_HOST} journalctl -u ${REMOTE_SERVICE_NAME} -n 30"
  exit 1
fi
echo "  ✓  Service is active"

echo "  ▶  Verifying public health endpoint ..."
curl --retry 3 --retry-delay 2 --retry-connrefused -fsS "${PUBLIC_API_BASE}/api/health" >/dev/null
echo "  ✓  Health OK"

echo "  ▶  Verifying /api/cli/subdomains (expect 401) ..."
CODE=$(curl -s -o /dev/null -w '%{http_code}' "${PUBLIC_API_BASE}/api/cli/subdomains")
if [ "${CODE}" != "401" ]; then
  echo "  ❌  Expected 401, got ${CODE}"
  exit 1
fi
echo "  ✓  Route exists (401 without auth)"

if [[ "${TELEGRAM_ENABLED_IN_ENV}" == "true" ]]; then
  echo "  ▶  Verifying /api/telegram/webhook ..."
  TG_CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "${PUBLIC_API_BASE}/api/telegram/webhook")
  if [ "${TG_CODE}" = "404" ]; then
    echo "  ❌  Telegram webhook returned 404"
    exit 1
  fi
  echo "  ✓  Telegram webhook exists (${TG_CODE})"
fi

echo "  ✅  API deploy complete → ${PUBLIC_API_BASE}"
echo ""
