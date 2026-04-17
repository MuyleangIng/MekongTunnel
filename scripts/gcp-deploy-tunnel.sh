#!/usr/bin/env bash
# ============================================================
#  scripts/gcp-deploy-tunnel.sh — Build and deploy the tunnel
#  server to GCP VM 1 (tunnel-server)
#
#  Usage:
#    ./scripts/gcp-deploy-tunnel.sh
#    LOCAL_ENV_FILE=.env.prod ./scripts/gcp-deploy-tunnel.sh
#
#  What it does:
#    1. Cross-compile tunnel server binary for linux/amd64
#    2. Upload binary + env to tunnel-server (34.158.38.176)
#    3. Install/update systemd unit
#    4. Restart and verify the service
# ============================================================
set -euo pipefail

REMOTE_HOST="${REMOTE_HOST:-muyleanging@34.158.38.176}"
REMOTE_SSH_PORT="${REMOTE_SSH_PORT:-2222}"
REMOTE_APP_DIR="${REMOTE_APP_DIR:-/opt/mekongtunnel}"
REMOTE_SERVICE_NAME="${REMOTE_SERVICE_NAME:-mekongtunnel.service}"
REMOTE_SERVER_BIN="${REMOTE_SERVER_BIN:-/usr/local/bin/mekongtunnel}"
LOCAL_ENV_FILE="${LOCAL_ENV_FILE:-.env.prod}"
WILDCARD_DOMAIN="${WILDCARD_DOMAIN:-proxy.mekongtunnel.dev}"
TMP_REMOTE_BIN="/tmp/mekongtunnel.new.$$"
TMP_REMOTE_ENV="/tmp/mekongtunnel.env.prod.$$"
SSH_OPTS=(-p "${REMOTE_SSH_PORT}" -o StrictHostKeyChecking=accept-new)

remote() {
  ssh "${SSH_OPTS[@]}" "${REMOTE_HOST}" "$@"
}

if [[ ! -f "${LOCAL_ENV_FILE}" ]]; then
  echo "  ❌  Missing env file: ${LOCAL_ENV_FILE}"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

mkdir -p bin
VERSION="$(git describe --tags --always --dirty)"

echo ""
echo "  ▶  Compiling tunnel server (linux/amd64) ..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -ldflags="-s -w -X main.version=${VERSION}" -trimpath -o "bin/mekongtunnel" ./cmd/mekongtunnel
echo "  ✓  Binary: bin/mekongtunnel"
echo "  ✓  Version: ${VERSION}"

echo "  ▶  Uploading binary and env to ${REMOTE_HOST} ..."
remote "cat > '${TMP_REMOTE_BIN}'" < "bin/mekongtunnel"
remote "cat > '${TMP_REMOTE_ENV}'" < "${LOCAL_ENV_FILE}"
echo "  ✓  Upload complete"

echo "  ▶  Installing service and runtime files ..."
ssh "${SSH_OPTS[@]}" "${REMOTE_HOST}" sudo bash -s \
  "${REMOTE_APP_DIR}" "${REMOTE_SERVER_BIN}" "${TMP_REMOTE_BIN}" \
  "${TMP_REMOTE_ENV}" "${REMOTE_SERVICE_NAME}" <<'INSTALL'
set -euo pipefail
REMOTE_APP_DIR="$1"
REMOTE_SERVER_BIN="$2"
TMP_REMOTE_BIN="$3"
TMP_REMOTE_ENV="$4"
REMOTE_SERVICE_NAME="$5"

mkdir -p "${REMOTE_APP_DIR}" "${REMOTE_APP_DIR}/data/certs" /opt/mekong/uploads
install -m 0755 "${TMP_REMOTE_BIN}" "${REMOTE_SERVER_BIN}"
install -m 0600 "${TMP_REMOTE_ENV}" "${REMOTE_APP_DIR}/.env.prod"
ln -sfn "${REMOTE_APP_DIR}/.env.prod" "${REMOTE_APP_DIR}/.env"
rm -f "${TMP_REMOTE_BIN}" "${TMP_REMOTE_ENV}"

cat > "/etc/systemd/system/${REMOTE_SERVICE_NAME}" <<EOF
[Unit]
Description=Mekong Tunnel Server
After=network.target

[Service]
Type=simple
WorkingDirectory=${REMOTE_APP_DIR}
EnvironmentFile=${REMOTE_APP_DIR}/.env
ExecStart=${REMOTE_SERVER_BIN}
Restart=always
RestartSec=3

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
  echo "      Check logs: ssh -p ${REMOTE_SSH_PORT} ${REMOTE_HOST} journalctl -u ${REMOTE_SERVICE_NAME} -n 50"
  exit 1
fi
echo "  ✓  Service is active"

echo "  ▶  Verifying running executable ..."
RUNNING_EXE=$(remote "pid=\$(systemctl show '${REMOTE_SERVICE_NAME}' --property=MainPID --value); [ -n \"\$pid\" ] && [ \"\$pid\" != \"0\" ] && readlink -f \"/proc/\$pid/exe\"")
if [ "${RUNNING_EXE}" != "${REMOTE_SERVER_BIN}" ]; then
  echo "  ❌  Service running wrong binary: ${RUNNING_EXE:-unknown}"
  exit 1
fi
echo "  ✓  Service is running ${REMOTE_SERVER_BIN}"

echo "  ▶  Verifying remote version ..."
REMOTE_VERSION=$(remote "'${REMOTE_SERVER_BIN}' version" 2>/dev/null || true)
echo "  ✓  ${REMOTE_VERSION:-unknown}"

echo "  ▶  Verifying listening ports ..."
remote "ss -tlnp | grep -E ':22|:8081|:8443|:9090'"

echo "  ✅  Tunnel server deploy complete → https://${WILDCARD_DOMAIN}"
echo ""
