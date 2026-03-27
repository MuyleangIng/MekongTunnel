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
#    2. Upload the binary and migrations to the server
#    3. Optionally upload a runtime env file and install the systemd unit
#    4. Restart the systemd service
#    5. Verify the service is running
#
#  Notes:
#    - This is a systemd deploy script.
#    - If LOCAL_ENV_FILE is set, the script uploads the env file and
#      manages the remote systemd unit for a self-contained deploy.
#    - If LOCAL_ENV_FILE is unset, the script keeps the previous behavior
#      and only updates the binary/migrations before restarting the service.
#    - Redis is optional. If REDIS_URL is unset on the server, the API
#      still runs in single-node mode.
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
LOG_DIR="${LOG_DIR:-${REPO_ROOT}/logs}"
LOG_FILE="${LOG_FILE:-${LOG_DIR}/deploy-api-$(date +%Y%m%d-%H%M%S).log}"
UPLOAD_CHUNK_SIZE="${UPLOAD_CHUNK_SIZE:-1048576}"

REMOTE_HOST="${REMOTE_HOST:-root@139.59.108.158}"
REMOTE_SSH_PORT="${REMOTE_SSH_PORT:-2222}"
REMOTE_DIR="${REMOTE_DIR:-/opt/mekong/api}"
REMOTE_SERVICE_NAME="${REMOTE_SERVICE_NAME:-mekong-api}"
BINARY_NAME="${BINARY_NAME:-mekong-api}"
PUBLIC_API_BASE="${PUBLIC_API_BASE:-https://api.angkorsearch.dev}"
LOCAL_ENV_FILE="${LOCAL_ENV_FILE:-}"
REMOTE_ENV_FILE="${REMOTE_ENV_FILE:-${REMOTE_DIR}/.env.prod}"
REMOTE_ENV_LINK="${REMOTE_ENV_LINK:-${REMOTE_DIR}/.env}"
REMOTE_SERVICE_DESCRIPTION="${REMOTE_SERVICE_DESCRIPTION:-MekongTunnel API}"
REMOTE_SERVICE_AFTER="${REMOTE_SERVICE_AFTER:-network.target postgresql.service}"
REMOTE_SERVICE_USER="${REMOTE_SERVICE_USER:-root}"
REMOTE_RESTART_SEC="${REMOTE_RESTART_SEC:-5}"
FORCE_INSTALL_SERVICE_UNIT="${FORCE_INSTALL_SERVICE_UNIT:-false}"
TMP_REMOTE_BIN="/tmp/${BINARY_NAME}.new.$$"
TMP_REMOTE_ENV="/tmp/${BINARY_NAME}.env.$$"
TMP_REMOTE_MIGRATIONS="/tmp/${BINARY_NAME}.migrations.tar.gz.$$"
TMP_UPLOAD_DIR=""
SSH_OPTS=(-p "${REMOTE_SSH_PORT}")
REMOTE_SERVICE_UNIT_NAME="${REMOTE_SERVICE_NAME}"

if [[ "${REMOTE_SERVICE_UNIT_NAME}" != *.service ]]; then
  REMOTE_SERVICE_UNIT_NAME="${REMOTE_SERVICE_UNIT_NAME}.service"
fi

mkdir -p "${LOG_DIR}"
exec > >(tee -a "${LOG_FILE}") 2>&1
cd "${REPO_ROOT}"

cleanup() {
  if [[ -n "${TMP_UPLOAD_DIR}" && -d "${TMP_UPLOAD_DIR}" ]]; then
    rm -rf "${TMP_UPLOAD_DIR}"
  fi
}
trap cleanup EXIT

remote() {
  ssh "${SSH_OPTS[@]}" "${REMOTE_HOST}" "$@"
}

upload_binary() {
  local local_bin="${REPO_ROOT}/bin/${BINARY_NAME}"

  if command -v pv >/dev/null 2>&1; then
    echo "  ▶  Using pv for upload progress output ..."
    pv -f -p -t -e -r -b "${local_bin}" | remote "cat > '${TMP_REMOTE_BIN}'"
    return
  fi

  echo "  ▶  'pv' not found locally; using chunked ssh upload progress logs ..."

  local total_bytes
  total_bytes="$(wc -c < "${local_bin}" | tr -d '[:space:]')"

  if [[ -z "${total_bytes}" || "${total_bytes}" -le 0 ]]; then
    echo "  ❌  Could not read binary size for upload"
    exit 1
  fi

  TMP_UPLOAD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/deploy-api-upload.XXXXXX")"
  split -b "${UPLOAD_CHUNK_SIZE}" "${local_bin}" "${TMP_UPLOAD_DIR}/chunk-"

  local chunks=("${TMP_UPLOAD_DIR}"/chunk-*)
  local chunk_count="${#chunks[@]}"
  local uploaded_bytes=0
  local chunk_index=0
  local chunk_bytes=0
  local percent=0

  echo "  ▶  Upload size: ${total_bytes} bytes in ${chunk_count} chunk(s) of up to ${UPLOAD_CHUNK_SIZE} bytes"
  remote "rm -f '${TMP_REMOTE_BIN}'"

  for chunk in "${chunks[@]}"; do
    chunk_index=$((chunk_index + 1))
    chunk_bytes="$(wc -c < "${chunk}" | tr -d '[:space:]')"
    echo "  ▶  Uploading chunk ${chunk_index}/${chunk_count} (${chunk_bytes} bytes) ..."
    remote "cat >> '${TMP_REMOTE_BIN}'" < "${chunk}"
    uploaded_bytes=$((uploaded_bytes + chunk_bytes))
    percent=$((uploaded_bytes * 100 / total_bytes))
    echo "  ✓  Uploaded chunk ${chunk_index}/${chunk_count} (${uploaded_bytes}/${total_bytes} bytes, ${percent}%)"
  done
}

upload_migrations() {
  local local_migrations_dir="${REPO_ROOT}/migrations"

  if [[ ! -d "${local_migrations_dir}" ]]; then
    echo "  ❌  Missing migrations directory: ${local_migrations_dir}"
    exit 1
  fi

  echo "  ▶  Uploading migrations/ ..."
  tar -C "${REPO_ROOT}" -czf - migrations | remote "cat > '${TMP_REMOTE_MIGRATIONS}'"
  remote "mkdir -p '${REMOTE_DIR}' && rm -rf '${REMOTE_DIR}/migrations' && tar -xzf '${TMP_REMOTE_MIGRATIONS}' -C '${REMOTE_DIR}' && rm -f '${TMP_REMOTE_MIGRATIONS}'"
  echo "  ✓  Migrations uploaded"
}

upload_env_file() {
  if [[ -z "${LOCAL_ENV_FILE}" ]]; then
    return
  fi

  if [[ ! -f "${LOCAL_ENV_FILE}" ]]; then
    echo "  ❌  Missing API env file: ${LOCAL_ENV_FILE}"
    exit 1
  fi

  echo "  ▶  Uploading API env file ..."
  remote "cat > '${TMP_REMOTE_ENV}'" < "${LOCAL_ENV_FILE}"
  remote "install -m 0600 '${TMP_REMOTE_ENV}' '${REMOTE_ENV_FILE}' && ln -sfn '${REMOTE_ENV_FILE}' '${REMOTE_ENV_LINK}' && rm -f '${TMP_REMOTE_ENV}'"
  echo "  ✓  API env installed at ${REMOTE_ENV_FILE}"
}

install_service_unit() {
  if [[ -z "${LOCAL_ENV_FILE}" ]]; then
    return
  fi

  if [[ "${FORCE_INSTALL_SERVICE_UNIT}" != "true" ]] && remote "test -f '/etc/systemd/system/${REMOTE_SERVICE_UNIT_NAME}'"; then
    echo "  ▶  Existing ${REMOTE_SERVICE_UNIT_NAME} found; keeping the current unit file"
    return
  fi

  echo "  ▶  Installing ${REMOTE_SERVICE_UNIT_NAME} ..."
  remote "\
    cat > '/etc/systemd/system/${REMOTE_SERVICE_UNIT_NAME}' <<'EOF'
[Unit]
Description=${REMOTE_SERVICE_DESCRIPTION}
After=${REMOTE_SERVICE_AFTER}

[Service]
Type=simple
User=${REMOTE_SERVICE_USER}
WorkingDirectory=${REMOTE_DIR}
EnvironmentFile=${REMOTE_ENV_LINK}
Environment=MIGRATIONS_DIR=${REMOTE_DIR}/migrations
ExecStart=${REMOTE_DIR}/${BINARY_NAME}
Restart=always
RestartSec=${REMOTE_RESTART_SEC}

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload && \
    (systemctl enable '${REMOTE_SERVICE_NAME}' >/dev/null 2>&1 || true)"
  echo "  ✓  Service unit installed"
}

mkdir -p "${REPO_ROOT}/bin"
VERSION="$(git describe --tags --always --dirty)"

echo ""
echo "  ▶  Writing deploy log to ${LOG_FILE}"
echo "  ▶  Compiling Go API (linux/amd64) ..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -ldflags="-s -w -X main.version=${VERSION}" -trimpath -o "${REPO_ROOT}/bin/${BINARY_NAME}" ./cmd/api
echo "  ✓  Binary: bin/${BINARY_NAME}"
echo "  ✓  Version: ${VERSION}"
ls -lh "${REPO_ROOT}/bin/${BINARY_NAME}"

echo "  ▶  Uploading to ${REMOTE_HOST}:${REMOTE_SSH_PORT}:${REMOTE_DIR}/ ..."
remote "mkdir -p '${REMOTE_DIR}'"
upload_binary
upload_migrations
remote "install -m 0755 '${TMP_REMOTE_BIN}' '${REMOTE_DIR}/${BINARY_NAME}' && rm -f '${TMP_REMOTE_BIN}'"
upload_env_file
install_service_unit
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
