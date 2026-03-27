#!/usr/bin/env bash
# ============================================================
#  scripts/deploy-tunnel.sh — Build and deploy the Mekong
#  tunnel server from the local working tree
#
#  Usage:
#    ./scripts/deploy-tunnel.sh
#
#  What it does:
#    1. Build mekongtunnel locally for linux/amd64
#    2. Upload binary and .env.prod to proxy.angkorsearch.dev:2222
#    3. Install /etc/systemd/system/mekongtunnel.service
#    4. Optionally install a wildcard nginx vhost (for example *.mekongtunnel.dev)
#    5. Restart and verify the tunnel service
#
#  Notes:
#    - This is a systemd deploy script for the existing VM workflow.
#    - Redis is optional. If REDIS_URL is omitted from the uploaded env
#      file, the tunnel edge still runs in single-node mode.
# ============================================================
set -euo pipefail

REMOTE_HOST="${REMOTE_HOST:-root@proxy.angkorsearch.dev}"
REMOTE_SSH_PORT="${REMOTE_SSH_PORT:-2222}"
REMOTE_APP_DIR="${REMOTE_APP_DIR:-/opt/mekongtunnel}"
REMOTE_SERVICE_NAME="${REMOTE_SERVICE_NAME:-mekongtunnel.service}"
REMOTE_SERVER_BIN="${REMOTE_SERVER_BIN:-/usr/local/bin/mekongtunnel}"
LOCAL_ENV_FILE="${LOCAL_ENV_FILE:-.env.prod}"
WILDCARD_DOMAIN="${WILDCARD_DOMAIN:-}"
REMOTE_WILDCARD_UPSTREAM="${REMOTE_WILDCARD_UPSTREAM:-https://127.0.0.1:8443}"
REMOTE_WILDCARD_SITE="${REMOTE_WILDCARD_SITE:-/etc/nginx/sites-available/mekong-wildcard.conf}"
REMOTE_WILDCARD_SITE_ENABLED="${REMOTE_WILDCARD_SITE_ENABLED:-/etc/nginx/sites-enabled/mekong-wildcard.conf}"
TMP_REMOTE_BIN="/tmp/mekongtunnel.new.$$"
TMP_REMOTE_ENV="/tmp/mekongtunnel.env.prod.$$"
TMP_REMOTE_NGINX="/tmp/mekongtunnel.nginx.$$"
TMP_LOCAL_NGINX=""
SSH_OPTS=(-p "${REMOTE_SSH_PORT}")

cleanup() {
  if [[ -n "${TMP_LOCAL_NGINX}" && -f "${TMP_LOCAL_NGINX}" ]]; then
    rm -f "${TMP_LOCAL_NGINX}"
  fi
}
trap cleanup EXIT

remote() {
  ssh "${SSH_OPTS[@]}" "${REMOTE_HOST}" "$@"
}

if [[ ! -f "${LOCAL_ENV_FILE}" ]]; then
  echo "  ❌  Missing env file: ${LOCAL_ENV_FILE}"
  exit 1
fi

mkdir -p bin
VERSION="$(git describe --tags --always --dirty)"

echo ""
echo "  ▶  Compiling tunnel server (linux/amd64) ..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -ldflags="-s -w -X main.version=${VERSION}" -trimpath -o "bin/mekongtunnel" ./cmd/mekongtunnel
echo "  ✓  Binary: bin/mekongtunnel"
echo "  ✓  Version: ${VERSION}"

echo "  ▶  Uploading binary and env to ${REMOTE_HOST}:${REMOTE_SSH_PORT} ..."
remote "cat > '${TMP_REMOTE_BIN}'" < "bin/mekongtunnel"
remote "cat > '${TMP_REMOTE_ENV}'" < "${LOCAL_ENV_FILE}"
echo "  ✓  Upload complete"

echo "  ▶  Installing service and runtime files ..."
remote "\
  mkdir -p '${REMOTE_APP_DIR}' '${REMOTE_APP_DIR}/data/certs' /opt/mekong/uploads && \
  install -m 0755 '${TMP_REMOTE_BIN}' '${REMOTE_SERVER_BIN}' && \
  install -m 0600 '${TMP_REMOTE_ENV}' '${REMOTE_APP_DIR}/.env.prod' && \
  ln -sfn '${REMOTE_APP_DIR}/.env.prod' '${REMOTE_APP_DIR}/.env' && \
  rm -f '${TMP_REMOTE_BIN}' '${TMP_REMOTE_ENV}' && \
  cat > /etc/systemd/system/${REMOTE_SERVICE_NAME} <<'EOF'
[Unit]
Description=Mekong tunnel server
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
  systemctl daemon-reload && \
  (systemctl enable ${REMOTE_SERVICE_NAME} >/dev/null 2>&1 || true) && \
  systemctl restart ${REMOTE_SERVICE_NAME}"
echo "  ✓  Install complete"

echo "  ▶  Verifying ${REMOTE_SERVICE_NAME} ..."
STATUS=$(remote "systemctl is-active '${REMOTE_SERVICE_NAME}'" 2>/dev/null || echo "unknown")
if [ "${STATUS}" != "active" ]; then
  echo "  ❌  Service not running (status: ${STATUS})"
  echo "      Check logs: ssh -p ${REMOTE_SSH_PORT} ${REMOTE_HOST} journalctl -u ${REMOTE_SERVICE_NAME} -n 50"
  echo ""
  exit 1
fi
echo "  ✓  Service is active"

echo "  ▶  Verifying running executable ..."
RUNNING_EXE=$(remote "pid=\$(systemctl show '${REMOTE_SERVICE_NAME}' --property=MainPID --value); [ -n \"\$pid\" ] && [ \"\$pid\" != \"0\" ] && readlink -f \"/proc/\$pid/exe\"")
if [ "${RUNNING_EXE}" != "${REMOTE_SERVER_BIN}" ]; then
  echo "  ❌  Service is active but not running ${REMOTE_SERVER_BIN}"
  echo "      Running executable: ${RUNNING_EXE:-unknown}"
  echo ""
  exit 1
fi
echo "  ✓  Service is running ${REMOTE_SERVER_BIN}"

echo "  ▶  Verifying installed binary version ..."
REMOTE_VERSION=$(remote "'${REMOTE_SERVER_BIN}' version" 2>/dev/null || true)
if [ -z "${REMOTE_VERSION}" ]; then
  echo "  ❌  Could not read remote binary version from ${REMOTE_SERVER_BIN}"
  echo ""
  exit 1
fi
echo "  ✓  ${REMOTE_VERSION}"

echo "  ▶  Verifying listening ports ..."
remote "ss -tlnp | egrep ':22|:8081|:8443|:9090'"

echo "  ▶  Checking token validation status ..."
TOKEN_STATUS=$(remote "journalctl -u '${REMOTE_SERVICE_NAME}' -n 50 --no-pager | grep -E 'Token validation enabled|token validation disabled|could not connect to database' | tail -n 1" 2>/dev/null || true)
if [[ "${TOKEN_STATUS}" == *"disabled"* ]] || [[ "${TOKEN_STATUS}" == *"could not connect to database"* ]]; then
  echo "  ❌  Reserved subdomains are disabled on the tunnel server"
  echo "      ${TOKEN_STATUS}"
  echo ""
  exit 1
fi
if [[ "${TOKEN_STATUS}" == *"Token validation enabled"* ]]; then
  echo "  ✓  ${TOKEN_STATUS}"
else
  echo "  ⚠  Could not confirm token validation from recent logs"
fi

if [[ -n "${WILDCARD_DOMAIN}" ]]; then
  echo "  ▶  Checking wildcard certificate files for ${WILDCARD_DOMAIN} ..."
  if ! remote "test -f '/etc/letsencrypt/live/${WILDCARD_DOMAIN}/fullchain.pem' && test -f '/etc/letsencrypt/live/${WILDCARD_DOMAIN}/privkey.pem'"; then
    echo "  ❌  Missing wildcard certificate for ${WILDCARD_DOMAIN}"
    echo "      Run this on the proxy host first:"
    echo "      certbot certonly --manual --preferred-challenges dns -d ${WILDCARD_DOMAIN} -d '*.${WILDCARD_DOMAIN}'"
    echo ""
    exit 1
  fi
  echo "  ✓  Wildcard certificate files found"

  TMP_LOCAL_NGINX="$(mktemp)"
  cat > "${TMP_LOCAL_NGINX}" <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${WILDCARD_DOMAIN} *.${WILDCARD_DOMAIN};
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${WILDCARD_DOMAIN} *.${WILDCARD_DOMAIN};

    ssl_certificate /etc/letsencrypt/live/${WILDCARD_DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${WILDCARD_DOMAIN}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    location / {
        proxy_pass ${REMOTE_WILDCARD_UPSTREAM};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_ssl_server_name on;
        proxy_ssl_name \$host;
        proxy_ssl_verify off;
        proxy_read_timeout 60s;
    }
}
EOF

  echo "  ▶  Installing wildcard nginx site for ${WILDCARD_DOMAIN} ..."
  remote "cat > '${TMP_REMOTE_NGINX}'" < "${TMP_LOCAL_NGINX}"
  remote "\
    install -m 0644 '${TMP_REMOTE_NGINX}' '${REMOTE_WILDCARD_SITE}' && \
    ln -sfn '${REMOTE_WILDCARD_SITE}' '${REMOTE_WILDCARD_SITE_ENABLED}' && \
    rm -f '${TMP_REMOTE_NGINX}' && \
    nginx -t && \
    systemctl reload nginx"
  echo "  ✓  Wildcard nginx site enabled"

  echo "  ▶  Verifying wildcard certificate for ${WILDCARD_DOMAIN} ..."
  CERT_INFO=$(remote "printf '' | openssl s_client -connect 127.0.0.1:443 -servername test.${WILDCARD_DOMAIN} 2>/dev/null | openssl x509 -noout -subject -ext subjectAltName" 2>/dev/null || true)
  if [[ "${CERT_INFO}" != *"${WILDCARD_DOMAIN}"* ]]; then
    echo "  ❌  nginx is not serving a certificate for ${WILDCARD_DOMAIN}"
    echo "      Issue a wildcard cert first:"
    echo "      certbot certonly --manual --preferred-challenges dns -d ${WILDCARD_DOMAIN} -d '*.${WILDCARD_DOMAIN}'"
    echo ""
    exit 1
  fi
  echo "  ✓  Wildcard certificate is active for ${WILDCARD_DOMAIN}"
fi

echo "  ✅  Tunnel server deploy complete"
echo ""
