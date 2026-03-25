#!/usr/bin/env bash
# update.sh — update a git-managed proxy host checkout, rebuild, and restart MekongTunnel.
# Preferred production deploy path is ./scripts/deploy-tunnel.sh from your local repo.
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/mekongtunnel}"
SERVICE_NAME="${SERVICE_NAME:-mekongtunnel.service}"
TARGET_REF="${1:-origin/main}"
SERVER_BIN="${SERVER_BIN:-/usr/local/bin/mekongtunnel}"
CLIENT_BIN="${CLIENT_BIN:-/usr/local/bin/mekong}"
ENV_FILE="${ENV_FILE:-${APP_DIR}/.env.prod}"
ACTIVE_ENV_FILE="${ACTIVE_ENV_FILE:-${APP_DIR}/.env}"

cd "${APP_DIR}"

if [[ ! -d "${APP_DIR}/.git" ]]; then
  echo "→ ERROR: ${APP_DIR} is not a git checkout"
  echo "→ Use scripts/deploy-tunnel.sh for direct binary deploys, or clone the repo first."
  exit 1
fi

echo "→ Stopping service..."
systemctl stop "${SERVICE_NAME}"

echo "→ Fetching latest code and tags..."
git fetch --force --prune --tags origin
git rev-parse --verify "${TARGET_REF}^{commit}" >/dev/null

echo "→ Resetting repository to ${TARGET_REF}..."
if [[ "${TARGET_REF}" == origin/* ]]; then
  branch="${TARGET_REF#origin/}"
  git checkout -B "${branch}" "${TARGET_REF}"
else
  git checkout --detach "${TARGET_REF}"
fi
git reset --hard "${TARGET_REF}"
git clean -fdx -e host_key -e data/ -e data-dev/ -e certs/ -e .env -e .env.* -e logs/

if [[ ! -f "${ENV_FILE}" ]]; then
  echo "→ ERROR: env file not found: ${ENV_FILE}"
  exit 1
fi

echo "→ Activating env file ${ENV_FILE} ..."
ln -sfn "${ENV_FILE}" "${ACTIVE_ENV_FILE}"

echo "→ Cleaning old binaries and Go caches..."
rm -f mekongtunnel "${SERVER_BIN}" "${CLIENT_BIN}"
go clean -cache -testcache -modcache

VERSION="$(git describe --tags --always)"
LDFLAGS="-s -w -X main.version=${VERSION}"

echo "→ Building server binary (${VERSION})..."
CGO_ENABLED=0 go build -ldflags="${LDFLAGS}" -trimpath -o mekongtunnel ./cmd/mekongtunnel
install -m 0755 mekongtunnel "${SERVER_BIN}"

echo "→ Building mekong client binary (${VERSION})..."
CGO_ENABLED=0 go build -ldflags="${LDFLAGS}" -trimpath -o "${CLIENT_BIN}" ./cmd/mekong
chmod +x "${CLIENT_BIN}"

echo "→ Installed versions:"
./mekongtunnel version
"${SERVER_BIN}" version
"${CLIENT_BIN}" version
echo "→ Active env:"
ls -l "${ACTIVE_ENV_FILE}"

echo "→ Starting service..."
systemctl start "${SERVICE_NAME}"

echo "→ Status:"
systemctl status "${SERVICE_NAME}" --no-pager

echo "→ Listening ports:"
ss -tlnp | egrep ':22|:8081|:8443|:9090' || true
