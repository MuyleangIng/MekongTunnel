#!/usr/bin/env bash
# ============================================================
#  scripts/run-api.sh — Run the MekongTunnel REST API
#  Author: Ing Muyleang (អុឹង មួយលៀង) — Ing_Muyleang
#
#  Usage:
#    ./scripts/run-api.sh           # dev (default)
#    ./scripts/run-api.sh dev       # local development  (.env.dev)
#    ./scripts/run-api.sh prod      # production config  (.env.prod)
#
#  First time setup:
#    cp .env.api .env.dev    # copy template, fill in dev values
#    cp .env.api .env.prod   # copy template, fill in prod values
# ============================================================
set -euo pipefail

ENV="${1:-dev}"
ENV_FILE=".env.${ENV}"

# ── Verify env file exists ─────────────────────────────────────────────────────
if [ ! -f "$ENV_FILE" ]; then
  echo ""
  echo "  ERROR: $ENV_FILE not found."
  echo ""
  echo "  Create it by copying the template:"
  echo "    cp .env.api $ENV_FILE"
  echo "  Then fill in your values and re-run."
  echo ""
  exit 1
fi

echo ""
echo "  ▶  Environment : $ENV_FILE"

# ── Load env vars ──────────────────────────────────────────────────────────────
# Export all non-comment, non-empty lines as environment variables
set -o allexport
# shellcheck source=/dev/null
source "$ENV_FILE"
set +o allexport

echo "  ▶  API address  : ${API_ADDR:-:8080}"
echo "  ▶  Frontend URL : ${FRONTEND_URL:-http://localhost:3000}"
echo "  ▶  Starting API ..."
echo ""

# ── Run ───────────────────────────────────────────────────────────────────────
go run ./cmd/api
