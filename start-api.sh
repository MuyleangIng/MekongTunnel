#!/usr/bin/env bash
# ============================================================
#  start-api.sh — Legacy wrapper (kept for compatibility)
#
#  Prefer using the new script directly:
#    ./scripts/run-api.sh dev    ← local development
#    ./scripts/run-api.sh prod   ← production config
#
#  Environment is now managed via .env.dev / .env.prod
#  See .env.api for the full reference template.
# ============================================================
cd "$(dirname "$0")"
exec ./scripts/run-api.sh dev
