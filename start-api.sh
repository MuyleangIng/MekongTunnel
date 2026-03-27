#!/usr/bin/env bash
# ============================================================
#  start-api.sh — Legacy wrapper (kept for compatibility)
#
#  Prefer using the new script directly:
#    ./scripts/run-api.sh dev    ← local development
#    ./scripts/run-api.sh prod   ← production config
#
#  Environment is now managed via .env.dev / .env.prod
#  See .env.dev.example / .env.prod.example for the templates.
# ============================================================
cd "$(dirname "$0")"
exec ./scripts/run-api.sh dev
