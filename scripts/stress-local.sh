#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:8080}"
USERS="${USERS:-1000}"
TUNNELS="${TUNNELS:-5000}"
CONCURRENCY="${CONCURRENCY:-100}"

go run ./cmd/apibench \
  -base-url "${BASE_URL}" \
  -mode full \
  -users "${USERS}" \
  -tunnels "${TUNNELS}" \
  -concurrency "${CONCURRENCY}"
