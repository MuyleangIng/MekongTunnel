#!/usr/bin/env bash
set -euo pipefail

ENVIRONMENT="${1:-dev}"
BASE_FILE="docker-compose.yml"
OVERRIDE_FILE="docker-compose.${ENVIRONMENT}.yml"
ENV_FILE=".env.compose.${ENVIRONMENT}"

if [[ ! -f "${OVERRIDE_FILE}" ]]; then
  echo "Missing compose override: ${OVERRIDE_FILE}"
  exit 1
fi

if [[ ! -f "${ENV_FILE}" ]]; then
  echo "Missing env file: ${ENV_FILE}"
  echo "Create it from .env.compose.${ENVIRONMENT}.example first."
  exit 1
fi

docker compose \
  --env-file "${ENV_FILE}" \
  -f "${BASE_FILE}" \
  -f "${OVERRIDE_FILE}" \
  run --rm api-init
