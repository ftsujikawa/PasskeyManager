#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PREFLIGHT_SCRIPT="${PREFLIGHT_SCRIPT:-$SCRIPT_DIR/preflight_sync_mvp_api.sh}"
SMOKE_SCRIPT="${SMOKE_SCRIPT:-$SCRIPT_DIR/smoke_sync_mvp_api.sh}"

BASE_URL="${BASE_URL:-http://127.0.0.1:8088}"
ENV_FILE="${ENV_FILE:-/opt/sync-mvp-api/.env}"
SERVICE_NAME="${SERVICE_NAME:-sync-mvp-api}"

[ -x "$PREFLIGHT_SCRIPT" ] || {
  echo "ERROR: preflight script is not executable: $PREFLIGHT_SCRIPT" >&2
  exit 1
}

[ -x "$SMOKE_SCRIPT" ] || {
  echo "ERROR: smoke script is not executable: $SMOKE_SCRIPT" >&2
  exit 1
}

echo "[1/2] preflight checks"
ENV_FILE="$ENV_FILE" "$PREFLIGHT_SCRIPT"

echo "[2/2] smoke checks"
BASE_URL="$BASE_URL" ENV_FILE="$ENV_FILE" SERVICE_NAME="$SERVICE_NAME" "$SMOKE_SCRIPT"

echo "OK: post-deploy verification completed."
