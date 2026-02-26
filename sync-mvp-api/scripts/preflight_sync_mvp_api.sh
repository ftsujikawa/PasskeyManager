#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${ENV_FILE:-/opt/sync-mvp-api/.env}"
SERVICE_FILE="${SERVICE_FILE:-/etc/systemd/system/sync-mvp-api.service}"
NGINX_SITE_FILE="${NGINX_SITE_FILE:-/etc/nginx/sites-available/sync-mvp-api}"
HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:8088/healthz}"

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

check_file() {
  local path="$1"
  [ -f "$path" ] || fail "missing file: $path"
}

echo "[1/7] check files"
check_file "$ENV_FILE"
check_file "$SERVICE_FILE"
check_file "$NGINX_SITE_FILE"

echo "[2/7] check required env keys"
grep -q '^TSUPASSWD_SYNC_BEARER_TOKEN=' "$ENV_FILE" || fail "missing TSUPASSWD_SYNC_BEARER_TOKEN in $ENV_FILE"
grep -q '^TSUPASSWD_SYNC_DB_PATH=' "$ENV_FILE" || fail "missing TSUPASSWD_SYNC_DB_PATH in $ENV_FILE"

echo "[3/7] check env file permissions"
owner_group="$(stat -c '%U:%G' "$ENV_FILE")"
mode="$(stat -c '%a' "$ENV_FILE")"
[ "$owner_group" = "root:root" ] || fail "unexpected owner/group for $ENV_FILE: $owner_group (expected root:root)"
[ "$mode" = "600" ] || fail "unexpected mode for $ENV_FILE: $mode (expected 600)"

echo "[4/7] check service unit syntax"
systemd-analyze verify "$SERVICE_FILE" >/dev/null

echo "[5/7] check nginx config syntax"
nginx -t >/dev/null

echo "[6/7] check service active"
systemctl is-active --quiet sync-mvp-api || fail "service is not active: sync-mvp-api"

echo "[7/7] health check"
curl -fsS "$HEALTH_URL" >/dev/null || fail "health check failed: $HEALTH_URL"

echo "OK: preflight passed."
