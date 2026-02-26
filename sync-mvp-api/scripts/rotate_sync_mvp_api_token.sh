#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${ENV_FILE:-/opt/sync-mvp-api/.env}"
SERVICE_NAME="${SERVICE_NAME:-sync-mvp-api}"
HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:8088/healthz}"
BACKUP_PATH="${BACKUP_PATH:-${ENV_FILE}.bak.$(date +%Y%m%d%H%M%S)}"

if [ ! -f "$ENV_FILE" ]; then
  echo "ERROR: env file not found: $ENV_FILE" >&2
  exit 1
fi

NEW_TOKEN="$(openssl rand -base64 48 | tr -d '\n')"
if [ -z "$NEW_TOKEN" ]; then
  echo "ERROR: generated token is empty" >&2
  exit 1
fi

cp "$ENV_FILE" "$BACKUP_PATH"

echo "backup saved: $BACKUP_PATH"

if grep -q '^TSUPASSWD_SYNC_BEARER_TOKEN=' "$ENV_FILE"; then
  sed -i "s#^TSUPASSWD_SYNC_BEARER_TOKEN=.*#TSUPASSWD_SYNC_BEARER_TOKEN=${NEW_TOKEN}#" "$ENV_FILE"
else
  printf '\nTSUPASSWD_SYNC_BEARER_TOKEN=%s\n' "$NEW_TOKEN" >> "$ENV_FILE"
fi

chown root:root "$ENV_FILE"
chmod 600 "$ENV_FILE"

echo "restarting service: $SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

echo "health check: $HEALTH_URL"
curl -fsS "$HEALTH_URL" >/dev/null

echo "OK: token rotated and service healthy."
echo "IMPORTANT: update PasskeyManager clients with the new bearer token."
