#!/usr/bin/env bash
set -euo pipefail

APP_ROOT="${APP_ROOT:-/opt/sync-mvp-api}"
ENV_FILE="${ENV_FILE:-$APP_ROOT/.env}"
SERVICE_NAME="${SERVICE_NAME:-sync-mvp-api}"
HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:8088/healthz}"
BACKUP_DIR="${BACKUP_DIR:-$APP_ROOT/backups}"

echo "== sync-mvp-api status report =="
echo "timestamp_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

echo
echo "[service]"
if systemctl is-active --quiet "$SERVICE_NAME"; then
  echo "active=true"
else
  echo "active=false"
fi
systemctl status "$SERVICE_NAME" --no-pager -n 5 || true

echo
echo "[healthz]"
if health_body="$(curl -fsS "$HEALTH_URL" 2>/dev/null)"; then
  echo "url=$HEALTH_URL"
  echo "$health_body"
else
  echo "url=$HEALTH_URL"
  echo "ERROR: healthz request failed"
fi

echo
echo "[env]"
if [ -f "$ENV_FILE" ]; then
  echo "env_file=$ENV_FILE"
  echo "env_owner_group=$(stat -c '%U:%G' "$ENV_FILE")"
  echo "env_mode=$(stat -c '%a' "$ENV_FILE")"
  if grep -q '^TSUPASSWD_SYNC_BEARER_TOKEN=' "$ENV_FILE"; then
    echo "bearer_token_present=true"
  else
    echo "bearer_token_present=false"
  fi
else
  echo "env_file_missing=$ENV_FILE"
fi

echo
echo "[backups]"
if [ -d "$BACKUP_DIR" ]; then
  echo "backup_dir=$BACKUP_DIR"
  find "$BACKUP_DIR" -mindepth 1 -maxdepth 1 -type d -name 'publish-*' | sort | tail -n 5
else
  echo "backup_dir_missing=$BACKUP_DIR"
fi

echo
echo "[disk]"
df -h "$APP_ROOT" || true

echo
echo "[recent_audit_logs]"
journalctl -u "$SERVICE_NAME" --since "-10 min" --no-pager | grep "audit.vault_op" | tail -n 20 || true
