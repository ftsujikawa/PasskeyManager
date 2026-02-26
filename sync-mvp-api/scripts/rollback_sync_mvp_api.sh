#!/usr/bin/env bash
set -euo pipefail

APP_ROOT="${APP_ROOT:-/opt/sync-mvp-api}"
PUBLISH_DIR="${PUBLISH_DIR:-$APP_ROOT/publish}"
BACKUP_DIR="${BACKUP_DIR:-$APP_ROOT/backups}"
SERVICE_NAME="${SERVICE_NAME:-sync-mvp-api}"
HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:8088/healthz}"
ROLLBACK_FROM="${1:-${ROLLBACK_FROM:-}}"

if [ ! -d "$BACKUP_DIR" ]; then
  echo "ERROR: backup directory not found: $BACKUP_DIR" >&2
  exit 1
fi

if [ -z "$ROLLBACK_FROM" ]; then
  ROLLBACK_FROM="$(find "$BACKUP_DIR" -mindepth 1 -maxdepth 1 -type d -name 'publish-*' | sort | tail -n 1)"
fi

if [ -z "$ROLLBACK_FROM" ] || [ ! -d "$ROLLBACK_FROM" ]; then
  echo "ERROR: rollback source not found. specify backup path as arg1 or set ROLLBACK_FROM." >&2
  exit 1
fi

echo "Rollback from: $ROLLBACK_FROM"
mkdir -p "$PUBLISH_DIR"
rm -rf "$PUBLISH_DIR"/*
cp -a "$ROLLBACK_FROM"/. "$PUBLISH_DIR"/

echo "Restart service: $SERVICE_NAME"
systemctl restart "$SERVICE_NAME"
systemctl status "$SERVICE_NAME" --no-pager

echo "Health check: $HEALTH_URL"
curl -fsS "$HEALTH_URL" >/dev/null

echo "OK: rollback complete."
