#!/usr/bin/env bash
set -euo pipefail

ARTIFACT_TAR="${1:-${ARTIFACT_TAR:-/tmp/sync-mvp-api-publish.tar.gz}}"
APP_ROOT="${APP_ROOT:-/opt/sync-mvp-api}"
PUBLISH_DIR="${PUBLISH_DIR:-$APP_ROOT/publish}"
SERVICE_NAME="${SERVICE_NAME:-sync-mvp-api}"
APP_USER="${APP_USER:-www-data}"
APP_GROUP="${APP_GROUP:-www-data}"

if [ ! -f "$ARTIFACT_TAR" ]; then
  echo "ERROR: artifact not found: $ARTIFACT_TAR" >&2
  echo "Usage: $0 /path/to/sync-mvp-api-publish.tar.gz" >&2
  exit 1
fi

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

echo "Extract: $ARTIFACT_TAR"
tar -xzf "$ARTIFACT_TAR" -C "$WORK_DIR"

if [ ! -f "$WORK_DIR/SyncMvpApi.dll" ]; then
  echo "ERROR: SyncMvpApi.dll not found in artifact root" >&2
  exit 1
fi

echo "Deploy to: $PUBLISH_DIR"
mkdir -p "$PUBLISH_DIR"
rm -rf "$PUBLISH_DIR"/*
cp -a "$WORK_DIR"/. "$PUBLISH_DIR"/

chown -R "$APP_USER":"$APP_GROUP" "$PUBLISH_DIR"

if [ -f "$APP_ROOT/.env" ]; then
  chown "$APP_USER":"$APP_GROUP" "$APP_ROOT/.env"
fi

echo "Restart service: $SERVICE_NAME"
systemctl restart "$SERVICE_NAME"
systemctl status "$SERVICE_NAME" --no-pager

echo "Health check"
curl -sS http://127.0.0.1:8088/healthz

echo
echo "OK: deploy complete."
