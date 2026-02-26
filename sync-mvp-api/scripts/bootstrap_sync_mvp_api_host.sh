#!/usr/bin/env bash
set -euo pipefail

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  echo "ERROR: run as root (sudo)." >&2
  exit 1
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_ROOT="${SOURCE_ROOT:-$(cd -- "$SCRIPT_DIR/.." && pwd)}"
APP_ROOT="${APP_ROOT:-/opt/sync-mvp-api}"
APP_USER="${APP_USER:-www-data}"
APP_GROUP="${APP_GROUP:-www-data}"

SERVICE_DST="/etc/systemd/system/sync-mvp-api.service"
TIMER_SERVICE_DST="/etc/systemd/system/sync-mvp-api-maintenance.service"
TIMER_DST="/etc/systemd/system/sync-mvp-api-maintenance.timer"
NGINX_DST="/etc/nginx/sites-available/sync-mvp-api"

mkdir -p "$APP_ROOT"
install -d -m 750 -o "$APP_USER" -g "$APP_GROUP" "$APP_ROOT/data"
install -d -m 755 "$APP_ROOT/scripts"

cp "$SOURCE_ROOT/.env.example" "$APP_ROOT/.env"
cp "$SOURCE_ROOT/scripts/sync-mvp-api.service.example" "$SERVICE_DST"
cp "$SOURCE_ROOT/scripts/sync-mvp-api-maintenance.service.example" "$TIMER_SERVICE_DST"
cp "$SOURCE_ROOT/scripts/sync-mvp-api-maintenance.timer.example" "$TIMER_DST"
cp "$SOURCE_ROOT/scripts/nginx-sync-mvp-api.conf.example" "$NGINX_DST"

cp "$SOURCE_ROOT/scripts/prune_sync_mvp_api_backups.sh" "$APP_ROOT/scripts/"
cp "$SOURCE_ROOT/scripts/report_sync_mvp_api_status.sh" "$APP_ROOT/scripts/"
cp "$SOURCE_ROOT/scripts/preflight_sync_mvp_api.sh" "$APP_ROOT/scripts/"
cp "$SOURCE_ROOT/scripts/smoke_sync_mvp_api.sh" "$APP_ROOT/scripts/"
cp "$SOURCE_ROOT/scripts/rotate_sync_mvp_api_token.sh" "$APP_ROOT/scripts/"
cp "$SOURCE_ROOT/scripts/rollback_sync_mvp_api.sh" "$APP_ROOT/scripts/"
cp "$SOURCE_ROOT/scripts/post_deploy_verify_sync_mvp_api.sh" "$APP_ROOT/scripts/"

chown root:root "$APP_ROOT/.env"
chmod 600 "$APP_ROOT/.env"
chmod +x "$APP_ROOT"/scripts/*.sh

ln -sf "$NGINX_DST" /etc/nginx/sites-enabled/sync-mvp-api

systemctl daemon-reload
systemctl enable sync-mvp-api
systemctl enable --now sync-mvp-api-maintenance.timer

echo "OK: bootstrap completed."
echo "Next: set production token in $APP_ROOT/.env, then start service."
