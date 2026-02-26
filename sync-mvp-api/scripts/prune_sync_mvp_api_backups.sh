#!/usr/bin/env bash
set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/opt/sync-mvp-api/backups}"
KEEP_COUNT="${KEEP_COUNT:-10}"
DRY_RUN="${DRY_RUN:-0}"

if ! [[ "$KEEP_COUNT" =~ ^[0-9]+$ ]]; then
  echo "ERROR: KEEP_COUNT must be non-negative integer: $KEEP_COUNT" >&2
  exit 1
fi

if [ ! -d "$BACKUP_DIR" ]; then
  echo "ERROR: backup directory not found: $BACKUP_DIR" >&2
  exit 1
fi

mapfile -t backups < <(find "$BACKUP_DIR" -mindepth 1 -maxdepth 1 -type d -name 'publish-*' | sort)
count="${#backups[@]}"

echo "backup_dir=$BACKUP_DIR"
echo "found=$count keep=$KEEP_COUNT dry_run=$DRY_RUN"

if [ "$count" -le "$KEEP_COUNT" ]; then
  echo "nothing to prune"
  exit 0
fi

prune_count=$((count - KEEP_COUNT))

echo "prune_count=$prune_count"
for ((i=0; i<prune_count; i++)); do
  target="${backups[$i]}"
  if [ "$DRY_RUN" = "1" ]; then
    echo "[dry-run] remove $target"
  else
    echo "remove $target"
    rm -rf "$target"
  fi
done

echo "OK: prune completed"
