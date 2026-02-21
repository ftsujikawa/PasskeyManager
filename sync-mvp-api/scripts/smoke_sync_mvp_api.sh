#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:8088}"
ENV_FILE="${ENV_FILE:-/opt/sync-mvp-api/.env}"
SERVICE_NAME="${SERVICE_NAME:-sync-mvp-api}"
USER_ID="${USER_ID:-SmokeUser$(date +%s)}"
BURST_COUNT="${BURST_COUNT:-90}"
EXPECT_429_MIN="${EXPECT_429_MIN:-1}"

if [ -f "$ENV_FILE" ]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

TOKEN="${TOKEN:-${TSUPASSWD_SYNC_BEARER_TOKEN:-${TSUPASSWD_SYNC_DEV_BEARER_TOKEN:-}}}"
if [ -z "$TOKEN" ]; then
  echo "ERROR: token is empty. Set TOKEN or TSUPASSWD_SYNC_BEARER_TOKEN (or TSUPASSWD_SYNC_DEV_BEARER_TOKEN)." >&2
  exit 1
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "[1/6] healthz"
HEALTH_BODY="$TMP_DIR/healthz.json"
HEALTH_CODE="$(curl -sS -o "$HEALTH_BODY" -w "%{http_code}" "$BASE_URL/healthz")"
if [ "$HEALTH_CODE" != "200" ]; then
  echo "ERROR: healthz expected 200, got $HEALTH_CODE" >&2
  cat "$HEALTH_BODY" >&2
  exit 1
fi
if ! grep -q '"ok":true' "$HEALTH_BODY"; then
  echo "ERROR: healthz body does not include \"ok\":true" >&2
  cat "$HEALTH_BODY" >&2
  exit 1
fi

echo "[2/6] 403 wrong token"
R403_BODY="$TMP_DIR/r403.txt"
R403_CODE="$(curl -sS -o "$R403_BODY" -w "%{http_code}" -H "Authorization: Bearer wrong-token" "$BASE_URL/v1/vaults/$USER_ID")"
if [ "$R403_CODE" != "403" ]; then
  echo "ERROR: expected 403, got $R403_CODE" >&2
  cat "$R403_BODY" >&2
  exit 1
fi

echo "[3/6] 200 seed PUT"
PUT200_BODY="$TMP_DIR/put200.json"
PUT200_CODE="$(curl -sS -o "$PUT200_BODY" -w "%{http_code}" -X PUT \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  --data '{
    "expected_version":0,
    "new_version":1,
    "device_id":"ops-smoke",
    "vault_blob":{"ciphertext_b64":"AA==","nonce_b64":"BB==","aad_b64":"CC==","alg":"AES-256-GCM"},
    "key_envelope":{"kek_scheme":"passkey+recovery_code_v1","wrapped_dek_b64":"DD==","wrap_nonce_b64":"EE==","kdf_salt_b64":"FF==","kdf_info":"vault-dek-wrap"},
    "meta":{"blob_sha256_b64":"GG=="}
  }' \
  "$BASE_URL/v1/vaults/$USER_ID")"
if [ "$PUT200_CODE" != "200" ]; then
  echo "ERROR: expected 200 for seed PUT, got $PUT200_CODE" >&2
  cat "$PUT200_BODY" >&2
  exit 1
fi

echo "[4/6] 200 GET"
GET200_BODY="$TMP_DIR/get200.json"
GET200_CODE="$(curl -sS -o "$GET200_BODY" -w "%{http_code}" -H "Authorization: Bearer $TOKEN" "$BASE_URL/v1/vaults/$USER_ID")"
if [ "$GET200_CODE" != "200" ]; then
  echo "ERROR: expected 200 for GET, got $GET200_CODE" >&2
  cat "$GET200_BODY" >&2
  exit 1
fi

echo "[5/6] 409 stale PUT"
R409_BODY="$TMP_DIR/r409.json"
R409_CODE="$(curl -sS -o "$R409_BODY" -w "%{http_code}" -X PUT \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  --data '{
    "expected_version":0,
    "new_version":2,
    "device_id":"ops-smoke-2",
    "vault_blob":{"ciphertext_b64":"AA==","nonce_b64":"BB==","aad_b64":"CC==","alg":"AES-256-GCM"},
    "key_envelope":{"kek_scheme":"passkey+recovery_code_v1","wrapped_dek_b64":"DD==","wrap_nonce_b64":"EE==","kdf_salt_b64":"FF==","kdf_info":"vault-dek-wrap"},
    "meta":{"blob_sha256_b64":"GG=="}
  }' \
  "$BASE_URL/v1/vaults/$USER_ID")"
if [ "$R409_CODE" != "409" ]; then
  echo "ERROR: expected 409, got $R409_CODE" >&2
  cat "$R409_BODY" >&2
  exit 1
fi
if ! grep -q '"VERSION_CONFLICT"' "$R409_BODY"; then
  echo "ERROR: 409 body does not include VERSION_CONFLICT" >&2
  cat "$R409_BODY" >&2
  exit 1
fi

echo "[6/6] 429 burst check"
BURST_CODES="$TMP_DIR/burst_codes.txt"
for i in $(seq 1 "$BURST_COUNT"); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -H "Authorization: Bearer $TOKEN" \
    "$BASE_URL/v1/vaults/$USER_ID" >> "$BURST_CODES"
done

COUNT_429="$(grep -c '^429$' "$BURST_CODES" || true)"
if [ "${COUNT_429:-0}" -lt "$EXPECT_429_MIN" ]; then
  echo "ERROR: expected at least $EXPECT_429_MIN responses with 429, got ${COUNT_429:-0}" >&2
  sort "$BURST_CODES" | uniq -c >&2
  exit 1
fi
sort "$BURST_CODES" | uniq -c

echo "[audit] audit.vault_op for 403/409"
if ! journalctl -u "$SERVICE_NAME" --since "-10 min" --no-pager | grep "audit.vault_op" | grep -E "auth_token_mismatch|version_conflict"; then
  echo "ERROR: expected audit.vault_op logs for auth_token_mismatch/version_conflict" >&2
  exit 1
fi

echo "OK: smoke test passed (403/200/409/429 + audit)."
