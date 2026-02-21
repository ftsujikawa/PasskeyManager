# sync-mvp-api 運用チェックリスト

対象: Ubuntu + systemd + nginx + Let's Encrypt 構成

## 1. systemd 稼働確認

```bash
sudo systemctl daemon-reload
sudo systemctl enable sync-mvp-api
sudo systemctl restart sync-mvp-api
sudo systemctl status sync-mvp-api --no-pager
```

期待値:
- `active (running)`
- 再起動後も自動起動 (`enabled`)

## 2. API ヘルス確認（サーバー内）

```bash
curl -sS http://127.0.0.1:8088/healthz
```

期待値:
- `{"ok":true,...}` が返る
- `db_path` が期待する SQLite ファイルを指す

### 2.1 JSON -> DB 初回移行の確認

前提: `.env` に `TSUPASSWD_SYNC_DB_PATH` と `TSUPASSWD_SYNC_STORE_PATH` を設定済み。

```bash
sudo systemctl restart sync-mvp-api
curl -sS http://127.0.0.1:8088/healthz
```

確認ポイント:
- `db_path` が想定パスである
- その後の 403/200/409 スモーク（本チェックリストの「3」）が成功する

## 3. API スモークテスト（403 / 200 / 409）

### シェル再接続時の事前手順（401 防止）

```bash
set -a
source /opt/sync-mvp-api/.env
set +a
TOKEN="${TSUPASSWD_SYNC_BEARER_TOKEN:-$TSUPASSWD_SYNC_DEV_BEARER_TOKEN}"
echo "TOKEN_LEN=${#TOKEN}"
```

確認ポイント:
- `TOKEN_LEN` が `0` でないこと
- `TOKEN` が空の場合は以降の API 呼び出しを実行しないこと

```bash
TOKEN="<TSUPASSWD_SYNC_BEARER_TOKEN>"
BASE="https://tsupasswd.com"
USER="SmokeUser$(date +%s)"

# 403 (不正トークン)
curl -i -H "Authorization: Bearer wrong-token" "$BASE/v1/vaults/$USER"

# 200 (初回PUT)
curl -i -X PUT "$BASE/v1/vaults/$USER" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  --data '{
    "expected_version": 0,
    "new_version": 1,
    "device_id": "ops-check",
    "vault_blob": {"ciphertext_b64":"AA==","nonce_b64":"BB==","aad_b64":"CC==","alg":"AES-256-GCM"},
    "key_envelope": {"kek_scheme":"passkey+recovery_code_v1","wrapped_dek_b64":"DD==","wrap_nonce_b64":"EE==","kdf_salt_b64":"FF==","kdf_info":"vault-dek-wrap"},
    "meta": {"blob_sha256_b64":"GG=="}
  }'

# 409 (競合PUT)
curl -i -X PUT "$BASE/v1/vaults/$USER" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  --data '{
    "expected_version": 0,
    "new_version": 2,
    "device_id": "ops-check-2",
    "vault_blob": {"ciphertext_b64":"AA==","nonce_b64":"BB==","aad_b64":"CC==","alg":"AES-256-GCM"},
    "key_envelope": {"kek_scheme":"passkey+recovery_code_v1","wrapped_dek_b64":"DD==","wrap_nonce_b64":"EE==","kdf_salt_b64":"FF==","kdf_info":"vault-dek-wrap"},
    "meta": {"blob_sha256_b64":"GG=="}
  }'
```

期待値:
- 403 テスト: HTTP 403
- 初回PUT: HTTP 200
- 競合PUT: HTTP 409 (`server_version` を含む)

## 4. ログ監視

```bash
sudo journalctl -u sync-mvp-api -n 200 --no-pager
sudo journalctl -u sync-mvp-api -f
```

確認ポイント:
- 連続クラッシュがない
- 5xx 相当のエラーが急増していない

## 5. nginx / TLS 確認

```bash
sudo nginx -t
sudo systemctl reload nginx
sudo certbot certificates
```

確認ポイント:
- `nginx -t` が成功
- 証明書期限が十分残っている

## 6. 障害時の初動

```bash
sudo systemctl restart sync-mvp-api
sudo journalctl -u sync-mvp-api -n 200 --no-pager
curl -i http://127.0.0.1:8088/healthz
```

再発時は以下を記録:
- 発生時刻
- 直前のデプロイ/設定変更
- `journalctl` の該当ログ
- `curl` のレスポンス（HTTPコードと本文）
