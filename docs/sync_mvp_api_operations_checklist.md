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
- `db_reachable=true` が返る
- `vault_count` が数値で返る
- `token_source` が返る（トークン値そのものは返らない）

異常系（DB未到達）の期待値:
- HTTP `503`
- `ok=false`
- `db_error` にエラー種別が入る

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

### 3.1 スモーク自動実行（推奨）

手動実行の代わりに、以下スクリプトで `403/200/409/429 + audit` を一括検証できる。

```bash
chmod +x scripts/smoke_sync_mvp_api.sh
sudo ./scripts/smoke_sync_mvp_api.sh
```

必要時のみ上書きする主な変数:

- `BASE_URL`（既定: `http://127.0.0.1:8088`）
- `ENV_FILE`（既定: `/opt/sync-mvp-api/.env`）
- `SERVICE_NAME`（既定: `sync-mvp-api`）
- `BURST_COUNT`（既定: `90`）

期待値:

- 終了コード `0`
- 末尾に `OK: smoke test passed (403/200/409/429 + audit).`

## 4. ログ監視

```bash
sudo journalctl -u sync-mvp-api -n 200 --no-pager
sudo journalctl -u sync-mvp-api -f
```

確認ポイント:
- 連続クラッシュがない
- 5xx 相当のエラーが急増していない

### 4.1 監査ログ（vault 操作）確認

監査ログは `audit.vault_op` プレフィックスで出力される。主な確認コマンド:

```bash
sudo journalctl -u sync-mvp-api --since "-10 min" --no-pager | grep "audit.vault_op"
```

期待値（例）:
- `method` に `GET` / `PUT` が出る
- `path` が `/v1/vaults/{userId}` 系で出る
- `result_code` に `200` / `403` / `409`（必要に応じて `401` / `404`）が出る
- `request_id` が出る（同一リクエスト追跡に利用）
- `user_id` / `remote_addr` が出る
- vault 本文（`ciphertext_b64` 等）が出力されない

### 4.2 ログ保管期間・ローテーション方針

- 保管期間: `journalctl` を 30 日保持（または運用要件に合わせて延長）
- ローテーション: systemd-journald のサイズ上限を設定し、ディスク逼迫を防ぐ

設定例（`/etc/systemd/journald.conf`）:

```ini
[Journal]
SystemMaxUse=1G
MaxRetentionSec=30day
```

反映:

```bash
sudo systemctl restart systemd-journald
sudo journalctl --disk-usage
```

## 5. nginx / TLS 確認

```bash
sudo nginx -t
sudo systemctl reload nginx
sudo certbot certificates
```

確認ポイント:
- `nginx -t` が成功
- 証明書期限が十分残っている

### 5.1 TLS 設定を厳格化する（初回または設定変更時）

`/etc/nginx/sites-available/tsupasswd.com`（実運用の server ブロック）で、少なくとも以下を満たす:

- `ssl_protocols TLSv1.2 TLSv1.3;`
- 弱い暗号/古いプロトコルを許可しない
- `server_tokens off;`

反映コマンド:

```bash
sudo nginx -t
sudo systemctl reload nginx
```

### 5.2 セキュリティヘッダを有効化する

同じ server ブロックで、以下ヘッダを有効化する（`always` 推奨）:

```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```

反映後の確認:

```bash
curl -I https://tsupasswd.com/healthz
```

期待値:
- `Strict-Transport-Security` が含まれる
- `X-Content-Type-Options: nosniff` が含まれる
- `X-Frame-Options: DENY` が含まれる
- `Referrer-Policy` が含まれる

### 5.3 既存 API フロー退行確認

ヘッダ/TLS 変更後に、必ず 403/200/409 スモークテスト（本チェックリストの「3」）を再実施する。

### 5.4 nginx `server` ブロック最小サンプル

`/etc/nginx/sites-available/tsupasswd.com` の例（環境に応じて `server_name` と証明書パスを調整）:

```nginx
server {
    listen 443 ssl http2;
    server_name tsupasswd.com;

    ssl_certificate /etc/letsencrypt/live/tsupasswd.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/tsupasswd.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    server_tokens off;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    location / {
        proxy_pass http://127.0.0.1:8088;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

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

## 7. 成果物配置運用のデプロイ自動化

本番サーバーが Git clone ではなく `/opt/sync-mvp-api/publish` に成果物配置する構成向け。

### 7.1 Windows 側で成果物を作成

```bat
sync-mvp-api\scripts\package_sync_mvp_api.cmd
```

出力物:

- `sync-mvp-api\sync-mvp-api-publish.tar.gz`

### 7.2 VPS で反映

tar.gz を `/tmp/sync-mvp-api-publish.tar.gz` へ転送後、以下を実行:

```bash
chmod +x scripts/deploy_sync_mvp_api_publish.sh
sudo ./scripts/deploy_sync_mvp_api_publish.sh /tmp/sync-mvp-api-publish.tar.gz
```

期待値:

- `systemctl status sync-mvp-api` が `active (running)`
- `curl -sS http://127.0.0.1:8088/healthz` が `{"ok":true,...}` を返す
