# Sync MVP API (Self-hosted)

PasskeyManager の `SyncClient` から呼ばれる最小 API です。

- `GET /v1/vaults/{userId}`
- `PUT /v1/vaults/{userId}`
- `Authorization: Bearer <token>` 必須

## 起動

```powershell
# 1) API 側トークン（未設定なら dev-token）
$env:TSUPASSWD_SYNC_DEV_BEARER_TOKEN = "dev-token"

# 1.5) DB保存先（未設定なら 実行フォルダ\vault-store.db）
$env:TSUPASSWD_SYNC_DB_PATH = "c:\\AppPackages\\PasskeyManager\\sync-mvp-api\\data\\vault-store.db"

# 1.6) 旧JSON保存先（初回移行元。未設定なら 実行フォルダ\vault-store.json）
$env:TSUPASSWD_SYNC_STORE_PATH = "c:\\AppPackages\\PasskeyManager\\sync-mvp-api\\data\\vault-store.json"

# 2) 起動
cd c:\AppPackages\PasskeyManager\sync-mvp-api
dotnet run
```

トークン環境変数の優先順位:

1. `TSUPASSWD_SYNC_BEARER_TOKEN`
2. `TSUPASSWD_SYNC_DEV_BEARER_TOKEN`
3. 未設定時は `dev-token`

レート制限の環境変数:

- `TSUPASSWD_SYNC_RATE_LIMIT_PER_MINUTE`（既定: `60`）
- `TSUPASSWD_SYNC_RATE_LIMIT_QUEUE_LIMIT`（既定: `0`）

永続化関連の環境変数:

1. `TSUPASSWD_SYNC_DB_PATH`（保存先SQLite DB）
2. `TSUPASSWD_SYNC_STORE_PATH`（旧JSON。DB空時の初回移行元）

起動URL:
- `http://127.0.0.1:8088`

## PasskeyManager 側の接続設定

PasskeyManager を起動するシェルで設定してください。

```powershell
$env:TSUPASSWD_SYNC_BASE_URL = "http://127.0.0.1:8088/"
$env:TSUPASSWD_SYNC_BEARER_TOKEN = "dev-token"
$env:TSUPASSWD_SYNC_USER_ID = "ContosoUserId"
```

## 疎通確認

### health
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8088/healthz"
```

### 初回 GET（404 expected）
```powershell
$h = @{ Authorization = "Bearer dev-token" }
Invoke-WebRequest -Uri "http://127.0.0.1:8088/v1/vaults/ContosoUserId" -Headers $h
```

### PUT
```powershell
$h = @{ Authorization = "Bearer dev-token"; "Content-Type" = "application/json" }
$body = @"
{
  "expected_version": 0,
  "new_version": 1,
  "device_id": "dev_win_01",
  "vault_blob": {
    "ciphertext_b64": "dGVzdA",
    "nonce_b64": "",
    "aad_b64": "",
    "alg": "AES-256-GCM"
  },
  "key_envelope": {
    "kek_scheme": "passkey+recovery_code_v1",
    "wrapped_dek_b64": "",
    "wrap_nonce_b64": "",
    "kdf_salt_b64": "",
    "kdf_info": "vault-dek-wrap"
  },
  "meta": {
    "blob_sha256_b64": ""
  }
}
"@
Invoke-RestMethod -Method Put -Uri "http://127.0.0.1:8088/v1/vaults/ContosoUserId" -Headers $h -Body $body
```

### GET（保存確認）
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8088/v1/vaults/ContosoUserId" -Headers $h
```

### 403（トークン不一致）
```powershell
$bad = @{ Authorization = "Bearer wrong-token" }
Invoke-WebRequest -Uri "http://127.0.0.1:8088/v1/vaults/ContosoUserId" -Headers $bad
```

### 409（バージョン競合）
```powershell
$h = @{ Authorization = "Bearer dev-token"; "Content-Type" = "application/json" }
$conflictBody = @"
{
  "expected_version": 0,
  "new_version": 2,
  "device_id": "dev_win_02",
  "vault_blob": { "ciphertext_b64": "dGVzdA", "nonce_b64": "", "aad_b64": "", "alg": "AES-256-GCM" },
  "key_envelope": { "kek_scheme": "passkey+recovery_code_v1", "wrapped_dek_b64": "", "wrap_nonce_b64": "", "kdf_salt_b64": "", "kdf_info": "vault-dek-wrap" },
  "meta": { "blob_sha256_b64": "" }
}
"@
Invoke-WebRequest -Method Put -Uri "http://127.0.0.1:8088/v1/vaults/ContosoUserId" -Headers $h -Body $conflictBody
```

### 429（レート制限）
`TSUPASSWD_SYNC_RATE_LIMIT_PER_MINUTE=2` など低めに設定して起動後、短時間に連続リクエストする。

```powershell
$h = @{ Authorization = "Bearer dev-token" }
1..5 | ForEach-Object {
  try {
    Invoke-WebRequest -Uri "http://127.0.0.1:8088/v1/vaults/ContosoUserId" -Headers $h
    "[$_] allowed"
  }
  catch {
    "[$_] status=$($_.Exception.Response.StatusCode.value__)"
  }
}
```

期待値:
- しきい値を超えたリクエストで `429` が返る

## 備考

- このMVPは PUT 後に SQLite DB へ永続化します（再起動後も復元）。
- 保存先は `TSUPASSWD_SYNC_DB_PATH` で変更できます。
- DB が空で旧JSONファイルが存在する場合、起動時に JSON から DB へ一度だけ移行します。
- 本番化時は DB 永続化・TLS・監査ログ・レート制限を追加してください。

## JSON -> DB 移行（運用手順）

1. サービス停止
2. `.env` に `TSUPASSWD_SYNC_DB_PATH` と `TSUPASSWD_SYNC_STORE_PATH` を設定
3. サービス起動（初回起動で DB が空なら自動移行）
4. smoke test（403/200/409）で動作確認

```bash
sudo systemctl restart sync-mvp-api
curl -sS http://127.0.0.1:8088/healthz
```
