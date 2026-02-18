# Sync MVP API (Self-hosted)

PasskeyManager の `SyncClient` から呼ばれる最小 API です。

- `GET /v1/vaults/{userId}`
- `PUT /v1/vaults/{userId}`
- `Authorization: Bearer <token>` 必須

## 起動

```powershell
# 1) API 側トークン（未設定なら dev-token）
$env:TSUPASSWD_SYNC_DEV_BEARER_TOKEN = "dev-token"

# 1.5) 保存ファイル（未設定なら 実行フォルダ\vault-store.json）
$env:TSUPASSWD_SYNC_STORE_PATH = "c:\\AppPackages\\PasskeyManager\\sync-mvp-api\\data\\vault-store.json"

# 2) 起動
cd c:\AppPackages\PasskeyManager\sync-mvp-api
dotnet run
```

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

## 備考

- このMVPは PUT 後に JSON ファイルへ永続化します（再起動後も復元）。
- 保存先は `TSUPASSWD_SYNC_STORE_PATH` で変更できます。
- 本番化時は DB 永続化・TLS・監査ログ・レート制限を追加してください。
