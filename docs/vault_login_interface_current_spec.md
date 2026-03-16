# Vault Login Interface Current Spec

この文書は、**現在の実装に基づく** Vault Login 情報インターフェース仕様をまとめたものです。

対象実装:

- `tsupasswd_js/background.js`
- `tsupasswd_js/popup.js`
- `tsupasswd_js/content-script.js`
- `tsupasswd_js/native-host/VaultHost/Program.cs`

この文書は、`docs/chrome_native_messaging_host.md` にある本体 Native Host 前提の仕様ではなく、**拡張側で現在実際に使われている Vault Host 実装**を正として記述します。

## 構成

Vault Login 情報は次の 3 層で取り扱います。

- Chrome 拡張 UI 層
  - popup (`popup.js`)
  - content script (`content-script.js`)
- Chrome 拡張 background 中継層
  - `background.js`
- Native Messaging Vault Host
  - `native-host/VaultHost/Program.cs`

## Native Messaging request 形式

基本 request 形式は次のとおりです。

```json
{
  "id": "vault-list-1",
  "version": 1,
  "command": "vault.login.list",
  "payload": {
    "includeDeleted": false,
    "requestId": "vault-list-1"
  }
}
```

### 共通フィールド

- `id`
  - リクエスト識別子
- `version`
  - 現在は `1`
- `command`
  - 実行コマンド名
- `payload`
  - コマンドごとの入力

## Native Messaging response 形式

成功時の基本形:

```json
{
  "ok": true,
  "id": "vault-list-1",
  "command": "vault.login.list",
  "result": {
    "items": []
  }
}
```

失敗時の基本形:

```json
{
  "ok": false,
  "id": "vault-list-1",
  "command": "vault.login.list",
  "error": "invalid_argument",
  "detail": "itemId is required."
}
```

## background 経由の拡張内メッセージ

Vault 用には次の message type を使います。

- `vault-connect`
- `vault-request`
- `vault-request-await`

`vault-request-await` の送信例:

```json
{
  "type": "vault-request-await",
  "target": "vault",
  "payload": {
    "id": "vault-list-1",
    "version": 1,
    "command": "vault.login.list",
    "payload": {
      "includeDeleted": false,
      "requestId": "vault-list-1"
    }
  }
}
```

background からの応答例:

```json
{
  "ok": true,
  "payload": {
    "ok": true,
    "id": "vault-list-1",
    "command": "vault.login.list",
    "result": {
      "items": []
    }
  },
  "raw": {
    "ok": true,
    "id": "vault-list-1",
    "command": "vault.login.list",
    "result": {
      "items": []
    }
  },
  "target": "vault"
}
```

## サポート command

現在の Vault Host 実装でサポートしている command は次のとおりです。

- `vault.status.get`
- `vault.login.list`
- `vault.login.save`
- `vault.login.update`
- `vault.login.delete`
- `vault.sync.resync`
- `vault.sync.push`

## Vault item データ構造

現在の実装で扱う Login item は概ね次の形です。

```json
{
  "itemId": "string",
  "title": "string",
  "username": "string",
  "password": "string",
  "url": "string",
  "notes": "string",
  "createdAt": "2026-03-15T12:34:56+00:00",
  "updatedAt": "2026-03-15T12:34:56+00:00",
  "deleted": false
}
```

### 注意

- `password` は **list 結果にも含まれうる**
- delete は物理削除ではなく **論理削除**
- 一覧取得時は `includeDeleted: false` が標準

## `vault.status.get`

Vault store の状態を返します。

### request

```json
{
  "id": "vault-status-1",
  "version": 1,
  "command": "vault.status.get",
  "payload": {
    "requestId": "vault-status-1"
  }
}
```

### response

```json
{
  "ok": true,
  "id": "vault-status-1",
  "command": "vault.status.get",
  "result": {
    "storePath": "C:\\Users\\user\\AppData\\Local\\tsupasswd\\vault-store.json",
    "nowUtc": "2026-03-15T12:34:56+00:00"
  }
}
```

## `vault.login.list`

Vault Login 一覧を返します。

### request

```json
{
  "id": "vault-list-1",
  "version": 1,
  "command": "vault.login.list",
  "payload": {
    "includeDeleted": false,
    "requestId": "vault-list-1"
  }
}
```

### request フィールド

- `includeDeleted`
  - `true` の場合は deleted item も返す
  - popup / content script では通常 `false`

### response

```json
{
  "ok": true,
  "id": "vault-list-1",
  "command": "vault.login.list",
  "result": {
    "items": [
      {
        "itemId": "abc123",
        "title": "Example",
        "username": "alice",
        "password": "secret",
        "url": "https://example.com",
        "notes": "",
        "createdAt": "2026-03-15T12:34:56+00:00",
        "updatedAt": "2026-03-15T12:34:56+00:00",
        "deleted": false
      }
    ]
  }
}
```

## `vault.login.save`

新しい Login item を保存します。

### request

```json
{
  "id": "vault-save-1",
  "version": 1,
  "command": "vault.login.save",
  "payload": {
    "title": "Example",
    "username": "alice",
    "password": "secret",
    "url": "https://example.com",
    "notes": "",
    "resync": false,
    "requestId": "vault-save-1"
  }
}
```

### request フィールド

- `title`
- `username`
- `password`
- `url`
- `notes`
- `resync`
  - `true` の場合は保存後に sync を実行
  - popup の現在実装では `false`
  - content script の保存経路では `true`
- `requestId`

### response

```json
{
  "ok": true,
  "id": "vault-save-1",
  "command": "vault.login.save",
  "result": {
    "itemId": "generated-id"
  }
}
```

`resync: true` の場合:

```json
{
  "ok": true,
  "id": "vault-save-1",
  "command": "vault.login.save",
  "result": {
    "itemId": "generated-id",
    "sync": {}
  }
}
```

## `vault.login.update`

既存 item を更新します。

### request

```json
{
  "id": "vault-update-1",
  "version": 1,
  "command": "vault.login.update",
  "payload": {
    "itemId": "existing-id",
    "title": "Example",
    "username": "alice",
    "password": "secret",
    "url": "https://example.com",
    "notes": "",
    "resync": false,
    "requestId": "vault-update-1"
  }
}
```

### 必須フィールド

- `itemId`

### 成功 response

```json
{
  "ok": true,
  "id": "vault-update-1",
  "command": "vault.login.update",
  "result": {
    "itemId": "existing-id"
  }
}
```

### 失敗 response

```json
{
  "ok": false,
  "id": "vault-update-1",
  "command": "vault.login.update",
  "error": "invalid_argument",
  "detail": "itemId is required."
}
```

または:

```json
{
  "ok": false,
  "id": "vault-update-1",
  "command": "vault.login.update",
  "error": "not_found",
  "detail": "itemId was not found."
}
```

## `vault.login.delete`

既存 item を論理削除します。

### request

```json
{
  "id": "vault-delete-1",
  "version": 1,
  "command": "vault.login.delete",
  "payload": {
    "itemId": "existing-id",
    "resync": true,
    "requestId": "vault-delete-1"
  }
}
```

### 動作

- `deleted = true` に更新
- `updatedAt` を更新
- 物理削除はしない

### response

```json
{
  "ok": true,
  "id": "vault-delete-1",
  "command": "vault.login.delete",
  "result": {
    "itemId": "existing-id"
  }
}
```

## `vault.sync.resync`

sync API から最新状態を取得して、ローカル store を更新します。

### request

```json
{
  "id": "vault-resync-1",
  "version": 1,
  "command": "vault.sync.resync",
  "payload": {
    "email": "user@example.com",
    "baseUrl": "http://127.0.0.1:8088",
    "requestId": "vault-resync-1"
  }
}
```

### 入力元

- `payload.email`
- 環境変数 `TSUPASSWD_SYNC_EMAIL`
- `payload.baseUrl`
- 環境変数 `TSUPASSWD_SYNC_BASE_URL`
- 未指定時の `baseUrl` 既定値は `http://127.0.0.1:8088`

### 成功 response

```json
{
  "ok": true,
  "id": "vault-resync-1",
  "command": "vault.sync.resync",
  "result": {
    "resync": true,
    "source": "sync-axum-api",
    "server_version": 123,
    "updated_at": "2026-03-15T12:34:56+00:00",
    "applied_item_count": 5,
    "storePath": "C:\\Users\\user\\AppData\\Local\\tsupasswd\\vault-store.json"
  }
}
```

### 主な失敗コード

- `invalid_argument`
  - `email` 不足
- `sync_login_failed`
- `sync_pull_failed`
- `sync_cipher_blob_unsupported`

## `vault.sync.push`

Vault Host 側で実装されています。

現在の popup 主導のメイン動線では `vault.sync.resync` と、`save/update/delete` の `resync` 制御が主に使われます。

## popup UI の現在仕様

popup では次の操作を提供します。

- Vault host 接続確認
- Vault status 確認
- Vault login 一覧表示
- Vault login 保存
- Vault login 更新
- Vault login 削除
- Vault resync

### 一覧表示

表示列:

- `title`
- `username`
- `url`
- `password` のマスク表示と Copy ボタン
- `itemId`

### フォーム反映

一覧行をクリックすると、次の入力欄に反映されます。

- `vaultItemId`
- `vaultTitle`
- `vaultUsername`
- `vaultUrl`
- `vaultNotes`

### popup 保存仕様

`vault.login.save` 送信時の現在仕様:

- `password` 必須
- `resync: false`
- 保存成功時は popup 側の password キャッシュに保持
- 保存後に一覧を再読込
- `vault.status.get` の結果も UI 表示に含める

### popup 更新仕様

`vault.login.update` 送信時の現在仕様:

- `itemId` 必須
- `password` 必須
- `resync: false`
- 成功時は password キャッシュ更新

### popup 削除仕様

`vault.login.delete` 送信時の現在仕様:

- `itemId` 必須
- `resync: true`

### popup resync 仕様

- `vault.sync.resync` を送る
- `payload` JSON は UI テキストエリアから一部上書き可能
- 実行開始時に一時的に `running` 状態を表示する

## content script の現在仕様

content script には Vault Login 用 helper があります。

### `requestVaultLoginSave`

- `vault.login.save` を送信
- `resync: true`

### `requestVaultLoginList`

- `vault.login.list` を送信
- `includeDeleted: false`
- 取得後、ページ host / `rpId` 前提で利用する

## 旧 passkey API との互換変換

background では、旧 passkey 形式の一部を Vault API に変換します。

### 変換ルール

- `list_passkeys` -> `vault.login.list`
- `add_passkey` -> `vault.login.save`
- `remove_passkey` -> `vault.login.delete`

### Vault item の passkey 互換形式

```json
{
  "id": "itemId",
  "title": "title",
  "rpId": "url から導出した host",
  "user": "username",
  "password": "password",
  "source": "tsupasswd_core",
  "backedUp": false,
  "removable": true,
  "vault": true,
  "notes": "notes",
  "url": "url",
  "updatedAt": "2026-03-15T12:34:56+00:00",
  "createdAt": "2026-03-15T12:34:56+00:00"
}
```

## 既知の差異

`docs/chrome_native_messaging_host.md` には次のような差異があります。

- 本体 `tsupasswd_core.exe` を前提に記述されている
- `vault.login.get` を含むが、現在の拡張側 VaultHost 実装には存在しない
- `vault.login.list` は password を返さない前提で書かれているが、現行 VaultHost 実装では password を返しうる
- `save/update/delete` の `resync` の既定的な扱いが現行 popup 実装と一致しない

このため、現時点の挙動確認・実装参照には本ドキュメントを優先します。
