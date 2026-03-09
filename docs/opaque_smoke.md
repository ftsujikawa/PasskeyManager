# opaque_smoke（OPAQUE + Vault API スモークテスト）

`sync-axum-api` が提供する OPAQUE 認証（register/login）と Vault API（PUT/GET）が、最低限の往復で動作することを確認するためのスモークテストです。

- 対象バイナリ: `sync-axum-api/src/bin/opaque_smoke.rs`
- 実行方法: `cargo run --bin opaque_smoke -- <args>`

## 1. 事前条件

- `sync-axum-api` が起動していること（デフォルト: `http://127.0.0.1:8088`）
- `cargo` が利用可能であること

### サーバ起動例

```powershell
# リポジトリルートで
cargo run --bin sync-axum-api
```

## 2. 実行例

### デフォルト引数で実行（ローカル開発用）

```powershell
cargo run --bin opaque_smoke
```

### 引数を明示して実行

```powershell
cargo run --bin opaque_smoke -- --base-url http://127.0.0.1:8088 --email alice@example.com --password password
```

- `--base-url`
  - 例: `http://127.0.0.1:8088`
- `--email`
  - Vault の `:email` と JWT の `sub` に相当
- `--password`
  - OPAQUE のパスワード

## 3. 期待される挙動

### 成功条件

- 終了コード `0`
- 以下の一連が完走する
  - **Register**: `/v1/auth/register/start` → `/v1/auth/register/finish`
  - **Login**: `/v1/auth/login/start` → `/v1/auth/login/finish`（JWT 発行）
  - **Vault PUT**: `/v1/vaults/:email`（JWT付き）
  - **Vault GET**: `/v1/vaults/:email`（JWT付き）

### 既存ユーザー/既存 Vault がある場合

このツールは回帰確認向けに、以下を許容する実装になっています。

- **Register の競合（例: HTTP 409）**
  - 既に登録済みユーザーの場合でも、スモークテストが `exit code 1` にならないように許容します。
- **Vault PUT のバージョン競合（HTTP 409 / VERSION_CONFLICT）**
  - サーバが返す `server_version` を取り込み、`expected_server_version` を更新してリトライします。

## 4. よくある失敗と対処

### 4.1 `os error 10048`（ポート競合）

既に同ポートで別プロセスが LISTEN している場合に発生します。

- 対処
  - 既存の `sync-axum-api` プロセスを停止する
  - またはサーバ側の待受ポートを変更する

### 4.2 `401/403`（Unauthorized / Forbidden）

- 原因
  - JWT が未発行/不正
  - `authorize` で `sub` と `:email` が一致していない
- 対処
  - `--email` がサーバが発行した JWT の `sub` と一致しているか確認

### 4.3 `404`（Vault not found）

初回実行や DB 初期状態では Vault が存在しないことがあります。

- 対処
  - `opaque_smoke` は PUT を行うため、通常はその後の GET で 200 になるはずです。
  - GET が 404 のままなら、サーバログ（DB接続やパス、ユーザー正規化）を確認してください。

## 5. CI/回帰確認での使い方（メモ）

- 成功時は `exit code 0`
- ネットワーク依存（サーバ起動が必要）なので、CI で実行する場合は
  - サーバをバックグラウンド起動
  - 起動待ち（health check）
  - `opaque_smoke` 実行
  - サーバ停止
  の順にします。
