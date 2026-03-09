# sync_opaque_export_key_operations

OPAQUE export key 永続化、Vault sync、復旧導線、verbose debug の運用手順です。

## 1. 概要

この変更で以下を実装しています。

- OPAQUE register 時に export key を取得
- export key を DPAPI で保護してレジストリ保存
- 起動後に export key を再読み込み
- `put_vault` で export key を使った wrap
- `restore_snapshot` で export key を使った unwrap
- 旧 session-key wrap データに対する復旧導線ログ
- verbose debug フラグによる詳細 `OutputDebugStringW` 制御

## 2. 関連する環境変数

### 必須

- `TSUPASSWD_SYNC_BASE_URL`
- `TSUPASSWD_SYNC_USER_ID`
- `TSUPASSWD_VAULT_RECOVERY_CODE`

### 任意

- `TSUPASSWD_SYNC_ALLOW_INSECURE_HTTP=1`
- `TSUPASSWD_SYNC_OPAQUE_SESSION_WRAP=1`
- `TSUPASSWD_SYNC_VERBOSE_DEBUG=1`
- `TSUPASSWD_PLUGIN_PERSIST_GET_ASSERTION_INFO=1`

## 3. 基本確認手順

### 3.1 初回作成と同期

- passkey を作成する
- `manual_resync` を実行する
- `restore_snapshot` を実行する

### 3.2 期待ログ

以下が出れば最低限の往復は成功です。

- `step=opaque_login_token_issued`
- `sync result=success operation=put_vault`
- `summary result=success operation=manual_resync`
- `sync result=success operation=restore_snapshot`

### 3.3 wrap 関連の補助ログ

`TSUPASSWD_SYNC_OPAQUE_SESSION_WRAP=1` のとき、以下のログで挙動を判別できます。

- `step=sync_wrap_skipped reason=opaque_export_key_missing fallback=plaintext_cipher`
- `reason=sync_wrap_failed ... fallback=plaintext_cipher fail_mode=fail_open`

現在の実装は互換性優先で **fail-open** です。wrap に失敗しても sync 自体は継続し、平文 cipher を送ります。

## 4. export key 永続化確認

### 保存先

- `HKCU\\Software\\HappyFactory\\PasskeyManager`

### 対象値

- `OpaqueExportKeyProtected`

### 期待状態

- 値が存在する
- `REG_BINARY`
- 平文ではない

## 5. 旧 session-key wrap データの復旧手順

`restore_snapshot` で unwrap に失敗し、以下のような recovery が出た場合を想定します。

- `legacy_hint=wrapped_with_old_session_key_or_mismatched_export_key`
- `recovery=disable_TSUPASSWD_SYNC_OPAQUE_SESSION_WRAP_then_manual_resync_to_overwrite_server`

### 手順

- `TSUPASSWD_SYNC_OPAQUE_SESSION_WRAP=0` にする
- 新しいプロセスでアプリを起動する
- `manual_resync` を実行する
- server 上の vault を現行形式で上書きする
- 必要なら `TSUPASSWD_SYNC_OPAQUE_SESSION_WRAP=1` に戻す

## 6. verbose debug

通常運用では詳細 DEBUG は抑制されます。

### ON

```powershell
setx TSUPASSWD_SYNC_VERBOSE_DEBUG 1
```

### OFF

```powershell
setx TSUPASSWD_SYNC_VERBOSE_DEBUG 0
```

### 注意

- `setx` の反映は新しいプロセスで有効になります。

## 7. Plugin temp ログの一時保存

通常運用では plugin の temp ログ出力は無効です。

### ON

```powershell
setx TSUPASSWD_PLUGIN_PERSIST_GET_ASSERTION_INFO 1
```

### OFF

```powershell
setx TSUPASSWD_PLUGIN_PERSIST_GET_ASSERTION_INFO 0
```

### 出力先

- `%TEMP%\tsupasswd_core_get_assertion_info.log`
- `%TEMP%\tsupasswd_core_get_assertion_status.log`
- `%TEMP%\tsupasswd_core_make_credential_status.log`

## 8. ビルド確認結果

今回の変更は VS 2026 の `MSBuild.exe` で以下を確認済みです。

- `Debug|x64` ビルド成功
- `0 warnings`
- `0 errors`

## 9. 関連ファイル

- `PluginManagement/PluginRegistrationManager.cpp`
- `PluginManagement/PluginRegistrationManager.h`
- `PluginAuthenticator/PluginAuthenticatorImpl.cpp`
- `src/SyncClient.cpp`
- `src/SyncClient.h`
