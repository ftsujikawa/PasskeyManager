# Sync Client 異常系ログ再現手順（fixed-format確認）

このドキュメントは、クライアント側ログの fixed-format（`key=value`）出力を異常系で確認するための手順です。

対象ケース:

1. `409 conflict`（`recovery=manual_resync_now`）
2. `read_encrypted_vault_data` 欠損/破損
3. `vault_unlock ui_required`

---

## 0. 事前準備

- アプリを起動して `Logs` を表示できる状態にする。
- Sync 設定（Base URL / Token / User ID）が有効であることを確認する。
- 必要ならログをクリアしてから開始する。

---

## 1) 409 conflict（`recovery=manual_resync_now`）

### 目的

`SyncEncryptedVaultWithRetry` の最終失敗時に、409系リカバリ導線が固定キーで出ることを確認する。

### 再現の考え方

- サーバーが `409` を返し続ける状況を作る。
- 典型例は「サーバー側をテスト用に固定409レスポンス化」または「競合状態を意図的に維持」。

### 期待ログ

- `sync result=failed ... status=409 ... recovery=manual_resync_now`
  - 少なくとも `recovery=manual_resync_now` が含まれること

### 確認ポイント

- リトライ過程で `sync result=retry_conflict` / `sync result=retry_backoff` が出ても問題なし
- 最終失敗行に `recovery=manual_resync_now` があること

---

## 2) `read_encrypted_vault_data` 欠損/破損

### 目的

ローカルVaultデータ異常時の警告が `operation=read_encrypted_vault_data` で統一されていることを確認する。

### 対象レジストリ

- Path: `HKCU\Software\Contoso\PasskeyManager`
- Value: `EncryptedVaultData` (REG_BINARY)

### パターンA: 値欠損

1. `EncryptedVaultData` を削除する。
2. `Manual Resync` など、`ReadEncryptedVaultData` を通る操作を実行する。

期待ログ:

- `sync result=failed operation=read_encrypted_vault_data reason=vault_data_missing recovery=recreate_vault_passkey_and_register_again`

### パターンB: 空/破損

1. `EncryptedVaultData` を空または不正サイズで書き込む。
2. 同様に `ReadEncryptedVaultData` を通る操作を実行する。

期待ログ（いずれか）:

- `reason=vault_data_empty_or_corrupt`
- `reason=vault_data_too_small_or_corrupt`
- `reason=vault_data_too_large_or_unexpected`

### 復旧

- `Run Vault Recovery` を実行して再生成
- または正常なスナップショット復元後に再試行

---

## 3) `vault_unlock ui_required`

### 目的

UI必須状態の拒否が `operation=vault_unlock reason=ui_required` で出ることを確認する。

### 再現例

- Vault Unlock が必要な状態で、UIを必要とする操作を実行する（`Add All` など）。
- サイレント実行不可/前景UI要求が発生するようにする。

### 期待ログ

- `summary result=rejected operation=vault_unlock reason=ui_required hr=...`

補足:

- `context=add_all` が付与されるケースあり

---

## 4. 完了判定（運用目線）

以下3種類が観測できれば、異常系ログ運用の最低条件は満たす。

- `recovery=manual_resync_now`（409最終失敗）
- `operation=read_encrypted_vault_data reason=...`（欠損/破損）
- `operation=vault_unlock reason=ui_required`（UI要求）

加えて、sync失敗ログ（`put_vault` / `restore_snapshot` / `test_connection`）では次を必須とする。

- `request_id=`（相関キー）
- `failure_kind=`（失敗分類）
- `name_not_resolved` の場合は `host=` を必須（`sync_failure=name_not_resolved` / `reason=name_not_resolved` の両経路）

---

## 5. 参照実装

- `MainPage.xaml.cpp`（UI操作ログ）
- `MainPage.xaml.h`（LogInfo/LogWarning/LogFailureの共通整形）
- `PluginManagement/PluginRegistrationManager.cpp`（sync retry / read_encrypted_vault_data）
- `PluginManagement/PluginCredentialManager.cpp`（vault_unlock）

---

## 6. ログキー自動チェック（PowerShell）

採取したログをテキスト保存し、以下で主要キーの有無と機微情報マーカー検出を自動判定できる。

### 推奨: 同梱 cmd スクリプトを使う

```cmd
docs\check_sync_log_keys.cmd captured_logs.txt
```

期待値:

- 必須キーが揃い、機微情報マーカー（`token=` など）が無ければ `PASS` が並び、終了コード `0`
- キー不足または機微情報マーカー検出時は `FAIL` が出て、終了コード `1`

### 参考: PowerShell ワンライナー

```powershell
$log = Get-Content -Raw -Path .\captured_logs.txt
$checks = @(
  @{ Name = '409_recovery'; Pattern = 'recovery=manual_resync_now' },
  @{ Name = 'read_encrypted_vault_data'; Pattern = 'operation=read_encrypted_vault_data\s+reason=' },
  @{ Name = 'vault_unlock_ui_required'; Pattern = 'operation=vault_unlock\s+reason=ui_required' }
)

$failed = @()
foreach ($c in $checks) {
  if ($log -match $c.Pattern) {
    Write-Host "PASS: $($c.Name)"
  }
  else {
    Write-Host "FAIL: $($c.Name)"
    $failed += $c.Name
  }
}

if ($failed.Count -gt 0) {
  Write-Error ("missing keys: " + ($failed -join ', '))
  exit 1
}

Write-Host 'OK: abnormal sync log keys are present.'
exit 0
```

注意:

- `captured_logs.txt` はアプリのログ表示をコピーして保存したテキストを想定。
- 未観測ケースがある運用では、`FAIL` が出るのは正常（要追加再現）である。

機微情報マスキング漏れの簡易チェック（任意）:

```cmd
findstr /i /r "token= authorization= authorization: bearer= access_token= refresh_token= client_secret=" captured_logs.txt
```

期待値:

- 何もヒットしない（出力なし）
- `INFO/WARNING/SUCCESS/FAILED` の `summary` / `sync` 行で `operation=` が付与されていること
- `message=` を含む行では `message_code=` が併記されていること
- `sync result=failed operation=(put_vault|restore_snapshot|test_connection)` 行で `request_id=` が付与されていること
- 同行で `failure_kind=` が付与されていること
- `INFO: sync state=start operation=(put_vault|restore_snapshot|manual_resync)` 行で `request_id=` が付与されていること

---

## 7. CI での自動検証

リポジトリには、ログキー検証を自動実行するワークフローを追加している。

- `./.github/workflows/sync-log-keys-check.yml`

このワークフローは次を検証する。

- `docs/samples/abnormal_sync_logs_pass.txt` は成功（exit `0`）すること
- `docs/samples/abnormal_sync_logs_fail.txt` は失敗（exit `1`）すること
- `docs/samples/abnormal_sync_logs_fail_request_id_format.txt` は `request_id_format_with_sync_start` で失敗（exit `1`）すること
- `docs/samples/abnormal_sync_logs_fail_failure_kind_value.txt` は `failure_kind_allowed_values` で失敗（exit `1`）すること
- サンプルログに機微情報マーカー（`token=` / `bearer=` / `authorization=` / `authorization:` / `access_token=` / `refresh_token=` / `client_secret=`）が含まれないこと

ローカルで同等のシナリオ検証を行う場合:

```cmd
docs\check_sync_log_keys_samples.cmd both
docs\check_sync_log_keys_samples.cmd pass
docs\check_sync_log_keys_samples.cmd fail
docs\check_sync_log_keys_samples.cmd batch
docs\check_sync_log_keys_samples.cmd fail_request_id_format
docs\check_sync_log_keys_samples.cmd fail_failure_kind_value
docs\check_sync_log_keys_samples.cmd fail_name_resolution_host
```

実運用ログ（抜粋ログ）を簡易検証する場合:

```cmd
docs\check_sync_runtime_log_keys.cmd <captured_runtime_logs.txt>
```

runtime checker の PASS/FAIL サンプルを一括検証する場合:

```cmd
docs\check_sync_runtime_log_keys_samples.cmd both
```

`check_sync_runtime_log_keys.cmd` は、次を重視する軽量チェック。

- 機微情報マーカー不在（`token=` / `bearer=` / `authorization=` など）
- `summary` / `sync` ログの `operation=` 存在
- `message=` がある行の `message_code=` 併記
- `sync state=start` / `sync result=failed|warning` 系での `request_id=` 整合
- `name_not_resolved` 系での `host=` 必須

注: 異常系シナリオ（`409_recovery` / `vault_unlock_ui_required` など）の「必須出現」は要求しない。

現在の checker で強制しているルール（12個）:

1. `409_recovery`
2. `read_encrypted_vault_data`
3. `vault_unlock_ui_required`
4. `sensitive_markers_absent`
5. `operation_key_present`
6. `message_code_with_message`
7. `request_id_with_sync_failure`
8. `request_id_with_sync_start`
9. `request_id_format_with_sync_start`
10. `failure_kind_with_sync_failure`
11. `name_not_resolved_host_required`
12. `failure_kind_allowed_values`

実行方法:

- PR説明文のひな形は `docs/PR_TEMPLATE_SNIPPETS.md`（超短文版/短縮版/フル版）を利用できる

1. GitHub の `Actions` タブを開く
2. `Sync Log Keys Check` を選択
3. `Run workflow`（`workflow_dispatch`）で `scenario` を選んで実行

`scenario` の選択肢:

- `both` : PASS/FAIL サンプルを両方実行
- `batch` : 全サンプルを一括検証（batch checker のみ実行）
- `runtime` : runtime サンプルを一括検証（runtime checker のみ実行）
- `pass` : PASS サンプルのみ実行
- `fail` : FAIL サンプルのみ実行
- `fail_request_id_format` : request_id フォーマット違反サンプルのみ実行
- `fail_failure_kind_value` : failure_kind 許容値違反サンプルのみ実行
- `fail_name_resolution_host` : `sync_failure=name_not_resolved` または `reason=name_not_resolved` で `host=` 欠落サンプルのみ実行

GitHub CLI から実行する場合:

初回のみ（未ログイン時）:

```powershell
gh auth login
gh repo set-default <ORG_OR_USER>/<REPO>
```

```powershell
gh workflow run sync-log-keys-check.yml -f scenario=both
gh run watch
```

単体実行の例:

```powershell
# PASS サンプルのみ（workflow 全体は success が期待値）
gh workflow run sync-log-keys-check.yml -f scenario=pass

# 全サンプルの一括検証のみ（batch checker を実行）
gh workflow run sync-log-keys-check.yml -f scenario=batch

# runtime サンプルの一括検証のみ（runtime checker を実行）
gh workflow run sync-log-keys-check.yml -f scenario=runtime

# FAIL サンプルのみ（checker は失敗し、workflow では expected failure として success が期待値）
gh workflow run sync-log-keys-check.yml -f scenario=fail

# request_id フォーマット違反サンプルのみ（expected failure として success が期待値）
gh workflow run sync-log-keys-check.yml -f scenario=fail_request_id_format

# failure_kind 許容値違反サンプルのみ（expected failure として success が期待値）
gh workflow run sync-log-keys-check.yml -f scenario=fail_failure_kind_value

# name_not_resolved の host 欠落サンプルのみ（expected failure として success が期待値）
gh workflow run sync-log-keys-check.yml -f scenario=fail_name_resolution_host
```

単体実行の確認済み結果:

- `scenario=pass`: `PASS sample should pass` のみ実行され、workflow 全体は `success`
- `scenario=runtime`: `Runtime batch sample checker should pass` のみ実行され、workflow 全体は `success`
- `scenario=fail`: `FAIL sample should fail` のみ実行され、checker の失敗を期待どおり確認して workflow 全体は `success`

実行結果の確認例:

```powershell
gh run list --workflow sync-log-keys-check.yml --limit 5
gh run view --log
```
