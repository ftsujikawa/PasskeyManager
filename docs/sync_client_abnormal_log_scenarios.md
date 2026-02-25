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

---

## 5. 参照実装

- `MainPage.xaml.cpp`（UI操作ログ）
- `MainPage.xaml.h`（LogInfo/LogWarning/LogFailureの共通整形）
- `PluginManagement/PluginRegistrationManager.cpp`（sync retry / read_encrypted_vault_data）
- `PluginManagement/PluginCredentialManager.cpp`（vault_unlock）

---

## 6. ログキー自動チェック（PowerShell）

採取したログをテキスト保存し、以下で3キーの有無を自動判定できる。

### 推奨: 同梱 cmd スクリプトを使う

```cmd
docs\check_sync_log_keys.cmd captured_logs.txt
```

期待値:

- 3キーが揃っていれば `PASS` が並び、終了コード `0`
- 不足があれば `FAIL` が出て、終了コード `1`

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

---

## 7. CI での自動検証

リポジトリには、ログキー検証を自動実行するワークフローを追加している。

- `./.github/workflows/sync-log-keys-check.yml`

このワークフローは次を検証する。

- `docs/samples/abnormal_sync_logs_pass.txt` は成功（exit `0`）すること
- `docs/samples/abnormal_sync_logs_fail.txt` は失敗（exit `1`）すること

実行方法:

1. GitHub の `Actions` タブを開く
2. `Sync Log Keys Check` を選択
3. `Run workflow`（`workflow_dispatch`）で `scenario` を選んで実行

`scenario` の選択肢:

- `both` : PASS/FAIL サンプルを両方実行
- `pass` : PASS サンプルのみ実行
- `fail` : FAIL サンプルのみ実行

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

# FAIL サンプルのみ（checker は失敗し、workflow では expected failure として success が期待値）
gh workflow run sync-log-keys-check.yml -f scenario=fail
```

実行結果の確認例:

```powershell
gh run list --workflow sync-log-keys-check.yml --limit 5
gh run view --log
```
