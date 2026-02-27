# PasskeyManager

PasskeyManager は、Windows 向けのパスキー管理/検証用アプリケーションです。

## Documentation

- `./docs/README.md`（運用ドキュメントの入口）
- `./docs/windows_app_install_troubleshooting.md`（MSIX インストール競合 0x80073cfb の対処手順）

## Security Design

- `./docs/tsupasswd_core_threat_model.md`（A-01: STRIDE 脅威モデル初版）
- `./docs/adr/0001-key-hierarchy-and-secret-storage.md`（A-02: 鍵階層と秘密保存方針）

## Roadmap Issue 一括起票

ロードマップ用のラベル作成と Issue 一括起票は、以下のスクリプトで実行できます。

- `./.github/scripts/bootstrap-roadmap.cmd`

詳細手順は次のドキュメントを参照してください。

- `./.github/scripts/README.md`

### クイックスタート

1. GitHub CLI を認証

```powershell
gh auth login
```

2. （必要に応じて）対象リポジトリを設定

```powershell
gh repo set-default <ORG_OR_USER>/<REPO>
```

3. リポジトリルートで実行

```powershell
.\.github\scripts\bootstrap-roadmap.cmd
```

### 再実行時の挙動

- 同名タイトルの open issue は作成スキップされます。
- ラベルは作成失敗時に更新にフォールバックします。
- 依存番号（`#1` 形式）はテンプレート値なので、起票後に必要なら更新してください。

## Sync 異常系ログ検証

異常系ログ（fixed-format: `key=value`）の再現/確認手順は次のドキュメントを参照してください。

- `./docs/sync_client_abnormal_log_scenarios.md`
- PR説明文の使い回しには `./docs/PR_TEMPLATE_SNIPPETS.md`（超短文版/短縮版/フル版）

ログ貼り付けテキスト（例: `captured_logs.txt`）から必須キーと機微情報マーカーを自動確認する場合:

```cmd
docs\check_sync_log_keys.cmd captured_logs.txt
```

実運用ログ（抜粋）を軽量チェックする場合（必須異常シナリオの出現は要求しない）:

```cmd
docs\check_sync_runtime_log_keys.cmd captured_runtime_logs.txt
```

runtime checker 自体のサンプルを一括検証する場合:

```cmd
docs\check_sync_runtime_log_keys_samples.cmd
```

全サンプルを一括で検証する場合:

```cmd
docs\check_sync_log_keys_samples.cmd
```

特定シナリオのみローカル検証する場合:

```cmd
docs\check_sync_log_keys_samples.cmd pass
docs\check_sync_log_keys_samples.cmd fail
docs\check_sync_log_keys_samples.cmd batch
docs\check_sync_log_keys_samples.cmd fail_request_id_format
docs\check_sync_log_keys_samples.cmd fail_failure_kind_value
docs\check_sync_log_keys_samples.cmd fail_name_resolution_host
```

GitHub Actions の `Sync Log Keys Check` でも、`scenario=both`（または push/pull_request）ではこの一括検証を実行します。

期待値:

- 必須キーを観測し、機微情報マーカーが無い場合: `PASS` 表示、終了コード `0`
- `INFO/WARNING/SUCCESS/FAILED` の `summary` / `sync` 行で `operation=` が付与されていること
- `message=` を含む行では `message_code=` が併記されていること
- `sync result=failed operation=(put_vault|restore_snapshot|test_connection)` 行で `request_id=` が付与されていること
- `sync result=failed operation=(put_vault|restore_snapshot|test_connection)` 行で `failure_kind=` が付与されていること
- `INFO: sync state=start operation=(put_vault|restore_snapshot|manual_resync)` 行で `request_id=` が付与されていること
- キー不足または機微情報マーカー検出時: `FAIL` 表示、終了コード `1`

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

GitHub Actions の手動実行（workflow_dispatch）を CLI から行う場合:

補助サンプル（回帰検証用）:

- `docs/samples/abnormal_sync_logs_fail_request_id_format.txt`
  - `request_id_format_with_sync_start` のみを狙って失敗させる
- `docs/samples/abnormal_sync_logs_fail_failure_kind_value.txt`
  - `failure_kind_allowed_values` のみを狙って失敗させる
- `docs/samples/abnormal_sync_logs_fail_name_resolution_host.txt`
  - `sync_failure=name_not_resolved` または `reason=name_not_resolved` で `host=` 欠落のみを狙って失敗させる

初回のみ（未ログイン時）:

```powershell
gh auth login
gh repo set-default <ORG_OR_USER>/<REPO>
```

```powershell
gh workflow run sync-log-keys-check.yml -f scenario=both
gh run watch
```

`scenario` は `both` / `batch` / `runtime` / `pass` / `fail` / `fail_request_id_format` / `fail_failure_kind_value` / `fail_name_resolution_host` を指定できます。

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

# name_not_resolved の host 欠落サンプルのみ（`sync_failure` / `reason` 両経路、expected failure として success が期待値）
gh workflow run sync-log-keys-check.yml -f scenario=fail_name_resolution_host
```

単体実行の確認済み結果:

- `scenario=pass`: `PASS sample should pass` のみ実行され、workflow 全体は `success`
- `scenario=runtime`: `Runtime batch sample checker should pass` のみ実行され、workflow 全体は `success`
- `scenario=fail`: `FAIL sample should fail` のみ実行され、checker の失敗を期待どおり確認して workflow 全体は `success`

実運用ログの代表例（fixed-format, key=value）:

```text
SUCCESS: summary result=success operation=delete_selected_credentials_everywhere request=1 run=1 attempts=1 elapsed_ms=75 hr=0 selected=3 cached=3 missing=0✅
INFO: summary state=running operation=delete_selected_credentials_everywhere request=1 run=1⏳
INFO: summary state=running operation=vault_recovery request_id=20260225T162435905Z-vault_recovery⏳
WARNING: sync result=failed operation=put_vault attempts=3/3 elapsed_ms=1523 hr=-2147012889 detail=failure_kind=client_error sync_failure=unexpected_or_server_error local_save=kept code=CLIENT_ERROR message_code=CLIENT_ERROR message=SyncClient::PutVault failed before receiving valid response. request_id=2026-02-25T16:24:40Z-put_vault
INFO: sync result=retry_backoff operation=put_vault attempt=3/3 backoff_ms=1000 elapsed_ms=517 request_id=2026-02-25T16:24:40Z-put_vaultℹ
WARNING: sync result=failed operation=restore_snapshot hr=-2147012889 detail=failure_kind=client_error sync_failure=name_not_resolved host=tsupasswd.example.invalid recovery=check_sync_base_url_dns_or_hosts local_save=kept code=CLIENT_ERROR message_code=CLIENT_ERROR message=SyncClient::GetVault failed before receiving valid response. request_id=20260225T162404950Z-restore_snapshot
WARNING: sync result=failed operation=test_connection attempts=1 hr=-2147012889 failure_kind=client_error sync_failure=name_not_resolved host=tsupasswd.example.invalid recovery=check_sync_base_url_dns_or_hosts code=CLIENT_ERROR request_id=20260225T162400808Z-test_connection message_code=CLIENT_ERROR message=SyncClient::GetVault failed before receiving valid response.⚠
WARNING: sync result=warning operation=manual_resync outcome=ended_with_warning_or_failure reason=name_not_resolved host=tsupasswd.example.invalid recovery=check_sync_base_url_dns_or_hosts request_id=20260225T162401808Z-manual_resync⚠
SUCCESS: sync result=success operation=save_settings fields=base_url,token,user_id✅
```

実行結果の確認例:

```powershell
gh run list --workflow sync-log-keys-check.yml --limit 5
gh run view --log
```
