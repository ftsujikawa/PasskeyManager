# PasskeyManager

PasskeyManager は、Windows 向けのパスキー管理/検証用アプリケーションです。

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

ログ貼り付けテキスト（例: `captured_logs.txt`）からキーの有無を自動確認する場合:

```cmd
docs\check_sync_log_keys.cmd captured_logs.txt
```

期待値:

- 全キー観測時: `PASS` 表示、終了コード `0`
- キー不足時: `FAIL` 表示、終了コード `1`

GitHub Actions の手動実行（workflow_dispatch）を CLI から行う場合:

初回のみ（未ログイン時）:

```powershell
gh auth login
gh repo set-default <ORG_OR_USER>/<REPO>
```

```powershell
gh workflow run sync-log-keys-check.yml -f scenario=both
gh run watch
```

`scenario` は `both` / `pass` / `fail` を指定できます。

単体実行の例:

```powershell
# PASS サンプルのみ（workflow 全体は success が期待値）
gh workflow run sync-log-keys-check.yml -f scenario=pass

# FAIL サンプルのみ（checker は失敗し、workflow では expected failure として success が期待値）
gh workflow run sync-log-keys-check.yml -f scenario=fail
```

単体実行の確認済み結果:

- `scenario=pass`: `PASS sample should pass` のみ実行され、workflow 全体は `success`
- `scenario=fail`: `FAIL sample should fail` のみ実行され、checker の失敗を期待どおり確認して workflow 全体は `success`

実運用ログの代表例（fixed-format, key=value）:

```text
SUCCESS: summary result=success request=1 run=1 attempts=1 elapsed_ms=75 hr=0 selected=3 cached=3 missing=0✅
INFO: summary state=running operation=delete_selected_credentials_everywhere request=1 run=1⏳
INFO: summary state=running operation=vault_recovery⏳
WARNING: sync result=failed attempts=3/3 elapsed_ms=1523 hr=-2147012889 detail=sync_failure=unexpected_or_server_error local_save=kept code=CLIENT_ERROR message=SyncClient::PutVault failed before receiving valid response.
INFO: sync result=retry_backoff attempt=3/3 backoff_ms=1000 elapsed_ms=517ℹ
WARNING: sync result=failed operation=restore_snapshot hr=-2147012889 detail=sync_failure=unexpected_or_server_error local_save=kept code=CLIENT_ERROR message=SyncClient::GetVault failed before receiving valid response.
WARNING: sync result=failed operation=test_connection attempts=1 hr=-2147012889 code=CLIENT_ERROR message=SyncClient::GetVault failed before receiving valid response.⚠
SUCCESS: sync result=success operation=save_settings fields=base_url,token,user_id✅
```

実行結果の確認例:

```powershell
gh run list --workflow sync-log-keys-check.yml --limit 5
gh run view --log
```
