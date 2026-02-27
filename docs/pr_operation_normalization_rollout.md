## Summary
ログ保守性・診断性の一貫性向上のため、sync/credential 関連ログの `operation` トークンを変数/共有定数経由に統一し、`name_not_resolved` 発生時の `host=` 必須方針を実装・運用ドキュメントに固定化しました。

## Background
- 同一処理内で `operation=...` の文字列直書きが混在しており、ログ修正時のメンテナンスコストが高かった
- `name_not_resolved` 時の診断で `host=` 欠落があると一次切り分けが難しいため、必須化を維持・明文化したかった

## Changes
### Code
- `MainPage.xaml.cpp`
  - sync/credential 操作ログの `operation` 直書きを関数内 `operation` 変数経由へ統一
  - `restore_snapshot` / `manual_resync` / `test_connection` などで `name_not_resolved` 時の `host=` 出力を統一
- `PluginManagement/PluginRegistrationManager.cpp`
  - `put_vault` / `vault_recovery` / `manual_resync` / `restore_snapshot` / `key_management` などのログ `operation` を変数経由へ統一
  - sync failure detail (`name_not_resolved`) で `host=` を含む構築を維持
- `PluginManagement/PluginCredentialManager.cpp`
  - `vault_unlock` operation token を共有定数化し、関連ログで統一
  - `LogVaultUnlockWarning` の debug 出力に残っていた固定 operation 文字列を変数経由へ統一

### Docs
- `docs/sync_client_abnormal_log_scenarios.md`
  - 固定ルールを追記（operation 直書き禁止方針 / `name_not_resolved` で `host=` 必須 / checker・CIとの整合運用）
- `docs/PR_TEMPLATE_SNIPPETS.md`
  - 今回対応向けの PR 文テンプレ（超短文版・短縮版）を追加

## Verification
- GitHub Actions: `Sync Log Keys Check` を各反映後に確認し成功
- 直近 run:
  - `22478970327` ✅
  - `22479183733` ✅
  - `22479802795` ✅
- 追加点検:
  - `name_not_resolved` 系ログで `host=` 付与漏れなし
  - 対象 C++ 実装で operation 直書き残件なし（対象範囲内）

## Rollback
- 対象コミットを revert:
  - `61dc34e` (vault unlock warning debug operation 統一)
  - `27d9e6a` (運用ルール docs 追記)
  - `0915727` (PR snippets 追記)
- 必要に応じて以下を合わせて戻す:
  - `docs/sync_client_abnormal_log_scenarios.md`
  - `docs/PR_TEMPLATE_SNIPPETS.md`
