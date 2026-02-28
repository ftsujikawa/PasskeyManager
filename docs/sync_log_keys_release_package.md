# Sync Log Keys Release Package

## 1) PR最終化（提出用）

### PRタイトル案
`Refactor sync/summary log key checks and submission artifacts`

### PR本文（短縮版）
- `delete_everywhere` FAILサンプル検証の誤検知を workflow 側で修正。
- runtime checker における `settings success` の `request_id` 検証を強化した一連の変更を、`both/fail` シナリオで確認。
- 監査提出用成果物（CSV、短縮コメント、ハンドオフ、提出メール）を追加。

### マージ前チェックリスト
- [x] `sync-log-keys-check` scenario=both が success
- [x] `sync-log-keys-check` scenario=fail が success
- [x] 監査提出物を `docs/` 配下に配置
- [x] 作業ツリー clean を確認

## 2) 3ファイル再監査（MainPage/RegistrationManager/CredentialManager）

### 実施結果
- 監査対象:
  - `MainPage.xaml.cpp`
  - `PluginManagement/PluginRegistrationManager.cpp`
  - `PluginManagement/PluginCredentialManager.cpp`
- `request=` キーの残存はなし（`request_id`へ統一済み）。
- 追加修正:
  - `set_vault_unlock_method` の `summary result=success/failed` に `request_id` を付与。
  - `set_silent_operation` / `copy_logs` / `delete_all_local_credentials` / `delete_all_credentials` / `activate_plugin` / `set_vault_lock_state` の summary ログへ `request_id` を付与。
  - runtime checker の評価対象を `INFO|SUCCESS|WARNING|FAILED` 行に限定し、`DEBUG` 行は対象外に明確化。
  - `runtime_sync_logs_pass.txt` に `DEBUG` 行（request_id なし）を追加し、対象外であることを回帰確認。

### 監査メモ（次フェーズ候補）
- `request_id` 強制対象は運用ログ行（`INFO|SUCCESS|WARNING|FAILED`）とし、`DEBUG` / 補助文字列は非対象。
- 次フェーズで、運用ログ対象の追加ルール（例: summary success 全般）を段階拡張する。

## 3) 提出物の1本化（本ドキュメント）

本ファイルを提出物インデックスとして利用し、詳細は以下を参照。

- 監査CSV: `docs/audit_submission_form.csv`
- PR短縮コメント: `docs/pr_comment_short.md`
- ハンドオフ: `docs/sync_log_keys_handoff.md`
- 提出メール文面: `docs/sync_log_keys_submission_mail.md`

## CI証跡
- scenario=both: https://github.com/ftsujikawa/PasskeyManager/actions/runs/22513165210
- scenario=fail: https://github.com/ftsujikawa/PasskeyManager/actions/runs/22513547225
- scenario=both（最新反映確認）: https://github.com/ftsujikawa/PasskeyManager/actions/runs/22514721481
- scenario=fail（最新反映確認）: https://github.com/ftsujikawa/PasskeyManager/actions/runs/22514734537

## 変更コミット
- `aa095ec` Fix delete_everywhere sample validation in workflow
- `ceb72db` Add audit submission CSV template
- `7bd6bc5` Add short PR comment summary
- `1d787d8` Add sync log keys handoff summary
- `95fdc4e` Add sync log keys submission mail template
- `aa14c56` Add release package doc and request_id to unlock summary logs
- `75a95d8` Expand summary request_id coverage and refresh release docs
- `6ce8161` Scope runtime checker to operational log lines
- `daed3e6` Add debug-line pass sample for runtime checker scope
