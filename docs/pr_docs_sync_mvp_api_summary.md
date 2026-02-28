# PR Summary: docs / sync-mvp-api の VS プロジェクト登録とログキー検証

## 概要
- Visual Studio プロジェクトにおける `docs` と `sync-mvp-api` 配下の表示/管理を強化しました。
- `sync/summary` ログキー検証チェッカーを再実行し、期待どおりの結果を確認しました。

## 変更ファイル
- `PasskeyManager.vcxproj`
- `PasskeyManager.vcxproj.filters`

## 主な変更点
1. `docs` 配下のファイルを VS プロジェクトへ明示登録
2. `docs` フィルター配下への割り当てを明示登録
3. `sync-mvp-api` 配下（`Properties`, `data`, `scripts` 含む）を VS プロジェクトへ追加
4. `sync-mvp-api` サブフィルターを追加し、各ファイルを正しいツリーへ割り当て

## 検証
実行コマンド:
- `docs\check_sync_log_keys_samples.cmd both`
- `docs\check_sync_runtime_log_keys_samples.cmd both`
- `docs\check_request_id_gap_blocks.cmd .`

結果:
- 異常系サンプルチェック: PASS（expected exit code と一致）
- ランタイムサンプルチェック: PASS（expected exit code と一致）
- block-aware gap checker: PASS（`ExitCode=0`）

## 直近コミット
- `d45e053` Add sync-mvp-api tree files to Visual Studio project
- `c8c7576` Register docs tree files in Visual Studio project
