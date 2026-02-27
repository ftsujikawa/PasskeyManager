## Summary
Sync 異常系ログ検証の運用性を強化しました。  
主に runtime checker を CI/手動実行で扱いやすくし、ドキュメントと workflow の整合を取りました。  
あわせて `.gitignore` を整理し、ローカル生成物・実行時ログの誤コミットを防止しています。

## Background
- runtime ログ向けの軽量 checker を追加済みだったため、CI 自動検証と workflow_dispatch 単体実行の導線を強化したかった
- 運用中に生成される `captured_runtime_logs*.txt` などが作業ノイズになりやすく、誤コミット防止も必要だった

## Changes
- CI workflow 強化（`Sync Log Keys Check`）
  - runtime checker 関連ファイルを push/pull_request の監視対象に追加
  - runtime checker スクリプト存在確認ステップを追加
  - runtime サンプル一括検証ステップを追加
  - workflow_dispatch の `scenario` に `runtime` を追加
  - `scenario=runtime` で runtime checker が単独実行されるよう条件分岐を拡張
- ドキュメント更新
  - `README.md` に `scenario=runtime` を追記（選択肢一覧・CLI例）
  - `docs/sync_client_abnormal_log_scenarios.md` に `runtime` 選択肢と CLI 実行例を追記
- `.gitignore` 整理
  - 不要な PowerShell 貼り付け痕・重複を削除
  - `captured_runtime_logs*.txt` / `AppPackages/` / `index.html` を ignore 対象化

## Verification
- ローカル
  - `git diff` / `git status` で差分確認
- CI
  - `Sync Log Keys Check` の直近実行が success
  - 対象コミット例:
    - `a244783` ci: validate runtime sync log checker samples in workflow
    - `a6ab10a` ci: add runtime-only workflow_dispatch scenario
    - `0990002` docs: add runtime scenario usage for workflow dispatch

## Rollback
- 問題発生時は該当コミットを revert して、従来の scenario（both/batch/pass/fail 系）のみ運用に戻せます。
