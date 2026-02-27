# Runtime Checker Rollout Completion

## Scope
`Sync Log Keys Check` workflow と関連ドキュメントに対して、runtime checker 連携を完了。

## Implemented
- workflow に runtime checker スクリプト存在確認を追加
- runtime サンプル一括検証ステップを追加
- `workflow_dispatch` に `scenario=runtime` を追加
- push/pull_request の `paths` を拡張（runtime checker 関連 docs 変更も自動起動）
- ドキュメントに runtime 実行方法と確認済み結果を追記
- PR 本文保存ファイルとスニペット導線を整備

## Verified Runs
- `22470623784` (`workflow_dispatch`, `scenario=runtime`) : success
- `22470866918` (`workflow_dispatch`, `scenario=both`) : success
- `22470571793` (push, docs index / saved PR body trigger check) : success
- `22470794705` (push, snippet TOC update) : success
- `22470669838` (push, runtime verification note update) : success
- `22471411086` (push, after duplicate-check reduction) : success

## CI Duration Comparison (push)
- After (`1d50123`): `22471411086` = `24s`
- Before (recent pushes):
  - `22470794705` = `27s`
  - `22470669838` = `26s`
  - `22470571793` = `55s`
  - `22470408671` = `28s`
  - `22469426419` = `33s`
  - `22469344505` = `33s`
- Before average (6 runs): `33.7s`
- Improvement: `-9.7s` (about `29%` faster)

## Notes
- `name_not_resolved_host_required` ルールを含む既存 checker 群との整合は維持。
- 本ロールアウト後、runtime checker の個別実行と全体実行の双方で正常完了を確認済み。
