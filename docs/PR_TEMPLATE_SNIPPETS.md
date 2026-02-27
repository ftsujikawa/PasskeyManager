# PR Template Snippets

## 使い分け

- **超短文版**: 1〜2行で速報的にまとめたいとき
- **短縮版**: 通常のPRで簡潔に説明したいとき
- **フル版**: 変更背景・検証・影響範囲まで丁寧に残したいとき

保存済みの最新PR本文（runtime checker 連携更新）は以下を参照:

- [docs/pr_runtime_checker_update.md](./pr_runtime_checker_update.md)

## 目次

1. [name_not_resolved host 必須化（超短文版）](#name_not_resolved-host-必須化超短文版)
2. [name_not_resolved host 必須化（短縮版）](#name_not_resolved-host-必須化短縮版)
3. [name_not_resolved host 必須化（フル版）](#name_not_resolved-host-必須化フル版)

## name_not_resolved host 必須化（超短文版）

```md
`name_not_resolved` のログ診断性向上のため、`sync_failure` / `reason` 両経路で `host=` 必須化を実装し、checker・CI・サンプル・ドキュメントを更新しました。`docs\check_sync_log_keys_samples.cmd both/pass/fail_name_resolution_host` でPASS/期待失敗を確認済みです。
```

## name_not_resolved host 必須化（短縮版）

```md
## 概要
`name_not_resolved` 時のログ診断性を強化し、`sync_failure` / `reason` の両経路で `host=` 必須化を実装・検証しました。`restore_snapshot` / `manual_resync` を含むサンプル、checker、CI、ドキュメント、PRテンプレを一貫更新しています。  
ローカルで `docs\check_sync_log_keys_samples.cmd both` / `pass` / `fail_name_resolution_host` を実行し、PASS=成功・FAIL=期待失敗を確認済みです。  
あわせてルール名を実態に合わせて `name_not_resolved_host_required` に統一しました。
```

## name_not_resolved host 必須化（フル版）

```md
## 概要
`name_not_resolved` 発生時のログ診断性を強化し、`restore_snapshot` / `manual_resync` を含めて `sync_failure` / `reason` 両経路で `host=` 必須化を実施しました。

## 変更内容
- 実装: `name_not_resolved` 時のログに `host=` を含める（`sync_failure` / `reason` 両対応）
- checker: `sync_failure=name_not_resolved` または `reason=name_not_resolved` 行で `host=` を必須化
- samples: FAIL/PASS サンプルを更新（欠落検知と正常ケースを明示）
- CI: FAIL/PASS サンプル妥当性チェックを強化
- docs/template: 運用手順とPRチェック項目を最新仕様へ更新
- 命名統一: `name_not_resolved_host_required`

## 検証
~~~cmd
docs\check_sync_log_keys_samples.cmd both
docs\check_sync_log_keys_samples.cmd pass
docs\check_sync_log_keys_samples.cmd fail_name_resolution_host
~~~

- PASSサンプル: ExitCode=0
- FAILサンプル: ExitCode=1（期待失敗）

## 影響範囲
- ログ文言、checker、CI、サンプル、ドキュメント
- 同期処理本体の機能フローへの破壊的変更なし

## ロールバック
- `docs/check_sync_log_keys.cmd`
- `.github/workflows/sync-log-keys-check.yml`
- `docs/samples/*` と関連ドキュメントの該当変更を戻す
```
