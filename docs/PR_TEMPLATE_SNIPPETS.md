# PR Template Snippets

## name_not_resolved host 必須化（短縮版）

```md
## 概要
`name_not_resolved` 時のログ診断性を強化し、`sync_failure` / `reason` の両経路で `host=` 必須化を実装・検証しました。`restore_snapshot` / `manual_resync` を含むサンプル、checker、CI、ドキュメント、PRテンプレを一貫更新しています。  
ローカルで `docs\check_sync_log_keys_samples.cmd both` / `pass` / `fail_name_resolution_host` を実行し、PASS=成功・FAIL=期待失敗を確認済みです。  
あわせてルール名を実態に合わせて `name_not_resolved_host_required` に統一しました。
```
