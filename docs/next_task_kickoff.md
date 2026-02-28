# Next Task Kickoff

## 目的
sync/summary ログの `request_id` 付与を段階的に拡大し、runtime checker 対象外の運用系 summary ログも統一する。

## 着手候補
1. `MainPage.xaml.cpp` の残存 `summary result=` ログ（request_id なし）を洗い出し、request_id を付与する。
2. `PluginRegistrationManager.cpp` / `PluginCredentialManager.cpp` の debug/summary ログで方針を決める（検証対象に含めるか、運用ログとして据え置くか）。
3. checker の対象拡張可否を決定し、必要なら fail サンプルを追加する。

## 完了条件（DoD）
- 追加対象として合意した summary ログで `request_id` が付与されている。
- `sync-log-keys-check` の `scenario=both` と `scenario=fail` が success。
- ドキュメント（release package）に変更内容と証跡URLが追記されている。

## 実行コマンド（例）
- `gh workflow run sync-log-keys-check.yml -f scenario=both`
- `gh workflow run sync-log-keys-check.yml -f scenario=fail`
