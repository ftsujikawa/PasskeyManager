# Next Task Kickoff

## 目的
sync/summary ログの `request_id` 付与を段階的に拡大しつつ、runtime checker の対象範囲を明文化して誤検知なしで運用する。

## 方針（確定案）
- checker対象:
  - `INFO|SUCCESS|WARNING|FAILED:` で出力される運用ログ（ユーザー可視ログ）
  - `summary` / `sync` の実行結果・状態遷移ログ
- checker非対象:
  - `DEBUG:` 行
  - ヘルパー関数内部の組み立て途中文字列
  - テスト/サンプル作成時の説明用文字列
- 判定ルール:
  - 対象ログでは `operation=` を必須
  - `summary result=` / `sync result=` の対象ログでは `request_id=` を必須
  - `request_id` は `YYYYMMDDThhmmssfffZ-operation` 形式を維持

## 着手候補
1. `MainPage.xaml.cpp` / `PluginRegistrationManager.cpp` / `PluginCredentialManager.cpp` の対象ログで `request_id` 付与漏れを再点検する。
2. runtime checker に「DEBUG行は対象外」のガードを明示し、対象ログのみ評価する。
3. checker 拡張時は fail サンプルを追加（対象ログのみで fail することを確認）する。

## 完了条件（DoD）
- 対象ログとして定義した summary/sync ログで `request_id` が付与されている。
- `sync-log-keys-check` の `scenario=both` と `scenario=fail` が success。
- ドキュメント（release package）に変更内容と証跡URLが追記されている。

## 次の実装ステップ
1. checker スクリプトで評価対象行の前提（`^(INFO|SUCCESS|WARNING|FAILED):`）を共通化。
2. 既存ルールを対象行に限定して評価するよう整理。
3. fail サンプルに DEBUG 行のみ不備のケースを追加し、誤検知しないことを確認。

## 実行コマンド（例）
- `gh workflow run sync-log-keys-check.yml -f scenario=both`
- `gh workflow run sync-log-keys-check.yml -f scenario=fail`
