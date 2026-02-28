件名: 【提出】sync-log-keys-check 改善対応（request_id 検証強化）

関係者各位

お疲れさまです。以下の対応を完了しましたので共有します。

- FAILサンプル検証（delete_everywhere）の誤検知を workflow 側で修正
- settings success（load_settings/save_settings）の request_id 検証強化を反映
- 監査提出用資料を作成（CSV/短縮PRコメント/ハンドオフ）

実施結果（CI）
- sync-log-keys-check scenario=both: success
  - https://github.com/ftsujikawa/PasskeyManager/actions/runs/22513165210
- sync-log-keys-check scenario=fail: success
  - https://github.com/ftsujikawa/PasskeyManager/actions/runs/22513547225
- 最新反映後 scenario=both: success
  - https://github.com/ftsujikawa/PasskeyManager/actions/runs/22513803740

関連コミット
- aa095ec: Fix delete_everywhere sample validation in workflow
- ceb72db: Add audit submission CSV template
- 7bd6bc5: Add short PR comment summary
- 1d787d8: Add sync log keys handoff summary

成果物
- docs/audit_submission_form.csv
- docs/pr_comment_short.md
- docs/sync_log_keys_handoff.md
- docs/sync_log_keys_submission_mail.md（本ファイル）

以上、よろしくお願いいたします。
