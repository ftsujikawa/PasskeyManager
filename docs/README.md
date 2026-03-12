# Docs Index

主要な運用ドキュメントへの入口です。

## sync-axum-api GCP Deployment

- `sync-axum-api-gcp/README.md`
  `sync-axum-api` の GCP デプロイ手順の入口
- `sync-axum-api-gcp/01_overview.md`
  全体構成、前提条件、デプロイの流れ
- `sync-axum-api-gcp/02_artifact_registry_and_image.md`
  Docker build、Artifact Registry、イメージ push
- `sync-axum-api-gcp/03_cloud_sql_and_secrets.md`
  Cloud SQL、Secret Manager、IAM 設定
- `sync-axum-api-gcp/04_cloud_run_deploy.md`
  Cloud Run デプロイと再デプロイ手順
- `sync-axum-api-gcp/05_troubleshooting.md`
  デプロイ時のトラブルシュート

## Sync 異常系ログ

- `sync_client_abnormal_log_scenarios.md`  
  異常系シナリオ、サンプル、GitHub Actions 実行手順
  （末尾に `Vault Schema v1 クイック回帰チェックリスト` を含む）
- `sync_opaque_export_key_operations.md`
  OPAQUE export key 永続化、Vault sync、復旧導線、verbose debug の運用手順
- `opaque_smoke.md`
  `sync-axum-api` の OPAQUE register/login と Vault PUT/GET のスモークテスト手順
- `check_sync_runtime_log_keys.cmd`  
  実運用ログ向けの軽量チェック（必須異常シナリオを要求しない）。現在は14ルールを検証し、`manual_resync` success summary の `request_id` フォーマット整合、`delete_selected_credentials_everywhere` success summary の `request_id` 必須、`load_settings` / `save_settings` sync success の `request_id` 必須とフォーマット整合を含む
- `check_sync_runtime_log_keys_samples.cmd`  
  runtime checker の PASS/FAIL サンプル一括検証
- `PR_TEMPLATE_SNIPPETS.md`  
  PR 説明文のひな形（超短文版 / 短縮版 / フル版）
- `pr_runtime_checker_update.md`  
  runtime checker 連携更新の保存済み PR 本文
- `runtime_checker_rollout_completion.md`  
  runtime checker 連携の完了記録（検証 run / CI時間比較を含む）

## Security Design

- `tsupasswd_core_threat_model.md`
- `adr/0001-key-hierarchy-and-secret-storage.md`

## Windows App Installation

- `windows_app_install_troubleshooting.md`  
  MSIX インストール時の競合エラー（例: 0x80073cfb）対処手順
