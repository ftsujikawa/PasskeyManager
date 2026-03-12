# sync-axum-api GCP Deployment Docs

`sync-axum-api` を GCP 上で運用するための手順を、用途ごとに分割したドキュメント群です。

## ドキュメント一覧

- `01_overview.md`
  全体構成、前提条件、デプロイの流れ
- `02_artifact_registry_and_image.md`
  Docker build、Artifact Registry への push、イメージ更新手順
- `03_cloud_sql_and_secrets.md`
  Cloud SQL for PostgreSQL、Secret Manager、IAM 設定
- `04_cloud_run_deploy.md`
  Cloud Run デプロイ、環境変数、Cloud SQL 接続、再デプロイ
- `05_troubleshooting.md`
  今回ハマったポイントを含むトラブルシュート集

## 推奨読む順番

1. `01_overview.md`
2. `02_artifact_registry_and_image.md`
3. `03_cloud_sql_and_secrets.md`
4. `04_cloud_run_deploy.md`
5. `05_troubleshooting.md`
