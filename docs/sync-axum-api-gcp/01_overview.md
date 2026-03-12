# sync-axum-api on GCP Overview

## 構成

`sync-axum-api` の本番構成は以下です。

- Cloud Run
- Artifact Registry
- Cloud SQL for PostgreSQL
- Secret Manager

## 前提条件

- GCP project ID: `sync-axum-api`
- region: `asia-northeast1`
- Cloud SQL instance name: `sync-axum-pg`
- Cloud Run service name: `sync-axum-api`
- Artifact Registry repository name: `sync-axum-api`

## API / サービス

有効化が必要な主な API は以下です。

- `run.googleapis.com`
- `artifactregistry.googleapis.com`
- `cloudbuild.googleapis.com`
- `sqladmin.googleapis.com`
- `secretmanager.googleapis.com`

有効化例:

```powershell
gcloud services enable run.googleapis.com artifactregistry.googleapis.com cloudbuild.googleapis.com sqladmin.googleapis.com secretmanager.googleapis.com --project=sync-axum-api
```

## デプロイ全体の流れ

1. Docker イメージを build する
2. Artifact Registry に push する
3. Cloud SQL for PostgreSQL を作成する
4. DB ユーザー / DB / Secret を設定する
5. Cloud Run にデプロイする
6. `/healthz` と Cloud Run logs で確認する

## 今回の本番値

- Cloud SQL 接続名: `sync-axum-api:asia-northeast1:sync-axum-pg`
- Cloud Run bind: `0.0.0.0:8080`
- dev login: `false`

## 注意点

- `--project` には project number ではなく project ID を使う
- Cloud Run では `TSUPASSWD_SYNC_BIND=0.0.0.0:8080` を使う
- `DATABASE_URL` は Cloud SQL 用に Secret Manager から渡す
- Cloud Run 起動前に DB 接続が行われるため、DB 設定不備でも `PORT=8080` エラーに見える
