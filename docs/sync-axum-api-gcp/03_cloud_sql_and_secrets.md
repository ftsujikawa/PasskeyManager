# Cloud SQL and Secret Manager

## Cloud SQL instance 作成

```powershell
gcloud sql instances create sync-axum-pg --database-version=POSTGRES_16 --tier=db-f1-micro --edition=ENTERPRISE --region=asia-northeast1 --project=sync-axum-api
```

## DB ユーザーのパスワード設定

`postgres` ユーザーを使う場合:

```powershell
gcloud sql users set-password postgres --instance=sync-axum-pg --password=NEW_DB_PASSWORD --project=sync-axum-api
```

## DB 作成

```powershell
gcloud sql databases create tsupasswd_sync --instance=sync-axum-pg --project=sync-axum-api
```

## 接続名の確認

```powershell
gcloud sql instances describe sync-axum-pg --project=sync-axum-api --format="value(connectionName)"
```

期待値:

```text
sync-axum-api:asia-northeast1:sync-axum-pg
```

## Secret Manager API

```powershell
gcloud services enable secretmanager.googleapis.com --project=sync-axum-api
```

## `DATABASE_URL` secret

Cloud Run から Cloud SQL を使うため、`DATABASE_URL` は Unix socket 形式で登録します。

```powershell
"postgres://postgres:NEW_DB_PASSWORD@localhost/tsupasswd_sync?host=/cloudsql/sync-axum-api:asia-northeast1:sync-axum-pg" | gcloud secrets create sync-axum-database-url --data-file=- --project=sync-axum-api
```

既存 secret の更新:

```powershell
"postgres://postgres:NEW_DB_PASSWORD@localhost/tsupasswd_sync?host=/cloudsql/sync-axum-api:asia-northeast1:sync-axum-pg" | gcloud secrets versions add sync-axum-database-url --data-file=- --project=sync-axum-api
```

## JWT secret

```powershell
"change-me-to-a-strong-random-secret" | gcloud secrets create sync-axum-jwt-secret --data-file=- --project=sync-axum-api
```

既存 secret の更新:

```powershell
"change-me-to-a-strong-random-secret" | gcloud secrets versions add sync-axum-jwt-secret --data-file=- --project=sync-axum-api
```

## IAM

Cloud Run 実行サービスアカウントに以下が必要です。

- `roles/secretmanager.secretAccessor`
- `roles/cloudsql.client`

project 全体に付与する例:

```powershell
gcloud projects add-iam-policy-binding sync-axum-api --member="serviceAccount:234451037830-compute@developer.gserviceaccount.com" --role="roles/secretmanager.secretAccessor"
```

```powershell
gcloud projects add-iam-policy-binding sync-axum-api --member="serviceAccount:234451037830-compute@developer.gserviceaccount.com" --role="roles/cloudsql.client"
```

## 重要な注意点

- Cloud SQL のパスワードと `sync-axum-database-url` の中身は必ず一致させる
- `DATABASE_URL` の古い値を何度も追加すると切り分けが難しくなる
- `@/dbname?...` の形式は `sqlx` で `empty host` を起こすため避ける
