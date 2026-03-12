# Troubleshooting

## `Repository not found`

原因候補:

- project ID が違う
- repository 名が違う
- region が違う

確認:

```powershell
gcloud artifacts repositories list --location=asia-northeast1 --project=sync-axum-api
```

## `Artifact Registry API has not been used`

```powershell
gcloud services enable artifactregistry.googleapis.com --project=sync-axum-api
```

## `Secret Manager API has not been used`

```powershell
gcloud services enable secretmanager.googleapis.com --project=sync-axum-api
```

## `Invalid secret spec`

`--set-secrets` の値が空白で壊れている可能性があります。

正しい例:

```powershell
--set-secrets "DATABASE_URL=sync-axum-database-url:latest,TSUPASSWD_SYNC_JWT_SECRET=sync-axum-jwt-secret:latest"
```

## `Invalid cloud sql instance names`

`INSTANCE_CONNECTION_NAME` というプレースホルダをそのまま入れている可能性があります。

確認:

```powershell
gcloud sql instances describe sync-axum-pg --project=sync-axum-api --format="value(connectionName)"
```

## `empty host`

`sqlx` で次のような URL は失敗します。

```text
postgres://postgres:PASS@/tsupasswd_sync?host=/cloudsql/...
```

修正例:

```text
postgres://postgres:PASS@localhost/tsupasswd_sync?host=/cloudsql/sync-axum-api:asia-northeast1:sync-axum-pg
```

## `password authentication failed for user "postgres"`

Cloud SQL 側のパスワードと `sync-axum-database-url` のパスワードが一致していません。

修正手順:

```powershell
gcloud sql users set-password postgres --instance=sync-axum-pg --password=NEW_DB_PASSWORD --project=sync-axum-api
```

```powershell
"postgres://postgres:NEW_DB_PASSWORD@localhost/tsupasswd_sync?host=/cloudsql/sync-axum-api:asia-northeast1:sync-axum-pg" | gcloud secrets versions add sync-axum-database-url --data-file=- --project=sync-axum-api
```

## `PORT=8080` に listen できない

Cloud Run の表面エラーですが、実際には以下が原因のことがあります。

- DB 認証失敗
- DB 接続タイムアウト
- `TSUPASSWD_SYNC_BIND` の値崩れ
- 起動時 panic

ログ確認:

```powershell
gcloud run services logs read sync-axum-api --region=asia-northeast1 --project=sync-axum-api --limit=50
```

## `TSUPASSWD_SYNC_BIND` に別 env が混入する

悪い例:

```text
TSUPASSWD_SYNC_BIND=0.0.0.0:8080 TSUPASSWD_SYNC_ENABLE_DEV_LOGIN=false
```

良い例:

```powershell
--set-env-vars "TSUPASSWD_SYNC_BIND=0.0.0.0:8080,TSUPASSWD_SYNC_ENABLE_DEV_LOGIN=false"
```

## 監査・確認コマンド

```powershell
gcloud run services describe sync-axum-api --region=asia-northeast1 --project=sync-axum-api
```

```powershell
gcloud run services logs read sync-axum-api --region=asia-northeast1 --project=sync-axum-api --limit=50
```

```powershell
gcloud secrets versions list sync-axum-database-url --project=sync-axum-api
```

```powershell
gcloud sql instances list --project=sync-axum-api
```
