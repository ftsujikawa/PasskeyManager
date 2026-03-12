# Cloud Run Deploy

## デプロイコマンド

```powershell
gcloud run deploy sync-axum-api --image asia-northeast1-docker.pkg.dev/sync-axum-api/sync-axum-api/api:latest --region asia-northeast1 --platform managed --allow-unauthenticated --add-cloudsql-instances sync-axum-api:asia-northeast1:sync-axum-pg --set-env-vars "TSUPASSWD_SYNC_BIND=0.0.0.0:8080,TSUPASSWD_SYNC_ENABLE_DEV_LOGIN=false" --set-secrets "DATABASE_URL=sync-axum-database-url:latest,TSUPASSWD_SYNC_JWT_SECRET=sync-axum-jwt-secret:latest"
```

## デプロイ時の重要ポイント

- `--set-env-vars` は 1 引数として渡す
- PowerShell では全体をダブルクォートで囲む
- `TSUPASSWD_SYNC_BIND` と `TSUPASSWD_SYNC_ENABLE_DEV_LOGIN` を 1 つの値として連結しない
- `--set-secrets` も 1 引数として渡す
- `INSTANCE_CONNECTION_NAME` のようなプレースホルダ文字列をそのまま入れない

## デプロイ後の確認

サービス情報確認:

```powershell
gcloud run services describe sync-axum-api --region=asia-northeast1 --project=sync-axum-api
```

ログ確認:

```powershell
gcloud run services logs read sync-axum-api --region=asia-northeast1 --project=sync-axum-api --limit=50
```

## 期待する環境変数状態

Cloud Run revision では、少なくとも次の形になっていることを確認します。

- `TSUPASSWD_SYNC_BIND=0.0.0.0:8080`
- `TSUPASSWD_SYNC_ENABLE_DEV_LOGIN=false`
- `DATABASE_URL` は Secret Manager 参照
- `TSUPASSWD_SYNC_JWT_SECRET` は Secret Manager 参照

## 再デプロイ

イメージ更新後は同じコマンドで再デプロイできます。

```powershell
docker build -t sync-axum-api .
docker tag sync-axum-api asia-northeast1-docker.pkg.dev/sync-axum-api/sync-axum-api/api:latest
docker push asia-northeast1-docker.pkg.dev/sync-axum-api/sync-axum-api/api:latest
```

```powershell
gcloud run deploy sync-axum-api --image asia-northeast1-docker.pkg.dev/sync-axum-api/sync-axum-api/api:latest --region asia-northeast1 --platform managed --allow-unauthenticated --add-cloudsql-instances sync-axum-api:asia-northeast1:sync-axum-pg --set-env-vars "TSUPASSWD_SYNC_BIND=0.0.0.0:8080,TSUPASSWD_SYNC_ENABLE_DEV_LOGIN=false" --set-secrets "DATABASE_URL=sync-axum-database-url:latest,TSUPASSWD_SYNC_JWT_SECRET=sync-axum-jwt-secret:latest"
```
