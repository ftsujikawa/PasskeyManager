# Artifact Registry and Docker Image

## Dockerfile

`passkeymanager` ルートの `Dockerfile` を使います。

この Dockerfile では Rust workspace の依存を含めて build するため、少なくとも以下を COPY します。

- `Cargo.toml`
- `Cargo.lock`
- `opaque-core`
- `opaque-ffi`
- `sync-axum-api`

Rust toolchain は `1.88` 以上を使用します。

## ローカル build

```powershell
docker build --progress=plain --no-cache -t sync-axum-api .
```

## Artifact Registry repository

作成例:

```powershell
gcloud artifacts repositories create sync-axum-api --repository-format=docker --location=asia-northeast1 --project=sync-axum-api
```

既に存在する場合は `ALREADY_EXISTS` が返るため、そのまま次へ進みます。

## Docker 認証

```powershell
gcloud auth configure-docker asia-northeast1-docker.pkg.dev
```

## tag / push

```powershell
docker tag sync-axum-api asia-northeast1-docker.pkg.dev/sync-axum-api/sync-axum-api/api:latest
docker push asia-northeast1-docker.pkg.dev/sync-axum-api/sync-axum-api/api:latest
```

## よくある失敗

### `Repository not found`

- project ID が違う
- repository 名が違う
- region が違う

確認例:

```powershell
gcloud artifacts repositories list --location=asia-northeast1 --project=sync-axum-api
```

### `Artifact Registry API has not been used`

```powershell
gcloud services enable artifactregistry.googleapis.com --project=sync-axum-api
```

### `tag does not exist`

- `docker tag` 前に `docker push` している
- `latest` を `lates` のように typo している
