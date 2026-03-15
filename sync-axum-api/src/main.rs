use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use base64::Engine as _;
use chrono::Utc;
use jsonwebtoken::{DecodingKey, EncodingKey, Validation};
use opaque_core::{
    server_login_finish, server_login_start, server_register_finish, server_register_start,
    server_setup_new, MessageBytes, PasswordFileBytes, ServerSetupBytes, ServerStateBytes,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{
    postgres::PgPoolOptions,
    Pool, Postgres,
};
use std::{env, net::SocketAddr, sync::Arc};
use tracing::{error, info};

#[derive(Clone)]
struct AppState {
    db: Pool<Postgres>,
    jwt_encoding_key: Arc<EncodingKey>,
    jwt_decoding_key: Arc<DecodingKey>,
    opaque_server_setup: Arc<ServerSetupBytes>,
}

async fn opaque_register_start(
    State(state): State<AppState>,
    Json(req): Json<OpaqueRegisterStartRequest>,
) -> impl IntoResponse {
    let email = normalize_email(&req.email);
    if email.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                code: "INVALID_EMAIL",
                message: "email is required",
            }),
        )
            .into_response();
    }

    let reg_request_bytes = match base64::engine::general_purpose::STANDARD
        .decode(req.registration_request_base64.as_bytes())
    {
        Ok(b) => MessageBytes { bytes: b },
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    code: "INVALID_REGISTRATION_REQUEST",
                    message: "invalid registration request",
                }),
            )
                .into_response();
        }
    };

    let reg_response = match server_register_start(
        &state.opaque_server_setup,
        &reg_request_bytes,
        email.as_bytes(),
    ) {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    code: "OPAQUE_REGISTER_FAILED",
                    message: "registration failed",
                }),
            )
                .into_response();
        }
    };

    (
        StatusCode::OK,
        Json(OpaqueRegisterStartResponse {
            registration_response_base64: base64::engine::general_purpose::STANDARD
                .encode(&reg_response.bytes),
        }),
    )
        .into_response()
}

async fn opaque_register_finish(
    State(state): State<AppState>,
    Json(req): Json<OpaqueRegisterFinishRequest>,
) -> impl IntoResponse {
    let email = normalize_email(&req.email);
    if email.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                code: "INVALID_EMAIL",
                message: "email is required",
            }),
        )
            .into_response();
    }

    let upload = match base64::engine::general_purpose::STANDARD
        .decode(req.registration_upload_base64.as_bytes())
    {
        Ok(b) => PasswordFileBytes { bytes: b },
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    code: "INVALID_REGISTRATION_UPLOAD",
                    message: "invalid registration upload",
                }),
            )
                .into_response();
        }
    };

    let password_file = match server_register_finish(&upload) {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    code: "OPAQUE_SERVER_FAILED",
                    message: "server registration failed",
                }),
            )
                .into_response();
        }
    };

    // Persist password_file for the user.
    let now_str = Utc::now().to_rfc3339();
    let file_b64 = base64::engine::general_purpose::STANDARD.encode(&password_file.bytes);

    if let Err(e) = sqlx::query(
        r#"
INSERT INTO users (email, password_file_base64, updated_at)
VALUES ($1, $2, $3)
ON CONFLICT(email) DO UPDATE SET
  password_file_base64 = EXCLUDED.password_file_base64,
  updated_at = EXCLUDED.updated_at;
"#,
    )
    .bind(&email)
    .bind(file_b64)
    .bind(now_str)
    .execute(&state.db)
    .await
    {
        error!("db error: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                code: "DB_ERROR",
                message: "db error",
            }),
        )
            .into_response();
    }

    (
        StatusCode::OK,
        Json(OpaqueRegisterFinishResponse { ok: true }),
    )
        .into_response()
}

async fn opaque_login_start(
    State(state): State<AppState>,
    Json(req): Json<OpaqueLoginStartRequest>,
) -> impl IntoResponse {
    let email = normalize_email(&req.email);
    if email.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                code: "INVALID_EMAIL",
                message: "email is required",
            }),
        )
            .into_response();
    }

    let cred_request = match base64::engine::general_purpose::STANDARD
        .decode(req.credential_request_base64.as_bytes())
    {
        Ok(b) => MessageBytes { bytes: b },
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    code: "INVALID_CREDENTIAL_REQUEST",
                    message: "invalid credential request",
                }),
            )
                .into_response();
        }
    };

    let file_bytes_opt = match sqlx::query_as::<_, (String,)>(
        r#"SELECT password_file_base64 FROM users WHERE email = $1;"#,
    )
    .bind(&email)
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some((file_b64,))) => {
            let decoded = base64::engine::general_purpose::STANDARD.decode(file_b64.as_bytes());
            match decoded {
                Ok(b) => Some(PasswordFileBytes { bytes: b }),
                Err(_) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse {
                            code: "DB_CORRUPT",
                            message: "corrupt stored opaque data",
                        }),
                    )
                        .into_response();
                }
            }
        }
        Ok(None) => None,
        Err(e) => {
            error!("db error: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    code: "DB_ERROR",
                    message: "db error",
                }),
            )
                .into_response();
        }
    };

    let (server_state, cred_response) = match server_login_start(
        &state.opaque_server_setup,
        file_bytes_opt.as_ref(),
        &cred_request,
        email.as_bytes(),
    ) {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    code: "OPAQUE_LOGIN_FAILED",
                    message: "login failed",
                }),
            )
                .into_response();
        }
    };

    (
        StatusCode::OK,
        Json(OpaqueLoginStartResponse {
            server_state_base64: base64::engine::general_purpose::STANDARD.encode(&server_state.bytes),
            credential_response_base64: base64::engine::general_purpose::STANDARD.encode(&cred_response.bytes),
        }),
    )
        .into_response()
}

async fn opaque_login_finish(
    State(state): State<AppState>,
    Json(req): Json<OpaqueLoginFinishRequest>,
) -> impl IntoResponse {
    let email = normalize_email(&req.email);
    if email.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                code: "INVALID_EMAIL",
                message: "email is required",
            }),
        )
            .into_response();
    }

    let server_state = match base64::engine::general_purpose::STANDARD
        .decode(req.server_state_base64.as_bytes())
    {
        Ok(b) => ServerStateBytes { bytes: b },
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    code: "INVALID_SERVER_STATE",
                    message: "invalid server state",
                }),
            )
                .into_response();
        }
    };

    let cred_finalization = match base64::engine::general_purpose::STANDARD
        .decode(req.credential_finalization_base64.as_bytes())
    {
        Ok(b) => MessageBytes { bytes: b },
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    code: "INVALID_CREDENTIAL_FINALIZATION",
                    message: "invalid credential finalization",
                }),
            )
                .into_response();
        }
    };

    let _server_session_key = match server_login_finish(&server_state, &cred_finalization) {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    code: "OPAQUE_LOGIN_FAILED",
                    message: "login failed",
                }),
            )
                .into_response();
        }
    };

    // Issue JWT (server-fixed secret) on successful login.
    let now = Utc::now().timestamp();
    let expires_in = 60 * 60;
    let claims = Claims {
        sub: email,
        iss: "tsupasswd-sync".to_string(),
        aud: "tsupasswd-client".to_string(),
        iat: now,
        exp: now + expires_in,
    };

    let token = match jsonwebtoken::encode(&jsonwebtoken::Header::default(), &claims, &state.jwt_encoding_key) {
        Ok(t) => t,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    code: "TOKEN_ISSUE_FAILED",
                    message: "failed to issue token",
                }),
            )
                .into_response();
        }
    };

    (
        StatusCode::OK,
        Json(DevLoginResponse {
            access_token: token,
            token_type: "Bearer",
            expires_in,
        }),
    )
        .into_response()
}

async fn dev_login(
    State(state): State<AppState>,
    Json(req): Json<DevLoginRequest>,
) -> impl IntoResponse {
    let email = normalize_email(&req.email);
    if email.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                code: "INVALID_EMAIL",
                message: "email is required",
            }),
        )
            .into_response();
    }

    let now = Utc::now().timestamp();
    let expires_in = 60 * 60;

    let claims = Claims {
        sub: email,
        iss: "tsupasswd-sync".to_string(),
        aud: "tsupasswd-client".to_string(),
        iat: now,
        exp: now + expires_in,
    };

    let token = match jsonwebtoken::encode(&jsonwebtoken::Header::default(), &claims, &state.jwt_encoding_key) {
        Ok(t) => t,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    code: "TOKEN_ISSUE_FAILED",
                    message: "failed to issue token",
                }),
            )
                .into_response();
        }
    };

    (
        StatusCode::OK,
        Json(DevLoginResponse {
            access_token: token,
            token_type: "Bearer",
            expires_in,
        }),
    )
        .into_response()
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    code: &'static str,
    message: &'static str,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    iss: String,
    aud: String,
    iat: i64,
    exp: i64,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    ok: bool,
    service: &'static str,
    database_url: String,
}

#[derive(Debug, Deserialize)]
struct DevLoginRequest {
    email: String,
}

#[derive(Debug, Serialize)]
struct DevLoginResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: i64,
}

#[derive(Debug, Deserialize)]
struct OpaqueRegisterStartRequest {
    email: String,
    registration_request_base64: String,
}

#[derive(Debug, Serialize)]
struct OpaqueRegisterStartResponse {
    registration_response_base64: String,
}

#[derive(Debug, Deserialize)]
struct OpaqueRegisterFinishRequest {
    email: String,
    registration_upload_base64: String,
}

#[derive(Debug, Serialize)]
struct OpaqueRegisterFinishResponse {
    ok: bool,
}

#[derive(Debug, Deserialize)]
struct OpaqueLoginStartRequest {
    email: String,
    credential_request_base64: String,
}

#[derive(Debug, Serialize)]
struct OpaqueLoginStartResponse {
    server_state_base64: String,
    credential_response_base64: String,
}

#[derive(Debug, Deserialize)]
struct OpaqueLoginFinishRequest {
    email: String,
    server_state_base64: String,
    credential_finalization_base64: String,
}

#[derive(Debug, Deserialize)]
struct PutVaultRequest {
    expected_server_version: i64,
    cipher_blob_base64: String,
}

#[derive(Debug, Serialize)]
struct GetVaultResponse {
    server_version: i64,
    cipher_blob_base64: String,
    updated_at: String,
}

#[derive(Debug, Serialize)]
struct PutVaultResponse {
    ok: bool,
    server_version: i64,
    updated_at: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let database_url = env::var("DATABASE_URL")
        .or_else(|_| env::var("TSUPASSWD_SYNC_DATABASE_URL"))
        .unwrap_or_else(|_| "postgres://postgres:postgres@127.0.0.1:5432/tsupasswd_sync".to_string());
    let bind = env::var("TSUPASSWD_SYNC_BIND")
        .or_else(|_| {
            env::var("PORT").map(|port| format!("0.0.0.0:{port}"))
        })
        .unwrap_or_else(|_| "127.0.0.1:8088".to_string());

    let jwt_secret = env::var("TSUPASSWD_SYNC_JWT_SECRET").unwrap_or_else(|_| "dev-jwt-secret".to_string());
    let enable_dev_login = env::var("TSUPASSWD_SYNC_ENABLE_DEV_LOGIN")
        .ok()
        .map(|v| v.trim().eq_ignore_ascii_case("true") || v.trim() == "1")
        .unwrap_or(true);

    let db = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;

    ensure_schema(&db).await?;

    let opaque_server_setup = load_or_create_opaque_server_setup(&db).await?;

    let state = AppState {
        db,
        jwt_encoding_key: Arc::new(EncodingKey::from_secret(jwt_secret.as_bytes())),
        jwt_decoding_key: Arc::new(DecodingKey::from_secret(jwt_secret.as_bytes())),
        opaque_server_setup: Arc::new(opaque_server_setup),
    };

    let mut app = Router::new().route("/healthz", get(healthz));

    if enable_dev_login {
        app = app.route("/v1/auth/dev/login", axum::routing::post(dev_login));
    }

    let app = app
        .route(
            "/v1/auth/register/start",
            axum::routing::post(opaque_register_start),
        )
        .route(
            "/v1/auth/register/finish",
            axum::routing::post(opaque_register_finish),
        )
        .route(
            "/v1/auth/login/start",
            axum::routing::post(opaque_login_start),
        )
        .route(
            "/v1/auth/login/finish",
            axum::routing::post(opaque_login_finish),
        )
        .route("/v1/vaults/:email", get(get_vault).put(put_vault))
        .with_state(state);

    let addr: SocketAddr = bind.parse()?;
    info!("listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn healthz(State(state): State<AppState>) -> impl IntoResponse {
    let ok = sqlx::query_scalar::<_, i64>("SELECT 1;")
        .fetch_one(&state.db)
        .await
        .is_ok();

    let database_url = env::var("DATABASE_URL")
        .or_else(|_| env::var("TSUPASSWD_SYNC_DATABASE_URL"))
        .unwrap_or_else(|_| "postgres://postgres:postgres@127.0.0.1:5432/tsupasswd_sync".to_string());

    let status = if ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (
        status,
        Json(HealthResponse {
            ok,
            service: "sync-axum-api",
            database_url,
        }),
    )
}

async fn get_vault(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(email): Path<String>,
) -> impl IntoResponse {
    let email = normalize_email(&email);
    if let Err(resp) = authorize(&state, &headers, &email) {
        return resp;
    }

    let row = sqlx::query_as::<_, (i64, String, String)>(
        r#"SELECT server_version, cipher_blob_base64, updated_at FROM vaults WHERE email = $1;"#,
    )
    .bind(email)
    .fetch_optional(&state.db)
    .await;

    let row = match row {
        Ok(Some((server_version, cipher_blob_base64, updated_at))) => (server_version, cipher_blob_base64, updated_at),
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    code: "VAULT_NOT_FOUND",
                    message: "vault not found",
                }),
            )
                .into_response();
        }
        Err(e) => {
            error!("db error: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    code: "DB_ERROR",
                    message: "db error",
                }),
            )
                .into_response();
        }
    };

    (
        StatusCode::OK,
        Json(GetVaultResponse {
            server_version: row.0,
            cipher_blob_base64: row.1,
            updated_at: row.2,
        }),
    )
        .into_response()
}

async fn put_vault(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(email): Path<String>,
    Json(req): Json<PutVaultRequest>,
) -> impl IntoResponse {
    let email = normalize_email(&email);
    if let Err(resp) = authorize(&state, &headers, &email) {
        return resp;
    }

    let now = Utc::now();
    let now_str = now.to_rfc3339();

    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            error!("db error: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    code: "DB_ERROR",
                    message: "db error",
                }),
            )
                .into_response();
        }
    };

    let current = sqlx::query_as::<_, (i64,)>(r#"SELECT server_version FROM vaults WHERE email = $1;"#)
        .bind(email.clone())
        .fetch_optional(&mut *tx)
        .await;

    let current_version = match current {
        Ok(Some((server_version,))) => server_version,
        Ok(None) => 0,
        Err(e) => {
            error!("db error: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    code: "DB_ERROR",
                    message: "db error",
                }),
            )
                .into_response();
        }
    };

    if req.expected_server_version != current_version {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "code": "VERSION_CONFLICT",
                "server_version": current_version,
            })),
        )
            .into_response();
    }

    let next_version = current_version + 1;

    if let Err(e) = sqlx::query(
        r#"
INSERT INTO vaults (email, server_version, cipher_blob_base64, updated_at)
VALUES ($1, $2, $3, $4)
ON CONFLICT(email) DO UPDATE SET
  server_version = EXCLUDED.server_version,
  cipher_blob_base64 = EXCLUDED.cipher_blob_base64,
  updated_at = EXCLUDED.updated_at;
"#,
    )
    .bind(email)
    .bind(next_version)
    .bind(req.cipher_blob_base64)
    .bind(now_str)
    .execute(&mut *tx)
    .await
    {
        error!("db error: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                code: "DB_ERROR",
                message: "db error",
            }),
        )
            .into_response();
    }

    if let Err(e) = tx.commit().await {
        error!("db error: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                code: "DB_ERROR",
                message: "db error",
            }),
        )
            .into_response();
    }

    (
        StatusCode::OK,
        Json(PutVaultResponse {
            ok: true,
            server_version: next_version,
            updated_at: now.to_rfc3339(),
        }),
    )
        .into_response()
}

fn authorize(state: &AppState, headers: &HeaderMap, expected_email: &str) -> Result<(), axum::response::Response> {
    let Some(value) = headers.get("Authorization").and_then(|v| v.to_str().ok()) else {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                code: "AUTH_MISSING",
                message: "missing authorization header",
            }),
        )
            .into_response());
    };

    let prefix = "Bearer ";
    if !value.starts_with(prefix) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                code: "AUTH_INVALID",
                message: "invalid authorization scheme",
            }),
        )
            .into_response());
    }

    let token = value[prefix.len()..].trim();

    let mut validation = Validation::default();
    validation.set_issuer(&["tsupasswd-sync"]);
    validation.set_audience(&["tsupasswd-client"]);

    let decoded = jsonwebtoken::decode::<Claims>(token, &state.jwt_decoding_key, &validation);
    let claims = match decoded {
        Ok(d) => d.claims,
        Err(_) => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    code: "AUTH_INVALID",
                    message: "invalid token",
                }),
            )
                .into_response());
        }
    };

    if claims.sub != normalize_email(expected_email) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                code: "AUTH_SUB_MISMATCH",
                message: "token subject mismatch",
            }),
        )
            .into_response());
    }

    Ok(())
}

fn normalize_email(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}

#[allow(dead_code)]
fn sha256_base64(input: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let digest = hasher.finalize();
    base64::engine::general_purpose::STANDARD.encode(digest)
}

async fn ensure_schema(db: &Pool<Postgres>) -> anyhow::Result<()> {
    sqlx::query(
        r#"
CREATE TABLE IF NOT EXISTS vaults (
  email TEXT PRIMARY KEY,
  server_version BIGINT NOT NULL,
  cipher_blob_base64 TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
"#,
    )
    .execute(db)
    .await?;

    sqlx::query(
        r#"
CREATE TABLE IF NOT EXISTS users (
  email TEXT PRIMARY KEY,
  password_file_base64 TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
"#,
    )
    .execute(db)
    .await?;

    sqlx::query(
        r#"
CREATE TABLE IF NOT EXISTS server_config (
  id BIGINT PRIMARY KEY CHECK (id = 1),
  opaque_server_setup_base64 TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
"#,
    )
    .execute(db)
    .await?;

    Ok(())
}

async fn load_or_create_opaque_server_setup(db: &Pool<Postgres>) -> anyhow::Result<ServerSetupBytes> {
    let row = sqlx::query_as::<_, (String,)>(
        r#"SELECT opaque_server_setup_base64 FROM server_config WHERE id = 1;"#,
    )
    .fetch_optional(db)
    .await?;

    if let Some((b64,)) = row {
        let bytes = base64::engine::general_purpose::STANDARD.decode(b64.as_bytes())?;
        return Ok(ServerSetupBytes { bytes });
    }

    let setup = server_setup_new()?;
    let now_str = Utc::now().to_rfc3339();
    let setup_b64 = base64::engine::general_purpose::STANDARD.encode(&setup.bytes);

    sqlx::query(
        r#"
INSERT INTO server_config (id, opaque_server_setup_base64, updated_at)
VALUES (1, $1, $2)
ON CONFLICT(id) DO UPDATE SET
  opaque_server_setup_base64 = EXCLUDED.opaque_server_setup_base64,
  updated_at = EXCLUDED.updated_at;
"#,
    )
    .bind(setup_b64)
    .bind(now_str)
    .execute(db)
    .await?;

    Ok(setup)
}
