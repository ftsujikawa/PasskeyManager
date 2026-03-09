use anyhow::{anyhow, Context, Result};
use base64::Engine as _;
use opaque_core::{
    client_login_finish, client_login_start, client_register_finish, client_register_start,
    MessageBytes,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
struct RegisterStartReq {
    email: String,
    registration_request_base64: String,
}

#[derive(Debug, Deserialize)]
struct RegisterStartResp {
    registration_response_base64: String,
}

#[derive(Debug, Serialize)]
struct RegisterFinishReq {
    email: String,
    registration_upload_base64: String,
}

#[derive(Debug, Deserialize)]
struct RegisterFinishResp {
    ok: bool,
}

#[derive(Debug, Serialize)]
struct LoginStartReq {
    email: String,
    credential_request_base64: String,
}

#[derive(Debug, Deserialize)]
struct LoginStartResp {
    server_state_base64: String,
    credential_response_base64: String,
}

#[derive(Debug, Serialize)]
struct LoginFinishReq {
    email: String,
    server_state_base64: String,
    credential_finalization_base64: String,
}

#[derive(Debug, Deserialize)]
struct TokenResp {
    access_token: String,
    token_type: String,
    expires_in: i64,
}

#[derive(Debug, Serialize)]
struct PutVaultReq {
    expected_server_version: i64,
    cipher_blob_base64: String,
}

#[derive(Debug, Deserialize)]
struct PutVaultResp {
    ok: bool,
    server_version: i64,
    updated_at: String,
}

#[derive(Debug, Deserialize)]
struct GetVaultResp {
    server_version: i64,
    cipher_blob_base64: String,
    updated_at: String,
}

#[derive(Debug, Deserialize)]
struct ErrorBody {
    server_version: Option<i64>,
}

fn get_arg(flag: &str) -> Option<String> {
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        if a == flag {
            return it.next();
        }
    }
    None
}

#[tokio::main]
async fn main() -> Result<()> {
    let base_url = get_arg("--base-url").unwrap_or_else(|| "http://127.0.0.1:8088".to_string());
    let email = get_arg("--email").unwrap_or_else(|| "alice@example.com".to_string());
    let password = get_arg("--password").unwrap_or_else(|| "password".to_string());

    let client = reqwest::Client::new();

    // Register: client start
    let (reg_state, reg_request) = client_register_start(password.as_bytes())
        .map_err(|e| anyhow!("client_register_start_failed: {e}"))?;

    // Register: server start
    let reg_start_req = RegisterStartReq {
        email: email.clone(),
        registration_request_base64:
            base64::engine::general_purpose::STANDARD.encode(&reg_request.bytes),
    };

    let reg_start_http = client
        .post(format!("{base_url}/v1/auth/register/start"))
        .json(&reg_start_req)
        .send()
        .await
        .context("register/start request failed")?;

    let reg_start_resp = if reg_start_http.status().is_success() {
        reg_start_http
            .json::<RegisterStartResp>()
            .await
            .context("register/start invalid json")?
    } else {
        let status = reg_start_http.status();
        let body = reg_start_http
            .text()
            .await
            .unwrap_or_else(|_| "".to_string());
        return Err(anyhow!(
            "register/start non-2xx status={} body={}",
            status,
            body
        ));
    };

    let reg_response_bytes = base64::engine::general_purpose::STANDARD
        .decode(reg_start_resp.registration_response_base64.as_bytes())
        .context("register/start response base64 decode failed")?;

    let reg_response = MessageBytes {
        bytes: reg_response_bytes,
    };

    // Register: client finish (upload)
    let (upload, _export_key) = client_register_finish(password.as_bytes(), &reg_state, &reg_response)
        .map_err(|e| anyhow!("client_register_finish_failed: {e}"))?;

    // Register: server finish
    let reg_finish_req = RegisterFinishReq {
        email: email.clone(),
        registration_upload_base64:
            base64::engine::general_purpose::STANDARD.encode(&upload.bytes),
    };

    let reg_finish_http = client
        .post(format!("{base_url}/v1/auth/register/finish"))
        .json(&reg_finish_req)
        .send()
        .await
        .context("register/finish request failed")?;

    if reg_finish_http.status().is_success() {
        let reg_finish_resp = reg_finish_http
            .json::<RegisterFinishResp>()
            .await
            .context("register/finish invalid json")?;

        if !reg_finish_resp.ok {
            return Err(anyhow!("register/finish returned ok=false"));
        }
    } else {
        let status = reg_finish_http.status();
        let body = reg_finish_http
            .text()
            .await
            .unwrap_or_else(|_| "".to_string());
        if status.as_u16() != 409 {
            return Err(anyhow!(
                "register/finish non-2xx status={} body={}",
                status,
                body
            ));
        }
    }

    // Login: client start
    let (login_state, cred_request) = client_login_start(password.as_bytes())
        .map_err(|e| anyhow!("client_login_start_failed: {e}"))?;

    let login_start_req = LoginStartReq {
        email: email.clone(),
        credential_request_base64:
            base64::engine::general_purpose::STANDARD.encode(&cred_request.bytes),
    };

    let login_start_resp = client
        .post(format!("{base_url}/v1/auth/login/start"))
        .json(&login_start_req)
        .send()
        .await
        .context("login/start request failed")?
        .error_for_status()
        .context("login/start non-2xx")?
        .json::<LoginStartResp>()
        .await
        .context("login/start invalid json")?;

    let server_state_bytes = base64::engine::general_purpose::STANDARD
        .decode(login_start_resp.server_state_base64.as_bytes())
        .context("login/start server_state base64 decode failed")?;

    let cred_resp_bytes = base64::engine::general_purpose::STANDARD
        .decode(login_start_resp.credential_response_base64.as_bytes())
        .context("login/start credential_response base64 decode failed")?;

    let server_state = opaque_core::ServerStateBytes {
        bytes: server_state_bytes,
    };

    let cred_resp = MessageBytes { bytes: cred_resp_bytes };

    // Login: client finish (finalization)
    let (cred_finalization, _session_key) = client_login_finish(password.as_bytes(), &login_state, &cred_resp)
        .map_err(|e| anyhow!("client_login_finish_failed: {e}"))?;

    let login_finish_req = LoginFinishReq {
        email: email.clone(),
        server_state_base64: base64::engine::general_purpose::STANDARD.encode(&server_state.bytes),
        credential_finalization_base64:
            base64::engine::general_purpose::STANDARD.encode(&cred_finalization.bytes),
    };

    let token_resp = client
        .post(format!("{base_url}/v1/auth/login/finish"))
        .json(&login_finish_req)
        .send()
        .await
        .context("login/finish request failed")?
        .error_for_status()
        .context("login/finish non-2xx")?
        .json::<TokenResp>()
        .await
        .context("login/finish invalid json")?;

    println!("access_token={}", token_resp.access_token);
    println!("token_type={}", token_resp.token_type);
    println!("expires_in={}", token_resp.expires_in);

    // Vault PUT/GET using the issued JWT
    let dummy_cipher_blob = base64::engine::general_purpose::STANDARD.encode(b"dummy_vault_cipher");
    let mut expected_server_version = 0i64;
    let put_resp = loop {
        let put_req = PutVaultReq {
            expected_server_version,
            cipher_blob_base64: dummy_cipher_blob.clone(),
        };

        let put_http = client
            .put(format!("{base_url}/v1/vaults/{email}"))
            .bearer_auth(&token_resp.access_token)
            .json(&put_req)
            .send()
            .await
            .context("vault put request failed")?;

        if put_http.status().is_success() {
            let put_resp = put_http
                .json::<PutVaultResp>()
                .await
                .context("vault put invalid json")?;
            if !put_resp.ok {
                return Err(anyhow!("vault put returned ok=false"));
            }
            break put_resp;
        }

        if put_http.status().as_u16() == 409 {
            let body = put_http
                .text()
                .await
                .unwrap_or_else(|_| "".to_string());
            let parsed = serde_json::from_str::<ErrorBody>(&body).ok();
            if let Some(sv) = parsed.and_then(|p| p.server_version) {
                expected_server_version = sv;
                continue;
            }
            return Err(anyhow!("vault put conflict body={}", body));
        }

        let status = put_http.status();
        let body = put_http.text().await.unwrap_or_else(|_| "".to_string());
        return Err(anyhow!("vault put non-2xx status={} body={}", status, body));
    };

    let get_http = client
        .get(format!("{base_url}/v1/vaults/{email}"))
        .bearer_auth(&token_resp.access_token)
        .send()
        .await
        .context("vault get request failed")?;

    if !get_http.status().is_success() {
        let status = get_http.status();
        let body = get_http.text().await.unwrap_or_else(|_| "".to_string());
        return Err(anyhow!("vault get non-2xx status={} body={}", status, body));
    }

    let get_resp = get_http
        .json::<GetVaultResp>()
        .await
        .context("vault get invalid json")?;

    if get_resp.cipher_blob_base64 != dummy_cipher_blob {
        return Err(anyhow!("vault get mismatch"));
    }

    println!("vault_put_server_version={}", put_resp.server_version);
    println!("vault_get_server_version={}", get_resp.server_version);
    println!("vault_put_updated_at={}", put_resp.updated_at);
    println!("vault_updated_at={}", get_resp.updated_at);

    Ok(())
}
