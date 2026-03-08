use anyhow::{anyhow, Result};
use opaque_ke::{
    key_exchange::tripledh::TripleDh, ksf, CipherSuite, ClientLogin, ClientLoginFinishParameters,
    ClientRegistration, ClientRegistrationFinishParameters, CredentialFinalization, CredentialRequest,
    CredentialResponse, RegistrationRequest, RegistrationResponse, RegistrationUpload, ServerLogin,
    ServerLoginParameters, ServerRegistration, ServerSetup,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha512;

// We intentionally keep the API byte-oriented so it can be surfaced via FFI
// without leaking opaque-ke generic types.

#[derive(Clone, Serialize, Deserialize)]
pub struct ServerSetupBytes {
    pub bytes: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PasswordFileBytes {
    pub bytes: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ClientStateBytes {
    pub bytes: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ServerStateBytes {
    pub bytes: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct MessageBytes {
    pub bytes: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SessionKeyBytes {
    pub bytes: Vec<u8>,
}

struct DefaultCipherSuite;

impl CipherSuite for DefaultCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = TripleDh<opaque_ke::Ristretto255, Sha512>;
    type Ksf = ksf::Identity;
}

type Suite = DefaultCipherSuite;

fn serialize<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    bincode::serialize(value).map_err(|e| anyhow!("serialize_failed: {e}"))
}

fn deserialize<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T> {
    bincode::deserialize(bytes).map_err(|e| anyhow!("deserialize_failed: {e}"))
}

pub fn server_setup_new() -> Result<ServerSetupBytes> {
    let mut rng = OsRng;
    let setup = ServerSetup::<Suite>::new(&mut rng);
    Ok(ServerSetupBytes {
        bytes: serialize(&setup)?,
    })
}

// Registration

pub fn client_register_start(password: &[u8]) -> Result<(ClientStateBytes, MessageBytes)> {
    let mut rng = OsRng;
    let start = ClientRegistration::<Suite>::start(&mut rng, password)
        .map_err(|e| anyhow!("client_register_start_failed: {e:?}"))?;

    Ok((
        ClientStateBytes {
            bytes: serialize(&start.state)?,
        },
        MessageBytes {
            bytes: serialize(&start.message)?,
        },
    ))
}

pub fn server_register_start(
    server_setup: &ServerSetupBytes,
    client_registration_request: &MessageBytes,
    server_user_id: &[u8],
) -> Result<MessageBytes> {
    let setup: ServerSetup<Suite> = deserialize(&server_setup.bytes)?;
    let req: RegistrationRequest<Suite> = deserialize(&client_registration_request.bytes)?;

    let start = ServerRegistration::<Suite>::start(&setup, req, server_user_id)
        .map_err(|e| anyhow!("server_register_start_failed: {e:?}"))?;

    Ok(MessageBytes {
        bytes: serialize(&start.message)?,
    })
}

pub fn client_register_finish(
    password: &[u8],
    client_state: &ClientStateBytes,
    server_registration_response: &MessageBytes,
) -> Result<(PasswordFileBytes, SessionKeyBytes)> {
    let mut rng = OsRng;
    let state: ClientRegistration<Suite> = deserialize(&client_state.bytes)?;
    let resp: RegistrationResponse<Suite> = deserialize(&server_registration_response.bytes)?;

    let finish = state
        .finish(
            &mut rng,
            password,
            resp,
            ClientRegistrationFinishParameters::default(),
        )
        .map_err(|e| anyhow!("client_register_finish_failed: {e:?}"))?;

    Ok((
        PasswordFileBytes {
            bytes: serialize(&finish.message)?,
        },
        SessionKeyBytes {
            bytes: finish.export_key.to_vec(),
        },
    ))
}

pub fn server_register_finish(registration_upload: &PasswordFileBytes) -> Result<PasswordFileBytes> {
    // The server should persist ServerRegistration (aka password file).
    // Client sends RegistrationUpload.
    let upload: RegistrationUpload<Suite> = deserialize(&registration_upload.bytes)?;
    let password_file = ServerRegistration::<Suite>::finish(upload);

    Ok(PasswordFileBytes {
        bytes: serialize(&password_file)?,
    })
}

// Login

pub fn client_login_start(password: &[u8]) -> Result<(ClientStateBytes, MessageBytes)> {
    let mut rng = OsRng;
    let start = ClientLogin::<Suite>::start(&mut rng, password)
        .map_err(|e| anyhow!("client_login_start_failed: {e:?}"))?;

    Ok((
        ClientStateBytes {
            bytes: serialize(&start.state)?,
        },
        MessageBytes {
            bytes: serialize(&start.message)?,
        },
    ))
}

pub fn server_login_start(
    server_setup: &ServerSetupBytes,
    password_file: Option<&PasswordFileBytes>,
    client_login_request: &MessageBytes,
    server_user_id: &[u8],
) -> Result<(ServerStateBytes, MessageBytes)> {
    let setup: ServerSetup<Suite> = deserialize(&server_setup.bytes)?;
    let file: Option<ServerRegistration<Suite>> = match password_file {
        Some(bytes) => Some(deserialize(&bytes.bytes)?),
        None => None,
    };
    let req: CredentialRequest<Suite> = deserialize(&client_login_request.bytes)?;

    let start = ServerLogin::<Suite>::start(
        &mut OsRng,
        &setup,
        file,
        req,
        server_user_id,
        ServerLoginParameters::default(),
    )
    .map_err(|e| anyhow!("server_login_start_failed: {e:?}"))?;

    Ok((
        ServerStateBytes {
            bytes: serialize(&start.state)?,
        },
        MessageBytes {
            bytes: serialize(&start.message)?,
        },
    ))
}

pub fn client_login_finish(
    password: &[u8],
    client_state: &ClientStateBytes,
    server_credential_response: &MessageBytes,
) -> Result<(MessageBytes, SessionKeyBytes)> {
    let mut rng = OsRng;
    let state: ClientLogin<Suite> = deserialize(&client_state.bytes)?;
    let resp: CredentialResponse<Suite> = deserialize(&server_credential_response.bytes)?;

    let finish = state
        .finish(
            &mut rng,
            password,
            resp,
            ClientLoginFinishParameters::default(),
        )
        .map_err(|e| anyhow!("client_login_finish_failed: {e:?}"))?;

    Ok((
        MessageBytes {
            bytes: serialize(&finish.message)?,
        },
        SessionKeyBytes {
            bytes: finish.session_key.to_vec(),
        },
    ))
}

pub fn server_login_finish(
    server_state: &ServerStateBytes,
    client_credential_finalization: &MessageBytes,
) -> Result<SessionKeyBytes> {
    let state: ServerLogin<Suite> = deserialize(&server_state.bytes)?;
    let msg: CredentialFinalization<Suite> = deserialize(&client_credential_finalization.bytes)?;

    let finish = state
        .finish(msg, ServerLoginParameters::default())
        .map_err(|e| anyhow!("server_login_finish_failed: {e:?}"))?;

    Ok(SessionKeyBytes {
        bytes: finish.session_key.to_vec(),
    })
}
