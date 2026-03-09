use std::{
    cell::RefCell,
    ffi::{c_char, c_uchar, CString},
    ptr,
    slice,
};

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

fn set_last_error(msg: impl Into<String>) {
    let s = msg.into();
    let c = CString::new(s).unwrap_or_else(|_| CString::new("opaque-ffi: invalid error").unwrap());
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = Some(c);
    });
}

fn clear_last_error() {
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = None;
    });
}

#[repr(C)]
pub struct ByteBuffer {
    pub ptr: *mut c_uchar,
    pub len: usize,
}

impl ByteBuffer {
    fn null() -> Self {
        Self {
            ptr: ptr::null_mut(),
            len: 0,
        }
    }
}

fn vec_to_bytebuffer(mut v: Vec<u8>) -> ByteBuffer {
    if v.is_empty() {
        return ByteBuffer::null();
    }
    let len = v.len();
    let ptr = v.as_mut_ptr();
    std::mem::forget(v);
    ByteBuffer { ptr, len }
}

unsafe fn bytebuffer_to_slice<'a>(buf: *const ByteBuffer) -> Option<&'a [u8]> {
    if buf.is_null() {
        return None;
    }
    let b = &*buf;
    if b.ptr.is_null() {
        return Some(&[]);
    }
    Some(slice::from_raw_parts(b.ptr as *const u8, b.len))
}

#[no_mangle]
pub extern "C" fn tsupasswd_opaque_free_bytes(buf: ByteBuffer) {
    if buf.ptr.is_null() {
        return;
    }
    unsafe {
        drop(Vec::from_raw_parts(buf.ptr as *mut u8, buf.len, buf.len));
    }
}

#[no_mangle]
pub extern "C" fn tsupasswd_opaque_free_cstring(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    unsafe {
        drop(CString::from_raw(s));
    }
}

#[no_mangle]
pub extern "C" fn tsupasswd_opaque_last_error() -> *mut c_char {
    let c = LAST_ERROR.with(|e| e.borrow().clone());
    match c {
        Some(cstr) => cstr.into_raw(),
        None => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn tsupasswd_opaque_version() -> *const c_char {
    static VERSION: &[u8] = b"0.1.0\0";
    VERSION.as_ptr() as *const c_char
}

#[no_mangle]
pub extern "C" fn tsupasswd_opaque_client_register_start(
    password: *const c_uchar,
    password_len: usize,
    out_client_state: *mut ByteBuffer,
    out_registration_request: *mut ByteBuffer,
) -> bool {
    clear_last_error();
    if out_client_state.is_null() || out_registration_request.is_null() {
        set_last_error("out_client_state or out_registration_request is null");
        return false;
    }
    if password.is_null() {
        set_last_error("password is null");
        return false;
    }

    let pw = unsafe { slice::from_raw_parts(password as *const u8, password_len) };
    match opaque_core::client_register_start(pw) {
        Ok((state, msg)) => unsafe {
            *out_client_state = vec_to_bytebuffer(state.bytes);
            *out_registration_request = vec_to_bytebuffer(msg.bytes);
            true
        },
        Err(e) => {
            set_last_error(format!("client_register_start failed: {e}"));
            false
        }
    }
}

#[no_mangle]
pub extern "C" fn tsupasswd_opaque_client_register_finish(
    password: *const c_uchar,
    password_len: usize,
    client_state: *const ByteBuffer,
    registration_response: *const ByteBuffer,
    out_registration_upload: *mut ByteBuffer,
    out_session_key: *mut ByteBuffer,
) -> bool {
    clear_last_error();
    if out_registration_upload.is_null() || out_session_key.is_null() {
        set_last_error("out_registration_upload or out_session_key is null");
        return false;
    }
    if password.is_null() {
        set_last_error("password is null");
        return false;
    }

    let pw = unsafe { slice::from_raw_parts(password as *const u8, password_len) };
    let state_bytes = unsafe { bytebuffer_to_slice(client_state) };
    let resp_bytes = unsafe { bytebuffer_to_slice(registration_response) };

    let (state_bytes, resp_bytes) = match (state_bytes, resp_bytes) {
        (Some(s), Some(r)) => (s, r),
        _ => {
            set_last_error("client_state or registration_response is null");
            return false;
        }
    };

    let state = opaque_core::ClientStateBytes {
        bytes: state_bytes.to_vec(),
    };
    let resp = opaque_core::MessageBytes {
        bytes: resp_bytes.to_vec(),
    };

    match opaque_core::client_register_finish(pw, &state, &resp) {
        Ok((upload, sk)) => unsafe {
            *out_registration_upload = vec_to_bytebuffer(upload.bytes);
            *out_session_key = vec_to_bytebuffer(sk.bytes);
            true
        },
        Err(e) => {
            set_last_error(format!("client_register_finish failed: {e}"));
            false
        }
    }
}

#[no_mangle]
pub extern "C" fn tsupasswd_opaque_client_login_start(
    password: *const c_uchar,
    password_len: usize,
    out_client_state: *mut ByteBuffer,
    out_credential_request: *mut ByteBuffer,
) -> bool {
    clear_last_error();
    if out_client_state.is_null() || out_credential_request.is_null() {
        set_last_error("out_client_state or out_credential_request is null");
        return false;
    }
    if password.is_null() {
        set_last_error("password is null");
        return false;
    }

    let pw = unsafe { slice::from_raw_parts(password as *const u8, password_len) };
    match opaque_core::client_login_start(pw) {
        Ok((state, msg)) => unsafe {
            *out_client_state = vec_to_bytebuffer(state.bytes);
            *out_credential_request = vec_to_bytebuffer(msg.bytes);
            true
        },
        Err(e) => {
            set_last_error(format!("client_login_start failed: {e}"));
            false
        }
    }
}

#[no_mangle]
pub extern "C" fn tsupasswd_opaque_client_login_finish(
    password: *const c_uchar,
    password_len: usize,
    client_state: *const ByteBuffer,
    credential_response: *const ByteBuffer,
    out_credential_finalization: *mut ByteBuffer,
    out_session_key: *mut ByteBuffer,
) -> bool {
    clear_last_error();
    if out_credential_finalization.is_null() || out_session_key.is_null() {
        set_last_error("out_credential_finalization or out_session_key is null");
        return false;
    }
    if password.is_null() {
        set_last_error("password is null");
        return false;
    }

    let pw = unsafe { slice::from_raw_parts(password as *const u8, password_len) };
    let state_bytes = unsafe { bytebuffer_to_slice(client_state) };
    let resp_bytes = unsafe { bytebuffer_to_slice(credential_response) };

    let (state_bytes, resp_bytes) = match (state_bytes, resp_bytes) {
        (Some(s), Some(r)) => (s, r),
        _ => {
            set_last_error("client_state or credential_response is null");
            return false;
        }
    };

    let state = opaque_core::ClientStateBytes {
        bytes: state_bytes.to_vec(),
    };
    let resp = opaque_core::MessageBytes {
        bytes: resp_bytes.to_vec(),
    };

    match opaque_core::client_login_finish(pw, &state, &resp) {
        Ok((finalization, sk)) => unsafe {
            *out_credential_finalization = vec_to_bytebuffer(finalization.bytes);
            *out_session_key = vec_to_bytebuffer(sk.bytes);
            true
        },
        Err(e) => {
            set_last_error(format!("client_login_finish failed: {e}"));
            false
        }
    }
}

#[no_mangle]
pub extern "C" fn tsupasswd_opaque_server_setup_new(out_server_setup: *mut ByteBuffer) -> bool {
    clear_last_error();
    if out_server_setup.is_null() {
        set_last_error("out_server_setup is null");
        return false;
    }

    match opaque_core::server_setup_new() {
        Ok(setup) => unsafe {
            *out_server_setup = vec_to_bytebuffer(setup.bytes);
            true
        },
        Err(e) => {
            set_last_error(format!("server_setup_new failed: {e}"));
            false
        }
    }
}

#[no_mangle]
pub extern "C" fn tsupasswd_opaque_server_register_start(
    server_setup: *const ByteBuffer,
    registration_request: *const ByteBuffer,
    server_user_id: *const c_uchar,
    server_user_id_len: usize,
    out_registration_response: *mut ByteBuffer,
) -> bool {
    clear_last_error();
    if out_registration_response.is_null() {
        set_last_error("out_registration_response is null");
        return false;
    }

    let setup_bytes = unsafe { bytebuffer_to_slice(server_setup) };
    let req_bytes = unsafe { bytebuffer_to_slice(registration_request) };

    let (setup_bytes, req_bytes) = match (setup_bytes, req_bytes) {
        (Some(s), Some(r)) => (s, r),
        _ => {
            set_last_error("server_setup or registration_request is null");
            return false;
        }
    };

    if server_user_id.is_null() {
        set_last_error("server_user_id is null");
        return false;
    }

    let user_id = unsafe { slice::from_raw_parts(server_user_id as *const u8, server_user_id_len) };

    let setup = opaque_core::ServerSetupBytes {
        bytes: setup_bytes.to_vec(),
    };
    let req = opaque_core::MessageBytes {
        bytes: req_bytes.to_vec(),
    };

    match opaque_core::server_register_start(&setup, &req, user_id) {
        Ok(resp) => unsafe {
            *out_registration_response = vec_to_bytebuffer(resp.bytes);
            true
        },
        Err(e) => {
            set_last_error(format!("server_register_start failed: {e}"));
            false
        }
    }
}

#[no_mangle]
pub extern "C" fn tsupasswd_opaque_server_register_finish(
    registration_upload: *const ByteBuffer,
    out_password_file: *mut ByteBuffer,
) -> bool {
    clear_last_error();
    if out_password_file.is_null() {
        set_last_error("out_password_file is null");
        return false;
    }

    let upload_bytes = unsafe { bytebuffer_to_slice(registration_upload) };
    let upload_bytes = match upload_bytes {
        Some(b) => b,
        None => {
            set_last_error("registration_upload is null");
            return false;
        }
    };

    let upload = opaque_core::PasswordFileBytes {
        bytes: upload_bytes.to_vec(),
    };

    match opaque_core::server_register_finish(&upload) {
        Ok(file) => unsafe {
            *out_password_file = vec_to_bytebuffer(file.bytes);
            true
        },
        Err(e) => {
            set_last_error(format!("server_register_finish failed: {e}"));
            false
        }
    }
}

#[no_mangle]
pub extern "C" fn tsupasswd_opaque_server_login_start(
    server_setup: *const ByteBuffer,
    password_file: *const ByteBuffer,
    credential_request: *const ByteBuffer,
    server_user_id: *const c_uchar,
    server_user_id_len: usize,
    out_server_state: *mut ByteBuffer,
    out_credential_response: *mut ByteBuffer,
) -> bool {
    clear_last_error();
    if out_server_state.is_null() || out_credential_response.is_null() {
        set_last_error("out_server_state or out_credential_response is null");
        return false;
    }

    let setup_bytes = unsafe { bytebuffer_to_slice(server_setup) };
    let req_bytes = unsafe { bytebuffer_to_slice(credential_request) };
    let (setup_bytes, req_bytes) = match (setup_bytes, req_bytes) {
        (Some(s), Some(r)) => (s, r),
        _ => {
            set_last_error("server_setup or credential_request is null");
            return false;
        }
    };

    if server_user_id.is_null() {
        set_last_error("server_user_id is null");
        return false;
    }
    let user_id = unsafe { slice::from_raw_parts(server_user_id as *const u8, server_user_id_len) };

    let setup = opaque_core::ServerSetupBytes {
        bytes: setup_bytes.to_vec(),
    };

    let req = opaque_core::MessageBytes {
        bytes: req_bytes.to_vec(),
    };

    let password_file_opt = unsafe { bytebuffer_to_slice(password_file) };
    let password_file_opt = password_file_opt.map(|b| opaque_core::PasswordFileBytes { bytes: b.to_vec() });

    match opaque_core::server_login_start(&setup, password_file_opt.as_ref(), &req, user_id) {
        Ok((state, resp)) => unsafe {
            *out_server_state = vec_to_bytebuffer(state.bytes);
            *out_credential_response = vec_to_bytebuffer(resp.bytes);
            true
        },
        Err(e) => {
            set_last_error(format!("server_login_start failed: {e}"));
            false
        }
    }
}

#[no_mangle]
pub extern "C" fn tsupasswd_opaque_server_login_finish(
    server_state: *const ByteBuffer,
    credential_finalization: *const ByteBuffer,
    out_session_key: *mut ByteBuffer,
) -> bool {
    clear_last_error();
    if out_session_key.is_null() {
        set_last_error("out_session_key is null");
        return false;
    }

    let state_bytes = unsafe { bytebuffer_to_slice(server_state) };
    let fin_bytes = unsafe { bytebuffer_to_slice(credential_finalization) };
    let (state_bytes, fin_bytes) = match (state_bytes, fin_bytes) {
        (Some(s), Some(f)) => (s, f),
        _ => {
            set_last_error("server_state or credential_finalization is null");
            return false;
        }
    };

    let state = opaque_core::ServerStateBytes {
        bytes: state_bytes.to_vec(),
    };
    let finalization = opaque_core::MessageBytes {
        bytes: fin_bytes.to_vec(),
    };

    match opaque_core::server_login_finish(&state, &finalization) {
        Ok(sk) => unsafe {
            *out_session_key = vec_to_bytebuffer(sk.bytes);
            true
        },
        Err(e) => {
            set_last_error(format!("server_login_finish failed: {e}"));
            false
        }
    }
}

