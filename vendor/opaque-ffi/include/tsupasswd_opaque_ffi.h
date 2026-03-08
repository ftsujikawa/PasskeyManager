#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32)
  #if defined(TSUPASSWD_OPAQUE_FFI_BUILD_DLL)
    #define TSUPASSWD_OPAQUE_FFI_API __declspec(dllexport)
  #else
    #define TSUPASSWD_OPAQUE_FFI_API __declspec(dllimport)
  #endif
#else
  #define TSUPASSWD_OPAQUE_FFI_API
#endif

typedef struct ByteBuffer {
    uint8_t* ptr;
    size_t len;
} ByteBuffer;

TSUPASSWD_OPAQUE_FFI_API void tsupasswd_opaque_free_bytes(ByteBuffer buf);
TSUPASSWD_OPAQUE_FFI_API void tsupasswd_opaque_free_cstring(char* s);

TSUPASSWD_OPAQUE_FFI_API char* tsupasswd_opaque_last_error(void);

TSUPASSWD_OPAQUE_FFI_API const char* tsupasswd_opaque_version(void);

TSUPASSWD_OPAQUE_FFI_API bool tsupasswd_opaque_client_register_start(
    const uint8_t* password,
    size_t password_len,
    ByteBuffer* out_client_state,
    ByteBuffer* out_registration_request);

TSUPASSWD_OPAQUE_FFI_API bool tsupasswd_opaque_client_register_finish(
    const uint8_t* password,
    size_t password_len,
    const ByteBuffer* client_state,
    const ByteBuffer* registration_response,
    ByteBuffer* out_registration_upload,
    ByteBuffer* out_session_key);

TSUPASSWD_OPAQUE_FFI_API bool tsupasswd_opaque_client_login_start(
    const uint8_t* password,
    size_t password_len,
    ByteBuffer* out_client_state,
    ByteBuffer* out_credential_request);

TSUPASSWD_OPAQUE_FFI_API bool tsupasswd_opaque_client_login_finish(
    const uint8_t* password,
    size_t password_len,
    const ByteBuffer* client_state,
    const ByteBuffer* credential_response,
    ByteBuffer* out_credential_finalization,
    ByteBuffer* out_session_key);

TSUPASSWD_OPAQUE_FFI_API bool tsupasswd_opaque_server_setup_new(ByteBuffer* out_server_setup);

TSUPASSWD_OPAQUE_FFI_API bool tsupasswd_opaque_server_register_start(
    const ByteBuffer* server_setup,
    const ByteBuffer* registration_request,
    const uint8_t* server_user_id,
    size_t server_user_id_len,
    ByteBuffer* out_registration_response);

TSUPASSWD_OPAQUE_FFI_API bool tsupasswd_opaque_server_register_finish(
    const ByteBuffer* registration_upload,
    ByteBuffer* out_password_file);

TSUPASSWD_OPAQUE_FFI_API bool tsupasswd_opaque_server_login_start(
    const ByteBuffer* server_setup,
    const ByteBuffer* password_file,
    const ByteBuffer* credential_request,
    const uint8_t* server_user_id,
    size_t server_user_id_len,
    ByteBuffer* out_server_state,
    ByteBuffer* out_credential_response);

TSUPASSWD_OPAQUE_FFI_API bool tsupasswd_opaque_server_login_finish(
    const ByteBuffer* server_state,
    const ByteBuffer* credential_finalization,
    ByteBuffer* out_session_key);

#ifdef __cplusplus
}
#endif
