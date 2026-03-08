#include "pch.h"

#include <algorithm>
#include <string>
#include <vector>

#include "tsupasswd_opaque_raii.hpp"

static bool OpaqueBoolFail(std::string* outError, const char* context)
{
    if (outError)
    {
        *outError = std::string(context) + ": " + tsupasswd::opaque::TakeLastErrorString();
    }
    return false;
}

bool TsuPasswdOpaqueFfiInProcessSmoke(std::string* outError)
{
    using tsupasswd::opaque::ByteBufferOwner;

    auto logStep = [](const char* s)
    {
        OutputDebugStringA(s);
        OutputDebugStringA("\n");
    };

    const std::string password = "test-password";
    const std::vector<uint8_t> userId = {'u', 's', 'e', 'r', '1'};

    ByteBufferOwner serverSetup;
    logStep("opaque_ffi_smoke step=server_setup_new begin");
    if (!tsupasswd_opaque_server_setup_new(serverSetup.out_ptr()))
    {
        return OpaqueBoolFail(outError, "server_setup_new failed");
    }
    logStep("opaque_ffi_smoke step=server_setup_new ok");

    ByteBufferOwner regClientState;
    ByteBufferOwner regReq;
    logStep("opaque_ffi_smoke step=client_register_start begin");
    if (!tsupasswd_opaque_client_register_start(
            reinterpret_cast<const uint8_t*>(password.data()),
            password.size(),
            regClientState.out_ptr(),
            regReq.out_ptr()))
    {
        return OpaqueBoolFail(outError, "client_register_start failed");
    }
    logStep("opaque_ffi_smoke step=client_register_start ok");

    ByteBufferOwner regResp;
    logStep("opaque_ffi_smoke step=server_register_start begin");
    if (!tsupasswd_opaque_server_register_start(
            &serverSetup.get(),
            &regReq.get(),
            userId.data(),
            userId.size(),
            regResp.out_ptr()))
    {
        return OpaqueBoolFail(outError, "server_register_start failed");
    }
    logStep("opaque_ffi_smoke step=server_register_start ok");

    ByteBufferOwner regUpload;
    ByteBufferOwner regSessionKey;
    logStep("opaque_ffi_smoke step=client_register_finish begin");
    if (!tsupasswd_opaque_client_register_finish(
            reinterpret_cast<const uint8_t*>(password.data()),
            password.size(),
            &regClientState.get(),
            &regResp.get(),
            regUpload.out_ptr(),
            regSessionKey.out_ptr()))
    {
        return OpaqueBoolFail(outError, "client_register_finish failed");
    }
    logStep("opaque_ffi_smoke step=client_register_finish ok");

    ByteBufferOwner passwordFile;
    logStep("opaque_ffi_smoke step=server_register_finish begin");
    if (!tsupasswd_opaque_server_register_finish(&regUpload.get(), passwordFile.out_ptr()))
    {
        return OpaqueBoolFail(outError, "server_register_finish failed");
    }
    logStep("opaque_ffi_smoke step=server_register_finish ok");

    ByteBufferOwner loginClientState;
    ByteBufferOwner credReq;
    logStep("opaque_ffi_smoke step=client_login_start begin");
    if (!tsupasswd_opaque_client_login_start(
            reinterpret_cast<const uint8_t*>(password.data()),
            password.size(),
            loginClientState.out_ptr(),
            credReq.out_ptr()))
    {
        return OpaqueBoolFail(outError, "client_login_start failed");
    }
    logStep("opaque_ffi_smoke step=client_login_start ok");

    ByteBufferOwner serverState;
    ByteBufferOwner credResp;
    logStep("opaque_ffi_smoke step=server_login_start begin");
    if (!tsupasswd_opaque_server_login_start(
            &serverSetup.get(),
            &passwordFile.get(),
            &credReq.get(),
            userId.data(),
            userId.size(),
            serverState.out_ptr(),
            credResp.out_ptr()))
    {
        return OpaqueBoolFail(outError, "server_login_start failed");
    }
    logStep("opaque_ffi_smoke step=server_login_start ok");

    ByteBufferOwner credFin;
    ByteBufferOwner clientSessionKey;
    logStep("opaque_ffi_smoke step=client_login_finish begin");
    if (!tsupasswd_opaque_client_login_finish(
            reinterpret_cast<const uint8_t*>(password.data()),
            password.size(),
            &loginClientState.get(),
            &credResp.get(),
            credFin.out_ptr(),
            clientSessionKey.out_ptr()))
    {
        return OpaqueBoolFail(outError, "client_login_finish failed");
    }
    logStep("opaque_ffi_smoke step=client_login_finish ok");

    ByteBufferOwner serverSessionKey;
    logStep("opaque_ffi_smoke step=server_login_finish begin");
    if (!tsupasswd_opaque_server_login_finish(&serverState.get(), &credFin.get(), serverSessionKey.out_ptr()))
    {
        return OpaqueBoolFail(outError, "server_login_finish failed");
    }
    logStep("opaque_ffi_smoke step=server_login_finish ok");

    if (clientSessionKey.size() != serverSessionKey.size())
    {
        if (outError)
        {
            *outError = "session_key_size_mismatch";
        }
        return false;
    }

    const bool match = std::equal(
        clientSessionKey.data(),
        clientSessionKey.data() + clientSessionKey.size(),
        serverSessionKey.data());

    if (!match)
    {
        if (outError)
        {
            *outError = "session_key_mismatch";
        }
        return false;
    }

    logStep("opaque_ffi_smoke step=done ok");
    return true;
}
