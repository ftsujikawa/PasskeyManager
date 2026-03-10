#include "pch.h"
#include "MainPage.xaml.h"
#include "PluginRegistrationManager.h"
#include "src/RequestId.h"
#include "src/SyncClient.h"
#include "src/SyncSnapshotStore.h"
#include "src/VaultCrypto.h"
#include "src/VaultSerialization.h"
#include <CorError.h>
#include <wil/safecast.h>
#include <functional>
#include <thread>

#pragma comment(lib, "Crypt32.lib")

namespace
{
    constexpr size_t kMinVaultCipherBlobBytes = 16;
    constexpr size_t kMaxVaultCipherBlobBytes = 64 * 1024;
    constexpr BYTE kVaultBlobMagic[4] = { 'T', 'V', 'D', '1' };
    constexpr BYTE kVaultBlobVersion = 1;
    constexpr size_t kVaultBlobHeaderBytes = 13; // magic(4) + version(1) + cipher_len(4) + checksum(4)
    constexpr wchar_t kSyncBaseUrlEnv[] = L"TSUPASSWD_SYNC_BASE_URL";
    constexpr wchar_t kSyncBearerTokenEnv[] = L"TSUPASSWD_SYNC_BEARER_TOKEN";
    constexpr wchar_t kSyncUserIdEnv[] = L"TSUPASSWD_SYNC_USER_ID";
    constexpr wchar_t kSyncAllowInsecureHttpEnv[] = L"TSUPASSWD_SYNC_ALLOW_INSECURE_HTTP";
    constexpr wchar_t kSyncOpaqueSessionWrapEnv[] = L"TSUPASSWD_SYNC_OPAQUE_SESSION_WRAP";
    constexpr wchar_t kSyncVerboseDebugEnv[] = L"TSUPASSWD_SYNC_VERBOSE_DEBUG";
    constexpr wchar_t kVaultSchemaSelfTestEnv[] = L"TSUPASSWD_VAULT_SCHEMA_SELF_TEST";
    constexpr wchar_t kVaultRecoveryCodeEnv[] = L"TSUPASSWD_VAULT_RECOVERY_CODE";
    constexpr wchar_t kDefaultSyncUserId[] = L"self";
    constexpr size_t kAuthenticatorDataFlagsOffset = 32;
    constexpr size_t kAuthenticatorDataAttestedDataOffset = 37;
    constexpr BYTE kAuthenticatorDataAttestedCredentialFlag = 0x40;

    constexpr wchar_t c_pluginProtectedOpaqueExportKey[] = L"OpaqueExportKeyProtected";

    enum class VaultBlobParseResult
    {
        NotFramed,
        Ok,
        Invalid
    };

    void AppendUint32LE(std::vector<BYTE>& out, uint32_t value);

    std::wstring GetUserEnvironmentRegistryValue(wchar_t const* name)
    {
        HKEY hKey = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Environment", 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        {
            return {};
        }

        wil::unique_hkey key{ hKey };
        DWORD type = 0;
        DWORD cbData = 0;
        if (RegQueryValueExW(key.get(), name, nullptr, &type, nullptr, &cbData) != ERROR_SUCCESS ||
            (type != REG_SZ && type != REG_EXPAND_SZ) ||
            cbData < sizeof(wchar_t))
        {
            return {};
        }

        std::wstring value(cbData / sizeof(wchar_t), L'\0');
        if (RegQueryValueExW(key.get(), name, nullptr, &type, reinterpret_cast<LPBYTE>(value.data()), &cbData) != ERROR_SUCCESS)
        {
            return {};
        }

        while (!value.empty() && value.back() == L'\0')
        {
            value.pop_back();
        }
        return value;
    }

    std::wstring GetProcessEnvironmentVariableValue(wchar_t const* name)
    {
        DWORD needed = GetEnvironmentVariableW(name, nullptr, 0);
        if (needed == 0)
        {
            return {};
        }

        std::wstring value(needed, L'\0');
        DWORD written = GetEnvironmentVariableW(name, value.data(), needed);
        if (written == 0)
        {
            return {};
        }

        value.resize(written);
        return value;
    }

    std::wstring GetEnvironmentVariableValue(wchar_t const* name)
    {
        auto processValue = GetProcessEnvironmentVariableValue(name);
        if (!processValue.empty())
        {
            return processValue;
        }
        return GetUserEnvironmentRegistryValue(name);
    }

    void ClearProcessEnvironmentVariableValue(wchar_t const* name)
    {
        SetEnvironmentVariableW(name, nullptr);
    }

    void ClearUserEnvironmentRegistryValue(wchar_t const* name)
    {
        HKEY hKey = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Environment", 0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS)
        {
            return;
        }

        wil::unique_hkey key{ hKey };
        RegDeleteValueW(key.get(), name);
    }

    bool IsTruthySetting(std::wstring value)
    {
        std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch)
        {
            return static_cast<wchar_t>(towlower(ch));
        });
        return value == L"1" || value == L"true" || value == L"yes" || value == L"on";
    }

    bool IsAllowInsecureHttpEnabled()
    {
        return IsTruthySetting(GetEnvironmentVariableValue(kSyncAllowInsecureHttpEnv));
    }

    bool IsOpaqueSessionWrapEnabled()
    {
        return IsTruthySetting(GetEnvironmentVariableValue(kSyncOpaqueSessionWrapEnv));
    }

    bool IsVerboseSyncDebugEnabled()
    {
        return IsTruthySetting(GetEnvironmentVariableValue(kSyncVerboseDebugEnv));
    }

    void DebugLogIfVerbose(std::wstring const& message)
    {
        if (!IsVerboseSyncDebugEnabled())
        {
            return;
        }
        OutputDebugStringW(message.c_str());
    }

    std::wstring GetNowIsoLikeTimestamp()
    {
        SYSTEMTIME st{};
        GetSystemTime(&st);

        wchar_t buffer[40]{};
        swprintf_s(
            buffer,
            L"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
            st.wYear,
            st.wMonth,
            st.wDay,
            st.wHour,
            st.wMinute,
            st.wSecond,
            st.wMilliseconds);
        return buffer;
    }

    std::wstring ResolveRequestId(std::wstring const& fallbackRequestId, tsupasswd::SyncHttpStatus const& status)
    {
        return status.RequestId.empty() ? fallbackRequestId : status.RequestId;
    }

    std::wstring BuildSyncFailureStatusMessage(HRESULT hr, tsupasswd::SyncHttpStatus const& status, std::wstring const&)
    {
        std::wstring detail =
            L"failure_kind=" + (FAILED(hr) ? std::wstring(L"client_error") : std::wstring(L"unexpected_or_server_error")) +
            L" sync_failure=" + (status.StatusCode >= 500 ? std::wstring(L"unexpected_or_server_error") : std::wstring(L"unexpected_or_server_error")) +
            L" local_save=kept";

        if (!status.ErrorCode.empty())
        {
            detail += L" code=" + status.ErrorCode;
            detail += L" message_code=" + status.ErrorCode;
        }
        if (!status.ErrorMessage.empty())
        {
            detail += L" message=" + status.ErrorMessage;
        }
        return detail;
    }

    bool TryIssueDevLoginToken(
        tsupasswd::SyncClient& syncClient,
        std::wstring const& syncUserId,
        std::wstring const& operation,
        std::wstring const& localRequestId,
        std::wstring const& syncBaseUrl,
        std::function<void(winrt::hstring const&)> const& statusSink,
        std::vector<uint8_t>* sessionKeyBytes = nullptr)
    {
        UNREFERENCED_PARAMETER(sessionKeyBytes);

        tsupasswd::SyncHttpStatus loginStatus{};
        std::wstring issuedToken;
        HRESULT hrLogin = syncClient.DevLogin(syncUserId, issuedToken, &loginStatus);
        if (SUCCEEDED(hrLogin) && !issuedToken.empty())
        {
            syncClient.SetBearerToken(issuedToken);
            ClearProcessEnvironmentVariableValue(kSyncBearerTokenEnv);
            ClearUserEnvironmentRegistryValue(kSyncBearerTokenEnv);
            statusSink(winrt::hstring{ L"INFO: sync state=observed operation=" + operation + L" step=dev_login_token_issued request_id=" + ResolveRequestId(localRequestId, loginStatus) + L"ℹ" });
            return true;
        }

        statusSink(winrt::hstring{ L"INFO: sync state=observed operation=" + operation + L" step=dev_login_token_unavailable hr=" + std::to_wstring(static_cast<int>(hrLogin)) + L" detail=" + BuildSyncFailureStatusMessage(hrLogin, loginStatus, syncBaseUrl) + L" request_id=" + ResolveRequestId(localRequestId, loginStatus) + L"ℹ" });
        return false;
    }

    std::wstring Base64StdEncode(uint8_t const* bytes, size_t len)
    {
        if (!bytes || len == 0)
        {
            return {};
        }

        DWORD needed = 0;
        if (!CryptBinaryToStringW(
                bytes,
                wil::safe_cast<DWORD>(len),
                CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                nullptr,
                &needed))
        {
            return {};
        }

        std::wstring encoded(needed, L'\0');
        if (!CryptBinaryToStringW(
                bytes,
                wil::safe_cast<DWORD>(len),
                CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                encoded.data(),
                &needed))
        {
            return {};
        }

        while (!encoded.empty() && encoded.back() == L'\0')
        {
            encoded.pop_back();
        }

        return encoded;
    }

    std::string Base64UrlEncode(uint8_t const* bytes, size_t len)
    {
        std::wstring base64 = Base64StdEncode(bytes, len);
        if (base64.empty())
        {
            return {};
        }

        std::string encoded = winrt::to_string(base64);
        std::replace(encoded.begin(), encoded.end(), '+', '-');
        std::replace(encoded.begin(), encoded.end(), '/', '_');
        while (!encoded.empty() && encoded.back() == '=')
        {
            encoded.pop_back();
        }
        return encoded;
    }

    bool Base64StdDecode(std::wstring const& b64, std::vector<BYTE>& out)
    {
        out.clear();
        if (b64.empty())
        {
            return false;
        }

        DWORD needed = 0;
        if (!CryptStringToBinaryW(
                b64.c_str(),
                0,
                CRYPT_STRING_BASE64,
                nullptr,
                &needed,
                nullptr,
                nullptr))
        {
            return false;
        }

        out.resize(needed);
        if (!CryptStringToBinaryW(
                b64.c_str(),
                0,
                CRYPT_STRING_BASE64,
                out.data(),
                &needed,
                nullptr,
                nullptr))
        {
            out.clear();
            return false;
        }

        out.resize(needed);
        return true;
    }

    bool Base64UrlDecode(std::wstring const& encoded, std::vector<BYTE>& out)
    {
        out.clear();
        if (encoded.empty())
        {
            return false;
        }

        std::wstring normalized = encoded;
        std::replace(normalized.begin(), normalized.end(), L'-', L'+');
        std::replace(normalized.begin(), normalized.end(), L'_', L'/');
        while ((normalized.size() % 4) != 0)
        {
            normalized.push_back(L'=');
        }

        return Base64StdDecode(normalized, out);
    }

    bool ProtectSecretForLocalUser(std::vector<BYTE> const& plainSecret, std::vector<BYTE>& protectedSecret)
    {
        protectedSecret.clear();
        if (plainSecret.empty())
        {
            return false;
        }

        DATA_BLOB input{};
        input.pbData = const_cast<BYTE*>(plainSecret.data());
        input.cbData = wil::safe_cast<DWORD>(plainSecret.size());
        DATA_BLOB output{};
        if (!CryptProtectData(&input, L"tsupasswd", nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &output))
        {
            return false;
        }

        protectedSecret.assign(output.pbData, output.pbData + output.cbData);
        if (output.pbData)
        {
            LocalFree(output.pbData);
        }
        return true;
    }

    bool UnprotectSecretForLocalUser(std::vector<BYTE> const& protectedSecret, std::vector<BYTE>& plainSecret)
    {
        plainSecret.clear();
        if (protectedSecret.empty())
        {
            return false;
        }

        DATA_BLOB input{};
        input.pbData = const_cast<BYTE*>(protectedSecret.data());
        input.cbData = wil::safe_cast<DWORD>(protectedSecret.size());
        DATA_BLOB output{};
        if (!CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &output))
        {
            return false;
        }

        plainSecret.assign(output.pbData, output.pbData + output.cbData);
        if (output.pbData)
        {
            LocalFree(output.pbData);
        }
        return true;
    }

    uint32_t ComputeVaultBlobChecksum(std::vector<BYTE> const& cipherText)
    {
        uint32_t checksum = 2166136261u;
        for (BYTE b : cipherText)
        {
            checksum ^= static_cast<uint32_t>(b);
            checksum *= 16777619u;
        }
        return checksum;
    }

    bool BuildVaultBlobWithIntegrity(std::vector<BYTE> const& cipherText, std::vector<BYTE>& framedBlob)
    {
        framedBlob.clear();
        if (cipherText.empty())
        {
            return false;
        }

        framedBlob.reserve(kVaultBlobHeaderBytes + cipherText.size());
        framedBlob.insert(framedBlob.end(), std::begin(kVaultBlobMagic), std::end(kVaultBlobMagic));
        framedBlob.push_back(kVaultBlobVersion);
        AppendUint32LE(framedBlob, static_cast<uint32_t>(cipherText.size()));
        AppendUint32LE(framedBlob, ComputeVaultBlobChecksum(cipherText));
        framedBlob.insert(framedBlob.end(), cipherText.begin(), cipherText.end());
        return true;
    }

    VaultBlobParseResult TryExtractVaultCipherWithIntegrity(std::vector<BYTE> const& storedBlob, std::vector<BYTE>& vaultCipher)
    {
        vaultCipher.clear();
        if (storedBlob.size() < kVaultBlobHeaderBytes)
        {
            vaultCipher = storedBlob;
            return VaultBlobParseResult::NotFramed;
        }

        if (!std::equal(std::begin(kVaultBlobMagic), std::end(kVaultBlobMagic), storedBlob.begin()) ||
            storedBlob[4] != kVaultBlobVersion)
        {
            vaultCipher = storedBlob;
            return VaultBlobParseResult::NotFramed;
        }

        uint32_t cipherLen =
            static_cast<uint32_t>(storedBlob[5]) |
            (static_cast<uint32_t>(storedBlob[6]) << 8) |
            (static_cast<uint32_t>(storedBlob[7]) << 16) |
            (static_cast<uint32_t>(storedBlob[8]) << 24);
        uint32_t expectedChecksum =
            static_cast<uint32_t>(storedBlob[9]) |
            (static_cast<uint32_t>(storedBlob[10]) << 8) |
            (static_cast<uint32_t>(storedBlob[11]) << 16) |
            (static_cast<uint32_t>(storedBlob[12]) << 24);

        if (storedBlob.size() != kVaultBlobHeaderBytes + cipherLen)
        {
            return VaultBlobParseResult::Invalid;
        }

        vaultCipher.assign(storedBlob.begin() + kVaultBlobHeaderBytes, storedBlob.end());
        if (ComputeVaultBlobChecksum(vaultCipher) != expectedChecksum)
        {
            vaultCipher.clear();
            return VaultBlobParseResult::Invalid;
        }

        return VaultBlobParseResult::Ok;
    }

    std::wstring FormatAaguid(BYTE const* bytes, size_t len)
    {
        if (bytes == nullptr || len != 16)
        {
            return {};
        }

        wchar_t buffer[37]{};
        swprintf_s(
            buffer,
            L"%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
            bytes[0],
            bytes[1],
            bytes[2],
            bytes[3],
            bytes[4],
            bytes[5],
            bytes[6],
            bytes[7],
            bytes[8],
            bytes[9],
            bytes[10],
            bytes[11],
            bytes[12],
            bytes[13],
            bytes[14],
            bytes[15]);
        return buffer;
    }

    bool TryExtractAttestationAaguid(WEBAUTHN_CREDENTIAL_ATTESTATION const* attestation, std::array<BYTE, 16>& outAaguid)
    {
        outAaguid.fill(0);
        if (attestation == nullptr ||
            attestation->pbAuthenticatorData == nullptr ||
            attestation->cbAuthenticatorData < (kAuthenticatorDataAttestedDataOffset + outAaguid.size()) ||
            (attestation->pbAuthenticatorData[kAuthenticatorDataFlagsOffset] & kAuthenticatorDataAttestedCredentialFlag) == 0)
        {
            return false;
        }

        std::copy_n(
            attestation->pbAuthenticatorData + kAuthenticatorDataAttestedDataOffset,
            outAaguid.size(),
            outAaguid.begin());
        return true;
    }

    void AppendUint32LE(std::vector<BYTE>& out, uint32_t value)
    {
        out.push_back(static_cast<BYTE>(value & 0xFF));
        out.push_back(static_cast<BYTE>((value >> 8) & 0xFF));
        out.push_back(static_cast<BYTE>((value >> 16) & 0xFF));
        out.push_back(static_cast<BYTE>((value >> 24) & 0xFF));
    }
}

namespace winrt::PasskeyManager::implementation {
    HRESULT PluginRegistrationManager::SyncEncryptedVaultWithRetry(
        std::vector<BYTE> const& encryptedVaultData,
        std::wstring const& syncUserId,
        std::function<void(winrt::hstring const&)> const& statusSink)
    {
        std::wstring operation = L"put_vault";
        std::wstring localRequestId = tsupasswd::BuildRequestId(operation);
        std::wstring syncBaseUrl = GetEnvironmentVariableValue(kSyncBaseUrlEnv);
        if (syncBaseUrl.empty())
        {
            statusSink(winrt::hstring{ L"INFO: sync result=skipped operation=" + operation + L" reason=base_url_missing hr=1 request_id=" + localRequestId + L"ℹ" });
            return S_FALSE;
        }

        DebugLogIfVerbose(
            L"DEBUG: sync put_vault base_url='" + syncBaseUrl + L"' user_id='" + syncUserId + L"'\n");

        statusSink(winrt::hstring{ L"INFO: sync state=start operation=" + operation + L" user_id=" + syncUserId + L" request_id=" + localRequestId + L"ℹ" });

        tsupasswd::SyncClient syncClient(syncBaseUrl);
        syncClient.SetApiKind(tsupasswd::SyncApiKind::Axum);
        syncClient.SetAllowInsecureHttp(IsAllowInsecureHttpEnabled());
        std::wstring bearerToken = GetEnvironmentVariableValue(kSyncBearerTokenEnv);
        std::vector<uint8_t> sessionKeyBytes;
        if (!bearerToken.empty())
        {
            syncClient.SetBearerToken(bearerToken);

            std::wstring recoveryCode = GetEnvironmentVariableValue(kVaultRecoveryCodeEnv);
            if (!recoveryCode.empty())
            {
                tsupasswd::SyncHttpStatus loginStatus{};
                std::wstring issuedToken;
                (void)syncClient.OpaqueLogin(syncUserId, recoveryCode, issuedToken, &sessionKeyBytes, &loginStatus);
            }
        }
        else
        {
            bool issuedDevLoginToken = TryIssueDevLoginToken(syncClient, syncUserId, operation, localRequestId, syncBaseUrl, statusSink, &sessionKeyBytes);
            if (!issuedDevLoginToken)
            {
                std::wstring recoveryCode = GetEnvironmentVariableValue(kVaultRecoveryCodeEnv);
                if (recoveryCode.empty())
                {
                    statusSink(winrt::hstring{ L"WARNING: sync result=rejected operation=" + operation + L" reason=recovery_code_missing recovery=set_TSUPASSWD_VAULT_RECOVERY_CODE request_id=" + localRequestId + L"⚠" });
                    return HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);
                }

                tsupasswd::SyncHttpStatus loginStatus{};
                std::wstring issuedToken;
                HRESULT hrLogin = syncClient.OpaqueLogin(syncUserId, recoveryCode, issuedToken, &sessionKeyBytes, &loginStatus);
                if (FAILED(hrLogin) || issuedToken.empty())
                {
                    tsupasswd::SyncHttpStatus regStatus{};
                    std::vector<uint8_t> regExportKey;
                    (void)syncClient.OpaqueRegister(syncUserId, recoveryCode, &regExportKey, &regStatus);
                    if (!regExportKey.empty())
                    {
                        (void)PluginRegistrationManager::getInstance().SetOpaqueExportKey(
                            std::vector<BYTE>(regExportKey.begin(), regExportKey.end()), localRequestId);
                    }
                    loginStatus = {};
                    issuedToken.clear();
                    hrLogin = syncClient.OpaqueLogin(syncUserId, recoveryCode, issuedToken, &sessionKeyBytes, &loginStatus);
                }

                if (SUCCEEDED(hrLogin) && !issuedToken.empty())
                {
                    syncClient.SetBearerToken(issuedToken);
                    statusSink(winrt::hstring{ L"INFO: sync state=observed operation=" + operation + L" step=opaque_login_token_issued request_id=" + ResolveRequestId(localRequestId, loginStatus) + L"ℹ" });
                }
                else
                {
                    statusSink(winrt::hstring{ L"WARNING: sync result=rejected operation=" + operation + L" step=opaque_login_failed hr=" + std::to_wstring(static_cast<int>(hrLogin)) + L" detail=" + BuildSyncFailureStatusMessage(hrLogin, loginStatus, syncBaseUrl) + L" request_id=" + ResolveRequestId(localRequestId, loginStatus) + L"⚠" });
                    return HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);
                }
            }
        }

        tsupasswd::PutVaultRequest putRequest{};
        putRequest.ExpectedVersion = 0;
        putRequest.NewVersion = 1;
        putRequest.DeviceId = L"tsupasswd_core_windows";
        std::vector<uint8_t> cipherPlain(encryptedVaultData.begin(), encryptedVaultData.end());
        auto buildCipherForSyncBase64 = [&]() -> std::wstring
        {
            std::vector<uint8_t> cipherForSync = cipherPlain;
            PluginRegistrationManager::getInstance().ReloadRegistryValues(localRequestId);
            auto exportKey = PluginRegistrationManager::getInstance().GetOpaqueExportKey();
            if (IsOpaqueSessionWrapEnabled() && exportKey.empty())
            {
                statusSink(winrt::hstring{ L"INFO: sync state=observed operation=" + operation + L" step=sync_wrap_skipped reason=opaque_export_key_missing fallback=plaintext_cipher request_id=" + localRequestId + L"ℹ" });
            }
            if (IsOpaqueSessionWrapEnabled() && !exportKey.empty())
            {
                tsupasswd::VaultCryptoError wrapError{};
                std::vector<uint8_t> wrapped;
                if (tsupasswd::WrapVaultCipherForSyncV1(cipherForSync, std::vector<uint8_t>(exportKey.begin(), exportKey.end()), wrapped, wrapError))
                {
                    cipherForSync = std::move(wrapped);
                }
                else
                {
                    statusSink(winrt::hstring{ L"WARNING: sync result=warning operation=" + operation + L" reason=sync_wrap_failed code=" + wrapError.Code + L" detail=" + wrapError.Detail + L" fallback=plaintext_cipher fail_mode=fail_open request_id=" + localRequestId + L"⚠" });
                }
            }
            return Base64StdEncode(cipherForSync.data(), wil::safe_cast<DWORD>(cipherForSync.size()));
        };

        putRequest.Blob.CiphertextBase64 = buildCipherForSyncBase64();
        putRequest.Blob.NonceBase64 = L"";
        putRequest.Blob.AadBase64 = L"";
        putRequest.Meta.CreatedAt = GetNowIsoLikeTimestamp();
        putRequest.Meta.UpdatedAt = putRequest.Meta.CreatedAt;
        putRequest.Meta.LastWriterDeviceId = putRequest.DeviceId;

        constexpr int kMaxAttempts = 3;
        DWORD backoffMs = 500;
        HRESULT hrSync = E_FAIL;
        tsupasswd::PutVaultResponse putResponse{};
        tsupasswd::SyncHttpStatus syncStatus{};
        auto syncStartTime = std::chrono::steady_clock::now();
        int attemptsUsed = 0;

        auto reauthIfUnauthorized = [&](tsupasswd::SyncHttpStatus const& status) -> HRESULT
        {
            if (status.StatusCode != 401 && status.StatusCode != 403)
            {
                return S_FALSE;
            }

            std::wstring recoveryCode = GetEnvironmentVariableValue(kVaultRecoveryCodeEnv);
            if (recoveryCode.empty())
            {
                return HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);
            }

            tsupasswd::SyncHttpStatus loginStatus{};
            std::wstring issuedToken;
            HRESULT hrLogin = syncClient.OpaqueLogin(syncUserId, recoveryCode, issuedToken, &sessionKeyBytes, &loginStatus);
            if (FAILED(hrLogin) || issuedToken.empty())
            {
                tsupasswd::SyncHttpStatus regStatus{};
                std::vector<uint8_t> regExportKey;
                (void)syncClient.OpaqueRegister(syncUserId, recoveryCode, &regExportKey, &regStatus);
                if (!regExportKey.empty())
                {
                    (void)PluginRegistrationManager::getInstance().SetOpaqueExportKey(
                        std::vector<BYTE>(regExportKey.begin(), regExportKey.end()), localRequestId);
                }
                loginStatus = {};
                issuedToken.clear();
                hrLogin = syncClient.OpaqueLogin(syncUserId, recoveryCode, issuedToken, &sessionKeyBytes, &loginStatus);
            }

            if (SUCCEEDED(hrLogin) && !issuedToken.empty())
            {
                syncClient.SetBearerToken(issuedToken);
                ClearProcessEnvironmentVariableValue(kSyncBearerTokenEnv);
                ClearUserEnvironmentRegistryValue(kSyncBearerTokenEnv);
                putRequest.Blob.CiphertextBase64 = buildCipherForSyncBase64();
                statusSink(winrt::hstring{ L"INFO: sync state=observed operation=" + operation + L" step=opaque_reauth_token_issued request_id=" + ResolveRequestId(localRequestId, loginStatus) + L"ℹ" });
                return S_OK;
            }

            statusSink(winrt::hstring{ L"WARNING: sync result=rejected operation=" + operation + L" step=opaque_reauth_failed hr=" + std::to_wstring(static_cast<int>(hrLogin)) + L" detail=" + BuildSyncFailureStatusMessage(hrLogin, loginStatus, syncBaseUrl) + L" request_id=" + ResolveRequestId(localRequestId, loginStatus) + L"⚠" });
            return HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);
        };

        for (int attempt = 1; attempt <= kMaxAttempts; ++attempt)
        {
            attemptsUsed = attempt;
            syncStatus = {};
            hrSync = syncClient.PutVault(syncUserId, putRequest, putResponse, &syncStatus);

            if (hrSync == HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED) && attempt == 1)
            {
                HRESULT hrReauth = reauthIfUnauthorized(syncStatus);
                if (hrReauth == S_OK)
                {
                    continue;
                }
            }

            if (hrSync == HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH) && syncStatus.ServerVersion >= 0)
            {
                auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - syncStartTime).count();
                putRequest.ExpectedVersion = syncStatus.ServerVersion;
                putRequest.NewVersion = syncStatus.ServerVersion + 1;
                statusSink(
                    winrt::hstring{
                        L"INFO: sync result=retry_conflict operation=" + operation + L" attempt=" +
                        std::to_wstring(attempt) +
                        L"/" +
                        std::to_wstring(kMaxAttempts) +
                        L" elapsed_ms=" +
                        std::to_wstring(elapsedMs) +
                        L" server_version=" +
                        std::to_wstring(syncStatus.ServerVersion) +
                        L" request_id=" +
                        ResolveRequestId(localRequestId, syncStatus) +
                        L"ℹ" });
                continue;
            }

            if (SUCCEEDED(hrSync))
            {
                auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - syncStartTime).count();
                statusSink(winrt::hstring{ L"SUCCESS: sync result=success operation=" + operation + L" attempts=" + std::to_wstring(attempt) + L"/" + std::to_wstring(kMaxAttempts) + L" elapsed_ms=" + std::to_wstring(elapsedMs) + L" hr=0 request_id=" + ResolveRequestId(localRequestId, syncStatus) + L"✅" });
                return S_OK;
            }

            bool shouldRetry =
                attempt < kMaxAttempts &&
                syncStatus.StatusCode != 401 &&
                syncStatus.StatusCode != 403 &&
                syncStatus.StatusCode != 404 &&
                syncStatus.StatusCode != 409;

            if (!shouldRetry)
            {
                break;
            }

            statusSink(
                winrt::hstring{
                    L"INFO: sync result=retry_backoff operation=" + operation + L" attempt=" +
                    std::to_wstring(attempt + 1) +
                    L"/" +
                    std::to_wstring(kMaxAttempts) +
                    L" backoff_ms=" +
                    std::to_wstring(backoffMs) +
                    L" elapsed_ms=" +
                    std::to_wstring(std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - syncStartTime).count()) +
                    L" request_id=" +
                    ResolveRequestId(localRequestId, syncStatus) +
                    L"ℹ" });

            std::this_thread::sleep_for(std::chrono::milliseconds(backoffMs));
            backoffMs *= 2;
        }

        std::wstring syncWarning =
            L"WARNING: sync result=failed operation=" + operation + L" attempts=" +
            std::to_wstring(attemptsUsed) +
            L"/" +
            std::to_wstring(kMaxAttempts) +
            L" elapsed_ms=" +
            std::to_wstring(std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - syncStartTime).count()) +
            L" hr=" + std::to_wstring(static_cast<int>(hrSync)) +
            L" detail=" + BuildSyncFailureStatusMessage(hrSync, syncStatus, syncBaseUrl);
        if (syncStatus.StatusCode == 409)
        {
            syncWarning += L" recovery=manual_resync_now";
        }
        if (syncStatus.RequestId.empty())
        {
            syncWarning += L" request_id=" + localRequestId;
        }
        statusSink(winrt::hstring{ syncWarning });
        return hrSync;
    }

    PluginRegistrationManager::PluginRegistrationManager() :
        m_pluginRegistered(false),
        m_initialized(false),
        // AUTHENTICATOR_STATE: Enum representing the state of a plugin authenticator in the Windows
        // third-party passkey plugin system. This state indicates whether the plugin is enabled or disabled.
        m_pluginState(AUTHENTICATOR_STATE::AuthenticatorState_Disabled)
    {
        Initialize();
    }

    PluginRegistrationManager::~PluginRegistrationManager()
    {
    }

    HRESULT PluginRegistrationManager::Initialize()
    {
        HRESULT hr = RefreshPluginState();
        RETURN_HR_IF_EXPECTED(S_OK, hr == NTE_NOT_FOUND);
        ReloadRegistryValues();
        RETURN_HR(hr);
    }

    HRESULT PluginRegistrationManager::RegisterPlugin()
    {
        // If the plugin is already registered, avoid calling Add again.
        // In that case, perform an update instead.
        {
            HRESULT hrState = RefreshPluginState();
            if (SUCCEEDED(hrState))
            {
                RETURN_HR(UpdatePlugin());
            }
            if (hrState != NTE_NOT_FOUND)
            {
                RETURN_HR(hrState);
            }
        }

        /*
        * This section creates a sample authenticatorInfo blob to include in the registration
        * request. This blob must CBOR encoded using the format defined
        * in https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetInfo
        *
        * 'AAGUID' maybe used to fetch information about the authenticator from the FIDO Metadata Service and other sources.
        * Refer: https://fidoalliance.org/metadata/
        *
        * 'extensions' field is used to perform feature detection on the authenticator
        * and maybe used to determine if the authenticator is filtered out.
        */
        std::string tempAaguidStr{ c_pluginAaguidString };
        tempAaguidStr.erase(std::remove(tempAaguidStr.begin(), tempAaguidStr.end(), L'-'), tempAaguidStr.end());
        std::transform(tempAaguidStr.begin(), tempAaguidStr.end(), tempAaguidStr.begin(), [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
        // The following hex strings represent the encoding of
        // {1: ["FIDO_2_0", "FIDO_2_1"], 2: ["prf", "hmac-secret"], 3: h'/* AAGUID */', 4: {"rk": true, "up": true, "uv": true},
        // 9: ["usb", "nfc", "ble", "internal", "hybrid"], 10: [{"alg": -7, "type": "public-key"}]}
        std::string authenticatorInfoStrPart1 = "A60182684649444F5F325F30684649444F5F325F310282637072666B686D61632D7365637265740350";
        std::string authenticatorInfoStrPart2 = "04A362726BF5627570F5627576F5098563757362636E666363626C6568696E7465726E616C666879627269640A81A263616C672664747970656A7075626C69632D6B6579";
        std::string fullAuthenticatorInfoStr = authenticatorInfoStrPart1 + tempAaguidStr + authenticatorInfoStrPart2;
        std::vector<BYTE> authenticatorInfo = hexStringToBytes(fullAuthenticatorInfoStr);

        // WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS: Structure containing options for registering a plugin authenticator
        // with the Windows platform. This includes authenticator name, class ID, supported RP IDs, logo data, and
        // CBOR-encoded authenticator information for FIDO compliance.
        PCWSTR supportedRpIds[] = {
            c_pluginRpId,
            c_pluginRpIdWebAuthnIo,
            c_pluginRpIdWebAuthnIoWww,
            c_pluginRpIdPasskeyOrg,
            c_pluginRpIdPasskeyOrgWww,
            c_pluginRpIdPasskeysIo,
            c_pluginRpIdPasskeysIoWww,
            c_pluginRpIdPasskeysGuru,
            c_pluginRpIdPasskeysGuruWww,
            c_pluginRpIdWebAuthnPasswordlessId,
            c_pluginRpIdWebAuthnPasswordlessIdWww
        };
        WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS addOptions{
            .pwszAuthenticatorName = c_pluginName,
            .rclsid = happyfactoryplugin_guid,
            .pwszPluginRpId = c_pluginRpId,
            .pwszLightThemeLogoSvg = L"PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZlcnNpb249IjEuMSIgd2lkdGg9IjkwcHgiIGhlaWdodD0iOTBweCIgdmlld0JveD0iMzAgMCA1MCA4NSIgc3R5bGU9ImZpbGwtcnVsZTpldmVub2RkOyBjbGlwLXJ1bGU6ZXZlbm9kZDsgc2hhcGUtcmVuZGVyaW5nOmdlb21ldHJpY1ByZWNpc2lvbjsgdGV4dC1yZW5kZXJpbmc6Z2VvbWV0cmljUHJlY2lzaW9uOyBpbWFnZS1yZW5kZXJpbmc6b3B0aW1pemVRdWFsaXR5OyI+PGRlZnM+PGxpbmVhckdyYWRpZW50IGlkPSJncmFkMSIgeDE9IjAlIiB5MT0iMTAwJSIgeDI9IjEwMCUiIHkyPSIwJSI+PHN0b3Agb2Zmc2V0PSIwJSIgc3R5bGU9InN0b3AtY29sb3I6IzRiZTBmYzsgc3RvcC1vcGFjaXR5OjEiIC8+PHN0b3Agb2Zmc2V0PSIxMDAlIiBzdHlsZT0ic3RvcC1jb2xvcjojMTY5NmUxOyBzdG9wLW9wYWNpdHk6MSIgLz48L2xpbmVhckdyYWRpZW50PjxsaW5lYXJHcmFkaWVudCBpZD0iZ3JhZDIiIHgxPSIxMDAlIiB5MT0iMTAwJSIgeDI9IjEwMCUiIHkyPSIwJSI+PHN0b3Agb2Zmc2V0PSIxMDAlIiBzdHlsZT0ic3RvcC1jb2xvcjojNGJlMGZjOyBzdG9wLW9wYWNpdHk6MSIgLz48c3RvcCBvZmZzZXQ9IjAlIiBzdHlsZT0ic3RvcC1jb2xvcjojMTY5NmUxOyBzdG9wLW9wYWNpdHk6MSIgLz48L2xpbmVhckdyYWRpZW50PjwvZGVmcz48Zz48cG9seWdvbiBwb2ludHM9IjQ4LDI0IDU4LDM2IDQ0LDY3IDMyLDYwIiBmaWxsPSJ1cmwoI2dyYWQyKSIgLz48cG9seWdvbiBwb2ludHM9IjMyLDYwIDQ0LDY3IDMyLjk0LDY4Ljg5IiBmaWxsPSJ1cmwoI2dyYWQyKSIgLz48cG9seWdvbiBwb2ludHM9IjQ0LDY3IDQ3LjE1LDYwIDQ4LDY1LjUiIGZpbGw9InVybCgjZ3JhZDEpIiAvPjxwb2x5Z29uIHBvaW50cz0iNDcuMTUsNjAgNTAuMzAsNTMgNTEuMTUsNTguNSIgZmlsbD0idXJsKCNncmFkMSkiIC8+PGNpcmNsZSBjeD0iNTUiIGN5PSIyNSIgcj0iMTgiIGZpbGw9InVybCgjZ3JhZDEpIiAvPjxjaXJjbGUgY3g9IjcyIiBjeT0iMjUiIHI9IjE4IiBmaWxsPSJ3aGl0ZSIgLz48L2c+PGc+PHJlY3QgeD0iNzAiIHk9IjMwIiB3aWR0aD0iMTYiIGhlaWdodD0iNDUiIGZpbGw9InVybCgjZ3JhZDIpIiAvPjxwb2x5Z29uIHBvaW50cz0iNzgsODEgNzAsNzUgODYsNzUiIGZpbGw9InVybCgjZ3JhZDIpIiAvPjxwb2x5Z29uIHBvaW50cz0iODYsNjcgODYsNzUgODguNSw3MSIgZmlsbD0idXJsKCNncmFkMSkiIC8+PHBvbHlnb24gcG9pbnRzPSI4Niw2NyA4Niw1OSA4OC41LDYzIiBmaWxsPSJ1cmwoI2dyYWQxKSIgLz48Y2lyY2xlIGN4PSI3NyIgY3k9IjI1IiByPSIxOCIgZmlsbD0idXJsKCNncmFkMSkiIC8+PGNpcmNsZSBjeD0iNzciIGN5PSIyMyIgcj0iMyIgZmlsbD0id2hpdGUiIC8+PC9nPjwvc3ZnPg==",
            .pwszDarkThemeLogoSvg = L"PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZlcnNpb249IjEuMSIgd2lkdGg9IjkwcHgiIGhlaWdodD0iOTBweCIgdmlld0JveD0iMzAgMCA1MCA4NSIgc3R5bGU9ImZpbGwtcnVsZTpldmVub2RkOyBjbGlwLXJ1bGU6ZXZlbm9kZDsgc2hhcGUtcmVuZGVyaW5nOmdlb21ldHJpY1ByZWNpc2lvbjsgdGV4dC1yZW5kZXJpbmc6Z2VvbWV0cmljUHJlY2lzaW9uOyBpbWFnZS1yZW5kZXJpbmc6b3B0aW1pemVRdWFsaXR5OyI+PGRlZnM+PGxpbmVhckdyYWRpZW50IGlkPSJncmFkMSIgeDE9IjAlIiB5MT0iMTAwJSIgeDI9IjEwMCUiIHkyPSIwJSI+PHN0b3Agb2Zmc2V0PSIwJSIgc3R5bGU9InN0b3AtY29sb3I6IzRiZTBmYzsgc3RvcC1vcGFjaXR5OjEiIC8+PHN0b3Agb2Zmc2V0PSIxMDAlIiBzdHlsZT0ic3RvcC1jb2xvcjojMTY5NmUxOyBzdG9wLW9wYWNpdHk6MSIgLz48L2xpbmVhckdyYWRpZW50PjxsaW5lYXJHcmFkaWVudCBpZD0iZ3JhZDIiIHgxPSIxMDAlIiB5MT0iMTAwJSIgeDI9IjEwMCUiIHkyPSIwJSI+PHN0b3Agb2Zmc2V0PSIxMDAlIiBzdHlsZT0ic3RvcC1jb2xvcjojNGJlMGZjOyBzdG9wLW9wYWNpdHk6MSIgLz48c3RvcCBvZmZzZXQ9IjAlIiBzdHlsZT0ic3RvcC1jb2xvcjojMTY5NmUxOyBzdG9wLW9wYWNpdHk6MSIgLz48L2xpbmVhckdyYWRpZW50PjwvZGVmcz48Zz48cG9seWdvbiBwb2ludHM9IjQ4LDI0IDU4LDM2IDQ0LDY3IDMyLDYwIiBmaWxsPSJ1cmwoI2dyYWQyKSIgLz48cG9seWdvbiBwb2ludHM9IjMyLDYwIDQ0LDY3IDMyLjk0LDY4Ljg5IiBmaWxsPSJ1cmwoI2dyYWQyKSIgLz48cG9seWdvbiBwb2ludHM9IjQ0LDY3IDQ3LjE1LDYwIDQ4LDY1LjUiIGZpbGw9InVybCgjZ3JhZDEpIiAvPjxwb2x5Z29uIHBvaW50cz0iNDcuMTUsNjAgNTAuMzAsNTMgNTEuMTUsNTguNSIgZmlsbD0idXJsKCNncmFkMSkiIC8+PGNpcmNsZSBjeD0iNTUiIGN5PSIyNSIgcj0iMTgiIGZpbGw9InVybCgjZ3JhZDEpIiAvPjxjaXJjbGUgY3g9IjcyIiBjeT0iMjUiIHI9IjE4IiBmaWxsPSJ3aGl0ZSIgLz48L2c+PGc+PHJlY3QgeD0iNzAiIHk9IjMwIiB3aWR0aD0iMTYiIGhlaWdodD0iNDUiIGZpbGw9InVybCgjZ3JhZDIpIiAvPjxwb2x5Z29uIHBvaW50cz0iNzgsODEgNzAsNzUgODYsNzUiIGZpbGw9InVybCgjZ3JhZDIpIiAvPjxwb2x5Z29uIHBvaW50cz0iODYsNjcgODYsNzUgODguNSw3MSIgZmlsbD0idXJsKCNncmFkMSkiIC8+PHBvbHlnb24gcG9pbnRzPSI4Niw2NyA4Niw1OSA4OC41LDYzIiBmaWxsPSJ1cmwoI2dyYWQxKSIgLz48Y2lyY2xlIGN4PSI3NyIgY3k9IjI1IiByPSIxOCIgZmlsbD0idXJsKCNncmFkMSkiIC8+PGNpcmNsZSBjeD0iNzciIGN5PSIyMyIgcj0iMyIgZmlsbD0id2hpdGUiIC8+PC9nPjwvc3ZnPg==",
            .cbAuthenticatorInfo = static_cast<DWORD>(authenticatorInfo.size()),
            .pbAuthenticatorInfo = authenticatorInfo.data(),
            .cSupportedRpIds = ARRAYSIZE(supportedRpIds),
            .ppwszSupportedRpIds = supportedRpIds
        };

        // PWEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_RESPONSE: Response structure returned by the plugin registration API, containing
        // the operation signing public key that will be used to verify signed plugin operation requests from the platform.
        PWEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_RESPONSE addResponse;

        // Call the plugin registration API
        HRESULT hrAdd = WebAuthNPluginAddAuthenticator(&addOptions, &addResponse);
        if (hrAdd == NTE_EXISTS)
        {
            // Already registered; update details instead.
            RETURN_HR(UpdatePlugin());
        }
        RETURN_IF_FAILED(hrAdd);

        // Ensure the response is freed when it goes out of scope
        auto cleanup = wil::scope_exit([&] {
            WebAuthNPluginFreeAddAuthenticatorResponse(addResponse);
        });

        // The response from plugin contains the public key used to sign plugin operation requests. Stash it for later use.
        wil::unique_hkey hKey;
        RETURN_IF_WIN32_ERROR(RegCreateKeyEx(
            HKEY_CURRENT_USER,
            c_pluginRegistryPath,
            0,
            nullptr,
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            nullptr,
            &hKey,
            nullptr));

        RETURN_IF_WIN32_ERROR(RegSetValueEx(
            hKey.get(),
            c_windowsPluginRequestSigningKeyRegKeyName,
            0,
            REG_BINARY,
            addResponse->pbOpSignPubKey,
            addResponse->cbOpSignPubKey));
        return S_OK;
    }

    HRESULT PluginRegistrationManager::UnregisterPlugin()
    {
        // Call the plugin unregistration API with the plugin's class ID
        RETURN_HR(WebAuthNPluginRemoveAuthenticator(happyfactoryplugin_guid));
    }

    HRESULT PluginRegistrationManager::UpdatePlugin()
    {
        /*
        * This section creates a sample authenticatorInfo blob to include in the registration
        * request. This blob must CBOR encoded using the format defined
        * in https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetInfo
        *
        * 'AAGUID' maybe used to fetch information about the authenticator from the FIDO Metadata Service and other sources.
        * Refer: https://fidoalliance.org/metadata/
        *
        * 'extensions' field is used to perform feature detection on the authenticator
        * and maybe used to determine if the authenticator is filtered out by the platform during web authentication
        * if the client has requested specific support for a extension that the authenticator does not support.
        */
        std::string tempAaguidStr{ c_pluginAaguidString };
        tempAaguidStr.erase(std::remove(tempAaguidStr.begin(), tempAaguidStr.end(), L'-'), tempAaguidStr.end());
        std::transform(tempAaguidStr.begin(), tempAaguidStr.end(), tempAaguidStr.begin(), [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
        // The following hex strings represent the encoding of
        // {1: ["FIDO_2_0", "FIDO_2_1"], 2: ["prf", "hmac-secret"], 3: h'/* AAGUID */', 4: {"rk": true, "up": true, "uv": true},
        // 9: ["usb", "nfc", "ble", "internal", "hybrid"], 10: [{"alg": -7, "type": "public-key"}]}
        std::string authenticatorInfoStrPart1 = "A60182684649444F5F325F30684649444F5F325F310282637072666B686D61632D7365637265740350";
        std::string authenticatorInfoStrPart2 = "04A362726BF5627570F5627576F5098563757362636E666363626C6568696E7465726E616C666879627269640A81A263616C672664747970656A7075626C69632D6B6579";
        std::string fullAuthenticatorInfoStr = authenticatorInfoStrPart1 + tempAaguidStr + authenticatorInfoStrPart2;
        std::vector<BYTE> authenticatorInfo = hexStringToBytes(fullAuthenticatorInfoStr);

        PCWSTR supportedRpIds[] = {
            c_pluginRpId,
            c_pluginRpIdWebAuthnIo,
            c_pluginRpIdWebAuthnIoWww,
            c_pluginRpIdPasskeyOrg,
            c_pluginRpIdPasskeyOrgWww,
            c_pluginRpIdPasskeysIo,
            c_pluginRpIdPasskeysIoWww,
            c_pluginRpIdPasskeysGuru,
            c_pluginRpIdPasskeysGuruWww,
            c_pluginRpIdWebAuthnPasswordlessId,
            c_pluginRpIdWebAuthnPasswordlessIdWww
        };

        // WEBAUTHN_PLUGIN_UPDATE_AUTHENTICATOR_DETAILS: Structure containing updated plugin information for an already
        // registered authenticator, including potentially new class IDs, names, logos, and authenticator information.
        WEBAUTHN_PLUGIN_UPDATE_AUTHENTICATOR_DETAILS updateDetails{
            .pwszAuthenticatorName = c_pluginName,
            .rclsid = happyfactoryplugin_guid,
            .rclsidNew = happyfactoryplugin_guid,
            .pwszLightThemeLogoSvg = L"PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZlcnNpb249IjEuMSIgd2lkdGg9IjkwcHgiIGhlaWdodD0iOTBweCIgdmlld0JveD0iMzAgMCA1MCA4NSIgc3R5bGU9ImZpbGwtcnVsZTpldmVub2RkOyBjbGlwLXJ1bGU6ZXZlbm9kZDsgc2hhcGUtcmVuZGVyaW5nOmdlb21ldHJpY1ByZWNpc2lvbjsgdGV4dC1yZW5kZXJpbmc6Z2VvbWV0cmljUHJlY2lzaW9uOyBpbWFnZS1yZW5kZXJpbmc6b3B0aW1pemVRdWFsaXR5OyI+PGRlZnM+PGxpbmVhckdyYWRpZW50IGlkPSJncmFkMSIgeDE9IjAlIiB5MT0iMTAwJSIgeDI9IjEwMCUiIHkyPSIwJSI+PHN0b3Agb2Zmc2V0PSIwJSIgc3R5bGU9InN0b3AtY29sb3I6IzRiZTBmYzsgc3RvcC1vcGFjaXR5OjEiIC8+PHN0b3Agb2Zmc2V0PSIxMDAlIiBzdHlsZT0ic3RvcC1jb2xvcjojMTY5NmUxOyBzdG9wLW9wYWNpdHk6MSIgLz48L2xpbmVhckdyYWRpZW50PjxsaW5lYXJHcmFkaWVudCBpZD0iZ3JhZDIiIHgxPSIxMDAlIiB5MT0iMTAwJSIgeDI9IjEwMCUiIHkyPSIwJSI+PHN0b3Agb2Zmc2V0PSIxMDAlIiBzdHlsZT0ic3RvcC1jb2xvcjojNGJlMGZjOyBzdG9wLW9wYWNpdHk6MSIgLz48c3RvcCBvZmZzZXQ9IjAlIiBzdHlsZT0ic3RvcC1jb2xvcjojMTY5NmUxOyBzdG9wLW9wYWNpdHk6MSIgLz48L2xpbmVhckdyYWRpZW50PjwvZGVmcz48Zz48cG9seWdvbiBwb2ludHM9IjQ4LDI0IDU4LDM2IDQ0LDY3IDMyLDYwIiBmaWxsPSJ1cmwoI2dyYWQyKSIgLz48cG9seWdvbiBwb2ludHM9IjMyLDYwIDQ0LDY3IDMyLjk0LDY4Ljg5IiBmaWxsPSJ1cmwoI2dyYWQyKSIgLz48cG9seWdvbiBwb2ludHM9IjQ0LDY3IDQ3LjE1LDYwIDQ4LDY1LjUiIGZpbGw9InVybCgjZ3JhZDEpIiAvPjxwb2x5Z29uIHBvaW50cz0iNDcuMTUsNjAgNTAuMzAsNTMgNTEuMTUsNTguNSIgZmlsbD0idXJsKCNncmFkMSkiIC8+PGNpcmNsZSBjeD0iNTUiIGN5PSIyNSIgcj0iMTgiIGZpbGw9InVybCgjZ3JhZDEpIiAvPjxjaXJjbGUgY3g9IjcyIiBjeT0iMjUiIHI9IjE4IiBmaWxsPSJ3aGl0ZSIgLz48L2c+PGc+PHJlY3QgeD0iNzAiIHk9IjMwIiB3aWR0aD0iMTYiIGhlaWdodD0iNDUiIGZpbGw9InVybCgjZ3JhZDIpIiAvPjxwb2x5Z29uIHBvaW50cz0iNzgsODEgNzAsNzUgODYsNzUiIGZpbGw9InVybCgjZ3JhZDIpIiAvPjxwb2x5Z29uIHBvaW50cz0iODYsNjcgODYsNzUgODguNSw3MSIgZmlsbD0idXJsKCNncmFkMSkiIC8+PHBvbHlnb24gcG9pbnRzPSI4Niw2NyA4Niw1OSA4OC41LDYzIiBmaWxsPSJ1cmwoI2dyYWQxKSIgLz48Y2lyY2xlIGN4PSI3NyIgY3k9IjI1IiByPSIxOCIgZmlsbD0idXJsKCNncmFkMSkiIC8+PGNpcmNsZSBjeD0iNzciIGN5PSIyMyIgcj0iMyIgZmlsbD0id2hpdGUiIC8+PC9nPjwvc3ZnPg==",
            .pwszDarkThemeLogoSvg = L"PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZlcnNpb249IjEuMSIgd2lkdGg9IjkwcHgiIGhlaWdodD0iOTBweCIgdmlld0JveD0iMzAgMCA1MCA4NSIgc3R5bGU9ImZpbGwtcnVsZTpldmVub2RkOyBjbGlwLXJ1bGU6ZXZlbm9kZDsgc2hhcGUtcmVuZGVyaW5nOmdlb21ldHJpY1ByZWNpc2lvbjsgdGV4dC1yZW5kZXJpbmc6Z2VvbWV0cmljUHJlY2lzaW9uOyBpbWFnZS1yZW5kZXJpbmc6b3B0aW1pemVRdWFsaXR5OyI+PGRlZnM+PGxpbmVhckdyYWRpZW50IGlkPSJncmFkMSIgeDE9IjAlIiB5MT0iMTAwJSIgeDI9IjEwMCUiIHkyPSIwJSI+PHN0b3Agb2Zmc2V0PSIwJSIgc3R5bGU9InN0b3AtY29sb3I6IzRiZTBmYzsgc3RvcC1vcGFjaXR5OjEiIC8+PHN0b3Agb2Zmc2V0PSIxMDAlIiBzdHlsZT0ic3RvcC1jb2xvcjojMTY5NmUxOyBzdG9wLW9wYWNpdHk6MSIgLz48L2xpbmVhckdyYWRpZW50PjxsaW5lYXJHcmFkaWVudCBpZD0iZ3JhZDIiIHgxPSIxMDAlIiB5MT0iMTAwJSIgeDI9IjEwMCUiIHkyPSIwJSI+PHN0b3Agb2Zmc2V0PSIxMDAlIiBzdHlsZT0ic3RvcC1jb2xvcjojNGJlMGZjOyBzdG9wLW9wYWNpdHk6MSIgLz48c3RvcCBvZmZzZXQ9IjAlIiBzdHlsZT0ic3RvcC1jb2xvcjojMTY5NmUxOyBzdG9wLW9wYWNpdHk6MSIgLz48L2xpbmVhckdyYWRpZW50PjwvZGVmcz48Zz48cG9seWdvbiBwb2ludHM9IjQ4LDI0IDU4LDM2IDQ0LDY3IDMyLDYwIiBmaWxsPSJ1cmwoI2dyYWQyKSIgLz48cG9seWdvbiBwb2ludHM9IjMyLDYwIDQ0LDY3IDMyLjk0LDY4Ljg5IiBmaWxsPSJ1cmwoI2dyYWQyKSIgLz48cG9seWdvbiBwb2ludHM9IjQ0LDY3IDQ3LjE1LDYwIDQ4LDY1LjUiIGZpbGw9InVybCgjZ3JhZDEpIiAvPjxwb2x5Z29uIHBvaW50cz0iNDcuMTUsNjAgNTAuMzAsNTMgNTEuMTUsNTguNSIgZmlsbD0idXJsKCNncmFkMSkiIC8+PGNpcmNsZSBjeD0iNTUiIGN5PSIyNSIgcj0iMTgiIGZpbGw9InVybCgjZ3JhZDEpIiAvPjxjaXJjbGUgY3g9IjcyIiBjeT0iMjUiIHI9IjE4IiBmaWxsPSJ3aGl0ZSIgLz48L2c+PGc+PHJlY3QgeD0iNzAiIHk9IjMwIiB3aWR0aD0iMTYiIGhlaWdodD0iNDUiIGZpbGw9InVybCgjZ3JhZDIpIiAvPjxwb2x5Z29uIHBvaW50cz0iNzgsODEgNzAsNzUgODYsNzUiIGZpbGw9InVybCgjZ3JhZDIpIiAvPjxwb2x5Z29uIHBvaW50cz0iODYsNjcgODYsNzUgODguNSw3MSIgZmlsbD0idXJsKCNncmFkMSkiIC8+PHBvbHlnb24gcG9pbnRzPSI4Niw2NyA4Niw1OSA4OC41LDYzIiBmaWxsPSJ1cmwoI2dyYWQxKSIgLz48Y2lyY2xlIGN4PSI3NyIgY3k9IjI1IiByPSIxOCIgZmlsbD0idXJsKCNncmFkMSkiIC8+PGNpcmNsZSBjeD0iNzciIGN5PSIyMyIgcj0iMyIgZmlsbD0id2hpdGUiIC8+PC9nPjwvc3ZnPg==",
            .cbAuthenticatorInfo = static_cast<DWORD>(authenticatorInfo.size()),
            .pbAuthenticatorInfo = authenticatorInfo.data(),
            .cSupportedRpIds = ARRAYSIZE(supportedRpIds),
            .ppwszSupportedRpIds = supportedRpIds
        };

        // Call the plugin update API
        RETURN_IF_FAILED(WebAuthNPluginUpdateAuthenticatorDetails(&updateDetails));

        return S_OK;
    }

    HRESULT PluginRegistrationManager::RefreshPluginState()
    {
        // Reset the plugin state and registration status
        m_pluginRegistered = false;
        // Reset to disabled state
        m_pluginState = AUTHENTICATOR_STATE::AuthenticatorState_Disabled;

        // AUTHENTICATOR_STATE: Enum representing various operational
        // states of a plugin authenticator (enabled, disabled, etc.)
        AUTHENTICATOR_STATE localPluginState;

        // Query the platform for the current plugin state using the get state API
        RETURN_IF_FAILED(WebAuthNPluginGetAuthenticatorState(happyfactoryplugin_guid, &localPluginState));

        // If the WebAuthNPluginGetAuthenticatorState function succeeded, that indicates the plugin is registered and localPluginState is the valid plugin state
        m_pluginRegistered = true;
        m_pluginState = localPluginState;
        return S_OK;
    }

    HRESULT PluginRegistrationManager::CreateVaultPasskey(HWND hWnd, std::wstring const& requestId)
    {
        HRESULT hr = S_OK;
        std::wstring operation = L"vault_recovery";
        std::wstring localRequestId = requestId;

        DWORD webauthnApiVersion = WebAuthNGetApiVersionNumber();
        if (localRequestId.empty())
        {
            localRequestId = tsupasswd::BuildRequestId(operation);
        }

        if (IsTruthySetting(GetEnvironmentVariableValue(kVaultSchemaSelfTestEnv)))
        {
            std::wstring selfTestError;
            if (!tsupasswd::RunVaultSerializationV1RegressionTests(selfTestError))
            {
                UpdatePasskeyOperationStatusText(
                    winrt::hstring{
                        L"WARNING: summary result=warning operation=" + operation +
                        L" step=vault_schema_v1_regression_test_failed detail=" + selfTestError +
                        L" request_id=" + localRequestId + L"⚠" });
            }
            else
            {
                UpdatePasskeyOperationStatusText(
                    winrt::hstring{
                        L"INFO: summary state=observed operation=" + operation +
                        L" step=vault_schema_v1_regression_test_passed request_id=" + localRequestId + L"ℹ" });
            }
        }

        UpdatePasskeyOperationStatusText(
            winrt::hstring{
                L"INFO: summary state=observed operation=" + operation +
                L" step=webauthn_api_version value=" + std::to_wstring(static_cast<int>(webauthnApiVersion)) +
                L" request_id=" + localRequestId + L"ℹ" });

        // populate the input structures
        WEBAUTHN_RP_ENTITY_INFORMATION rpEntity = {};
        rpEntity.dwVersion = WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION;
        rpEntity.pwszName = c_rpName;
        rpEntity.pwszId = c_pluginRpId;
        WEBAUTHN_USER_ENTITY_INFORMATION userEntity = {};
        userEntity.dwVersion = WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION;
        userEntity.pwszName = c_userName;
        userEntity.pwszDisplayName = c_userDisplayName;
        std::wstring syncUserId = GetUserEnvironmentRegistryValue(kSyncUserIdEnv);
        if (syncUserId.empty())
        {
            syncUserId = GetProcessEnvironmentVariableValue(kSyncUserIdEnv);
        }
        if (syncUserId.empty())
        {
            syncUserId = kDefaultSyncUserId;
        }
        std::string userId = winrt::to_string(syncUserId);
        userEntity.pbId = reinterpret_cast<BYTE*>(userId.data());
        userEntity.cbId = static_cast<DWORD>(userId.size());

        WEBAUTHN_COSE_CREDENTIAL_PARAMETER credentialParameter = {};
        credentialParameter.dwVersion = WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION;
        credentialParameter.pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;
        credentialParameter.lAlg = WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256;

        WEBAUTHN_COSE_CREDENTIAL_PARAMETERS credentialParameters = {};
        credentialParameters.cCredentialParameters = 1;
        credentialParameters.pCredentialParameters = &credentialParameter;

        WEBAUTHN_CREDENTIAL rgExcludeCredential[] = { 0 }; // TestFree(.pbId)

        WEBAUTHN_CLIENT_DATA clientData = {};
        clientData.dwVersion = WEBAUTHN_CLIENT_DATA_CURRENT_VERSION;
        clientData.pwszHashAlgId = WEBAUTHN_HASH_ALGORITHM_SHA_256;
        std::array<uint8_t, 32> challengeBytes{};
        RETURN_IF_NTSTATUS_FAILED(BCryptGenRandom(
            nullptr,
            challengeBytes.data(),
            wil::safe_cast<ULONG>(challengeBytes.size()),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG));
        std::string challenge = Base64UrlEncode(challengeBytes.data(), wil::safe_cast<DWORD>(challengeBytes.size()));
        RETURN_HR_IF(E_UNEXPECTED, challenge.empty());
        std::string clientDataJson =
            "{\"type\":\"webauthn.create\","
            "\"challenge\":\"" + challenge + "\"," 
            "\"origin\":\"https://happyfactory.dev\"," 
            "\"crossOrigin\":false}";
        clientData.pbClientDataJSON = reinterpret_cast<BYTE*>(clientDataJson.data());
        clientData.cbClientDataJSON = static_cast<DWORD>(clientDataJson.size());

        WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS webAuthNCredentialOptions = {};
        webAuthNCredentialOptions.dwVersion = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_CURRENT_VERSION;
        webAuthNCredentialOptions.dwTimeoutMilliseconds = 180 * 1000;
        webAuthNCredentialOptions.CredentialList.cCredentials = 0;
        webAuthNCredentialOptions.CredentialList.pCredentials = nullptr;
        BOOL hmacSecretExtensionValue = TRUE;
        WEBAUTHN_EXTENSION hmacSecretExtension = {};
        hmacSecretExtension.pwszExtensionIdentifier = WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET;
        hmacSecretExtension.cbExtension = sizeof(BOOL);
        hmacSecretExtension.pvExtension = &hmacSecretExtensionValue;
        webAuthNCredentialOptions.Extensions.cExtensions = 1;
        webAuthNCredentialOptions.Extensions.pExtensions = &hmacSecretExtension;
        webAuthNCredentialOptions.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY;
        webAuthNCredentialOptions.bRequireResidentKey = FALSE;
        webAuthNCredentialOptions.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_PREFERRED;
        webAuthNCredentialOptions.dwAttestationConveyancePreference = WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_ANY;
        webAuthNCredentialOptions.dwFlags = 0;
        webAuthNCredentialOptions.bEnablePrf = TRUE;
        std::array<BYTE, WEBAUTHN_CTAP_ONE_HMAC_SECRET_LENGTH> prfRawSaltBytes{
            0x74, 0x73, 0x75, 0x70, 0x61, 0x73, 0x73, 0x77, 0x64, 0x2d, 0x76, 0x61, 0x75, 0x6c, 0x74, 0x2d,
            0x70, 0x72, 0x66, 0x2d, 0x76, 0x32, 0x2d, 0x73, 0x61, 0x6c, 0x74, 0x2d, 0x30, 0x30, 0x30, 0x31 };
        WEBAUTHN_HMAC_SECRET_SALT prfGlobalEval = {};
        prfGlobalEval.cbFirst = wil::safe_cast<DWORD>(prfRawSaltBytes.size());
        prfGlobalEval.pbFirst = prfRawSaltBytes.data();
        prfGlobalEval.cbSecond = 0;
        prfGlobalEval.pbSecond = nullptr;
        webAuthNCredentialOptions.pPRFGlobalEval = &prfGlobalEval;

        UpdatePasskeyOperationStatusText(winrt::hstring{ L"INFO: summary state=running operation=" + operation + L" step=open_passkey_prompt request_id=" + localRequestId + L"ℹ" });

        unique_webauthn_credential_attestation pCredentialAttestation = nullptr;
        hr = WebAuthNAuthenticatorMakeCredential(
            hWnd,
            &rpEntity,
            &userEntity,
            &credentialParameters,
            &clientData,
            &webAuthNCredentialOptions,
            &pCredentialAttestation);

        wchar_t makeCredHrHex[11] = {};
        swprintf_s(makeCredHrHex, L"0x%08X", static_cast<unsigned int>(hr));
        std::wstring makeCredentialResult =
            L"INFO: summary state=observed operation=" + operation +
            L" step=webauthn_make_credential_returned hr=" + std::to_wstring(static_cast<int>(hr)) +
            L" hr_hex=" + std::wstring(makeCredHrHex) +
            L" win32=" + std::to_wstring(static_cast<unsigned long>(HRESULT_FACILITY(hr) == FACILITY_WIN32 ? HRESULT_CODE(hr) : 0)) +
            L" request_id=" + localRequestId + L"ℹ";
        UpdatePasskeyOperationStatusText(winrt::hstring{ makeCredentialResult });

        bool attestationPrfEnabledObserved = false;
        bool attestationPrfEnabled = false;
        bool attestationHmacSecretEnabledObserved = false;
        bool attestationHmacSecretEnabled = false;
        bool attestationAaguidObserved = false;
        std::wstring attestationAaguid;
        std::wstring attestationProvider;

        if (SUCCEEDED(hr) && pCredentialAttestation)
        {
            if (pCredentialAttestation.get()->dwVersion >= WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_5)
            {
                attestationPrfEnabledObserved = true;
                attestationPrfEnabled = pCredentialAttestation.get()->bPrfEnabled ? true : false;
                UpdatePasskeyOperationStatusText(
                    winrt::hstring{
                        L"INFO: summary state=observed operation=" + operation +
                        L" step=credential_attestation_prf_enabled value=" +
                        std::to_wstring(static_cast<int>(pCredentialAttestation.get()->bPrfEnabled)) +
                        L" request_id=" + localRequestId + L"ℹ" });
            }

            {
                bool found = false;
                bool enabled = false;
                auto const& exts = pCredentialAttestation.get()->Extensions;
                for (DWORD i = 0; i < exts.cExtensions; i++)
                {
                    auto const& ext = exts.pExtensions[i];
                    if (ext.pwszExtensionIdentifier != nullptr &&
                        wcscmp(ext.pwszExtensionIdentifier, WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET) == 0 &&
                        ext.cbExtension == sizeof(BOOL) &&
                        ext.pvExtension != nullptr)
                    {
                        found = true;
                        enabled = (*reinterpret_cast<BOOL*>(ext.pvExtension)) ? true : false;
                        break;
                    }
                }
                if (found)
                {
                    attestationHmacSecretEnabledObserved = true;
                    attestationHmacSecretEnabled = enabled;
                    UpdatePasskeyOperationStatusText(
                        winrt::hstring{
                            L"INFO: summary state=observed operation=" + operation +
                            L" step=credential_attestation_hmac_secret_enabled value=" +
                            std::to_wstring(static_cast<int>(enabled)) +
                            L" request_id=" + localRequestId + L"ℹ" });
                }
                else
                {
                    UpdatePasskeyOperationStatusText(
                        winrt::hstring{
                            L"INFO: summary state=observed operation=" + operation +
                            L" step=credential_attestation_hmac_secret_enabled status=unavailable request_id=" +
                            localRequestId + L"ℹ" });
                }
            }

            std::array<BYTE, 16> observedAaguidBytes{};
            if (TryExtractAttestationAaguid(pCredentialAttestation.get(), observedAaguidBytes))
            {
                std::wstring observedAaguid = FormatAaguid(observedAaguidBytes.data(), observedAaguidBytes.size());
                std::string expectedAaguidNarrow{ c_pluginAaguidString };
                std::wstring expectedAaguid(expectedAaguidNarrow.begin(), expectedAaguidNarrow.end());
                std::wstring provider = (_wcsicmp(observedAaguid.c_str(), expectedAaguid.c_str()) == 0) ? L"tsupasswd_core" : L"other";

                attestationAaguidObserved = true;
                attestationAaguid = observedAaguid;
                attestationProvider = provider;

                UpdatePasskeyOperationStatusText(
                    winrt::hstring{
                        L"INFO: summary state=observed operation=" + operation +
                        L" step=credential_attestation_aaguid value=" + observedAaguid +
                        L" expected=" + expectedAaguid +
                        L" provider=" + provider +
                        L" request_id=" + localRequestId + L"ℹ" });
            }
            else
            {
                UpdatePasskeyOperationStatusText(
                    winrt::hstring{
                        L"INFO: summary state=observed operation=" + operation +
                        L" step=credential_attestation_aaguid status=unavailable request_id=" +
                        localRequestId + L"ℹ" });
            }
        }

        auto pluginLastStatus = wil::reg::try_get_value_dword(
            HKEY_CURRENT_USER,
            c_pluginRegistryPath,
            c_windowsPluginLastMakeCredentialStatusRegKeyName);
        if (pluginLastStatus.has_value())
        {
            std::wstring pluginStatusResult =
                L"INFO: summary state=observed operation=" + operation + L" step=plugin_last_make_credential_status hr=" +
                std::to_wstring(static_cast<int>(static_cast<HRESULT>(pluginLastStatus.value()))) +
                L" request_id=" +
                localRequestId +
                L"ℹ";
            UpdatePasskeyOperationStatusText(winrt::hstring{ pluginStatusResult });
        }
        else
        {
            UpdatePasskeyOperationStatusText(winrt::hstring{ L"INFO: summary state=observed operation=" + operation + L" step=plugin_last_make_credential_status status=not_written request_id=" + localRequestId + L"ℹ" });
        }

        if (SUCCEEDED(hr))
        {
            std::wstring recoveryCode = GetEnvironmentVariableValue(kVaultRecoveryCodeEnv);
            if (recoveryCode.empty())
            {
                UpdatePasskeyOperationStatusText(winrt::hstring{ L"WARNING: summary result=failed operation=" + operation + L" reason=recovery_code_missing recovery=set_TSUPASSWD_VAULT_RECOVERY_CODE request_id=" + localRequestId + L"⚠" });
                return HRESULT_FROM_WIN32(ERROR_NOT_READY);
            }

            WEBAUTHN_CLIENT_DATA assertionClientData = {};
            assertionClientData.dwVersion = WEBAUTHN_CLIENT_DATA_CURRENT_VERSION;
            assertionClientData.pwszHashAlgId = WEBAUTHN_HASH_ALGORITHM_SHA_256;
            std::string assertionClientDataJson =
                "{\"type\":\"webauthn.get\","
                "\"challenge\":\"" + challenge + "\"," 
                "\"origin\":\"https://happyfactory.dev\"," 
                "\"crossOrigin\":false}";
            assertionClientData.pbClientDataJSON = reinterpret_cast<BYTE*>(assertionClientDataJson.data());
            assertionClientData.cbClientDataJSON = static_cast<DWORD>(assertionClientDataJson.size());

            WEBAUTHN_HMAC_SECRET_SALT prfSalt = {};
            prfSalt.cbFirst = wil::safe_cast<DWORD>(prfRawSaltBytes.size());
            prfSalt.pbFirst = prfRawSaltBytes.data();
            prfSalt.cbSecond = 0;
            prfSalt.pbSecond = nullptr;

            WEBAUTHN_HMAC_SECRET_SALT_VALUES prfSaltValues = {};
            prfSaltValues.pGlobalHmacSalt = &prfSalt;
            prfSaltValues.cCredWithHmacSecretSaltList = 0;
            prfSaltValues.pCredWithHmacSecretSaltList = nullptr;

            WEBAUTHN_CREDENTIAL_EX allowCredential = {};
            allowCredential.dwVersion = WEBAUTHN_CREDENTIAL_EX_CURRENT_VERSION;
            allowCredential.cbId = pCredentialAttestation.get()->cbCredentialId;
            allowCredential.pbId = pCredentialAttestation.get()->pbCredentialId;
            allowCredential.pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;
            allowCredential.dwTransports = 0;

            if (allowCredential.cbId == 0 || allowCredential.pbId == nullptr)
            {
                UpdatePasskeyOperationStatusText(
                    winrt::hstring{
                        L"WARNING: summary result=failed operation=" + operation +
                        L" reason=allow_credential_id_missing cbId=" + std::to_wstring(static_cast<unsigned long>(allowCredential.cbId)) +
                        L" pbId=" + std::wstring(allowCredential.pbId ? L"non_null" : L"null") +
                        L" request_id=" + localRequestId + L"⚠" });
                return E_INVALIDARG;
            }

            PWEBAUTHN_CREDENTIAL_EX rgAllowCredentials[] = { &allowCredential };
            WEBAUTHN_CREDENTIAL_LIST allowList = {};
            allowList.cCredentials = 1;
            allowList.ppCredentials = rgAllowCredentials;

            WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS getAssertionOptions = {};
            getAssertionOptions.dwVersion = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_CURRENT_VERSION;
            getAssertionOptions.dwTimeoutMilliseconds = 180 * 1000;
            getAssertionOptions.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY;
            getAssertionOptions.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_PREFERRED;
            getAssertionOptions.dwFlags = WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG;
            getAssertionOptions.pAllowCredentialList = &allowList;
            getAssertionOptions.pHmacSecretSaltValues = &prfSaltValues;

            UpdatePasskeyOperationStatusText(
                winrt::hstring{ L"INFO: summary state=running operation=" + operation +
                L" step=webauthn_get_assertion_start request_id=" + localRequestId + L"ℹ" });

            HRESULT getAssertionHr = S_OK;
            unique_webauthn_assertion pAssertion = nullptr;
            hr = WebAuthNAuthenticatorGetAssertion(
                hWnd,
                c_pluginRpId,
                &assertionClientData,
                &getAssertionOptions,
                &pAssertion);
            getAssertionHr = hr;

            {
                DWORD prfCbFirst = 0;
                bool prfFirstNonNull = false;
                if (pAssertion && pAssertion.get()->pHmacSecret)
                {
                    prfCbFirst = pAssertion.get()->pHmacSecret->cbFirst;
                    prfFirstNonNull = pAssertion.get()->pHmacSecret->pbFirst != nullptr;
                }
                UpdatePasskeyOperationStatusText(
                    winrt::hstring{
                        L"INFO: summary state=observed operation=" + operation +
                        L" step=webauthn_get_assertion_hmac_secret "
                        L" assertion=" + std::wstring(pAssertion ? L"non_null" : L"null") +
                        L" hmac=" + std::wstring((pAssertion && pAssertion.get()->pHmacSecret) ? L"non_null" : L"null") +
                        L" cbFirst=" + std::to_wstring(static_cast<unsigned long>(prfCbFirst)) +
                        L" pbFirst=" + std::wstring(prfFirstNonNull ? L"non_null" : L"null") +
                        L" request_id=" + localRequestId + L"ℹ" });
            }

            wchar_t getAssertHrHex[11] = {};
            swprintf_s(getAssertHrHex, L"0x%08X", static_cast<unsigned int>(hr));
            UpdatePasskeyOperationStatusText(
                winrt::hstring{ L"INFO: summary state=observed operation=" + operation +
                L" step=webauthn_get_assertion_returned hr=" + std::to_wstring(static_cast<int>(hr)) +
                L" hr_hex=" + std::wstring(getAssertHrHex) +
                L" win32=" + std::to_wstring(static_cast<unsigned long>(HRESULT_FACILITY(hr) == FACILITY_WIN32 ? HRESULT_CODE(hr) : 0)) +
                L" flags=" + std::to_wstring(static_cast<unsigned long>(getAssertionOptions.dwFlags)) +
                L" allow=" + std::to_wstring(static_cast<unsigned long>(allowList.cCredentials)) +
                L" salt_global_cb=" + std::to_wstring(static_cast<unsigned long>(prfSaltValues.pGlobalHmacSalt ? prfSaltValues.pGlobalHmacSalt->cbFirst : 0)) +
                L" allow_cbId=" + std::to_wstring(static_cast<unsigned long>(allowCredential.cbId)) +
                L" allow_pbId=" + std::wstring(allowCredential.pbId ? L"non_null" : L"null") +
                L" request_id=" + localRequestId + L"ℹ" });
            RETURN_IF_FAILED(hr);

            std::vector<uint8_t> prfSecret;
            bool usedRegistryFallback = false;
            if (pAssertion && pAssertion.get()->pHmacSecret != nullptr &&
                pAssertion.get()->pHmacSecret->pbFirst != nullptr &&
                pAssertion.get()->pHmacSecret->cbFirst > 0)
            {
                prfSecret.assign(
                    pAssertion.get()->pHmacSecret->pbFirst,
                    pAssertion.get()->pHmacSecret->pbFirst + pAssertion.get()->pHmacSecret->cbFirst);
            }
            else
            {
                // Fallback path for environments where plugin GetAssertion cannot surface pHmacSecret.
                auto protectedOpt = wil::reg::try_get_value_binary(
                    HKEY_CURRENT_USER,
                    c_pluginRegistryPath,
                    c_pluginProtectedHMACSecretInput,
                    REG_BINARY);
                if (protectedOpt.has_value() && !protectedOpt->empty())
                {
                    std::vector<BYTE> plainSecret;
                    if (UnprotectSecretForLocalUser(protectedOpt.value(), plainSecret) && !plainSecret.empty())
                    {
                        prfSecret.assign(plainSecret.begin(), plainSecret.end());
                        usedRegistryFallback = true;
                        UpdatePasskeyOperationStatusText(
                            winrt::hstring{
                                L"INFO: summary state=observed operation=" + operation +
                                L" step=prf_hmac_secret_fallback source=registry_dpapi request_id=" + localRequestId + L"ℹ" });
                    }
                }
            }

            if (prfSecret.empty())
            {
                std::wstring detail =
                    L" api_version=" + std::to_wstring(static_cast<int>(webauthnApiVersion)) +
                    L" get_assertion_hr=" + std::to_wstring(static_cast<int>(getAssertionHr)) +
                    L" att_prf_observed=" + std::to_wstring(static_cast<int>(attestationPrfEnabledObserved)) +
                    L" att_prf_enabled=" + std::to_wstring(static_cast<int>(attestationPrfEnabled)) +
                    L" att_hmac_observed=" + std::to_wstring(static_cast<int>(attestationHmacSecretEnabledObserved)) +
                    L" att_hmac_enabled=" + std::to_wstring(static_cast<int>(attestationHmacSecretEnabled)) +
                    L" att_aaguid_observed=" + std::to_wstring(static_cast<int>(attestationAaguidObserved)) +
                    (attestationAaguidObserved ? (L" att_aaguid=" + attestationAaguid) : L"") +
                    (!attestationProvider.empty() ? (L" att_provider=" + attestationProvider) : L"") +
                    L" fallback_registry=" + std::to_wstring(static_cast<int>(usedRegistryFallback));

                UpdatePasskeyOperationStatusText(
                    winrt::hstring{
                        L"INFO: sync result=warning operation=" + operation +
                        L" reason=prf_hmac_secret_missing_but_continuing_for_v3" +
                        detail +
                        L" request_id=" + localRequestId + L"ℹ" });
            }
            else
            {
                RETURN_IF_FAILED(SetHMACSecret(std::vector<BYTE>(prfSecret.begin(), prfSecret.end()), localRequestId));
                UpdatePasskeyOperationStatusText(winrt::hstring{ L"SUCCESS: summary result=success operation=" + operation + L" step=prf_hmac_secret_stored request_id=" + localRequestId + L"✅" });
            }

            std::vector<uint8_t> recoveryBytes;
            {
                std::string utf8 = winrt::to_string(recoveryCode);
                recoveryBytes.assign(utf8.begin(), utf8.end());
            }
            if (recoveryBytes.empty())
            {
                UpdatePasskeyOperationStatusText(winrt::hstring{ L"WARNING: summary result=failed operation=" + operation + L" reason=recovery_code_invalid recovery=set_TSUPASSWD_VAULT_RECOVERY_CODE request_id=" + localRequestId + L"⚠" });
                return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
            }

            std::vector<BYTE> vaultPlaintext;
            {
                tsupasswd::VaultDocumentV1 vaultDoc{};
                vaultDoc.SchemaVersion = 1;
                vaultDoc.VaultId = localRequestId;
                vaultDoc.Revision = 1;

                if (tsupasswd::SerializeVaultDocumentV1ToUtf8Bytes(vaultDoc, vaultPlaintext))
                {
                    UpdatePasskeyOperationStatusText(winrt::hstring{ L"INFO: summary state=ready operation=" + operation + L" step=vault_schema_v1_initialized request_id=" + localRequestId + L"ℹ" });
                }
                else
                {
                    UpdatePasskeyOperationStatusText(winrt::hstring{ L"WARNING: summary result=failed operation=" + operation + L" reason=vault_schema_v1_initialize_failed request_id=" + localRequestId + L"⚠" });
                    return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
                }
            }

            std::vector<uint8_t> encryptedVaultData;
            tsupasswd::VaultCryptoError cryptoError{};
            std::vector<uint8_t> vaultPlaintextBytes(vaultPlaintext.begin(), vaultPlaintext.end());
            if (!tsupasswd::EncryptVaultV3(vaultPlaintextBytes, recoveryBytes, encryptedVaultData, cryptoError))
            {
                UpdatePasskeyOperationStatusText(winrt::hstring{ L"WARNING: summary result=failed operation=" + operation + L" reason=vault_encrypt_failed code=" + cryptoError.Code + L" detail=" + cryptoError.Detail + L" request_id=" + localRequestId + L"⚠" });
                return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
            }

            RETURN_IF_FAILED(WriteEncryptedVaultData(std::vector<BYTE>(encryptedVaultData.begin(), encryptedVaultData.end())));

            tsupasswd::SyncSnapshotRecord snapshot{};
            snapshot.SnapshotId = GetNowIsoLikeTimestamp() + L"-local-create";
            snapshot.CapturedAt = GetNowIsoLikeTimestamp();
            snapshot.UserId = syncUserId;
            snapshot.ServerVersion = -1;
            snapshot.Source = L"local-create";
            snapshot.CipherBytes.assign(encryptedVaultData.begin(), encryptedVaultData.end());
            auto hrSnapshot = tsupasswd::SyncSnapshotStore::Append(snapshot);
            if (FAILED(hrSnapshot))
            {
                std::wstring snapshotOperation = L"vault_recovery_snapshot_history_append";
                UpdatePasskeyOperationStatusText(winrt::hstring{ L"INFO: sync result=warning operation=" + snapshotOperation + L" hr=" + std::to_wstring(static_cast<int>(hrSnapshot)) + L" request_id=" + localRequestId + L"ℹ" });
            }

            // Best-effort self-hosted sync. Local success must not be blocked by remote sync failure.
            SyncEncryptedVaultWithRetry(
                std::vector<BYTE>(encryptedVaultData.begin(), encryptedVaultData.end()),
                syncUserId,
                [this](winrt::hstring const& status)
                {
                    UpdatePasskeyOperationStatusText(status);
                });
        }

        std::wstring finalResult = L"INFO: summary state=done operation=" + operation + L" step=create_vault_passkey_final hr=" + std::to_wstring(static_cast<int>(hr)) + L" request_id=" + localRequestId + L"ℹ";
        UpdatePasskeyOperationStatusText(winrt::hstring{ finalResult });

        return hr;
    }

    HRESULT PluginRegistrationManager::SetHMACSecret(std::vector<BYTE> hmacSecret, std::wstring const& requestId)
    {
        // Persist the secret only as a DPAPI-protected blob (never plain text).
        std::wstring operation = L"key_management";
        std::wstring localRequestId = requestId;
        if (localRequestId.empty())
        {
            localRequestId = tsupasswd::BuildRequestId(operation);
        }

        std::lock_guard<std::mutex> lock(m_pluginOperationConfigMutex);
        if (hmacSecret.empty())
        {
            wil::unique_hkey hKey;
            RETURN_IF_WIN32_ERROR(RegCreateKeyEx(HKEY_CURRENT_USER, c_pluginRegistryPath, 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr));
            LONG deleteProtected = RegDeleteValue(hKey.get(), c_pluginProtectedHMACSecretInput);
            if (deleteProtected != ERROR_SUCCESS && deleteProtected != ERROR_FILE_NOT_FOUND)
            {
                RETURN_HR(HRESULT_FROM_WIN32(deleteProtected));
            }
            LONG deleteLegacy = RegDeleteValue(hKey.get(), c_pluginHMACSecretInput);
            if (deleteLegacy != ERROR_SUCCESS && deleteLegacy != ERROR_FILE_NOT_FOUND)
            {
                RETURN_HR(HRESULT_FROM_WIN32(deleteLegacy));
            }
            m_hmacSecret.clear();
            UpdatePasskeyOperationStatusText(winrt::hstring{ L"INFO: audit result=success operation=" + operation + L" event=prf_secret_cleared storage=registry request_id=" + localRequestId + L"ℹ" });
            return S_OK;
        }

        if (m_hmacSecret != hmacSecret)
        {
            std::vector<BYTE> protectedSecret;
            if (!ProtectSecretForLocalUser(hmacSecret, protectedSecret))
            {
                UpdatePasskeyOperationStatusText(winrt::hstring{ L"WARNING: audit result=failed operation=" + operation + L" event=prf_secret_protect_failed reason=dpapi_protect_failed request_id=" + localRequestId + L"⚠" });
                RETURN_HR(E_FAIL);
            }

            wil::unique_hkey hKey;
            RETURN_IF_WIN32_ERROR(RegCreateKeyEx(HKEY_CURRENT_USER, c_pluginRegistryPath, 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr));
            RETURN_IF_WIN32_ERROR(RegSetValueEx(hKey.get(), c_pluginProtectedHMACSecretInput, 0, REG_BINARY, reinterpret_cast<PBYTE>(protectedSecret.data()), wil::safe_cast<DWORD>(protectedSecret.size())));
            LONG deleteLegacy = RegDeleteValue(hKey.get(), c_pluginHMACSecretInput);
            if (deleteLegacy != ERROR_SUCCESS && deleteLegacy != ERROR_FILE_NOT_FOUND)
            {
                RETURN_HR(HRESULT_FROM_WIN32(deleteLegacy));
            }
            m_hmacSecret = hmacSecret;
            UpdatePasskeyOperationStatusText(winrt::hstring{ L"SUCCESS: audit result=success operation=" + operation + L" event=prf_secret_rotated storage=dpapi_protected request_id=" + localRequestId + L"✅" });
        }
        return S_OK;
    }

    HRESULT PluginRegistrationManager::SetOpaqueExportKey(std::vector<BYTE> exportKey, std::wstring const& requestId)
    {
        std::wstring operation = L"key_management";
        std::wstring localRequestId = requestId;
        if (localRequestId.empty())
        {
            localRequestId = tsupasswd::BuildRequestId(operation);
        }

        std::lock_guard<std::mutex> lock(m_pluginOperationConfigMutex);
        if (exportKey.empty())
        {
            wil::unique_hkey hKey;
            RETURN_IF_WIN32_ERROR(RegCreateKeyEx(HKEY_CURRENT_USER, c_pluginRegistryPath, 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr));
            LONG deleteProtected = RegDeleteValue(hKey.get(), c_pluginProtectedOpaqueExportKey);
            if (deleteProtected != ERROR_SUCCESS && deleteProtected != ERROR_FILE_NOT_FOUND)
            {
                RETURN_HR(HRESULT_FROM_WIN32(deleteProtected));
            }
            m_opaqueExportKey.clear();
            UpdatePasskeyOperationStatusText(winrt::hstring{ L"INFO: audit result=success operation=" + operation + L" event=opaque_export_key_cleared storage=registry request_id=" + localRequestId + L"\u2139" });
            return S_OK;
        }

        if (m_opaqueExportKey != exportKey)
        {
            std::vector<BYTE> protectedSecret;
            if (!ProtectSecretForLocalUser(exportKey, protectedSecret))
            {
                UpdatePasskeyOperationStatusText(winrt::hstring{ L"WARNING: audit result=failed operation=" + operation + L" event=opaque_export_key_protect_failed reason=dpapi_protect_failed request_id=" + localRequestId + L"\u26a0" });
                RETURN_HR(E_FAIL);
            }

            wil::unique_hkey hKey;
            RETURN_IF_WIN32_ERROR(RegCreateKeyEx(HKEY_CURRENT_USER, c_pluginRegistryPath, 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr));
            RETURN_IF_WIN32_ERROR(RegSetValueEx(hKey.get(), c_pluginProtectedOpaqueExportKey, 0, REG_BINARY, protectedSecret.data(), static_cast<DWORD>(protectedSecret.size())));
            m_opaqueExportKey = exportKey;
            UpdatePasskeyOperationStatusText(winrt::hstring{ L"SUCCESS: audit result=success operation=" + operation + L" event=opaque_export_key_stored storage=dpapi_protected request_id=" + localRequestId + L"\u2705" });
        }

        return S_OK;
    }

    void PluginRegistrationManager::ReloadRegistryValues(std::wstring const& requestId)
    {
        std::wstring operation = L"key_registry_reload";
        std::wstring keyManagementOperation = L"key_management";
        std::wstring localRequestId = requestId;
        if (localRequestId.empty())
        {
            localRequestId = tsupasswd::BuildRequestId(operation);
        }

        std::lock_guard<std::mutex> lock(m_pluginOperationConfigMutex);

        auto protectedOpt = wil::reg::try_get_value_binary(HKEY_CURRENT_USER, c_pluginRegistryPath, c_pluginProtectedHMACSecretInput, REG_BINARY);
        if (protectedOpt.has_value() && !protectedOpt->empty())
        {
            std::vector<BYTE> plainSecret;
            if (UnprotectSecretForLocalUser(protectedOpt.value(), plainSecret))
            {
                m_hmacSecret = std::move(plainSecret);
            }
            else
            {
                UpdatePasskeyOperationStatusText(winrt::hstring{ L"WARNING: audit result=failed operation=" + keyManagementOperation + L" event=prf_secret_unprotect_failed source=dpapi_protected request_id=" + localRequestId + L"⚠" });
            }
        }
        else
        {
            auto legacyOpt = wil::reg::try_get_value_binary(HKEY_CURRENT_USER, c_pluginRegistryPath, c_pluginHMACSecretInput, REG_BINARY);
            if (legacyOpt.has_value() && !legacyOpt->empty())
            {
                // Migration path from legacy plain-text value.
                m_hmacSecret = legacyOpt.value();
                std::vector<BYTE> protectedSecret;
                if (!ProtectSecretForLocalUser(m_hmacSecret, protectedSecret))
                {
                    UpdatePasskeyOperationStatusText(winrt::hstring{ L"WARNING: audit result=failed operation=" + keyManagementOperation + L" event=legacy_prf_secret_migration_failed reason=dpapi_protect_failed request_id=" + localRequestId + L"⚠" });
                }
                else
                {
                    wil::unique_hkey hKey;
                    if (RegCreateKeyEx(HKEY_CURRENT_USER, c_pluginRegistryPath, 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr) != ERROR_SUCCESS)
                    {
                        UpdatePasskeyOperationStatusText(winrt::hstring{ L"WARNING: audit result=failed operation=" + keyManagementOperation + L" event=legacy_prf_secret_migration_failed reason=registry_open_failed request_id=" + localRequestId + L"⚠" });
                    }
                    else if (RegSetValueEx(hKey.get(), c_pluginProtectedHMACSecretInput, 0, REG_BINARY, reinterpret_cast<PBYTE>(protectedSecret.data()), wil::safe_cast<DWORD>(protectedSecret.size())) != ERROR_SUCCESS)
                    {
                        UpdatePasskeyOperationStatusText(winrt::hstring{ L"WARNING: audit result=failed operation=" + keyManagementOperation + L" event=legacy_prf_secret_migration_failed reason=registry_write_failed request_id=" + localRequestId + L"⚠" });
                    }
                    else
                    {
                        RegDeleteValue(hKey.get(), c_pluginHMACSecretInput);
                        UpdatePasskeyOperationStatusText(winrt::hstring{ L"SUCCESS: audit result=success operation=" + keyManagementOperation + L" event=legacy_prf_secret_migrated source=registry_plaintext target=dpapi_protected request_id=" + localRequestId + L"✅" });
                    }
                }
            }
        }

        auto exportOpt = wil::reg::try_get_value_binary(HKEY_CURRENT_USER, c_pluginRegistryPath, c_pluginProtectedOpaqueExportKey, REG_BINARY);
        if (exportOpt.has_value() && !exportOpt->empty())
        {
            std::vector<BYTE> plainExport;
            if (UnprotectSecretForLocalUser(exportOpt.value(), plainExport))
            {
                m_opaqueExportKey = std::move(plainExport);
            }
            else
            {
                UpdatePasskeyOperationStatusText(winrt::hstring{ L"WARNING: audit result=failed operation=" + keyManagementOperation + L" event=opaque_export_key_unprotect_failed reason=dpapi_unprotect_failed request_id=" + localRequestId + L"⚠" });
            }
        }
    }

    HRESULT PluginRegistrationManager::WriteEncryptedVaultData(std::vector<BYTE> cipherText)
    {
        RETURN_HR_IF(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), cipherText.empty() || cipherText.size() < kMinVaultCipherBlobBytes);
        RETURN_HR_IF(HRESULT_FROM_WIN32(ERROR_FILE_TOO_LARGE), cipherText.size() > kMaxVaultCipherBlobBytes);

        std::vector<BYTE> framedBlob;
        RETURN_HR_IF(E_FAIL, !BuildVaultBlobWithIntegrity(cipherText, framedBlob));

        std::lock_guard<std::mutex> lock(m_pluginOperationConfigMutex);
        wil::unique_hkey hKey;
        RETURN_IF_WIN32_ERROR(RegCreateKeyEx(HKEY_CURRENT_USER, c_pluginRegistryPath, 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr));
        RETURN_IF_WIN32_ERROR(RegSetValueEx(hKey.get(), c_pluginEncryptedVaultData, 0, REG_BINARY, reinterpret_cast<PBYTE>(framedBlob.data()), wil::safe_cast<DWORD>(framedBlob.size())));
        return S_OK;
    }

    HRESULT PluginRegistrationManager::ReadEncryptedVaultData(std::vector<BYTE>& cipherText, std::wstring const& requestId)
    {
        std::wstring operation = L"read_encrypted_vault_data";
        std::wstring localRequestId = requestId;
        if (localRequestId.empty())
        {
            localRequestId = tsupasswd::BuildRequestId(operation);
        }
        std::lock_guard<std::mutex> lock(m_pluginOperationConfigMutex);
        cipherText.clear();

        auto opt = wil::reg::try_get_value_binary(HKEY_CURRENT_USER, c_pluginRegistryPath, c_pluginEncryptedVaultData, REG_BINARY);
        if (!opt)
        {
            UpdatePasskeyOperationStatusText(winrt::hstring{ L"WARNING: sync result=failed operation=" + operation + L" reason=vault_data_missing recovery=restore_snapshot_then_retry request_id=" + localRequestId + L"⚠" });
            DebugLogIfVerbose(L"DEBUG: sync result=failed operation=" + operation + L" reason=vault_data_missing source=registry\n");
            return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
        }

        if (opt->empty())
        {
            UpdatePasskeyOperationStatusText(winrt::hstring{ L"WARNING: sync result=failed operation=" + operation + L" reason=vault_data_empty_or_corrupt recovery=recreate_vault_passkey_then_retry request_id=" + localRequestId + L"⚠" });
            DebugLogIfVerbose(L"DEBUG: sync result=failed operation=" + operation + L" reason=vault_data_empty_or_corrupt\n");
            return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
        }

        std::vector<BYTE> vaultCipher;
        VaultBlobParseResult parseResult = TryExtractVaultCipherWithIntegrity(opt.value(), vaultCipher);
        if (parseResult == VaultBlobParseResult::Invalid)
        {
            UpdatePasskeyOperationStatusText(winrt::hstring{ L"WARNING: sync result=failed operation=" + operation + L" reason=vault_data_integrity_check_failed recovery=recreate_vault_passkey_then_retry request_id=" + localRequestId + L"⚠" });
            DebugLogIfVerbose(L"DEBUG: sync result=failed operation=" + operation + L" reason=vault_data_integrity_check_failed\n");
            return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
        }
        if (parseResult == VaultBlobParseResult::NotFramed)
        {
            vaultCipher = opt.value();
        }

        if (vaultCipher.size() < kMinVaultCipherBlobBytes)
        {
            UpdatePasskeyOperationStatusText(winrt::hstring{ L"WARNING: sync result=failed operation=" + operation + L" reason=vault_data_too_small_or_corrupt recovery=recreate_vault_passkey_then_retry request_id=" + localRequestId + L"⚠" });
            std::wstring msg = L"DEBUG: sync result=failed operation=" + operation + L" reason=vault_data_too_small_or_corrupt size=" + std::to_wstring(vaultCipher.size()) + L"\n";
            DebugLogIfVerbose(msg);
            return HRESULT_FROM_WIN32(ERROR_FILE_CORRUPT);
        }

        if (vaultCipher.size() > kMaxVaultCipherBlobBytes)
        {
            UpdatePasskeyOperationStatusText(winrt::hstring{ L"WARNING: sync result=failed operation=" + operation + L" reason=vault_data_too_large_or_unexpected recovery=recreate_vault_passkey_then_retry request_id=" + localRequestId + L"⚠" });
            std::wstring msg = L"DEBUG: sync result=failed operation=" + operation + L" reason=vault_data_too_large_or_unexpected size=" + std::to_wstring(vaultCipher.size()) + L"\n";
            DebugLogIfVerbose(msg);
            return HRESULT_FROM_WIN32(ERROR_FILE_TOO_LARGE);
        }

        cipherText = std::move(vaultCipher);
        return S_OK;
    }

    HRESULT PluginRegistrationManager::ClearLocalEncryptedVaultData(std::wstring const& requestId)
    {
        std::wstring operation = L"clear_local_encrypted_vault_data";
        std::wstring localRequestId = requestId;
        if (localRequestId.empty())
        {
            localRequestId = tsupasswd::BuildRequestId(operation);
        }

        std::lock_guard<std::mutex> lock(m_pluginOperationConfigMutex);
        wil::unique_hkey hKey;
        RETURN_IF_WIN32_ERROR(RegCreateKeyExW(
            HKEY_CURRENT_USER,
            c_pluginRegistryPath,
            0,
            nullptr,
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            nullptr,
            &hKey,
            nullptr));

        LONG deleteResult = RegDeleteValueW(hKey.get(), c_pluginEncryptedVaultData);
        if (deleteResult != ERROR_SUCCESS && deleteResult != ERROR_FILE_NOT_FOUND)
        {
            UpdatePasskeyOperationStatusText(winrt::hstring{ L"WARNING: sync result=failed operation=" + operation + L" reason=registry_delete_failed hr=" + std::to_wstring(static_cast<int>(HRESULT_FROM_WIN32(deleteResult))) + L" request_id=" + localRequestId + L"⚠" });
            return HRESULT_FROM_WIN32(deleteResult);
        }

        UpdatePasskeyOperationStatusText(winrt::hstring{ L"SUCCESS: sync result=success operation=" + operation + L" hr=0 request_id=" + localRequestId + L"✅" });
        return S_OK;
    }

    HRESULT PluginRegistrationManager::ManualResyncSelfHostedVault(std::wstring const& requestId)
    {
        std::wstring operation = L"manual_resync";
        std::wstring localRequestId = requestId;
        if (localRequestId.empty())
        {
            localRequestId = tsupasswd::BuildRequestId(operation);
        }

        std::wstring syncUserId = GetUserEnvironmentRegistryValue(kSyncUserIdEnv);
        if (syncUserId.empty())
        {
            syncUserId = GetProcessEnvironmentVariableValue(kSyncUserIdEnv);
        }
        if (syncUserId.empty())
        {
            syncUserId = kDefaultSyncUserId;
        }

        std::vector<BYTE> encryptedVaultData;
        HRESULT hrReadVault = ReadEncryptedVaultData(encryptedVaultData, localRequestId);
        if (FAILED(hrReadVault))
        {
            bool canAttemptRestore =
                hrReadVault == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) ||
                hrReadVault == HRESULT_FROM_WIN32(ERROR_INVALID_DATA) ||
                hrReadVault == HRESULT_FROM_WIN32(ERROR_FILE_CORRUPT);

            if (canAttemptRestore)
            {
                UpdatePasskeyOperationStatusText(
                    winrt::hstring{
                        L"INFO: sync state=auto_recover operation=" + operation +
                        L" step=restore_snapshot_then_retry reason=local_vault_missing_or_invalid request_id=" +
                        localRequestId +
                        L"ℹ" });

                HRESULT hrRestore = RestoreSelfHostedVaultSnapshot(localRequestId);
                if (SUCCEEDED(hrRestore))
                {
                    encryptedVaultData.clear();
                    hrReadVault = ReadEncryptedVaultData(encryptedVaultData, localRequestId);
                }
            }
        }

        RETURN_IF_FAILED(hrReadVault);

        UpdatePasskeyOperationStatusText(winrt::hstring{ L"INFO: sync state=start operation=" + operation + L" request_id=" + localRequestId + L"ℹ" });
        auto hrSync = SyncEncryptedVaultWithRetry(
            encryptedVaultData,
            syncUserId,
            [this](winrt::hstring const& status)
            {
                UpdatePasskeyOperationStatusText(status);
            });

        return hrSync;
    }

    HRESULT PluginRegistrationManager::RestoreSelfHostedVaultSnapshot(std::wstring const& requestId)
    {
        std::wstring operation = L"restore_snapshot";
        std::wstring localRequestId = requestId;
        if (localRequestId.empty())
        {
            localRequestId = tsupasswd::BuildRequestId(operation);
        }
        std::wstring syncBaseUrl = GetEnvironmentVariableValue(kSyncBaseUrlEnv);
        if (syncBaseUrl.empty())
        {
            UpdatePasskeyOperationStatusText(winrt::hstring{ L"WARNING: sync result=skipped operation=" + operation + L" reason=base_url_missing hr=1 request_id=" + localRequestId + L"⚠" });
            return S_FALSE;
        }

        std::wstring syncUserId = GetEnvironmentVariableValue(kSyncUserIdEnv);
        if (syncUserId.empty())
        {
            syncUserId = kDefaultSyncUserId;
        }

        UpdatePasskeyOperationStatusText(winrt::hstring{ L"INFO: sync state=start operation=" + operation + L" user_id=" + syncUserId + L" request_id=" + localRequestId + L"ℹ" });

        tsupasswd::SyncClient syncClient(syncBaseUrl);
        syncClient.SetApiKind(tsupasswd::SyncApiKind::Axum);
        syncClient.SetAllowInsecureHttp(IsAllowInsecureHttpEnabled());
        std::wstring bearerToken = GetEnvironmentVariableValue(kSyncBearerTokenEnv);
        std::vector<uint8_t> sessionKeyBytes;
        if (!bearerToken.empty())
        {
            syncClient.SetBearerToken(bearerToken);

            std::wstring recoveryCode = GetEnvironmentVariableValue(kVaultRecoveryCodeEnv);
            if (!recoveryCode.empty())
            {
                tsupasswd::SyncHttpStatus loginStatus{};
                std::wstring issuedToken;
                (void)syncClient.OpaqueLogin(syncUserId, recoveryCode, issuedToken, &sessionKeyBytes, &loginStatus);
            }
        }
        else
        {
            bool issuedDevLoginToken = TryIssueDevLoginToken(
                syncClient,
                syncUserId,
                operation,
                localRequestId,
                syncBaseUrl,
                [&](winrt::hstring const& text)
                {
                    UpdatePasskeyOperationStatusText(text);
                },
                &sessionKeyBytes);
            if (!issuedDevLoginToken)
            {
                std::wstring recoveryCode = GetEnvironmentVariableValue(kVaultRecoveryCodeEnv);
                if (recoveryCode.empty())
                {
                    UpdatePasskeyOperationStatusText(winrt::hstring{ L"WARNING: sync result=rejected operation=" + operation + L" reason=recovery_code_missing recovery=set_TSUPASSWD_VAULT_RECOVERY_CODE request_id=" + localRequestId + L"⚠" });
                    return HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);
                }

                tsupasswd::SyncHttpStatus loginStatus{};
                std::wstring issuedToken;
                HRESULT hrLogin = syncClient.OpaqueLogin(syncUserId, recoveryCode, issuedToken, &sessionKeyBytes, &loginStatus);
                if (FAILED(hrLogin) || issuedToken.empty())
                {
                    tsupasswd::SyncHttpStatus regStatus{};
                    std::vector<uint8_t> regExportKey;
                    (void)syncClient.OpaqueRegister(syncUserId, recoveryCode, &regExportKey, &regStatus);
                    if (!regExportKey.empty())
                    {
                        (void)SetOpaqueExportKey(std::vector<BYTE>(regExportKey.begin(), regExportKey.end()), localRequestId);
                    }
                    loginStatus = {};
                    issuedToken.clear();
                    hrLogin = syncClient.OpaqueLogin(syncUserId, recoveryCode, issuedToken, &sessionKeyBytes, &loginStatus);
                }

                if (SUCCEEDED(hrLogin) && !issuedToken.empty())
                {
                    syncClient.SetBearerToken(issuedToken);
                    UpdatePasskeyOperationStatusText(winrt::hstring{ L"INFO: sync state=observed operation=" + operation + L" step=opaque_login_token_issued request_id=" + ResolveRequestId(localRequestId, loginStatus) + L"ℹ" });
                }
                else
                {
                    UpdatePasskeyOperationStatusText(winrt::hstring{ L"WARNING: sync result=rejected operation=" + operation + L" step=opaque_login_failed hr=" + std::to_wstring(static_cast<int>(hrLogin)) + L" " + BuildSyncFailureStatusMessage(hrLogin, loginStatus, syncBaseUrl) + L" request_id=" + ResolveRequestId(localRequestId, loginStatus) + L"⚠" });
                    return HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);
                }
            }
        }

        tsupasswd::VaultRecord record{};
        tsupasswd::SyncHttpStatus status{};
        HRESULT hr = syncClient.GetVault(syncUserId, record, &status);
        if (hr == HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED) && (status.StatusCode == 401 || status.StatusCode == 403))
        {
            std::wstring recoveryCode = GetEnvironmentVariableValue(kVaultRecoveryCodeEnv);
            if (!recoveryCode.empty())
            {
                tsupasswd::SyncHttpStatus loginStatus{};
                std::wstring issuedToken;
                HRESULT hrLogin = syncClient.OpaqueLogin(syncUserId, recoveryCode, issuedToken, &sessionKeyBytes, &loginStatus);
                if (FAILED(hrLogin) || issuedToken.empty())
                {
                    tsupasswd::SyncHttpStatus regStatus{};
                    std::vector<uint8_t> regExportKey;
                    (void)syncClient.OpaqueRegister(syncUserId, recoveryCode, &regExportKey, &regStatus);
                    if (!regExportKey.empty())
                    {
                        (void)SetOpaqueExportKey(std::vector<BYTE>(regExportKey.begin(), regExportKey.end()), localRequestId);
                    }
                    loginStatus = {};
                    issuedToken.clear();
                    hrLogin = syncClient.OpaqueLogin(syncUserId, recoveryCode, issuedToken, &sessionKeyBytes, &loginStatus);
                }

                if (SUCCEEDED(hrLogin) && !issuedToken.empty())
                {
                    syncClient.SetBearerToken(issuedToken);
                    ClearProcessEnvironmentVariableValue(kSyncBearerTokenEnv);
                    ClearUserEnvironmentRegistryValue(kSyncBearerTokenEnv);
                    UpdatePasskeyOperationStatusText(winrt::hstring{ L"INFO: sync state=observed operation=" + operation + L" step=opaque_reauth_token_issued request_id=" + ResolveRequestId(localRequestId, loginStatus) + L"ℹ" });
                    status = {};
                    record = {};
                    hr = syncClient.GetVault(syncUserId, record, &status);
                }
            }
        }

        if (FAILED(hr))
        {
            if (hr == HRESULT_FROM_WIN32(ERROR_NOT_FOUND) || status.StatusCode == 404)
            {
                std::wstring warning = L"WARNING: sync result=failed operation=" + operation + L" hr=-2147023728 status=404 reason=snapshot_not_found failure_kind=not_found";
                if (!status.RequestId.empty())
                {
                    warning += L" request_id=" + status.RequestId;
                }
                else
                {
                    warning += L" request_id=" + localRequestId;
                }
                warning += L"⚠";
                UpdatePasskeyOperationStatusText(winrt::hstring{ warning });
                return hr;
            }

            std::wstring warning =
                L"WARNING: sync result=failed operation=" + operation + L" hr=" +
                std::to_wstring(static_cast<int>(hr)) +
                L" detail=" + BuildSyncFailureStatusMessage(hr, status, syncBaseUrl);
            if (status.RequestId.empty())
            {
                warning += L" request_id=" + localRequestId;
            }
            UpdatePasskeyOperationStatusText(winrt::hstring{ warning });
            return hr;
        }

        if (record.Blob.CiphertextBase64.empty())
        {
            DebugLogIfVerbose(
                L"DEBUG: restore_snapshot empty_ciphertext server_version=" +
                std::to_wstring(record.VaultVersion) +
                L" updated_at='" + record.Meta.UpdatedAt + L"'\n");
            UpdatePasskeyOperationStatusText(
                winrt::hstring{
                    L"WARNING: sync result=failed operation=" + operation +
                    L" reason=empty_ciphertext hr=-2147024883 failure_kind=client_error request_id=" +
                    ResolveRequestId(localRequestId, status) +
                    L"⚠" });
            return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
        }

        std::vector<BYTE> cipherBytes;
        if (!Base64StdDecode(record.Blob.CiphertextBase64, cipherBytes))
        {
            // 互換性: 既存のMVPサーバや過去データがURL-safe Base64を返す場合がある
            if (!Base64UrlDecode(record.Blob.CiphertextBase64, cipherBytes))
            {
                std::wstring preview = record.Blob.CiphertextBase64;
                if (preview.size() > 24)
                {
                    preview = preview.substr(0, 24) + L"...";
                }
                DebugLogIfVerbose(
                    L"DEBUG: restore_snapshot invalid_ciphertext base64_len=" +
                    std::to_wstring(record.Blob.CiphertextBase64.size()) +
                    L" base64_prefix='" + preview + L"'\n");

                UpdatePasskeyOperationStatusText(
                    winrt::hstring{
                        L"WARNING: sync result=failed operation=" + operation + L" reason=invalid_ciphertext hr=-2147024883 failure_kind=client_error request_id=" +
                        ResolveRequestId(localRequestId, status) +
                        L"⚠" });
                return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
            }
        }

        winrt::PasskeyManager::implementation::PluginRegistrationManager::getInstance().ReloadRegistryValues(localRequestId);
        auto exportKey = winrt::PasskeyManager::implementation::PluginRegistrationManager::getInstance().GetOpaqueExportKey();
        if (IsOpaqueSessionWrapEnabled() && !exportKey.empty())
        {
            tsupasswd::VaultCryptoError unwrapError{};
            std::vector<uint8_t> unwrapped;
            if (tsupasswd::UnwrapVaultCipherForSyncV1(
                std::vector<uint8_t>(cipherBytes.begin(), cipherBytes.end()),
                std::vector<uint8_t>(exportKey.begin(), exportKey.end()),
                unwrapped,
                unwrapError))
            {
                cipherBytes.assign(unwrapped.begin(), unwrapped.end());
            }
            else if (unwrapError.Code != L"not_wrapped")
            {
                UpdatePasskeyOperationStatusText(
                    winrt::hstring{
                        L"WARNING: sync result=failed operation=" + operation +
                        L" reason=sync_unwrap_failed code=" + unwrapError.Code +
                        L" detail=" + unwrapError.Detail +
                        L" legacy_hint=wrapped_with_old_session_key_or_mismatched_export_key" +
                        L" recovery=disable_TSUPASSWD_SYNC_OPAQUE_SESSION_WRAP_then_manual_resync_to_overwrite_server" +
                        L" request_id=" + ResolveRequestId(localRequestId, status) +
                        L"⚠" });
                return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
            }
        }

        RETURN_IF_FAILED(WriteEncryptedVaultData(cipherBytes));

        tsupasswd::SyncSnapshotRecord snapshot{};
        snapshot.SnapshotId = GetNowIsoLikeTimestamp() + L"-server-restore";
        snapshot.CapturedAt = GetNowIsoLikeTimestamp();
        snapshot.UserId = syncUserId;
        snapshot.ServerVersion = record.VaultVersion;
        snapshot.Source = L"server-restore";
        snapshot.CipherBytes = cipherBytes;
        auto hrSnapshot = tsupasswd::SyncSnapshotStore::Append(snapshot);
        if (FAILED(hrSnapshot))
        {
            std::wstring snapshotOperation = L"restore_snapshot_snapshot_history_append";
            UpdatePasskeyOperationStatusText(winrt::hstring{ L"INFO: sync result=warning operation=" + snapshotOperation + L" hr=" + std::to_wstring(static_cast<int>(hrSnapshot)) + L" request_id=" + localRequestId + L"ℹ" });
        }

        std::wstring success =
            L"SUCCESS: sync result=success operation=" + operation + L" hr=0 bytes=" +
            std::to_wstring(cipherBytes.size()) +
            L" server_version=" +
            std::to_wstring(record.VaultVersion) +
            L" request_id=" +
            ResolveRequestId(localRequestId, status) +
            L"✅";
        UpdatePasskeyOperationStatusText(winrt::hstring{ success });
        return S_OK;
    }
}
