#include "pch.h"
#include "MainPage.xaml.h"
#include "PluginRegistrationManager.h"
#include "src/SyncClient.h"
#include "src/SyncSnapshotStore.h"
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
    constexpr wchar_t kDefaultSyncUserId[] = L"ContosoUserId";

    enum class VaultBlobParseResult
    {
        NotFramed,
        Ok,
        Invalid
    };

    void AppendUint32LE(std::vector<BYTE>& out, uint32_t value)
    {
        out.push_back(static_cast<BYTE>(value & 0xFF));
        out.push_back(static_cast<BYTE>((value >> 8) & 0xFF));
        out.push_back(static_cast<BYTE>((value >> 16) & 0xFF));
        out.push_back(static_cast<BYTE>((value >> 24) & 0xFF));
    }

    bool ReadUint32LE(std::vector<BYTE> const& bytes, size_t offset, uint32_t& outValue)
    {
        if (offset + sizeof(uint32_t) > bytes.size())
        {
            return false;
        }

        outValue =
            static_cast<uint32_t>(bytes[offset]) |
            (static_cast<uint32_t>(bytes[offset + 1]) << 8) |
            (static_cast<uint32_t>(bytes[offset + 2]) << 16) |
            (static_cast<uint32_t>(bytes[offset + 3]) << 24);
        return true;
    }

    uint32_t ComputeFnv1a32(std::vector<BYTE> const& data)
    {
        uint32_t hash = 2166136261u;
        for (BYTE b : data)
        {
            hash ^= static_cast<uint32_t>(b);
            hash *= 16777619u;
        }
        return hash;
    }

    bool BuildVaultBlobWithIntegrity(std::vector<BYTE> const& cipherText, std::vector<BYTE>& outBlob)
    {
        outBlob.clear();
        if (cipherText.empty())
        {
            return false;
        }

        outBlob.reserve(kVaultBlobHeaderBytes + cipherText.size());
        outBlob.insert(outBlob.end(), std::begin(kVaultBlobMagic), std::end(kVaultBlobMagic));
        outBlob.push_back(kVaultBlobVersion);
        AppendUint32LE(outBlob, static_cast<uint32_t>(cipherText.size()));
        AppendUint32LE(outBlob, ComputeFnv1a32(cipherText));
        outBlob.insert(outBlob.end(), cipherText.begin(), cipherText.end());
        return true;
    }

    VaultBlobParseResult TryExtractVaultCipherWithIntegrity(std::vector<BYTE> const& storedBlob, std::vector<BYTE>& outCipherText)
    {
        outCipherText.clear();

        if (storedBlob.size() < kVaultBlobHeaderBytes)
        {
            return VaultBlobParseResult::NotFramed;
        }

        if (!std::equal(std::begin(kVaultBlobMagic), std::end(kVaultBlobMagic), storedBlob.begin()))
        {
            return VaultBlobParseResult::NotFramed;
        }

        if (storedBlob[4] != kVaultBlobVersion)
        {
            return VaultBlobParseResult::Invalid;
        }

        uint32_t cipherLength = 0;
        uint32_t expectedChecksum = 0;
        if (!ReadUint32LE(storedBlob, 5, cipherLength) || !ReadUint32LE(storedBlob, 9, expectedChecksum))
        {
            return VaultBlobParseResult::Invalid;
        }

        size_t expectedTotalSize = kVaultBlobHeaderBytes + static_cast<size_t>(cipherLength);
        if (expectedTotalSize != storedBlob.size())
        {
            return VaultBlobParseResult::Invalid;
        }

        outCipherText.assign(storedBlob.begin() + kVaultBlobHeaderBytes, storedBlob.end());
        if (ComputeFnv1a32(outCipherText) != expectedChecksum)
        {
            outCipherText.clear();
            return VaultBlobParseResult::Invalid;
        }

        return VaultBlobParseResult::Ok;
    }

    std::wstring GetProcessEnvironmentVariableValue(wchar_t const* name)
    {
        DWORD needed = GetEnvironmentVariableW(name, nullptr, 0);
        if (needed != 0)
        {
            std::wstring value;
            value.resize(needed);
            DWORD written = GetEnvironmentVariableW(name, value.data(), needed);
            if (written != 0)
            {
                value.resize(written);
                return value;
            }
        }

        return L"";
    }

    std::wstring GetUserEnvironmentRegistryValue(wchar_t const* name)
    {
        // Fallback for GUI/app-model launch paths where process env does not inherit
        // latest shell variables. setx writes to HKCU\Environment.
        HKEY hKey = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Environment", 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        {
            return L"";
        }

        auto keyCleanup = wil::scope_exit([&]() {
            RegCloseKey(hKey);
        });

        DWORD type = 0;
        DWORD sizeBytes = 0;
        LONG queryResult = RegQueryValueExW(hKey, name, nullptr, &type, nullptr, &sizeBytes);
        if (queryResult != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ) || sizeBytes < sizeof(wchar_t))
        {
            return L"";
        }

        std::wstring value;
        value.resize(sizeBytes / sizeof(wchar_t));
        queryResult = RegQueryValueExW(
            hKey,
            name,
            nullptr,
            &type,
            reinterpret_cast<LPBYTE>(value.data()),
            &sizeBytes);
        if (queryResult != ERROR_SUCCESS)
        {
            return L"";
        }

        while (!value.empty() && value.back() == L'\0')
        {
            value.pop_back();
        }
        return value;
    }

    std::wstring GetEnvironmentVariableValue(wchar_t const* name)
    {
        std::wstring value = GetProcessEnvironmentVariableValue(name);
        if (!value.empty())
        {
            return value;
        }

        // Fallback for GUI/app-model launch paths where process env does not inherit
        // latest shell variables. setx writes to HKCU\Environment.
        return GetUserEnvironmentRegistryValue(name);
    }

    std::wstring GetNowIsoLikeTimestamp()
    {
        SYSTEMTIME st{};
        GetSystemTime(&st);
        wchar_t buffer[32]{};
        swprintf_s(buffer, L"%04u-%02u-%02uT%02u:%02u:%02uZ",
            st.wYear,
            st.wMonth,
            st.wDay,
            st.wHour,
            st.wMinute,
            st.wSecond);
        return buffer;
    }

    std::wstring BuildRequestId(std::wstring const& operation)
    {
        SYSTEMTIME st{};
        GetSystemTime(&st);
        wchar_t timestamp[40]{};
        swprintf_s(
            timestamp,
            L"%04u%02u%02uT%02u%02u%02u%03uZ",
            st.wYear,
            st.wMonth,
            st.wDay,
            st.wHour,
            st.wMinute,
            st.wSecond,
            st.wMilliseconds);
        return std::wstring{ timestamp } + L"-" + operation;
    }

    std::string Base64UrlEncode(const uint8_t* data, DWORD dataSize)
    {
        DWORD requiredSize = 0;
        if (!CryptBinaryToStringA(
            data,
            dataSize,
            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
            nullptr,
            &requiredSize))
        {
            return {};
        }

        std::string encoded(requiredSize, '\0');
        if (!CryptBinaryToStringA(
            data,
            dataSize,
            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
            encoded.data(),
            &requiredSize))
        {
            return {};
        }

        if (!encoded.empty() && encoded.back() == '\0')
        {
            encoded.pop_back();
        }

        std::replace(encoded.begin(), encoded.end(), '+', '-');
        std::replace(encoded.begin(), encoded.end(), '/', '_');
        while (!encoded.empty() && encoded.back() == '=')
        {
            encoded.pop_back();
        }

        return encoded;
    }

    bool Base64UrlDecode(std::wstring const& encodedWide, std::vector<BYTE>& outBytes)
    {
        outBytes.clear();
        if (encodedWide.empty())
        {
            return false;
        }

        std::string encoded = winrt::to_string(encodedWide);
        std::replace(encoded.begin(), encoded.end(), '-', '+');
        std::replace(encoded.begin(), encoded.end(), '_', '/');
        while ((encoded.size() % 4) != 0)
        {
            encoded.push_back('=');
        }

        DWORD required = 0;
        if (!CryptStringToBinaryA(
            encoded.c_str(),
            static_cast<DWORD>(encoded.size()),
            CRYPT_STRING_BASE64,
            nullptr,
            &required,
            nullptr,
            nullptr))
        {
            return false;
        }

        outBytes.resize(required);
        if (!CryptStringToBinaryA(
            encoded.c_str(),
            static_cast<DWORD>(encoded.size()),
            CRYPT_STRING_BASE64,
            outBytes.data(),
            &required,
            nullptr,
            nullptr))
        {
            outBytes.clear();
            return false;
        }

        outBytes.resize(required);
        return !outBytes.empty();
    }

    bool ProtectSecretForLocalUser(std::vector<BYTE> const& plainSecret, std::vector<BYTE>& outProtectedBlob)
    {
        outProtectedBlob.clear();
        if (plainSecret.empty())
        {
            return false;
        }

        DATA_BLOB plainBlob = {
            .cbData = static_cast<DWORD>(plainSecret.size()),
            .pbData = const_cast<PBYTE>(plainSecret.data())
        };
        DATA_BLOB protectedBlob{};
        if (!CryptProtectData(
            &plainBlob,
            L"tsupasswd_core_hmac_secret",
            nullptr,
            nullptr,
            nullptr,
            CRYPTPROTECT_UI_FORBIDDEN,
            &protectedBlob))
        {
            return false;
        }

        auto cleanup = wil::scope_exit([&]() {
            if (protectedBlob.pbData)
            {
                LocalFree(protectedBlob.pbData);
            }
        });

        outProtectedBlob.assign(protectedBlob.pbData, protectedBlob.pbData + protectedBlob.cbData);
        return !outProtectedBlob.empty();
    }

    bool UnprotectSecretForLocalUser(std::vector<BYTE> const& protectedBlobBytes, std::vector<BYTE>& outPlainSecret)
    {
        outPlainSecret.clear();
        if (protectedBlobBytes.empty())
        {
            return false;
        }

        DATA_BLOB protectedBlob = {
            .cbData = static_cast<DWORD>(protectedBlobBytes.size()),
            .pbData = const_cast<PBYTE>(protectedBlobBytes.data())
        };
        DATA_BLOB plainBlob{};
        if (!CryptUnprotectData(
            &protectedBlob,
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            CRYPTPROTECT_UI_FORBIDDEN,
            &plainBlob))
        {
            return false;
        }

        auto cleanup = wil::scope_exit([&]() {
            if (plainBlob.pbData)
            {
                LocalFree(plainBlob.pbData);
            }
        });

        outPlainSecret.assign(plainBlob.pbData, plainBlob.pbData + plainBlob.cbData);
        return !outPlainSecret.empty();
    }

    std::wstring ClassifySyncFailureKind(HRESULT hr, tsupasswd::SyncHttpStatus const& status)
    {
        switch (status.StatusCode)
        {
        case 401:
        case 403:
            return L"authorization";
        case 404:
            return L"not_found";
        case 409:
            return L"version_conflict";
        case 429:
            return L"rate_limited";
        default:
            break;
        }

        if (status.StatusCode >= 500)
        {
            return L"server_error";
        }
        if (status.StatusCode > 0)
        {
            return L"http_error";
        }
        if (status.ErrorCode == L"CLIENT_ERROR")
        {
            return L"client_error";
        }
        if (FAILED(hr))
        {
            return L"transport_or_unknown";
        }
        return L"none";
    }

    bool IsNameResolutionFailure(HRESULT hr)
    {
        return HRESULT_CODE(hr) == 12007;
    }

    std::wstring BuildSyncFailureStatusMessage(HRESULT hr, tsupasswd::SyncHttpStatus const& status)
    {
        std::wstring detail = L"failure_kind=" + ClassifySyncFailureKind(hr, status) + L" ";
        switch (status.StatusCode)
        {
        case 401:
            detail += L"sync_failure=unauthorized recovery=check_authorization_header_and_token";
            break;
        case 403:
            detail += L"sync_failure=forbidden recovery=verify_sync_bearer_token";
            break;
        case 409:
            detail += L"sync_failure=version_conflict recovery=refresh_latest_state_and_retry";
            if (status.ServerVersion >= 0)
            {
                detail += L" server_version=" + std::to_wstring(status.ServerVersion);
            }
            break;
        case 429:
            detail += L"sync_failure=rate_limited recovery=wait_and_retry";
            break;
        default:
            if (IsNameResolutionFailure(hr))
            {
                detail += L"sync_failure=name_not_resolved recovery=check_sync_base_url_dns_or_hosts local_save=kept";
            }
            else
            {
                detail += L"sync_failure=unexpected_or_server_error local_save=kept";
            }
            if (status.StatusCode > 0)
            {
                detail += L" status=" + std::to_wstring(status.StatusCode);
            }
            break;
        }

        if (!status.ErrorCode.empty())
        {
            detail += L" code=" + status.ErrorCode;
        }
        if (!status.RequestId.empty())
        {
            detail += L" request_id=" + status.RequestId;
        }
        if (!status.ErrorMessage.empty())
        {
            if (!status.ErrorCode.empty())
            {
                detail += L" message_code=" + status.ErrorCode;
            }
            else
            {
                detail += L" message_code=remote_error_message_present";
            }
            detail += L" message=" + status.ErrorMessage;
        }

        return detail;
    }

    std::wstring ResolveRequestId(std::wstring const& fallbackRequestId, tsupasswd::SyncHttpStatus const& status)
    {
        if (!status.RequestId.empty())
        {
            return status.RequestId;
        }
        return fallbackRequestId;
    }

    HRESULT SyncEncryptedVaultWithRetry(
        std::vector<BYTE> const& encryptedVaultData,
        std::wstring const& syncUserId,
        std::function<void(winrt::hstring const&)> const& statusSink)
    {
        std::wstring localRequestId = BuildRequestId(L"put_vault");
        std::wstring syncBaseUrl = GetEnvironmentVariableValue(kSyncBaseUrlEnv);
        if (syncBaseUrl.empty())
        {
            statusSink(winrt::hstring{ L"INFO: sync result=skipped operation=put_vault reason=base_url_missing hr=1 request_id=" + localRequestId + L"ℹ" });
            return S_FALSE;
        }

        statusSink(winrt::hstring{ L"INFO: sync state=start operation=put_vault user_id=" + syncUserId + L" request_id=" + localRequestId + L"ℹ" });

        tsupasswd::SyncClient syncClient(syncBaseUrl);
        std::wstring bearerToken = GetEnvironmentVariableValue(kSyncBearerTokenEnv);
        if (!bearerToken.empty())
        {
            syncClient.SetBearerToken(bearerToken);
        }

        tsupasswd::PutVaultRequest putRequest{};
        putRequest.ExpectedVersion = 0;
        putRequest.NewVersion = 1;
        putRequest.DeviceId = L"tsupasswd_core_windows";
        putRequest.Blob.CiphertextBase64 = winrt::to_hstring(Base64UrlEncode(encryptedVaultData.data(), wil::safe_cast<DWORD>(encryptedVaultData.size()))).c_str();
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

        for (int attempt = 1; attempt <= kMaxAttempts; ++attempt)
        {
            attemptsUsed = attempt;
            syncStatus = {};
            hrSync = syncClient.PutVault(syncUserId, putRequest, putResponse, &syncStatus);

            if (hrSync == HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH) && syncStatus.ServerVersion >= 0)
            {
                auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - syncStartTime).count();
                putRequest.ExpectedVersion = syncStatus.ServerVersion;
                putRequest.NewVersion = syncStatus.ServerVersion + 1;
                statusSink(
                    winrt::hstring{
                        L"INFO: sync result=retry_conflict operation=put_vault attempt=" +
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
                statusSink(winrt::hstring{ L"SUCCESS: sync result=success operation=put_vault attempts=" + std::to_wstring(attempt) + L"/" + std::to_wstring(kMaxAttempts) + L" elapsed_ms=" + std::to_wstring(elapsedMs) + L" hr=0 request_id=" + ResolveRequestId(localRequestId, syncStatus) + L"✅" });
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
                    L"INFO: sync result=retry_backoff operation=put_vault attempt=" +
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
            L"WARNING: sync result=failed operation=put_vault attempts=" +
            std::to_wstring(attemptsUsed) +
            L"/" +
            std::to_wstring(kMaxAttempts) +
            L" elapsed_ms=" +
            std::to_wstring(std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - syncStartTime).count()) +
            L" hr=" + std::to_wstring(static_cast<int>(hrSync)) +
            L" detail=" + BuildSyncFailureStatusMessage(hrSync, syncStatus);
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

}

namespace winrt::PasskeyManager::implementation {
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
        // 9: ["internal"], 10: [{"alg": -7, "type": "public-key"}]}
        std::string authenticatorInfoStrPart1 = "A60182684649444F5F325F30684649444F5F325F310282637072666B686D61632D7365637265740350";
        std::string authenticatorInfoStrPart2 = "04A362726BF5627570F5627576F5098168696E7465726E616C0A81A263616C672664747970656A7075626C69632D6B6579";
        std::string fullAuthenticatorInfoStr = authenticatorInfoStrPart1 + tempAaguidStr + authenticatorInfoStrPart2;
        std::vector<BYTE> authenticatorInfo = hexStringToBytes(fullAuthenticatorInfoStr);

        // WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS: Structure containing options for registering a plugin authenticator
        // with the Windows platform. This includes authenticator name, class ID, supported RP IDs, logo data, and
        // CBOR-encoded authenticator information for FIDO compliance.
        PCWSTR supportedRpIds[] = { c_pluginRpId };
        WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS addOptions{
            .pwszAuthenticatorName = c_pluginName,
            .rclsid = contosoplugin_guid,
            .pwszPluginRpId = c_pluginRpId,
            .pwszLightThemeLogoSvg = L"PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZlcnNpb249IjEuMSIgdmlld0JveD0iMzAgMCA1MCA4NSIgc3R5bGU9ImZpbGwtcnVsZTpldmVub2RkOyBjbGlwLXJ1bGU6ZXZlbm9kZDsgc2hhcGUtcmVuZGVyaW5nOmdlb21ldHJpY1ByZWNpc2lvbjsgdGV4dC1yZW5kZXJpbmc6Z2VvbWV0cmljUHJlY2lzaW9uOyBpbWFnZS1yZW5kZXJpbmc6b3B0aW1pemVRdWFsaXR5OyI+PGRlZnM+PGxpbmVhckdyYWRpZW50IGlkPSJncmFkMSIgeDE9IjAlIiB5MT0iMTAwJSIgeDI9IjEwMCUiIHkyPSIwJSI+PHN0b3Agb2Zmc2V0PSIwJSIgc3R5bGU9InN0b3AtY29sb3I6IzRiZTBmYzsgc3RvcC1vcGFjaXR5OjEiIC8+PHN0b3Agb2Zmc2V0PSIxMDAlIiBzdHlsZT0ic3RvcC1jb2xvcjojMTY5NmUxOyBzdG9wLW9wYWNpdHk6MSIgLz48L2xpbmVhckdyYWRpZW50PjxsaW5lYXJHcmFkaWVudCBpZD0iZ3JhZDIiIHgxPSIxMDAlIiB5MT0iMTAwJSIgeDI9IjEwMCUiIHkyPSIwJSI+PHN0b3Agb2Zmc2V0PSIxMDAlIiBzdHlsZT0ic3RvcC1jb2xvcjojNGJlMGZjOyBzdG9wLW9wYWNpdHk6MSIgLz48c3RvcCBvZmZzZXQ9IjAlIiBzdHlsZT0ic3RvcC1jb2xvcjojMTY5NmUxOyBzdG9wLW9wYWNpdHk6MSIgLz48L2xpbmVhckdyYWRpZW50PjwvZGVmcz48Zz48cG9seWdvbiBwb2ludHM9IjQ4LDI0IDU4LDM2IDQ0LDY3IDMyLDYwIiBmaWxsPSJ1cmwoI2dyYWQyKSIgLz48cG9seWdvbiBwb2ludHM9IjMyLDYwIDQ0LDY3IDMyLjk0LDY4Ljg5IiBmaWxsPSJ1cmwoI2dyYWQyKSIgLz48cG9seWdvbiBwb2ludHM9IjQ0LDY3IDQ3LjE1LDYwIDQ4LDY1LjUiIGZpbGw9InVybCgjZ3JhZDEpIiAvPjxwb2x5Z29uIHBvaW50cz0iNDcuMTUsNjAgNTAuMzAsNTMgNTEuMTUsNTguNSIgZmlsbD0idXJsKCNncmFkMSkiIC8+PGNpcmNsZSBjeD0iNTUiIGN5PSIyNSIgcj0iMTgiIGZpbGw9InVybCgjZ3JhZDEpIiAvPjxjaXJjbGUgY3g9IjcyIiBjeT0iMjUiIHI9IjE4IiBmaWxsPSJ3aGl0ZSIgLz48L2c+PGc+PHJlY3QgeD0iNzAiIHk9IjMwIiB3aWR0aD0iMTYiIGhlaWdodD0iNDUiIGZpbGw9InVybCgjZ3JhZDIpIiAvPjxwb2x5Z29uIHBvaW50cz0iNzgsODEgNzAsNzUgODYsNzUiIGZpbGw9InVybCgjZ3JhZDIpIiAvPjxwb2x5Z29uIHBvaW50cz0iODYsNjcgODYsNzUgODguNSw3MSIgZmlsbD0idXJsKCNncmFkMSkiIC8+PHBvbHlnb24gcG9pbnRzPSI4Niw2NyA4Niw1OSA4OC41LDYzIiBmaWxsPSJ1cmwoI2dyYWQxKSIgLz48Y2lyY2xlIGN4PSI3NyIgY3k9IjI1IiByPSIxOCIgZmlsbD0idXJsKCNncmFkMSkiIC8+PGNpcmNsZSBjeD0iNzciIGN5PSIyMyIgcj0iMyIgZmlsbD0id2hpdGUiIC8+PC9nPjwvc3ZnPg==",
            .pwszDarkThemeLogoSvg = L"PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZlcnNpb249IjEuMSIgdmlld0JveD0iMzAgMCA1MCA4NSIgc3R5bGU9ImZpbGwtcnVsZTpldmVub2RkOyBjbGlwLXJ1bGU6ZXZlbm9kZDsgc2hhcGUtcmVuZGVyaW5nOmdlb21ldHJpY1ByZWNpc2lvbjsgdGV4dC1yZW5kZXJpbmc6Z2VvbWV0cmljUHJlY2lzaW9uOyBpbWFnZS1yZW5kZXJpbmc6b3B0aW1pemVRdWFsaXR5OyI+PGRlZnM+PGxpbmVhckdyYWRpZW50IGlkPSJncmFkMSIgeDE9IjAlIiB5MT0iMTAwJSIgeDI9IjEwMCUiIHkyPSIwJSI+PHN0b3Agb2Zmc2V0PSIwJSIgc3R5bGU9InN0b3AtY29sb3I6IzRiZTBmYzsgc3RvcC1vcGFjaXR5OjEiIC8+PHN0b3Agb2Zmc2V0PSIxMDAlIiBzdHlsZT0ic3RvcC1jb2xvcjojMTY5NmUxOyBzdG9wLW9wYWNpdHk6MSIgLz48L2xpbmVhckdyYWRpZW50PjxsaW5lYXJHcmFkaWVudCBpZD0iZ3JhZDIiIHgxPSIxMDAlIiB5MT0iMTAwJSIgeDI9IjEwMCUiIHkyPSIwJSI+PHN0b3Agb2Zmc2V0PSIxMDAlIiBzdHlsZT0ic3RvcC1jb2xvcjojNGJlMGZjOyBzdG9wLW9wYWNpdHk6MSIgLz48c3RvcCBvZmZzZXQ9IjAlIiBzdHlsZT0ic3RvcC1jb2xvcjojMTY5NmUxOyBzdG9wLW9wYWNpdHk6MSIgLz48L2xpbmVhckdyYWRpZW50PjwvZGVmcz48Zz48cG9seWdvbiBwb2ludHM9IjQ4LDI0IDU4LDM2IDQ0LDY3IDMyLDYwIiBmaWxsPSJ1cmwoI2dyYWQyKSIgLz48cG9seWdvbiBwb2ludHM9IjMyLDYwIDQ0LDY3IDMyLjk0LDY4Ljg5IiBmaWxsPSJ1cmwoI2dyYWQyKSIgLz48cG9seWdvbiBwb2ludHM9IjQ0LDY3IDQ3LjE1LDYwIDQ4LDY1LjUiIGZpbGw9InVybCgjZ3JhZDEpIiAvPjxwb2x5Z29uIHBvaW50cz0iNDcuMTUsNjAgNTAuMzAsNTMgNTEuMTUsNTguNSIgZmlsbD0idXJsKCNncmFkMSkiIC8+PGNpcmNsZSBjeD0iNTUiIGN5PSIyNSIgcj0iMTgiIGZpbGw9InVybCgjZ3JhZDEpIiAvPjxjaXJjbGUgY3g9IjcyIiBjeT0iMjUiIHI9IjE4IiBmaWxsPSJ3aGl0ZSIgLz48L2c+PGc+PHJlY3QgeD0iNzAiIHk9IjMwIiB3aWR0aD0iMTYiIGhlaWdodD0iNDUiIGZpbGw9InVybCgjZ3JhZDIpIiAvPjxwb2x5Z29uIHBvaW50cz0iNzgsODEgNzAsNzUgODYsNzUiIGZpbGw9InVybCgjZ3JhZDIpIiAvPjxwb2x5Z29uIHBvaW50cz0iODYsNjcgODYsNzUgODguNSw3MSIgZmlsbD0idXJsKCNncmFkMSkiIC8+PHBvbHlnb24gcG9pbnRzPSI4Niw2NyA4Niw1OSA4OC41LDYzIiBmaWxsPSJ1cmwoI2dyYWQxKSIgLz48Y2lyY2xlIGN4PSI3NyIgY3k9IjI1IiByPSIxOCIgZmlsbD0idXJsKCNncmFkMSkiIC8+PGNpcmNsZSBjeD0iNzciIGN5PSIyMyIgcj0iMyIgZmlsbD0id2hpdGUiIC8+PC9nPjwvc3ZnPg==",
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
        RETURN_HR(WebAuthNPluginRemoveAuthenticator(contosoplugin_guid));
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
        // 9: ["internal"], 10: [{"alg": -7, "type": "public-key"}]}
        std::string authenticatorInfoStrPart1 = "A60182684649444F5F325F30684649444F5F325F310282637072666B686D61632D7365637265740350";
        std::string authenticatorInfoStrPart2 = "04A362726BF5627570F5627576F5098168696E7465726E616C0A81A263616C672664747970656A7075626C69632D6B6579";
        std::string fullAuthenticatorInfoStr = authenticatorInfoStrPart1 + tempAaguidStr + authenticatorInfoStrPart2;
        std::vector<BYTE> authenticatorInfo = hexStringToBytes(fullAuthenticatorInfoStr);

        PCWSTR supportedRpIds[] = { c_pluginRpId };

        // WEBAUTHN_PLUGIN_UPDATE_AUTHENTICATOR_DETAILS: Structure containing updated plugin information for an already
        // registered authenticator, including potentially new class IDs, names, logos, and authenticator information.
        WEBAUTHN_PLUGIN_UPDATE_AUTHENTICATOR_DETAILS updateDetails{
            .pwszAuthenticatorName = c_pluginName,
            .rclsid = contosoplugin_guid,
            .rclsidNew = contosoplugin_guid,
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
        RETURN_IF_FAILED(WebAuthNPluginGetAuthenticatorState(contosoplugin_guid, &localPluginState));

        // If the WebAuthNPluginGetAuthenticatorState function succeeded, that indicates the plugin is registered and localPluginState is the valid plugin state
        m_pluginRegistered = true;
        m_pluginState = localPluginState;
        return S_OK;
    }

    HRESULT PluginRegistrationManager::CreateVaultPasskey(HWND hWnd, std::wstring const& requestId)
    {
        HRESULT hr = S_OK;
        std::wstring localRequestId = requestId;
        if (localRequestId.empty())
        {
            localRequestId = BuildRequestId(L"vault_recovery");
        }

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
            "\"origin\":\"https://contoso.com\"," 
            "\"crossOrigin\":false}";
        clientData.pbClientDataJSON = reinterpret_cast<BYTE*>(clientDataJson.data());
        clientData.cbClientDataJSON = static_cast<DWORD>(clientDataJson.size());

        WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS webAuthNCredentialOptions = {};
        webAuthNCredentialOptions.dwVersion = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_CURRENT_VERSION;
        webAuthNCredentialOptions.dwTimeoutMilliseconds = 180 * 1000;
        webAuthNCredentialOptions.CredentialList.cCredentials = 0;
        webAuthNCredentialOptions.CredentialList.pCredentials = nullptr;
        webAuthNCredentialOptions.Extensions.cExtensions = 0;
        webAuthNCredentialOptions.Extensions.pExtensions = nullptr;
        webAuthNCredentialOptions.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY;
        webAuthNCredentialOptions.bRequireResidentKey = FALSE;
        webAuthNCredentialOptions.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_PREFERRED;
        webAuthNCredentialOptions.dwAttestationConveyancePreference = WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_ANY;
        webAuthNCredentialOptions.dwFlags = 0;
        // tsupasswd_core保存先ではまず安定動作を優先し、PRF要求は行わない。
        webAuthNCredentialOptions.bEnablePrf = false;
        webAuthNCredentialOptions.pPRFGlobalEval = nullptr;

        UpdatePasskeyOperationStatusText(winrt::hstring{ L"INFO: summary state=running operation=vault_recovery step=open_passkey_prompt request_id=" + localRequestId + L"ℹ" });

        unique_webauthn_credential_attestation pCredentialAttestation = nullptr;
        hr = WebAuthNAuthenticatorMakeCredential(
            hWnd,
            &rpEntity,
            &userEntity,
            &credentialParameters,
            &clientData,
            &webAuthNCredentialOptions,
            &pCredentialAttestation);

        std::wstring makeCredentialResult = L"INFO: summary state=observed operation=vault_recovery step=webauthn_make_credential_returned hr=" + std::to_wstring(static_cast<int>(hr)) + L" request_id=" + localRequestId + L"ℹ";
        UpdatePasskeyOperationStatusText(winrt::hstring{ makeCredentialResult });

        auto pluginLastStatus = wil::reg::try_get_value_dword(
            HKEY_CURRENT_USER,
            c_pluginRegistryPath,
            c_windowsPluginLastMakeCredentialStatusRegKeyName);
        if (pluginLastStatus.has_value())
        {
            std::wstring pluginStatusResult =
                L"INFO: summary state=observed operation=vault_recovery step=plugin_last_make_credential_status hr=" +
                std::to_wstring(static_cast<int>(static_cast<HRESULT>(pluginLastStatus.value()))) +
                L" request_id=" +
                localRequestId +
                L"ℹ";
            UpdatePasskeyOperationStatusText(winrt::hstring{ pluginStatusResult });
        }
        else
        {
            UpdatePasskeyOperationStatusText(winrt::hstring{ L"INFO: summary state=observed operation=vault_recovery step=plugin_last_make_credential_status status=not_written request_id=" + localRequestId + L"ℹ" });
        }

        if (SUCCEEDED(hr))
        {
            DATA_BLOB entropy = {};
            DATA_BLOB* pEntropy = nullptr;
            if (pCredentialAttestation.get()->pHmacSecret != nullptr)
            {
                std::vector<BYTE> hmacSecretInput(
                    pCredentialAttestation.get()->pHmacSecret->pbFirst,
                    pCredentialAttestation.get()->pHmacSecret->pbFirst + pCredentialAttestation.get()->pHmacSecret->cbFirst);
                RETURN_IF_FAILED(SetHMACSecret(hmacSecretInput));
                UpdatePasskeyOperationStatusText(winrt::hstring{ L"SUCCESS: summary result=success operation=vault_recovery step=prf_hmac_secret_stored request_id=" + localRequestId + L"✅" });
                entropy.cbData = pCredentialAttestation.get()->pHmacSecret->cbFirst;
                entropy.pbData = pCredentialAttestation.get()->pHmacSecret->pbFirst;
                pEntropy = &entropy;
            }
            else
            {
                // PRF未対応時は、認証成功そのものをVault解除のゲートとして扱うフォールバックに切替える。
                RETURN_IF_FAILED(SetHMACSecret({}));
                UpdatePasskeyOperationStatusText(winrt::hstring{ L"INFO: summary state=observed operation=vault_recovery step=prf_hmac_secret_missing fallback=non_prf request_id=" + localRequestId + L"ℹ" });
            }

            DATA_BLOB vaultData = {
                .cbData = static_cast<DWORD>(wcslen(c_dummySecretVault) * sizeof(wchar_t)),
                .pbData = reinterpret_cast<BYTE*>(const_cast<PWSTR>(c_dummySecretVault))
            };
            DATA_BLOB cipherText = {};
            RETURN_IF_WIN32_BOOL_FALSE(CryptProtectData(
                &vaultData,
                nullptr,
                pEntropy,
                nullptr,
                nullptr,
                CRYPTPROTECT_UI_FORBIDDEN,
                &cipherText));

            // Use RAII to ensure cipherText.pbData is always freed, even on early returns
            auto cipherTextCleanup = wil::scope_exit([&] {
                if (cipherText.pbData)
                {
                    LocalFree(cipherText.pbData);
                }
            });

            std::vector<BYTE> encryptedVaultData(cipherText.pbData, cipherText.pbData + cipherText.cbData);
            RETURN_IF_FAILED(WriteEncryptedVaultData(encryptedVaultData));

            tsupasswd::SyncSnapshotRecord snapshot{};
            snapshot.SnapshotId = GetNowIsoLikeTimestamp() + L"-local-create";
            snapshot.CapturedAt = GetNowIsoLikeTimestamp();
            snapshot.UserId = syncUserId;
            snapshot.ServerVersion = -1;
            snapshot.Source = L"local-create";
            snapshot.CipherBytes = encryptedVaultData;
            auto hrSnapshot = tsupasswd::SyncSnapshotStore::Append(snapshot);
            if (FAILED(hrSnapshot))
            {
                UpdatePasskeyOperationStatusText(winrt::hstring{ L"INFO: sync result=warning operation=vault_recovery_snapshot_history_append hr=" + std::to_wstring(static_cast<int>(hrSnapshot)) + L" request_id=" + localRequestId + L"ℹ" });
            }

            // Best-effort self-hosted sync. Local success must not be blocked by remote sync failure.
            SyncEncryptedVaultWithRetry(
                encryptedVaultData,
                syncUserId,
                [this](winrt::hstring const& status)
                {
                    UpdatePasskeyOperationStatusText(status);
                });
        }

        std::wstring finalResult = L"INFO: summary state=done operation=vault_recovery step=create_vault_passkey_final hr=" + std::to_wstring(static_cast<int>(hr)) + L" request_id=" + localRequestId + L"ℹ";
        UpdatePasskeyOperationStatusText(winrt::hstring{ finalResult });

        return hr;
    }

    HRESULT PluginRegistrationManager::SetHMACSecret(std::vector<BYTE> hmacSecret)
    {
        // Persist the secret only as a DPAPI-protected blob (never plain text).
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
            return S_OK;
        }

        if (m_hmacSecret != hmacSecret)
        {
            std::vector<BYTE> protectedSecret;
            RETURN_HR_IF(E_FAIL, !ProtectSecretForLocalUser(hmacSecret, protectedSecret));

            wil::unique_hkey hKey;
            RETURN_IF_WIN32_ERROR(RegCreateKeyEx(HKEY_CURRENT_USER, c_pluginRegistryPath, 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr));
            RETURN_IF_WIN32_ERROR(RegSetValueEx(hKey.get(), c_pluginProtectedHMACSecretInput, 0, REG_BINARY, reinterpret_cast<PBYTE>(protectedSecret.data()), wil::safe_cast<DWORD>(protectedSecret.size())));
            LONG deleteLegacy = RegDeleteValue(hKey.get(), c_pluginHMACSecretInput);
            if (deleteLegacy != ERROR_SUCCESS && deleteLegacy != ERROR_FILE_NOT_FOUND)
            {
                RETURN_HR(HRESULT_FROM_WIN32(deleteLegacy));
            }
            m_hmacSecret = hmacSecret;
        }
        return S_OK;
    }

    void PluginRegistrationManager::ReloadRegistryValues()
    {
        std::lock_guard<std::mutex> lock(m_pluginOperationConfigMutex);

        auto protectedOpt = wil::reg::try_get_value_binary(HKEY_CURRENT_USER, c_pluginRegistryPath, c_pluginProtectedHMACSecretInput, REG_BINARY);
        if (protectedOpt.has_value() && !protectedOpt->empty())
        {
            std::vector<BYTE> plainSecret;
            if (UnprotectSecretForLocalUser(protectedOpt.value(), plainSecret))
            {
                m_hmacSecret = std::move(plainSecret);
            }
            return;
        }

        auto legacyOpt = wil::reg::try_get_value_binary(HKEY_CURRENT_USER, c_pluginRegistryPath, c_pluginHMACSecretInput, REG_BINARY);
        if (!legacyOpt.has_value() || legacyOpt->empty())
        {
            return;
        }

        // Migration path from legacy plain-text value.
        m_hmacSecret = legacyOpt.value();
        std::vector<BYTE> protectedSecret;
        if (!ProtectSecretForLocalUser(m_hmacSecret, protectedSecret))
        {
            return;
        }

        wil::unique_hkey hKey;
        if (RegCreateKeyEx(HKEY_CURRENT_USER, c_pluginRegistryPath, 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr) != ERROR_SUCCESS)
        {
            return;
        }
        if (RegSetValueEx(hKey.get(), c_pluginProtectedHMACSecretInput, 0, REG_BINARY, reinterpret_cast<PBYTE>(protectedSecret.data()), wil::safe_cast<DWORD>(protectedSecret.size())) != ERROR_SUCCESS)
        {
            return;
        }
        RegDeleteValue(hKey.get(), c_pluginHMACSecretInput);
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

    HRESULT PluginRegistrationManager::ReadEncryptedVaultData(std::vector<BYTE>& cipherText)
    {
        std::lock_guard<std::mutex> lock(m_pluginOperationConfigMutex);
        cipherText.clear();

        auto opt = wil::reg::try_get_value_binary(HKEY_CURRENT_USER, c_pluginRegistryPath, c_pluginEncryptedVaultData, REG_BINARY);
        if (!opt)
        {
            UpdatePasskeyOperationStatusText(L"WARNING: sync result=failed operation=read_encrypted_vault_data reason=vault_data_missing recovery=recreate_vault_passkey_and_register_again⚠");
            OutputDebugStringW(L"DEBUG: sync result=failed operation=read_encrypted_vault_data reason=vault_data_missing source=registry\n");
            return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
        }

        if (opt->empty())
        {
            UpdatePasskeyOperationStatusText(L"WARNING: sync result=failed operation=read_encrypted_vault_data reason=vault_data_empty_or_corrupt recovery=recreate_vault_passkey_then_retry⚠");
            OutputDebugStringW(L"DEBUG: sync result=failed operation=read_encrypted_vault_data reason=vault_data_empty_or_corrupt\n");
            return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
        }

        std::vector<BYTE> vaultCipher;
        VaultBlobParseResult parseResult = TryExtractVaultCipherWithIntegrity(opt.value(), vaultCipher);
        if (parseResult == VaultBlobParseResult::Invalid)
        {
            UpdatePasskeyOperationStatusText(L"WARNING: sync result=failed operation=read_encrypted_vault_data reason=vault_data_integrity_check_failed recovery=recreate_vault_passkey_then_retry⚠");
            OutputDebugStringW(L"DEBUG: sync result=failed operation=read_encrypted_vault_data reason=vault_data_integrity_check_failed\n");
            return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
        }
        if (parseResult == VaultBlobParseResult::NotFramed)
        {
            vaultCipher = opt.value();
        }

        if (vaultCipher.size() < kMinVaultCipherBlobBytes)
        {
            UpdatePasskeyOperationStatusText(L"WARNING: sync result=failed operation=read_encrypted_vault_data reason=vault_data_too_small_or_corrupt recovery=recreate_vault_passkey_then_retry⚠");
            std::wstring msg = L"DEBUG: sync result=failed operation=read_encrypted_vault_data reason=vault_data_too_small_or_corrupt size=" + std::to_wstring(vaultCipher.size()) + L"\n";
            OutputDebugStringW(msg.c_str());
            return HRESULT_FROM_WIN32(ERROR_FILE_CORRUPT);
        }

        if (vaultCipher.size() > kMaxVaultCipherBlobBytes)
        {
            UpdatePasskeyOperationStatusText(L"WARNING: sync result=failed operation=read_encrypted_vault_data reason=vault_data_too_large_or_unexpected recovery=recreate_vault_passkey_then_retry⚠");
            std::wstring msg = L"DEBUG: sync result=failed operation=read_encrypted_vault_data reason=vault_data_too_large_or_unexpected size=" + std::to_wstring(vaultCipher.size()) + L"\n";
            OutputDebugStringW(msg.c_str());
            return HRESULT_FROM_WIN32(ERROR_FILE_TOO_LARGE);
        }

        cipherText = std::move(vaultCipher);
        return S_OK;
    }

    HRESULT PluginRegistrationManager::ManualResyncSelfHostedVault(std::wstring const& requestId)
    {
        std::wstring localRequestId = requestId;
        if (localRequestId.empty())
        {
            localRequestId = BuildRequestId(L"manual_resync");
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
        RETURN_IF_FAILED(ReadEncryptedVaultData(encryptedVaultData));

        UpdatePasskeyOperationStatusText(winrt::hstring{ L"INFO: sync state=start operation=manual_resync request_id=" + localRequestId + L"ℹ" });
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
        std::wstring localRequestId = requestId;
        if (localRequestId.empty())
        {
            localRequestId = BuildRequestId(L"restore_snapshot");
        }
        std::wstring syncBaseUrl = GetEnvironmentVariableValue(kSyncBaseUrlEnv);
        if (syncBaseUrl.empty())
        {
            UpdatePasskeyOperationStatusText(winrt::hstring{ L"WARNING: sync result=skipped operation=restore_snapshot reason=base_url_missing hr=1 request_id=" + localRequestId + L"⚠" });
            return S_FALSE;
        }

        std::wstring syncUserId = GetEnvironmentVariableValue(kSyncUserIdEnv);
        if (syncUserId.empty())
        {
            syncUserId = kDefaultSyncUserId;
        }

        UpdatePasskeyOperationStatusText(winrt::hstring{ L"INFO: sync state=start operation=restore_snapshot user_id=" + syncUserId + L" request_id=" + localRequestId + L"ℹ" });

        tsupasswd::SyncClient syncClient(syncBaseUrl);
        std::wstring bearerToken = GetEnvironmentVariableValue(kSyncBearerTokenEnv);
        if (!bearerToken.empty())
        {
            syncClient.SetBearerToken(bearerToken);
        }

        tsupasswd::VaultRecord record{};
        tsupasswd::SyncHttpStatus status{};
        HRESULT hr = syncClient.GetVault(syncUserId, record, &status);
        if (FAILED(hr))
        {
            if (hr == HRESULT_FROM_WIN32(ERROR_NOT_FOUND) || status.StatusCode == 404)
            {
                std::wstring warning = L"WARNING: sync result=failed operation=restore_snapshot hr=-2147023728 status=404 reason=snapshot_not_found failure_kind=not_found";
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
                L"WARNING: sync result=failed operation=restore_snapshot hr=" +
                std::to_wstring(static_cast<int>(hr)) +
                L" detail=" + BuildSyncFailureStatusMessage(hr, status);
            if (status.RequestId.empty())
            {
                warning += L" request_id=" + localRequestId;
            }
            UpdatePasskeyOperationStatusText(winrt::hstring{ warning });
            return hr;
        }

        std::vector<BYTE> cipherBytes;
        if (!Base64UrlDecode(record.Blob.CiphertextBase64, cipherBytes))
        {
            UpdatePasskeyOperationStatusText(
                winrt::hstring{
                    L"WARNING: sync result=failed operation=restore_snapshot reason=invalid_ciphertext hr=-2147024883 failure_kind=client_error request_id=" +
                    ResolveRequestId(localRequestId, status) +
                    L"⚠" });
            return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
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
            UpdatePasskeyOperationStatusText(winrt::hstring{ L"INFO: sync result=warning operation=restore_snapshot_snapshot_history_append hr=" + std::to_wstring(static_cast<int>(hrSnapshot)) + L"ℹ" });
        }

        std::wstring success =
            L"SUCCESS: sync result=success operation=restore_snapshot hr=0 bytes=" +
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
