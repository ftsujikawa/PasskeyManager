#include "pch.h"
#include "MainPage.xaml.h"
#include "PluginRegistrationManager.h"
#include "src/SyncClient.h"
#include <CorError.h>
#include <wil/safecast.h>

#pragma comment(lib, "Crypt32.lib")

namespace
{
    constexpr size_t kMinVaultCipherBlobBytes = 16;
    constexpr size_t kMaxVaultCipherBlobBytes = 64 * 1024;
    constexpr wchar_t kSyncBaseUrlEnv[] = L"TSUPASSWD_SYNC_BASE_URL";
    constexpr wchar_t kSyncBearerTokenEnv[] = L"TSUPASSWD_SYNC_BEARER_TOKEN";
    constexpr wchar_t kSyncUserIdEnv[] = L"TSUPASSWD_SYNC_USER_ID";
    constexpr wchar_t kDefaultSyncUserId[] = L"ContosoUserId";

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

    std::wstring BuildSyncFailureStatusMessage(HRESULT hrSync, tsupasswd::SyncHttpStatus const& status)
    {
        std::wstring detail;
        switch (status.StatusCode)
        {
        case 401:
            detail = L"Self-hosted sync failed: unauthorized (401). Check Authorization header format and token setting.";
            break;
        case 403:
            detail = L"Self-hosted sync failed: forbidden (403). Verify TSUPASSWD_SYNC_BEARER_TOKEN matches server token.";
            break;
        case 409:
            detail = L"Self-hosted sync failed: version conflict (409). Try sync again after refreshing latest state.";
            if (status.ServerVersion >= 0)
            {
                detail += L" server_version=" + std::to_wstring(status.ServerVersion);
            }
            break;
        case 429:
            detail = L"Self-hosted sync failed: rate limited (429). Wait about 1 minute, then retry.";
            break;
        default:
            detail = L"Self-hosted sync failed (local save is kept).";
            if (status.StatusCode > 0)
            {
                detail += L" status=" + std::to_wstring(status.StatusCode) + L".";
            }
            break;
        }

        if (!status.ErrorCode.empty())
        {
            detail += L" code=" + status.ErrorCode + L".";
        }
        if (!status.ErrorMessage.empty())
        {
            detail += L" message=" + status.ErrorMessage + L".";
        }

        detail += L" hr=" + std::to_wstring(static_cast<int>(hrSync));
        return detail;
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

    HRESULT PluginRegistrationManager::CreateVaultPasskey(HWND hWnd)
    {
        HRESULT hr = S_OK;

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

        UpdatePasskeyOperationStatusText(L"INFO: Opening passkey prompt. If 'Something went wrong' appears, complete or cancel and check the next HRESULT log.ℹ");

        unique_webauthn_credential_attestation pCredentialAttestation = nullptr;
        hr = WebAuthNAuthenticatorMakeCredential(
            hWnd,
            &rpEntity,
            &userEntity,
            &credentialParameters,
            &clientData,
            &webAuthNCredentialOptions,
            &pCredentialAttestation);

        std::wstring makeCredentialResult = L"INFO: WebAuthNAuthenticatorMakeCredential returned: " + std::to_wstring(static_cast<int>(hr)) + L"ℹ";
        UpdatePasskeyOperationStatusText(winrt::hstring{ makeCredentialResult });

        auto pluginLastStatus = wil::reg::try_get_value_dword(
            HKEY_CURRENT_USER,
            c_pluginRegistryPath,
            c_windowsPluginLastMakeCredentialStatusRegKeyName);
        if (pluginLastStatus.has_value())
        {
            std::wstring pluginStatusResult =
                L"INFO: Plugin LastMakeCredentialStatus: " +
                std::to_wstring(static_cast<int>(static_cast<HRESULT>(pluginLastStatus.value()))) +
                L"ℹ";
            UpdatePasskeyOperationStatusText(winrt::hstring{ pluginStatusResult });
        }
        else
        {
            UpdatePasskeyOperationStatusText(L"INFO: Plugin LastMakeCredentialStatus: <not written>ℹ");
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
                UpdatePasskeyOperationStatusText(L"SUCCESS: PRF/HMAC secret returned and stored.✅");
                entropy.cbData = pCredentialAttestation.get()->pHmacSecret->cbFirst;
                entropy.pbData = pCredentialAttestation.get()->pHmacSecret->pbFirst;
                pEntropy = &entropy;
            }
            else
            {
                // PRF未対応時は、認証成功そのものをVault解除のゲートとして扱うフォールバックに切替える。
                RETURN_IF_FAILED(SetHMACSecret({}));
                UpdatePasskeyOperationStatusText(L"INFO: PRF/HMAC secret was not returned. Using non-PRF vault protection fallback.ℹ");
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

            // Best-effort self-hosted sync. Local success must not be blocked by remote sync failure.
            std::wstring syncBaseUrl = GetEnvironmentVariableValue(kSyncBaseUrlEnv);
            if (syncBaseUrl.empty())
            {
                UpdatePasskeyOperationStatusText(L"INFO: Self-hosted sync skipped (TSUPASSWD_SYNC_BASE_URL is not set).ℹ");
            }
            else
            {
                UpdatePasskeyOperationStatusText(
                    winrt::hstring{ L"INFO: Self-hosted sync user_id: " + syncUserId + L"ℹ" });

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

                tsupasswd::PutVaultResponse putResponse{};
                tsupasswd::SyncHttpStatus syncStatus{};
                HRESULT hrSync = syncClient.PutVault(syncUserId, putRequest, putResponse, &syncStatus);
                if (hrSync == HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH) && syncStatus.ServerVersion >= 0)
                {
                    putRequest.ExpectedVersion = syncStatus.ServerVersion;
                    putRequest.NewVersion = syncStatus.ServerVersion + 1;
                    UpdatePasskeyOperationStatusText(
                        winrt::hstring{
                            L"INFO: Self-hosted sync version conflict detected. Retrying once with server_version=" +
                            std::to_wstring(syncStatus.ServerVersion) + L"...ℹ" });

                    tsupasswd::SyncHttpStatus retryStatus{};
                    hrSync = syncClient.PutVault(syncUserId, putRequest, putResponse, &retryStatus);
                    syncStatus = retryStatus;
                }

                if (SUCCEEDED(hrSync))
                {
                    UpdatePasskeyOperationStatusText(L"SUCCESS: Self-hosted vault sync completed.✅");
                }
                else
                {
                    std::wstring syncWarning = L"WARNING: " + BuildSyncFailureStatusMessage(hrSync, syncStatus);
                    UpdatePasskeyOperationStatusText(winrt::hstring{ syncWarning });
                }
            }
        }

        std::wstring finalResult = L"INFO: CreateVaultPasskey final HRESULT: " + std::to_wstring(static_cast<int>(hr)) + L"ℹ";
        UpdatePasskeyOperationStatusText(winrt::hstring{ finalResult });

        return hr;
    }

    HRESULT PluginRegistrationManager::SetHMACSecret(std::vector<BYTE> hmacSecret)
    {
        // This function saves the random HMAC secret generated in plain text.
        // In a real application, the HMAC secret is either retrieved from the server or may be user supplied
        // or saved in encrypted form.
        std::lock_guard<std::mutex> lock(m_pluginOperationConfigMutex);
        if (hmacSecret.empty())
        {
            wil::unique_hkey hKey;
            RETURN_IF_WIN32_ERROR(RegCreateKeyEx(HKEY_CURRENT_USER, c_pluginRegistryPath, 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr));
            LONG deleteResult = RegDeleteValue(hKey.get(), c_pluginHMACSecretInput);
            if (deleteResult != ERROR_SUCCESS && deleteResult != ERROR_FILE_NOT_FOUND)
            {
                RETURN_HR(HRESULT_FROM_WIN32(deleteResult));
            }
            m_hmacSecret.clear();
            return S_OK;
        }

        if (m_hmacSecret != hmacSecret)
        {
            wil::unique_hkey hKey;
            RETURN_IF_WIN32_ERROR(RegCreateKeyEx(HKEY_CURRENT_USER, c_pluginRegistryPath, 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr));
            RETURN_IF_WIN32_ERROR(RegSetValueEx(hKey.get(), c_pluginHMACSecretInput, 0, REG_BINARY, reinterpret_cast<PBYTE>(hmacSecret.data()), wil::safe_cast<DWORD>(hmacSecret.size())));
            m_hmacSecret = hmacSecret;
        }
        return S_OK;
    }

    HRESULT PluginRegistrationManager::WriteEncryptedVaultData(std::vector<BYTE> cipherText)
    {
        std::lock_guard<std::mutex> lock(m_pluginOperationConfigMutex);
        wil::unique_hkey hKey;
        RETURN_IF_WIN32_ERROR(RegCreateKeyEx(HKEY_CURRENT_USER, c_pluginRegistryPath, 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr));
        RETURN_IF_WIN32_ERROR(RegSetValueEx(hKey.get(), c_pluginEncryptedVaultData, 0, REG_BINARY, reinterpret_cast<PBYTE>(cipherText.data()), wil::safe_cast<DWORD>(cipherText.size())));
        return S_OK;
    }

    HRESULT PluginRegistrationManager::ReadEncryptedVaultData(std::vector<BYTE>& cipherText)
    {
        std::lock_guard<std::mutex> lock(m_pluginOperationConfigMutex);
        cipherText.clear();

        auto opt = wil::reg::try_get_value_binary(HKEY_CURRENT_USER, c_pluginRegistryPath, c_pluginEncryptedVaultData, REG_BINARY);
        if (!opt)
        {
            UpdatePasskeyOperationStatusText(L"WARNING: Vault data is missing. Recovery: set Vault Unlock to Passkey and register again.");
            OutputDebugStringW(L"PluginRegistrationManager::ReadEncryptedVaultData - no EncryptedVaultData in registry.\n");
            return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
        }

        if (opt->empty())
        {
            UpdatePasskeyOperationStatusText(L"WARNING: Vault data is empty/corrupted. Recovery: re-create Vault Unlock passkey then retry.");
            OutputDebugStringW(L"PluginRegistrationManager::ReadEncryptedVaultData - EncryptedVaultData is empty.\n");
            return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
        }

        if (opt->size() < kMinVaultCipherBlobBytes)
        {
            UpdatePasskeyOperationStatusText(L"WARNING: Vault data is too small/corrupted. Recovery: re-create Vault Unlock passkey then retry.");
            std::wstring msg = L"PluginRegistrationManager::ReadEncryptedVaultData - EncryptedVaultData is too small. size=" + std::to_wstring(opt->size()) + L"\n";
            OutputDebugStringW(msg.c_str());
            return HRESULT_FROM_WIN32(ERROR_FILE_CORRUPT);
        }

        if (opt->size() > kMaxVaultCipherBlobBytes)
        {
            UpdatePasskeyOperationStatusText(L"WARNING: Vault data is too large/unexpected. Recovery: re-create Vault Unlock passkey then retry.");
            std::wstring msg = L"PluginRegistrationManager::ReadEncryptedVaultData - EncryptedVaultData is too large. size=" + std::to_wstring(opt->size()) + L"\n";
            OutputDebugStringW(msg.c_str());
            return HRESULT_FROM_WIN32(ERROR_FILE_TOO_LARGE);
        }

        cipherText = opt.value();
        return S_OK;
    }
}
