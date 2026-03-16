#include "pch.h"
#include "NativeMessagingHost.h"

#include "PluginManagement/PluginCredentialManager.h"
#include "PluginManagement/PluginRegistrationManager.h"
#include "src/RequestId.h"
#include "src/VaultCrypto.h"
#include "src/VaultSerialization.h"
#include <algorithm>
#include <string>
#include <vector>
#include <winrt/Windows.Data.Json.h>

namespace
{
    using namespace winrt::Windows::Data::Json;
    using winrt::PasskeyManager::implementation::PluginCredentialManager;
    using winrt::PasskeyManager::implementation::PluginRegistrationManager;

    constexpr wchar_t kVaultRecoveryCodeEnv[] = L"TSUPASSWD_VAULT_RECOVERY_CODE";
    constexpr wchar_t kSyncBaseUrlEnv[] = L"TSUPASSWD_SYNC_BASE_URL";
    constexpr wchar_t kSyncUserIdEnv[] = L"TSUPASSWD_SYNC_USER_ID";
    constexpr wchar_t kNativeHostFlag[] = L"--native-messaging-host";

    bool IsPipeHandle(HANDLE handle)
    {
        if (handle == nullptr || handle == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        DWORD type = GetFileType(handle);
        return type == FILE_TYPE_PIPE;
    }

    std::wstring GetEnvironmentVariableValue(wchar_t const* name)
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
                while (!value.empty() && value.back() == L'\0')
                {
                    value.pop_back();
                }
                return value;
            }
        }

        HKEY hKey = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Environment", 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        {
            return L"";
        }

        auto cleanup = wil::scope_exit([&]() {
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

    void AppendPersistentSyncDiagnosticLog(std::wstring const& message)
    {
        std::wstring appDataRoot = GetEnvironmentVariableValue(L"LOCALAPPDATA");
        if (appDataRoot.empty())
        {
            return;
        }

        std::wstring logDirectory = appDataRoot + L"\\tsupasswd";
        std::wstring logPath = logDirectory + L"\\sync-diagnostic.log";
        CreateDirectoryW(logDirectory.c_str(), nullptr);

        HANDLE handle = CreateFileW(
            logPath.c_str(),
            FILE_APPEND_DATA,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (handle == INVALID_HANDLE_VALUE)
        {
            return;
        }

        std::string utf8 = winrt::to_string(winrt::hstring{ message });
        DWORD written = 0;
        WriteFile(handle, utf8.data(), static_cast<DWORD>(utf8.size()), &written, nullptr);
        CloseHandle(handle);
    }

    bool TryGetString(JsonObject const& obj, wchar_t const* key, std::wstring& out)
    {
        if (!obj.HasKey(key))
        {
            return false;
        }
        auto value = obj.GetNamedValue(key, nullptr);
        if (!value || value.ValueType() != JsonValueType::String)
        {
            return false;
        }
        out = value.GetString().c_str();
        return true;
    }

    bool TryGetBool(JsonObject const& obj, wchar_t const* key, bool& out)
    {
        if (!obj.HasKey(key))
        {
            return false;
        }
        auto value = obj.GetNamedValue(key, nullptr);
        if (!value || value.ValueType() != JsonValueType::Boolean)
        {
            return false;
        }
        out = value.GetBoolean();
        return true;
    }

    std::wstring HResultToErrorCode(HRESULT hr)
    {
        switch (hr)
        {
        case S_OK:
            return L"ok";
        case E_INVALIDARG:
            return L"invalid_request";
        case HRESULT_FROM_WIN32(ERROR_NOT_FOUND):
            return L"not_found";
        case HRESULT_FROM_WIN32(ERROR_NOT_READY):
            return L"recovery_code_missing";
        case HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED):
            return L"vault_locked";
        case HRESULT_FROM_WIN32(ERROR_ACCESS_DISABLED_BY_POLICY):
            return L"sync_not_configured";
        default:
            return L"internal_error";
        }
    }

    std::wstring HResultToMessage(HRESULT hr)
    {
        switch (hr)
        {
        case E_INVALIDARG:
            return L"Invalid request payload";
        case HRESULT_FROM_WIN32(ERROR_NOT_FOUND):
            return L"Requested item was not found";
        case HRESULT_FROM_WIN32(ERROR_NOT_READY):
            return L"Recovery code is not configured";
        case HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED):
            return L"Vault access was denied";
        case HRESULT_FROM_WIN32(ERROR_ACCESS_DISABLED_BY_POLICY):
            return L"Sync is not configured or blocked by policy";
        default:
            return L"Internal error";
        }
    }

    JsonObject BuildErrorObject(HRESULT hr)
    {
        JsonObject error;
        error.SetNamedValue(L"code", JsonValue::CreateStringValue(HResultToErrorCode(hr)));
        error.SetNamedValue(L"message", JsonValue::CreateStringValue(HResultToMessage(hr)));
        error.SetNamedValue(L"retryable", JsonValue::CreateBooleanValue(false));
        JsonObject details;
        details.SetNamedValue(L"hresult", JsonValue::CreateNumberValue(static_cast<double>(hr)));
        error.SetNamedValue(L"details", details);
        return error;
    }

    JsonObject BuildSuccessResponse(std::wstring const& id, JsonObject const& result)
    {
        JsonObject response;
        response.SetNamedValue(L"id", JsonValue::CreateStringValue(id));
        response.SetNamedValue(L"version", JsonValue::CreateNumberValue(1));
        response.SetNamedValue(L"ok", JsonValue::CreateBooleanValue(true));
        response.SetNamedValue(L"result", result);
        response.SetNamedValue(L"error", JsonValue::CreateNullValue());
        return response;
    }

    JsonObject BuildErrorResponse(std::wstring const& id, HRESULT hr)
    {
        JsonObject response;
        response.SetNamedValue(L"id", JsonValue::CreateStringValue(id));
        response.SetNamedValue(L"version", JsonValue::CreateNumberValue(1));
        response.SetNamedValue(L"ok", JsonValue::CreateBooleanValue(false));
        response.SetNamedValue(L"result", JsonValue::CreateNullValue());
        response.SetNamedValue(L"error", BuildErrorObject(hr));
        return response;
    }

    HRESULT TryLoadVaultDocument(tsupasswd::VaultDocumentV1& outDoc, std::wstring const& requestId)
    {
        outDoc = {};
        std::vector<BYTE> cipherText;
        HRESULT hrRead = PluginRegistrationManager::getInstance().ReadEncryptedVaultData(cipherText, requestId);
        if (FAILED(hrRead))
        {
            return hrRead;
        }

        std::wstring recoveryCode = GetEnvironmentVariableValue(kVaultRecoveryCodeEnv);
        if (recoveryCode.empty())
        {
            return HRESULT_FROM_WIN32(ERROR_NOT_READY);
        }

        std::string utf8 = winrt::to_string(winrt::hstring{ recoveryCode });
        std::vector<uint8_t> recoveryBytes(utf8.begin(), utf8.end());
        if (recoveryBytes.empty())
        {
            return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
        }

        tsupasswd::VaultCryptoError cryptoError{};
        std::vector<uint8_t> plainBytes;
        if (!tsupasswd::DecryptVaultV3(cipherText, recoveryBytes, plainBytes, cryptoError))
        {
            return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
        }

        std::wstring decryptedJson = winrt::to_hstring(std::string(reinterpret_cast<char const*>(plainBytes.data()), plainBytes.size())).c_str();
        std::wstring parseError;
        if (!tsupasswd::DeserializeVaultDocumentV1(decryptedJson, outDoc, parseError))
        {
            return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
        }

        return S_OK;
    }

    JsonObject BuildVaultItemJson(tsupasswd::VaultItemV1 const& item, bool includeSecret)
    {
        JsonObject json;
        json.SetNamedValue(L"itemId", JsonValue::CreateStringValue(item.ItemId));
        json.SetNamedValue(L"title", JsonValue::CreateStringValue(item.Title));
        json.SetNamedValue(L"username", JsonValue::CreateStringValue(item.Login.Username));
        json.SetNamedValue(L"url", JsonValue::CreateStringValue(item.Login.Url));
        json.SetNamedValue(L"notes", JsonValue::CreateStringValue(item.Notes));
        json.SetNamedValue(L"createdAt", JsonValue::CreateStringValue(item.CreatedAt));
        json.SetNamedValue(L"updatedAt", JsonValue::CreateStringValue(item.UpdatedAt));
        json.SetNamedValue(L"deleted", JsonValue::CreateBooleanValue(item.Deleted));
        if (includeSecret)
        {
            json.SetNamedValue(L"password", JsonValue::CreateStringValue(item.Login.Password));
        }
        return json;
    }

    HRESULT HandleStatus(JsonObject const&, std::wstring const&, JsonObject& outResult)
    {
        auto& credMgr = PluginCredentialManager::getInstance();
        JsonObject result;
        result.SetNamedValue(L"vaultLocked", JsonValue::CreateBooleanValue(credMgr.GetVaultLock()));
        result.SetNamedValue(L"silentOperation", JsonValue::CreateBooleanValue(credMgr.GetSilentOperation()));
        result.SetNamedValue(L"recoveryCodeAvailable", JsonValue::CreateBooleanValue(!GetEnvironmentVariableValue(kVaultRecoveryCodeEnv).empty()));
        bool syncConfigured = !GetEnvironmentVariableValue(kSyncBaseUrlEnv).empty() && !GetEnvironmentVariableValue(kSyncUserIdEnv).empty();
        result.SetNamedValue(L"syncConfigured", JsonValue::CreateBooleanValue(syncConfigured));
        result.SetNamedValue(L"uiRequired", JsonValue::CreateBooleanValue(credMgr.GetVaultLock()));
        outResult = result;
        return S_OK;
    }

    HRESULT HandleList(JsonObject const& payload, std::wstring const& requestId, JsonObject& outResult)
    {
        bool includeDeleted = false;
        (void)TryGetBool(payload, L"includeDeleted", includeDeleted);

        tsupasswd::VaultDocumentV1 vaultDoc{};
        HRESULT hr = TryLoadVaultDocument(vaultDoc, requestId);
        if (FAILED(hr))
        {
            return hr;
        }

        JsonArray items;
        for (auto const& item : vaultDoc.Items)
        {
            if (item.ItemType != tsupasswd::VaultItemType::Login)
            {
                continue;
            }
            if (!includeDeleted && item.Deleted)
            {
                continue;
            }
            items.Append(BuildVaultItemJson(item, false));
        }

        JsonObject result;
        result.SetNamedValue(L"items", items);
        outResult = result;
        return S_OK;
    }

    HRESULT HandleGet(JsonObject const& payload, std::wstring const& requestId, JsonObject& outResult)
    {
        std::wstring itemId;
        RETURN_HR_IF(E_INVALIDARG, !TryGetString(payload, L"itemId", itemId) || itemId.empty());
        bool includeSecret = false;
        (void)TryGetBool(payload, L"includeSecret", includeSecret);

        tsupasswd::VaultItemV1 item{};
        HRESULT hr = PluginCredentialManager::getInstance().GetVaultLoginItemById(itemId, item, requestId);
        if (FAILED(hr))
        {
            return hr;
        }

        JsonObject result;
        result.SetNamedValue(L"item", BuildVaultItemJson(item, includeSecret));
        outResult = result;
        return S_OK;
    }

    HRESULT HandleSave(JsonObject const& payload, std::wstring const& requestId, JsonObject& outResult)
    {
        AppendPersistentSyncDiagnosticLog(
            L"INFO: sync state=running operation=native_host_save step=enter request_id=" + requestId + L"\n");
        std::wstring title;
        std::wstring username;
        std::wstring password;
        std::wstring url;
        std::wstring notes;
        bool resync = true;
        RETURN_HR_IF(E_INVALIDARG, !TryGetString(payload, L"title", title));
        RETURN_HR_IF(E_INVALIDARG, !TryGetString(payload, L"username", username));
        RETURN_HR_IF(E_INVALIDARG, !TryGetString(payload, L"password", password));
        (void)TryGetString(payload, L"url", url);
        (void)TryGetString(payload, L"notes", notes);
        (void)TryGetBool(payload, L"resync", resync);

        AppendPersistentSyncDiagnosticLog(
            L"INFO: sync state=running operation=native_host_save step=before_plugin_save resync=" + std::wstring(resync ? L"true" : L"false") +
            L" request_id=" + requestId + L"\n");
        HRESULT hr = PluginCredentialManager::getInstance().SaveLoginItemToVaultWithPasskey(nullptr, title, username, password, url, notes, requestId, resync);
        if (FAILED(hr))
        {
            AppendPersistentSyncDiagnosticLog(
                L"WARNING: sync result=failed operation=native_host_save step=plugin_save_failed hr=" + std::to_wstring(static_cast<int>(hr)) +
                L" request_id=" + requestId + L"\n");
            return hr;
        }

        AppendPersistentSyncDiagnosticLog(
            L"SUCCESS: sync result=success operation=native_host_save step=plugin_save_completed request_id=" + requestId + L"\n");

        tsupasswd::VaultDocumentV1 vaultDoc{};
        hr = TryLoadVaultDocument(vaultDoc, requestId + L"-after-save");
        if (FAILED(hr))
        {
            AppendPersistentSyncDiagnosticLog(
                L"WARNING: sync result=failed operation=native_host_save step=load_after_save_failed hr=" + std::to_wstring(static_cast<int>(hr)) +
                L" request_id=" + requestId + L"\n");
            return hr;
        }

        std::wstring savedItemId;
        for (auto it = vaultDoc.Items.rbegin(); it != vaultDoc.Items.rend(); ++it)
        {
            if (it->ItemType == tsupasswd::VaultItemType::Login && !it->Deleted)
            {
                if (it->Title == title && it->Login.Username == username && it->Login.Url == url)
                {
                    savedItemId = it->ItemId;
                    break;
                }
            }
        }

        JsonObject result;
        result.SetNamedValue(L"itemId", JsonValue::CreateStringValue(savedItemId));
        result.SetNamedValue(L"saved", JsonValue::CreateBooleanValue(true));
        result.SetNamedValue(L"synced", JsonValue::CreateBooleanValue(resync));
        outResult = result;
        AppendPersistentSyncDiagnosticLog(
            L"SUCCESS: sync result=success operation=native_host_save step=completed request_id=" + requestId + L"\n");
        return S_OK;
    }

    HRESULT HandleUpdate(JsonObject const& payload, std::wstring const& requestId, JsonObject& outResult)
    {
        AppendPersistentSyncDiagnosticLog(
            L"INFO: sync state=running operation=native_host_update step=enter request_id=" + requestId + L"\n");
        std::wstring itemId;
        std::wstring title;
        std::wstring username;
        std::wstring password;
        std::wstring url;
        std::wstring notes;
        bool resync = true;
        RETURN_HR_IF(E_INVALIDARG, !TryGetString(payload, L"itemId", itemId) || itemId.empty());
        RETURN_HR_IF(E_INVALIDARG, !TryGetString(payload, L"title", title));
        RETURN_HR_IF(E_INVALIDARG, !TryGetString(payload, L"username", username));
        RETURN_HR_IF(E_INVALIDARG, !TryGetString(payload, L"password", password));
        (void)TryGetString(payload, L"url", url);
        (void)TryGetString(payload, L"notes", notes);
        (void)TryGetBool(payload, L"resync", resync);

        HRESULT hr = PluginCredentialManager::getInstance().UpdateVaultLoginItemById(itemId, title, username, password, url, notes, requestId, resync);
        if (FAILED(hr))
        {
            return hr;
        }

        JsonObject result;
        result.SetNamedValue(L"itemId", JsonValue::CreateStringValue(itemId));
        result.SetNamedValue(L"updated", JsonValue::CreateBooleanValue(true));
        result.SetNamedValue(L"synced", JsonValue::CreateBooleanValue(resync));
        outResult = result;
        return S_OK;
    }

    HRESULT HandleDelete(JsonObject const& payload, std::wstring const& requestId, JsonObject& outResult)
    {
        std::wstring itemId;
        bool resync = true;
        RETURN_HR_IF(E_INVALIDARG, !TryGetString(payload, L"itemId", itemId) || itemId.empty());
        (void)TryGetBool(payload, L"resync", resync);

        HRESULT hr = PluginCredentialManager::getInstance().DeleteVaultLoginItemById(itemId, requestId, resync);
        if (FAILED(hr))
        {
            return hr;
        }

        JsonObject result;
        result.SetNamedValue(L"itemId", JsonValue::CreateStringValue(itemId));
        result.SetNamedValue(L"deleted", JsonValue::CreateBooleanValue(true));
        result.SetNamedValue(L"synced", JsonValue::CreateBooleanValue(resync));
        outResult = result;
        return S_OK;
    }

    HRESULT HandleResync(JsonObject const&, std::wstring const& requestId, JsonObject& outResult)
    {
        HRESULT hr = PluginRegistrationManager::getInstance().ManualResyncSelfHostedVault(requestId);
        if (FAILED(hr))
        {
            return hr;
        }

        JsonObject merge;
        merge.SetNamedValue(L"addedFromServer", JsonValue::CreateNumberValue(0));
        merge.SetNamedValue(L"updatedFromServer", JsonValue::CreateNumberValue(0));
        merge.SetNamedValue(L"tombstonesApplied", JsonValue::CreateNumberValue(0));
        merge.SetNamedValue(L"duplicatesCollapsed", JsonValue::CreateNumberValue(0));

        JsonObject result;
        result.SetNamedValue(L"synced", JsonValue::CreateBooleanValue(true));
        result.SetNamedValue(L"merge", merge);
        outResult = result;
        return S_OK;
    }

    HRESULT DispatchCommand(JsonObject const& request, JsonObject& response)
    {
        std::wstring id = tsupasswd::BuildRequestId(L"native_host");
        (void)TryGetString(request, L"id", id);

        std::wstring command;
        if (!TryGetString(request, L"command", command) || command.empty())
        {
            response = BuildErrorResponse(id, E_INVALIDARG);
            return E_INVALIDARG;
        }

        JsonObject payload;
        auto payloadValue = request.GetNamedValue(L"payload", nullptr);
        if (payloadValue && payloadValue.ValueType() == JsonValueType::Object)
        {
            payload = payloadValue.GetObjectW();
        }

        JsonObject result;
        HRESULT hr = E_NOTIMPL;
        if (command == L"vault.status.get")
        {
            hr = HandleStatus(payload, id, result);
        }
        else if (command == L"vault.login.list")
        {
            hr = HandleList(payload, id, result);
        }
        else if (command == L"vault.login.get")
        {
            hr = HandleGet(payload, id, result);
        }
        else if (command == L"vault.login.save")
        {
            hr = HandleSave(payload, id, result);
        }
        else if (command == L"vault.login.update")
        {
            hr = HandleUpdate(payload, id, result);
        }
        else if (command == L"vault.login.delete")
        {
            hr = HandleDelete(payload, id, result);
        }
        else if (command == L"vault.sync.resync")
        {
            hr = HandleResync(payload, id, result);
        }

        if (SUCCEEDED(hr))
        {
            response = BuildSuccessResponse(id, result);
        }
        else
        {
            response = BuildErrorResponse(id, hr == E_NOTIMPL ? HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED) : hr);
        }
        return hr;
    }

    bool ReadExact(HANDLE handle, void* buffer, DWORD size)
    {
        BYTE* cursor = static_cast<BYTE*>(buffer);
        DWORD remaining = size;
        while (remaining > 0)
        {
            DWORD read = 0;
            if (!ReadFile(handle, cursor, remaining, &read, nullptr) || read == 0)
            {
                return false;
            }
            cursor += read;
            remaining -= read;
        }
        return true;
    }

    bool WriteExact(HANDLE handle, void const* buffer, DWORD size)
    {
        BYTE const* cursor = static_cast<BYTE const*>(buffer);
        DWORD remaining = size;
        while (remaining > 0)
        {
            DWORD written = 0;
            if (!WriteFile(handle, cursor, remaining, &written, nullptr) || written == 0)
            {
                return false;
            }
            cursor += written;
            remaining -= written;
        }
        return true;
    }
}

namespace tsupasswd
{
    bool IsNativeMessagingHostMode(std::wstring const& args)
    {
        if (args.find(kNativeHostFlag) != std::wstring::npos)
        {
            return true;
        }

        HANDLE stdinHandle = GetStdHandle(STD_INPUT_HANDLE);
        HANDLE stdoutHandle = GetStdHandle(STD_OUTPUT_HANDLE);
        return IsPipeHandle(stdinHandle) && IsPipeHandle(stdoutHandle);
    }

    int RunNativeMessagingHost(std::wstring const&)
    {
        PluginCredentialManager::getInstance();
        PluginRegistrationManager::getInstance();

        HANDLE stdinHandle = GetStdHandle(STD_INPUT_HANDLE);
        HANDLE stdoutHandle = GetStdHandle(STD_OUTPUT_HANDLE);
        if (stdinHandle == INVALID_HANDLE_VALUE || stdoutHandle == INVALID_HANDLE_VALUE)
        {
            return 1;
        }

        while (true)
        {
            uint32_t messageSize = 0;
            if (!ReadExact(stdinHandle, &messageSize, sizeof(messageSize)))
            {
                break;
            }
            if (messageSize == 0 || messageSize > (16u * 1024u * 1024u))
            {
                return 2;
            }

            std::string requestUtf8(messageSize, '\0');
            if (!ReadExact(stdinHandle, requestUtf8.data(), messageSize))
            {
                return 3;
            }

            JsonObject response;
            try
            {
                std::wstring requestWide = winrt::to_hstring(requestUtf8).c_str();
                auto request = JsonObject::Parse(requestWide);
                (void)DispatchCommand(request, response);
            }
            catch (...)
            {
                response = BuildErrorResponse(tsupasswd::BuildRequestId(L"native_host_parse"), E_INVALIDARG);
            }

            std::string responseUtf8 = winrt::to_string(response.Stringify());
            uint32_t responseSize = static_cast<uint32_t>(responseUtf8.size());
            if (!WriteExact(stdoutHandle, &responseSize, sizeof(responseSize)) ||
                !WriteExact(stdoutHandle, responseUtf8.data(), responseSize))
            {
                return 4;
            }
        }

        return 0;
    }
}
