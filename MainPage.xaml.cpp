#include "pch.h"
#include "MainPage.xaml.h"
#if __has_include("MainPage.g.cpp")
#include "MainPage.g.cpp"
#include "App.xaml.h"
#include <ncrypt.h>
#include "Credential.h"
#endif
#include "PluginManagement/PluginRegistrationManager.h"
#include "PluginManagement/PluginCredentialManager.h"
#include "PluginAuthenticator/PluginAuthenticatorImpl.h"
#include "src/SyncHistoryStore.h"
#include "src/SyncClient.h"
#include <future>
#include <coroutine>
#include <thread>
#include <chrono>
#include <DispatcherQueue.h>
#include <winrt/Microsoft.ui.interop.h>
#include <winrt/Microsoft.UI.Content.h>
#include <winrt/Windows.Security.Credentials.UI.h>
#include <winrt/Windows.ApplicationModel.DataTransfer.h>

namespace winrt {
    using namespace winrt::Microsoft::UI::Xaml;
}

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace {
    constexpr wchar_t kSyncBaseUrlEnv[] = L"TSUPASSWD_SYNC_BASE_URL";
    constexpr wchar_t kSyncBearerTokenEnv[] = L"TSUPASSWD_SYNC_BEARER_TOKEN";
    constexpr wchar_t kSyncUserIdEnv[] = L"TSUPASSWD_SYNC_USER_ID";

    std::wstring DescribeCredentialOperationFailure(HRESULT hr)
    {
        if (hr == NTE_EXISTS || hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS))
        {
            return L"credential_already_present_in_cache";
        }
        if (hr == HRESULT_FROM_WIN32(ERROR_NOT_FOUND))
        {
            return L"no_credentials_available_to_sync";
        }
        if (hr == E_NOT_VALID_STATE)
        {
            return L"vault_locked_or_ui_unlock_required";
        }
        if (hr == HRESULT_FROM_WIN32(ERROR_WRITE_FAULT))
        {
            return L"credential_store_update_failed";
        }
        if (hr == E_INVALIDARG)
        {
            return L"invalid_credential_selection";
        }
        return L"unexpected_credential_operation_failure";
    }

    std::wstring TrimCopy(std::wstring value)
    {
        auto first = value.find_first_not_of(L" \t\r\n");
        if (first == std::wstring::npos)
        {
            return L"";
        }
        auto last = value.find_last_not_of(L" \t\r\n");
        return value.substr(first, last - first + 1);
    }

    std::wstring GetProcessEnvironmentValue(wchar_t const* name)
    {
        DWORD needed = GetEnvironmentVariableW(name, nullptr, 0);
        if (needed == 0)
        {
            return L"";
        }

        std::wstring value;
        value.resize(needed);
        DWORD written = GetEnvironmentVariableW(name, value.data(), needed);
        if (written == 0)
        {
            return L"";
        }

        value.resize(written);
        return value;
    }

    std::wstring InferHistoryResult(std::wstring const& rawLine)
    {
        if (rawLine.rfind(L"SUCCESS:", 0) == 0)
        {
            return L"success";
        }
        if (rawLine.rfind(L"FAILED:", 0) == 0)
        {
            return L"failed";
        }
        if (rawLine.rfind(L"WARNING:", 0) == 0)
        {
            return L"warning";
        }
        if (rawLine.rfind(L"INFO:", 0) == 0)
        {
            return L"info";
        }
        return L"unknown";
    }

    std::wstring InferHistoryOperation(std::wstring const& rawLine)
    {
        if (rawLine.find(L"Snapshot") != std::wstring::npos)
        {
            return L"snapshot";
        }
        if (rawLine.find(L"Queue") != std::wstring::npos)
        {
            return L"queue";
        }
        if (rawLine.find(L"sync") != std::wstring::npos || rawLine.find(L"Self-hosted") != std::wstring::npos)
        {
            return L"sync";
        }
        return L"general";
    }

    std::wstring BuildHistoryTimestamp()
    {
        std::time_t raw = std::time(nullptr);
        std::tm tmLocal{};
        localtime_s(&tmLocal, &raw);
        wchar_t buffer[32]{};
        wcsftime(buffer, ARRAYSIZE(buffer), L"%Y-%m-%d %H:%M:%S", &tmLocal);
        return buffer;
    }

    std::wstring BuildSnapshotCandidateLabel(tsupasswd::SyncSnapshotRecord const& snapshot)
    {
        std::wstring label = snapshot.CapturedAt;
        if (label.empty())
        {
            label = snapshot.SnapshotId;
        }

        label += L" | source=" + snapshot.Source;
        if (!snapshot.UserId.empty())
        {
            label += L" | user=" + snapshot.UserId;
        }
        if (snapshot.ServerVersion >= 0)
        {
            label += L" | v=" + std::to_wstring(snapshot.ServerVersion);
        }
        label += L" | bytes=" + std::to_wstring(snapshot.CipherBytes.size());
        return label;
    }

    bool IsSyncRetryDetailLine(std::wstring const& line)
    {
        return line.rfind(L"INFO: Self-hosted sync user_id:", 0) == 0 ||
            line.rfind(L"INFO: Self-hosted sync version conflict detected.", 0) == 0 ||
            line.rfind(L"INFO: Self-hosted sync retry ", 0) == 0;
    }

    std::wstring GetUserEnvironmentRegistryValue(wchar_t const* name)
    {
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

    std::wstring ReadSyncSettingValue(wchar_t const* name)
    {
        auto processValue = GetProcessEnvironmentValue(name);
        if (!processValue.empty())
        {
            return processValue;
        }

        return GetUserEnvironmentRegistryValue(name);
    }

    HRESULT WriteSyncSettingValue(wchar_t const* name, std::wstring const& value)
    {
        wil::unique_hkey hKey;
        RETURN_IF_WIN32_ERROR(RegCreateKeyExW(
            HKEY_CURRENT_USER,
            L"Environment",
            0,
            nullptr,
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            nullptr,
            &hKey,
            nullptr));

        if (value.empty())
        {
            LONG deleteResult = RegDeleteValueW(hKey.get(), name);
            if (deleteResult != ERROR_SUCCESS && deleteResult != ERROR_FILE_NOT_FOUND)
            {
                RETURN_HR(HRESULT_FROM_WIN32(deleteResult));
            }
            RETURN_IF_WIN32_BOOL_FALSE(SetEnvironmentVariableW(name, nullptr));
            return S_OK;
        }

        auto bytes = static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t));
        RETURN_IF_WIN32_ERROR(RegSetValueExW(
            hKey.get(),
            name,
            0,
            REG_SZ,
            reinterpret_cast<BYTE const*>(value.c_str()),
            bytes));

        RETURN_IF_WIN32_BOOL_FALSE(SetEnvironmentVariableW(name, value.c_str()));
        return S_OK;
    }

    bool IsValidSyncBaseUrl(std::wstring const& baseUrl)
    {
        if (baseUrl.empty())
        {
            return false;
        }

        auto lower = winrt::to_string(winrt::hstring(baseUrl));
        std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        return lower.rfind("http://", 0) == 0 || lower.rfind("https://", 0) == 0;
    }

    bool IsValidSyncUserId(std::wstring const& userId)
    {
        if (userId.empty())
        {
            return false;
        }

        return std::all_of(userId.begin(), userId.end(), [](wchar_t ch)
        {
            return (ch >= L'0' && ch <= L'9') ||
                (ch >= L'a' && ch <= L'z') ||
                (ch >= L'A' && ch <= L'Z') ||
                ch == L'-' ||
                ch == L'_' ||
                ch == L'.';
        });
    }

    std::wstring NormalizeSyncBaseUrl(std::wstring baseUrl)
    {
        baseUrl = TrimCopy(std::move(baseUrl));
        if (!baseUrl.empty() && baseUrl.back() != L'/')
        {
            baseUrl.push_back(L'/');
        }
        return baseUrl;
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

    std::wstring ExtractLogTokenValue(std::wstring const& line, std::wstring const& token)
    {
        auto start = line.find(token);
        if (start == std::wstring::npos)
        {
            return L"";
        }

        start += token.size();
        auto end = line.find(L' ', start);
        if (end == std::wstring::npos)
        {
            end = line.size();
        }

        std::wstring value = line.substr(start, end - start);
        while (!value.empty() && (value.back() == L'.' || value.back() == L','))
        {
            value.pop_back();
        }
        return value;
    }

    void CALLBACK WebAuthNStatusChangeCallback(void* context)
    {
        auto mainPage = static_cast<winrt::PasskeyManager::implementation::MainPage*>(context);
        if (mainPage)
        {
            mainPage->DispatcherQueue().TryEnqueue([mainPage]()
            {
                mainPage->UpdatePluginEnableState();
            });
        }
    }

    DWORD RegisterWebAuthNStatusChangeCallback(void* context)
    {
        auto app = winrt::Microsoft::UI::Xaml::Application::Current().as<winrt::PasskeyManager::implementation::App>();

        DWORD cookie{};
        THROW_IF_FAILED(WebAuthNPluginRegisterStatusChangeCallback(
            &WebAuthNStatusChangeCallback,
            context,
            contosoplugin_guid,
            &cookie));
        return cookie;
    }

    DWORD UnregisterWebAuthNStatusChangeCallback()
    {
        auto app = winrt::Microsoft::UI::Xaml::Application::Current().as<winrt::PasskeyManager::implementation::App>();

        DWORD cookie{};
        THROW_IF_FAILED(WebAuthNPluginUnregisterStatusChangeCallback(&cookie));
        return cookie;
    }
}

namespace winrt::PasskeyManager::implementation
{
    winrt::fire_and_forget MainPage::UpdatePluginEnableState()
    {
        winrt::apartment_context ui_thread;

        co_await winrt::resume_background();
        auto hr = PluginRegistrationManager::getInstance().RefreshPluginState();
        auto pluginState = PluginRegistrationManager::getInstance().GetPluginState();
        bool vaultLocked = PluginCredentialManager::getInstance().GetVaultLock();
        bool silentOperation = PluginCredentialManager::getInstance().GetSilentOperation();
        VaultUnlockMethod vaultUnlockMethod = PluginCredentialManager::getInstance().GetVaultUnlockMethod();

        co_await ui_thread;
        VaultUnlockControl().IsChecked(vaultLocked);
        UpdateVaultUnlockControlText(vaultLocked);
        SetVaultLockSwitchState(vaultUnlockMethod == VaultUnlockMethod::Passkey);
        silentOperationSwitch().IsOn(silentOperation);
        if (FAILED(hr))
        {
            pluginStateRun().Text(L"Not Registered");
            auto resources = Application::Current().Resources();
            auto neutralBrush = resources.Lookup(winrt::box_value(L"SystemFillColorNeutralBrush")).as<winrt::Microsoft::UI::Xaml::Media::SolidColorBrush>();
            pluginStateRun().Foreground(neutralBrush);
            pluginActivationHintText().Text(L"Plugin is not registered. If it still appears in Windows Settings, close and reopen Settings, then click Refresh.");
            pluginActivationHintText().Visibility(Microsoft::UI::Xaml::Visibility::Visible);
            registerPluginButton().IsEnabled(true);
            updatePluginButton().IsEnabled(false);
            unregisterPluginButton().IsEnabled(false);
            activatePluginButton().IsEnabled(false);
            activatePluginButton().Content(box_value(L"Enable"));
        }
        else
        {
            registerPluginButton().IsEnabled(false);
            updatePluginButton().IsEnabled(true);
            unregisterPluginButton().IsEnabled(true);
            activatePluginButton().IsEnabled(pluginState != AuthenticatorState_Enabled);
            UpdatePluginStateTextBlock(pluginState);
        }
        co_return;
    }

    winrt::IAsyncAction MainPage::refreshSnapshotCandidatesButton_Click(IInspectable const&, Microsoft::UI::Xaml::RoutedEventArgs const&)
    {
        ReloadSnapshotCandidates();
        LogInfo(L"sync result=success operation=refresh_snapshot_candidates");
        co_return;
    }

    winrt::IAsyncAction MainPage::restoreSelectedSnapshotButton_Click(IInspectable const&, Microsoft::UI::Xaml::RoutedEventArgs const&)
    {
        int32_t selectedIndex = snapshotCandidatesCombo().SelectedIndex();
        if (selectedIndex < 0)
        {
            LogWarning(L"sync result=rejected operation=restore_selected_snapshot reason=no_selection");
            co_return;
        }

        size_t candidateCount = m_syncSnapshotCandidates.size();
        if (candidateCount == 0 || static_cast<size_t>(selectedIndex) >= candidateCount)
        {
            LogWarning(L"sync result=rejected operation=restore_selected_snapshot reason=candidate_stale");
            co_return;
        }

        size_t actualIndex = candidateCount - 1 - static_cast<size_t>(selectedIndex);
        auto const chosen = m_syncSnapshotCandidates.at(actualIndex);

        auto weakThis = get_weak();
        restoreSelectedSnapshotButton().IsEnabled(false);
        LogInProgress(L"summary state=running operation=restore_selected_snapshot");

        co_await winrt::resume_background();
        HRESULT hr = PluginRegistrationManager::getInstance().WriteEncryptedVaultData(chosen.CipherBytes);

        co_await wil::resume_foreground(DispatcherQueue());
        if (auto self = weakThis.get())
        {
            self->restoreSelectedSnapshotButton().IsEnabled(true);
            if (SUCCEEDED(hr))
            {
                std::wstring detail =
                    L"sync result=success operation=restore_selected_snapshot source=" +
                    chosen.Source +
                    L" bytes=" +
                    std::to_wstring(chosen.CipherBytes.size());
                self->LogSuccess(winrt::hstring{ detail });
            }
            else
            {
                self->LogFailure(L"summary result=failed operation=restore_selected_snapshot step=write_local_snapshot", hr);
            }
        }
        co_return;
    }

    winrt::IAsyncAction MainPage::restoreSyncSnapshotButton_Click(IInspectable const&, Microsoft::UI::Xaml::RoutedEventArgs const&)
    {
        auto weakThis = get_weak();
        restoreSyncSnapshotButton().IsEnabled(false);
        LogInProgress(L"summary state=running operation=restore_snapshot");

        co_await winrt::resume_background();
        HRESULT hr = PluginRegistrationManager::getInstance().RestoreSelfHostedVaultSnapshot();

        co_await wil::resume_foreground(DispatcherQueue());
        if (auto self = weakThis.get())
        {
            self->restoreSyncSnapshotButton().IsEnabled(true);
            if (SUCCEEDED(hr))
            {
                self->ReloadSnapshotCandidates();
            }
            else
            {
                self->syncStatusTextBlock().Text(L"WARNING: sync result=warning operation=restore_snapshot outcome=ended_with_warning_or_failure⚠");
            }
        }
        co_return;
    }

    winrt::IAsyncAction MainPage::runVaultRecoveryButton_Click(IInspectable const&, RoutedEventArgs const&)
    {
        auto strongThis = get_strong();
        auto weakThis = get_weak();
        runVaultRecoveryButton().IsEnabled(false);
        quickCreateVaultPasskeyButton().IsEnabled(false);
        LogInProgress(L"summary state=running operation=vault_recovery");
        vaultRecoveryHintText().Text(L"Vault passkey registration in progress. In storage selection, choose tsupasswd_core and complete the prompt.");
        vaultRecoveryHintText().Visibility(Microsoft::UI::Xaml::Visibility::Visible);

        com_ptr<App> curApp = winrt::Microsoft::UI::Xaml::Application::Current().as<App>();
        HWND hwnd = curApp->GetNativeWindowHandle();

        co_await winrt::resume_background();
        HRESULT hrState = PluginRegistrationManager::getInstance().RefreshPluginState();
        AUTHENTICATOR_STATE pluginState = PluginRegistrationManager::getInstance().GetPluginState();
        bool pluginEnabled = SUCCEEDED(hrState) && pluginState == AuthenticatorState_Enabled;
        for (int attempt = 0; attempt < 5 && !pluginEnabled; ++attempt)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            hrState = PluginRegistrationManager::getInstance().RefreshPluginState();
            pluginState = PluginRegistrationManager::getInstance().GetPluginState();
            pluginEnabled = SUCCEEDED(hrState) && pluginState == AuthenticatorState_Enabled;
        }
        HRESULT hrSetMethod = pluginEnabled
            ? PluginCredentialManager::getInstance().SetVaultUnlockMethod(VaultUnlockMethod::Passkey)
            : HRESULT_FROM_WIN32(ERROR_NOT_READY);
        HRESULT hrSetSilent = pluginEnabled
            ? PluginCredentialManager::getInstance().SetSilentOperation(false)
            : HRESULT_FROM_WIN32(ERROR_NOT_READY);

        co_await wil::resume_foreground(DispatcherQueue());
        if (!pluginEnabled)
        {
            if (auto self{ weakThis.get() })
            {
                std::wstring stateText = L"Unknown";
                if (SUCCEEDED(hrState))
                {
                    if (pluginState == AuthenticatorState_Enabled)
                    {
                        stateText = L"Enabled";
                    }
                    else if (pluginState == AuthenticatorState_Disabled)
                    {
                        stateText = L"Disabled";
                    }
                }

                self->runVaultRecoveryButton().IsEnabled(true);
                self->quickCreateVaultPasskeyButton().IsEnabled(true);
                self->SetVaultLockSwitchState(false);
                self->vaultRecoveryHintText().Text(L"Plugin is not enabled. Click 'Enable in Settings', then run Create Vault Passkey again.");
                self->vaultRecoveryHintText().Visibility(Microsoft::UI::Xaml::Visibility::Visible);
                self->LogWarning(winrt::hstring{ L"summary result=rejected operation=vault_recovery reason=plugin_not_enabled state=" + stateText + L" action=open_settings" });

                auto uri = Windows::Foundation::Uri(L"ms-settings:passkeys-advancedoptions");
                bool launched = co_await Windows::System::Launcher::LaunchUriAsync(uri);
                if (launched)
                {
                    self->LogSuccess(L"summary result=success operation=vault_recovery action=open_settings");
                }
                else
                {
                    self->LogWarning(L"summary result=failed operation=vault_recovery action=open_settings reason=launch_failed");
                }
            }
            co_return;
        }

        if (auto self{ weakThis.get() })
        {
            self->LogInfo(L"summary state=ready operation=vault_recovery stage=precheck_passed next=create_vault_passkey");
        }

        // Let the log/hint text render before WebAuthN dialog appears.
        co_await winrt::resume_after(std::chrono::milliseconds(150));

        if (IsIconic(hwnd))
        {
            ShowWindow(hwnd, SW_RESTORE);
        }
        ShowWindow(hwnd, SW_SHOW);
        SetForegroundWindow(hwnd);
        SetActiveWindow(hwnd);

        HRESULT hrCreatePasskey = hrSetMethod;
        if (SUCCEEDED(hrSetMethod))
        {
            co_await winrt::resume_background();
            hrCreatePasskey = PluginRegistrationManager::getInstance().CreateVaultPasskey(hwnd);
            co_await wil::resume_foreground(DispatcherQueue());
        }
        if (hrCreatePasskey == NTE_USER_CANCELLED || hrCreatePasskey == HRESULT_FROM_WIN32(ERROR_CANCELLED))
        {
            if (auto self{ weakThis.get() })
            {
                self->LogInfo(winrt::hstring{ L"summary result=cancelled operation=vault_recovery step=create_vault_passkey hr=" + std::to_wstring(static_cast<int>(hrCreatePasskey)) + L" reason=user_cancelled" });
            }
        }
        if (auto self{ weakThis.get() })
        {
            self->SetVaultLockSwitchState(true);
            self->runVaultRecoveryButton().IsEnabled(true);
            self->quickCreateVaultPasskeyButton().IsEnabled(true);

            if (FAILED(hrSetMethod))
            {
                self->SetVaultLockSwitchState(false);
                self->vaultRecoveryHintText().Text(L"Failed to switch Vault Unlock method to Passkey. Retry after Refresh.");
                self->vaultRecoveryHintText().Visibility(Microsoft::UI::Xaml::Visibility::Visible);
                self->LogFailure(L"summary result=failed operation=vault_recovery step=set_unlock_method_passkey", hrSetMethod);
                co_return;
            }

            if (FAILED(hrSetSilent))
            {
                self->LogWarning(winrt::hstring{ L"summary result=warning operation=vault_recovery step=set_silent_off hr=" + std::to_wstring(static_cast<int>(hrSetSilent)) + L" detail=plugin_ui_visibility_unset" });
            }

            self->LogInfo(winrt::hstring{ L"summary state=observed operation=vault_recovery step=create_vault_passkey_returned hr=" + std::to_wstring(static_cast<int>(hrCreatePasskey)) });
            if (FAILED(hrCreatePasskey))
            {
                HRESULT pluginPerformStatus = S_OK;
                HRESULT pluginUvStatus = S_OK;
                HRESULT pluginRequestSignStatus = S_OK;
                {
                    std::lock_guard<std::mutex> lock(curApp->m_pluginOperationOptionsMutex);
                    pluginPerformStatus = curApp->m_pluginOperationStatus.performOperationStatus;
                    pluginUvStatus = curApp->m_pluginOperationStatus.uvSignatureVerificationStatus;
                    pluginRequestSignStatus = curApp->m_pluginOperationStatus.requestSignatureVerificationStatus;
                }
                self->LogInfo(winrt::hstring{ L"summary state=observed operation=vault_recovery step=plugin_perform_operation_status hr=" + std::to_wstring(static_cast<int>(pluginPerformStatus)) });
                self->LogInfo(winrt::hstring{ L"summary state=observed operation=vault_recovery step=plugin_uv_signature_verification_status hr=" + std::to_wstring(static_cast<int>(pluginUvStatus)) });
                self->LogInfo(winrt::hstring{ L"summary state=observed operation=vault_recovery step=plugin_request_signature_verification_status hr=" + std::to_wstring(static_cast<int>(pluginRequestSignStatus)) });
            }

            if (SUCCEEDED(hrCreatePasskey))
            {
                self->vaultRecoveryHintText().Text(L"");
                self->vaultRecoveryHintText().Visibility(Microsoft::UI::Xaml::Visibility::Collapsed);
                self->runVaultRecoveryButton().Visibility(Microsoft::UI::Xaml::Visibility::Collapsed);
                self->LogSuccess(L"summary result=success operation=vault_recovery outcome=passkey_created");
                co_return;
            }

            if (hrCreatePasskey == NTE_EXISTS)
            {
                self->vaultRecoveryHintText().Text(L"");
                self->vaultRecoveryHintText().Visibility(Microsoft::UI::Xaml::Visibility::Collapsed);
                self->runVaultRecoveryButton().Visibility(Microsoft::UI::Xaml::Visibility::Collapsed);
                self->LogSuccess(L"summary result=success operation=vault_recovery outcome=passkey_already_exists");
                co_return;
            }

            if (hrCreatePasskey == NTE_NOT_SUPPORTED || hrCreatePasskey == HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED))
            {
                self->SetVaultLockSwitchState(false);
                self->vaultRecoveryHintText().Text(L"Passkey registration is not supported by the selected authenticator. Try selecting tsupasswd_core and retry.");
                self->vaultRecoveryHintText().Visibility(Microsoft::UI::Xaml::Visibility::Visible);
                self->LogWarning(L"summary result=failed operation=vault_recovery reason=authenticator_not_supported_prf_hmac");
                co_return;
            }

            self->SetVaultLockSwitchState(false);
            if (hrCreatePasskey == NTE_USER_CANCELLED || hrCreatePasskey == HRESULT_FROM_WIN32(ERROR_CANCELLED))
            {
                self->vaultRecoveryHintText().Text(L"Passkey registration was cancelled (0x800704C7). In storage selection choose tsupasswd_core and complete the prompt.");
                self->vaultRecoveryHintText().Visibility(Microsoft::UI::Xaml::Visibility::Visible);
                self->LogInfo(winrt::hstring{ L"summary result=cancelled operation=vault_recovery step=create_vault_passkey hr=" + std::to_wstring(static_cast<int>(hrCreatePasskey)) + L" reason=user_cancelled" });
            }
            else
            {
                self->vaultRecoveryHintText().Text(L"Vault passkey registration failed. Check the latest FAILED/INFO log line for the HRESULT and retry.");
                self->vaultRecoveryHintText().Visibility(Microsoft::UI::Xaml::Visibility::Visible);
                self->LogFailure(L"summary result=failed operation=vault_recovery step=create_vault_passkey", hrCreatePasskey);
            }
        }
        co_return;
    }

    winrt::IAsyncAction MainPage::vaultLockSwitch_Toggled(IInspectable const& sender, Microsoft::UI::Xaml::RoutedEventArgs const&)
    {
        if (m_suppressVaultLockSwitchToggled)
        {
            co_return;
        }

        auto toggleSwitch = sender.as<Microsoft::UI::Xaml::Controls::ToggleSwitch>();
        bool toggleSwitchState = toggleSwitch.IsOn();

        com_ptr<App> curApp = winrt::Microsoft::UI::Xaml::Application::Current().as<App>();
        HWND hwnd = curApp->GetNativeWindowHandle();

        auto weakThis = get_weak();
        co_await winrt::resume_background();
        auto unlockMethod = toggleSwitchState ? VaultUnlockMethod::Passkey : VaultUnlockMethod::Consent;
        auto hr = PluginCredentialManager::getInstance().SetVaultUnlockMethod(unlockMethod);
        HRESULT hrSetSilent = S_OK;
        if (unlockMethod == VaultUnlockMethod::Passkey)
        {
            hrSetSilent = PluginCredentialManager::getInstance().SetSilentOperation(false);
        }

        co_await wil::resume_foreground(DispatcherQueue());
        auto self = weakThis.get();
        if (FAILED(hr))
        {
            SetVaultLockSwitchState(!toggleSwitchState);
            if (self)
            {
                self->LogFailure(L"summary result=failed operation=set_vault_unlock_method", hr);
            }
        }
        else if (self)
        {
            std::wstring methodValue = (unlockMethod == VaultUnlockMethod::Passkey) ? L"passkey" : L"consent";
            self->LogSuccess(winrt::hstring{ L"summary result=success operation=set_vault_unlock_method method=" + methodValue });
            if (unlockMethod == VaultUnlockMethod::Passkey && FAILED(hrSetSilent))
            {
                self->LogWarning(winrt::hstring{ L"summary result=warning operation=vault_recovery step=set_silent_off hr=" + std::to_wstring(static_cast<int>(hrSetSilent)) + L" detail=plugin_ui_visibility_unset" });
            }
        }

        if (unlockMethod == VaultUnlockMethod::Passkey)
        {
            if (self)
            {
                self->LogInfo(L"summary state=running operation=vault_recovery trigger=unlock_method_toggle step=create_vault_passkey_start");
            }
            // Let the log render before WebAuthN blocks the UI thread.
            co_await winrt::resume_after(std::chrono::milliseconds(50));

            if (IsIconic(hwnd))
            {
                ShowWindow(hwnd, SW_RESTORE);
            }
            ShowWindow(hwnd, SW_SHOW);
            SetForegroundWindow(hwnd);
            SetActiveWindow(hwnd);

            hr = PluginRegistrationManager::getInstance().CreateVaultPasskey(hwnd);
            if (hr == NTE_USER_CANCELLED || hr == HRESULT_FROM_WIN32(ERROR_CANCELLED))
            {
                if (self)
                {
                    self->LogInfo(winrt::hstring{ L"summary result=cancelled operation=vault_recovery step=create_vault_passkey hr=" + std::to_wstring(static_cast<int>(hr)) + L" reason=user_cancelled" });
                }
            }

            self = weakThis.get();
            if (SUCCEEDED(hr) || hr == NTE_EXISTS)
            {
                if (self)
                {
                    if (hr == NTE_EXISTS)
                    {
                        self->LogSuccess(L"summary result=success operation=vault_recovery outcome=passkey_already_exists");
                    }
                    else
                    {
                        self->LogSuccess(L"summary result=success operation=vault_recovery outcome=passkey_created");
                    }
                }
            }
            else
            {
                SetVaultLockSwitchState(false);
                if (self)
                {
                    if (hr == NTE_USER_CANCELLED || hr == HRESULT_FROM_WIN32(ERROR_CANCELLED))
                    {
                        self->LogInfo(winrt::hstring{ L"summary result=cancelled operation=vault_recovery step=create_vault_passkey hr=" + std::to_wstring(static_cast<int>(hr)) + L" reason=user_cancelled" });
                    }
                    else
                    {
                        self->LogFailure(L"summary result=failed operation=vault_recovery step=create_vault_passkey", hr);
                    }

                    if (hr == NTE_NOT_SUPPORTED)
                    {
                        self->LogWarning(L"summary result=failed operation=vault_recovery reason=authenticator_not_supported_prf_hmac");
                    }
                }
            }
        }
        co_return;
    }

    winrt::IAsyncAction MainPage::silentOperationSwitch_Toggled(IInspectable const& sender, Microsoft::UI::Xaml::RoutedEventArgs const&)
    {
        auto toggleSwitch = sender.as<Microsoft::UI::Xaml::Controls::ToggleSwitch>();
        auto toggleSwitchState = toggleSwitch.IsOn();

        auto weakThis = get_weak();

        co_await winrt::resume_background();
        auto hr = PluginCredentialManager::getInstance().SetSilentOperation(toggleSwitchState);
        if (FAILED(hr))
        {
            co_await wil::resume_foreground(DispatcherQueue());
            if (auto self{ weakThis.get() })
            {
                self->LogFailure(L"summary result=failed operation=set_silent_operation", hr);
            }
        }
        co_return;
    }

    MainPage::MainPage()
    {
        m_credentialListViewModel = winrt::make<PasskeyManager::implementation::CredentialListViewModel>();
        DataContext(m_credentialListViewModel);

        auto weakThis = get_weak();
        m_registryWatcher = wil::make_registry_watcher(
            HKEY_CURRENT_USER,
            c_pluginRegistryPath,
            true,
            [weakThis](wil::RegistryChangeKind changeKind) -> winrt::fire_and_forget {
                bool shouldLogWarning = false;
                if (changeKind == wil::RegistryChangeKind::Modify)
                {
                    auto& credMgr = PluginCredentialManager::getInstance();
                    credMgr.ReloadRegistryValues();
                    if (credMgr.GetVaultLock() && credMgr.GetSilentOperation())
                    {
                        credMgr.SetSilentOperation(false);
                        shouldLogWarning = true;
                    }
                }
                if (auto self{ weakThis.get() })
                {
                    co_await wil::resume_foreground(self->DispatcherQueue());
                    if (shouldLogWarning)
                    {
                        self->LogWarning(winrt::hstring{ L"summary result=rejected operation=vault_unlock reason=ui_required hr=" + std::to_wstring(static_cast<int>(E_NOT_VALID_STATE)) + L"" });
                    }
                    self->UpdatePluginEnableState();
                }
            });
        std::wstring mockDBfilePath;
        PluginCredentialManager::getInstance().GetCredentialStorageFolderPath(mockDBfilePath);
        THROW_IF_FAILED(m_mockCredentialsDBWatcher.create(mockDBfilePath.c_str(),
            true,
            wil::FolderChangeEvents::All,
            [weakThis](wil::FolderChangeEvent, PCWSTR) -> winrt::fire_and_forget {
                PluginCredentialManager::getInstance().ReloadRegistryValues();
                if (auto self{ weakThis.get() })
                {
                    co_await wil::resume_foreground(self->DispatcherQueue());
                    self->UpdatePluginEnableState();
                    self->UpdateCredentialList();
                }
            }));

        m_cookie = RegisterWebAuthNStatusChangeCallback(static_cast<void*>(this));
    }

    MainPage::~MainPage()
    {
        if (m_cookie.has_value())
        {
            m_cookie = UnregisterWebAuthNStatusChangeCallback();
        }
    }

    winrt::IAsyncAction MainPage::refreshButton_Click(IInspectable const&, RoutedEventArgs const&)
    {
        UpdatePluginEnableState();
        UpdateCredentialList();
        co_return;
    }

    winrt::fire_and_forget MainPage::UpdateCredentialList()
    {
        m_credentialListViewModel.credentials().Clear();
        auto weakThis = get_weak();
        co_await winrt::resume_background();

        PluginCredentialManager& pluginCredentialManager = PluginCredentialManager::getInstance();
        pluginCredentialManager.ReloadCredentialManager();

        co_await wil::resume_foreground(DispatcherQueue());
        auto credentialViewList = pluginCredentialManager.GetCredentialListViewModel();

        auto self = weakThis.get();
        if (!self)
        {
            co_return;
        }

        if (pluginCredentialManager.IsLocalCredentialMetadataLoaded())
        {
            std::wstring countOfLocalCreds = std::to_wstring(pluginCredentialManager.GetLocalCredentialCount()) + L" passkeys in Local DB";
            self->credsStatsRun1().Text(countOfLocalCreds);
        }
        else
        {
            self->credsStatsRun1().Text(L"Local DB not loaded");
        }

        if (pluginCredentialManager.IsCachedCredentialsMetadataLoaded())
        {
            std::wstring countOfPluginCreds = std::to_wstring(pluginCredentialManager.GetCachedCredentialCount()) + L" passkeys in system Cache";
            self->credsStatsRun2().Text(countOfPluginCreds);
        }
        else
        {
            self->credsStatsRun2().Text(L"Windows Cache Data not loaded");
        }

        self->m_credentialListViewModel.credentials().Clear();
        for (auto& credListItem : credentialViewList)
        {
            self->m_credentialListViewModel.credentials().Append(*credListItem.detach());
        }
        co_return;
    }

    winrt::IAsyncAction MainPage::OnNavigatedTo(Navigation::NavigationEventArgs e)
    {
        UpdatePluginEnableState();
        UpdateCredentialList();
        LoadSyncHistory();
        ReloadSnapshotCandidates();
        co_await loadSyncSettingsButton_Click(nullptr, nullptr);
        co_return;
    }

    void MainPage::ReloadSnapshotCandidates()
    {
        m_syncSnapshotCandidates = tsupasswd::SyncSnapshotStore::Load();

        snapshotCandidatesCombo().Items().Clear();
        for (auto it = m_syncSnapshotCandidates.rbegin(); it != m_syncSnapshotCandidates.rend(); ++it)
        {
            snapshotCandidatesCombo().Items().Append(winrt::box_value(winrt::hstring{ BuildSnapshotCandidateLabel(*it) }));
        }

        if (snapshotCandidatesCombo().Items().Size() > 0)
        {
            snapshotCandidatesCombo().SelectedIndex(0);
            auto latest = m_syncSnapshotCandidates.back();
            syncStatusTextBlock().Text(winrt::hstring{ L"INFO: sync state=ready operation=load_snapshot_candidates count=" + std::to_wstring(m_syncSnapshotCandidates.size()) + L" selected=latestℹ" });
        }
        else
        {
            syncStatusTextBlock().Text(L"INFO: sync state=ready operation=load_snapshot_candidates count=0 reason=no_snapshot_historyℹ");
        }
    }

    void MainPage::LoadSyncHistory()
    {
        m_isRestoringLogHistory = true;
        m_logEntries = tsupasswd::SyncHistoryStore::Load();
        RebuildLogView();
        m_isRestoringLogHistory = false;
    }

    void MainPage::PersistSyncHistoryEntry(winrt::hstring const& line)
    {
        std::wstring rawLine = line.c_str();
        tsupasswd::SyncHistoryEntry entry{};
        entry.Timestamp = BuildHistoryTimestamp();
        entry.Operation = InferHistoryOperation(rawLine);
        entry.Result = InferHistoryResult(rawLine);
        auto statusCode = ExtractLogTokenValue(rawLine, L"status=");
        entry.StatusCode = statusCode.empty() ? 0 : _wtoi(statusCode.c_str());
        entry.ErrorCode = ExtractLogTokenValue(rawLine, L"code=");
        entry.ErrorMessage = ExtractLogTokenValue(rawLine, L"message=");
        auto serverVersion = ExtractLogTokenValue(rawLine, L"server_version=");
        entry.ServerVersion = serverVersion.empty() ? -1 : _wtoi64(serverVersion.c_str());
        entry.RequestId = ExtractLogTokenValue(rawLine, L"request_id=");
        entry.RawLine = rawLine;

        auto hr = tsupasswd::SyncHistoryStore::Append(entry);
        if (FAILED(hr))
        {
            OutputDebugStringW((L"DEBUG: summary result=failed operation=persist_sync_history_entry hr=" + std::to_wstring(static_cast<int>(hr)) + L"\n").c_str());
        }
    }

    winrt::IAsyncAction MainPage::loadSyncSettingsButton_Click(IInspectable const&, Microsoft::UI::Xaml::RoutedEventArgs const&)
    {
        auto baseUrl = ReadSyncSettingValue(kSyncBaseUrlEnv);
        auto token = ReadSyncSettingValue(kSyncBearerTokenEnv);
        auto userId = ReadSyncSettingValue(kSyncUserIdEnv);

        syncBaseUrlTextBox().Text(baseUrl);
        syncBearerTokenBox().Password(token);
        syncUserIdTextBox().Text(userId);

        syncStatusTextBlock().Text(L"SUCCESS: sync result=success operation=load_settings source=process_registry✅");
        LogInfo(L"sync result=success operation=load_settings source=process_registry");
        co_return;
    }

    winrt::IAsyncAction MainPage::saveSyncSettingsButton_Click(IInspectable const&, Microsoft::UI::Xaml::RoutedEventArgs const&)
    {
        std::wstring baseUrl = NormalizeSyncBaseUrl(syncBaseUrlTextBox().Text().c_str());
        std::wstring token = TrimCopy(syncBearerTokenBox().Password().c_str());
        std::wstring userId = TrimCopy(syncUserIdTextBox().Text().c_str());

        syncBaseUrlTextBox().Text(baseUrl);

        if (!baseUrl.empty() && !IsValidSyncBaseUrl(baseUrl))
        {
            syncStatusTextBlock().Text(L"WARNING: sync result=rejected operation=save_settings reason=invalid_base_url⚠");
            LogWarning(L"sync result=rejected operation=save_settings reason=invalid_base_url");
            co_return;
        }
        if (!userId.empty() && !IsValidSyncUserId(userId))
        {
            syncStatusTextBlock().Text(L"WARNING: sync result=rejected operation=save_settings reason=invalid_user_id⚠");
            LogWarning(L"sync result=rejected operation=save_settings reason=invalid_user_id");
            co_return;
        }

        HRESULT hr = S_OK;
        hr = WriteSyncSettingValue(kSyncBaseUrlEnv, baseUrl);
        if (SUCCEEDED(hr))
        {
            hr = WriteSyncSettingValue(kSyncBearerTokenEnv, token);
        }
        if (SUCCEEDED(hr))
        {
            hr = WriteSyncSettingValue(kSyncUserIdEnv, userId);
        }

        if (FAILED(hr))
        {
            syncStatusTextBlock().Text(L"FAILED: summary result=failed operation=save_settings❌");
            LogFailure(L"summary result=failed operation=save_settings", hr);
            co_return;
        }

        syncStatusTextBlock().Text(L"SUCCESS: sync result=success operation=save_settings fields=base_url,token,user_id✅");
        LogSuccess(L"sync result=success operation=save_settings fields=base_url,token,user_id");
        co_return;
    }

    winrt::IAsyncAction MainPage::testSyncConnectionButton_Click(IInspectable const&, Microsoft::UI::Xaml::RoutedEventArgs const&)
    {
        std::wstring baseUrl = NormalizeSyncBaseUrl(syncBaseUrlTextBox().Text().c_str());
        std::wstring token = TrimCopy(syncBearerTokenBox().Password().c_str());
        std::wstring userId = TrimCopy(syncUserIdTextBox().Text().c_str());

        syncBaseUrlTextBox().Text(baseUrl);

        if (!IsValidSyncBaseUrl(baseUrl))
        {
            syncStatusTextBlock().Text(L"WARNING: sync result=rejected operation=test_connection reason=invalid_base_url⚠");
            LogWarning(L"sync result=rejected operation=test_connection reason=invalid_base_url");
            co_return;
        }
        if (token.empty())
        {
            syncStatusTextBlock().Text(L"WARNING: sync result=rejected operation=test_connection reason=token_empty⚠");
            LogWarning(L"sync result=rejected operation=test_connection reason=token_empty");
            co_return;
        }
        if (!IsValidSyncUserId(userId))
        {
            syncStatusTextBlock().Text(L"WARNING: sync result=rejected operation=test_connection reason=invalid_user_id⚠");
            LogWarning(L"sync result=rejected operation=test_connection reason=invalid_user_id");
            co_return;
        }

        auto weakThis = get_weak();
        testSyncConnectionButton().IsEnabled(false);
        syncStatusTextBlock().Text(L"INFO: summary state=running operation=test_connection⏳");
        LogInProgress(L"summary state=running operation=test_connection");

        co_await winrt::resume_background();
        tsupasswd::SyncClient syncClient(baseUrl);
        syncClient.SetBearerToken(token);
        tsupasswd::VaultRecord record{};
        tsupasswd::SyncHttpStatus status{};
        HRESULT hr = syncClient.GetVault(userId, record, &status);

        co_await wil::resume_foreground(DispatcherQueue());
        auto self = weakThis.get();
        if (!self)
        {
            co_return;
        }

        self->testSyncConnectionButton().IsEnabled(true);
        if (SUCCEEDED(hr) || hr == HRESULT_FROM_WIN32(ERROR_NOT_FOUND))
        {
            self->syncStatusTextBlock().Text(L"SUCCESS: sync result=success operation=test_connection outcome=reachable_or_not_found✅");
            self->LogSuccess(L"sync result=success operation=test_connection outcome=reachable_or_not_found");
            co_return;
        }

        std::wstring detail =
            L"sync result=failed operation=test_connection attempts=1 hr=" +
            std::to_wstring(static_cast<int>(hr));
        detail += L" failure_kind=" + ClassifySyncFailureKind(hr, status);
        if (status.StatusCode > 0)
        {
            detail += L" status=" + std::to_wstring(status.StatusCode);
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
        self->syncStatusTextBlock().Text(L"WARNING: sync result=failed operation=test_connection outcome=request_failed⚠");
        self->LogWarning(winrt::hstring{ detail });
        co_return;
    }

    winrt::IAsyncAction MainPage::manualSyncButton_Click(IInspectable const&, Microsoft::UI::Xaml::RoutedEventArgs const&)
    {
        auto weakThis = get_weak();
        manualSyncButton().IsEnabled(false);
        LogInProgress(L"summary state=running operation=manual_resync");

        co_await winrt::resume_background();
        HRESULT hr = PluginRegistrationManager::getInstance().ManualResyncSelfHostedVault();

        co_await wil::resume_foreground(DispatcherQueue());
        if (auto self = weakThis.get())
        {
            self->manualSyncButton().IsEnabled(true);
            if (FAILED(hr))
            {
                self->syncStatusTextBlock().Text(L"WARNING: sync result=warning operation=manual_resync outcome=ended_with_warning_or_failure⚠");
            }
        }
        co_return;
    }

    winrt::IAsyncAction MainPage::unregisterPluginButton_Click(IInspectable const&, RoutedEventArgs const&)
    {
        LogInProgress(L"summary state=running operation=unregister_plugin");
        auto weakThis = get_weak();

        if (m_cookie.has_value())
        {
            m_cookie = UnregisterWebAuthNStatusChangeCallback();
        }

        co_await winrt::resume_background();
        HRESULT hr = PluginRegistrationManager::getInstance().UnregisterPlugin();

        co_await wil::resume_foreground(DispatcherQueue());

        auto self = weakThis.get();
        if (!self)
        {
            co_return;
        }

        self->UpdatePluginEnableState();
        if (FAILED(hr))
        {
            self->LogFailure(L"summary result=failed operation=unregister_plugin", hr);
            co_return;
        }

        bool removed = false;
        for (int attempt = 0; attempt < 5; ++attempt)
        {
            co_await winrt::resume_background();
            HRESULT hrState = PluginRegistrationManager::getInstance().RefreshPluginState();
            removed = (hrState == NTE_NOT_FOUND);

            co_await wil::resume_foreground(DispatcherQueue());
            if (auto latest = weakThis.get())
            {
                latest->UpdatePluginEnableState();
            }

            if (removed)
            {
                break;
            }

            co_await winrt::resume_background();
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

        if (removed)
        {
            self->LogSuccess(L"summary result=success operation=unregister_plugin");
        }
        else
        {
            self->LogWarning(L"summary result=warning operation=unregister_plugin outcome=still_visible_in_settings");
        }
    }

    winrt::IAsyncAction MainPage::registerPluginButton_Click(IInspectable const&, RoutedEventArgs const&)
    {
        LogInProgress(L"summary state=running operation=register_plugin");
        auto weakThis = get_weak();
        co_await winrt::resume_background();
        HRESULT hr = PluginRegistrationManager::getInstance().RegisterPlugin();

        co_await wil::resume_foreground(DispatcherQueue());
        auto self = weakThis.get();
        if (!self)
        {
            co_return;
        }

        self->UpdatePluginEnableState();

        if (FAILED(hr))
        {
            self->LogFailure(L"summary result=failed operation=register_plugin", hr);
            co_return;
        }
        self->LogSuccess(L"summary result=success operation=register_plugin");

        m_cookie = RegisterWebAuthNStatusChangeCallback(static_cast<void*>(this));
    }

    winrt::IAsyncAction MainPage::updatePluginButton_Click(IInspectable const&, RoutedEventArgs const&)
    {
        LogInProgress(L"summary state=running operation=update_plugin");
        auto weakThis = get_weak();
        co_await winrt::resume_background();
        HRESULT hr = PluginRegistrationManager::getInstance().UpdatePlugin();

        co_await wil::resume_foreground(DispatcherQueue());

        auto self = weakThis.get();
        if (!self)
        {
            co_return;
        }

        self->UpdatePluginEnableState();

        if (FAILED(hr))
        {
            self->LogFailure(L"summary result=failed operation=update_plugin", hr);
            co_return;
        }
        self->LogSuccess(L"summary result=success operation=update_plugin");
    }

    winrt::IAsyncAction MainPage::addAllPluginCredentials_Click(IInspectable const&, RoutedEventArgs const&)
    {
        LogInProgress(L"summary state=running operation=add_all_credentials");

        auto& credentialManager = PluginCredentialManager::getInstance();
        com_ptr<App> curApp = winrt::Microsoft::UI::Xaml::Application::Current().as<App>();
        HWND hwnd = curApp->GetNativeWindowHandle();
        if (credentialManager.GetVaultLock())
        {
            LogInProgress(L"summary state=running operation=vault_unlock trigger=add_all");
            HRESULT hrUnlock = credentialManager.UnlockCredentialVaultWithPasskey(hwnd);
            if (FAILED(hrUnlock))
            {
                if (hrUnlock == E_NOT_VALID_STATE)
                {
                    LogWarning(winrt::hstring{ L"summary result=rejected operation=vault_unlock reason=ui_required hr=" + std::to_wstring(static_cast<int>(hrUnlock)) + L" context=add_all" });
                }
                else
                {
                    LogFailure(L"summary result=failed operation=vault_unlock context=add_all", hrUnlock);
                }
                co_return;
            }
            LogSuccess(L"summary result=success operation=vault_unlock context=add_all");
        }

        auto weakThis = get_weak();
        co_await winrt::resume_background();
        credentialManager.ReloadCredentialManager();
        DWORD localCredentialCount = credentialManager.GetLocalCredentialCount();
        if (localCredentialCount == 0)
        {
            co_await wil::resume_foreground(DispatcherQueue());
            if (auto self = weakThis.get())
            {
                self->UpdateCredentialList();
                self->LogWarning(L"summary result=rejected operation=add_all_credentials reason=no_local_credentials");
            }
            co_return;
        }
        HRESULT hr = credentialManager.AddAllPluginCredentials();

        co_await wil::resume_foreground(DispatcherQueue());

        auto self = weakThis.get();
        if (!self)
        {
            co_return;
        }

        self->UpdateCredentialList();
        if (hr == NTE_EXISTS || hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS))
        {
            self->LogInfo(L"summary result=success operation=add_all_credentials outcome=already_cached_no_new");
            co_return;
        }
        if (FAILED(hr))
        {
            std::wstring detail = DescribeCredentialOperationFailure(hr);
            self->LogFailure(winrt::hstring{ L"summary result=failed operation=add_all_credentials detail=" + detail }, hr);
            co_return;
        }
        self->LogSuccess(L"summary result=success operation=add_all_credentials");
        co_return;
    }

    winrt::IAsyncAction MainPage::addSelectedCredentials_Click(IInspectable const&, Microsoft::UI::Xaml::RoutedEventArgs const&)
    {
        LogInProgress(L"summary state=running operation=add_selected_credentials");

        std::vector<std::vector<UINT8>> credentialIdList;
        auto selectedItems = credentialListView().SelectedItems();
        if (selectedItems.Size() == 0)
        {
            LogWarning(L"summary result=rejected operation=add_selected_credentials reason=no_selection");
            co_return;
        }

        for (auto item : selectedItems)
        {
            auto credential = item.as<PasskeyManager::implementation::Credential>();
            auto reader = winrt::Windows::Storage::Streams::DataReader::FromBuffer(credential->CredentialId());
            std::vector<UINT8> credentialIdToAdd(reader.UnconsumedBufferLength());
            reader.ReadBytes(credentialIdToAdd);
            credentialIdList.push_back(credentialIdToAdd);
        }

        LogInProgress(winrt::hstring{ L"summary state=selected operation=add_selected_credentials selected=" + std::to_wstring(credentialIdList.size()) });

        auto weakThis = get_weak();
        co_await winrt::resume_background();
        HRESULT hr = PluginCredentialManager::getInstance().AddPluginCredentialById(credentialIdList);

        co_await wil::resume_foreground(DispatcherQueue());

        auto self = weakThis.get();
        if (!self)
        {
            co_return;
        }

        self->UpdateCredentialList();
        if (hr == NTE_EXISTS || hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS))
        {
            self->LogInfo(L"summary result=success operation=add_selected_credentials outcome=already_cached_no_new");
            co_return;
        }
        if (FAILED(hr))
        {
            std::wstring detail = DescribeCredentialOperationFailure(hr);
            self->LogFailure(winrt::hstring{ L"summary result=failed operation=add_selected_credentials detail=" + detail }, hr);
            co_return;
        }
        self->LogSuccess(L"summary result=success operation=add_selected_credentials");
        co_return;
    }

    winrt::IAsyncAction MainPage::deleteAllPluginCredentials_Click(IInspectable const&, Microsoft::UI::Xaml::RoutedEventArgs const&)
    {
        LogInProgress(L"summary state=running operation=delete_all_cached_credentials");

        auto weakThis = get_weak();
        co_await winrt::resume_background();
        auto& credentialManager = PluginCredentialManager::getInstance();
        credentialManager.ReloadCredentialManager();
        HRESULT hr = S_OK;
        if (credentialManager.GetCachedCredentialCount() == 0)
        {
            hr = HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
        }
        else
        {
            hr = credentialManager.DeleteAllPluginCredentials();
        }

        co_await wil::resume_foreground(DispatcherQueue());

        auto self = weakThis.get();
        if (!self)
        {
            co_return;
        }

        self->UpdateCredentialList();
        if (hr == HRESULT_FROM_WIN32(ERROR_NOT_FOUND))
        {
            self->LogInfo(L"summary result=not_found operation=delete_all_cached_credentials");
            co_return;
        }
        if (FAILED(hr))
        {
            self->LogFailure(L"summary result=failed operation=delete_all_cached_credentials", hr);
            co_return;
        }
        self->LogSuccess(L"summary result=success operation=delete_all_cached_credentials");
        co_return;
    }

    winrt::IAsyncAction MainPage::deleteSelectedPluginCredentials_Click(IInspectable const&, Microsoft::UI::Xaml::RoutedEventArgs const&)
    {
        LogInProgress(L"summary state=running operation=delete_selected_cached_credentials");

        // find the list of creds with checkbox checked
        std::vector<std::vector<UINT8>> credentialIdList;
        auto selectedItems = credentialListView().SelectedItems();
        if (selectedItems.Size() == 0)
        {
            LogWarning(L"summary result=rejected operation=delete_selected_cached_credentials reason=no_selection");
            co_return;
        }

        for (auto item : selectedItems)
        {
            auto credential = item.as<PasskeyManager::implementation::Credential>();
            auto reader = winrt::Windows::Storage::Streams::DataReader::FromBuffer(credential->CredentialId());
            std::vector<UINT8> credentialIdToDelete(reader.UnconsumedBufferLength());
            reader.ReadBytes(credentialIdToDelete);
            credentialIdList.push_back(credentialIdToDelete);
        }

        // update the status block with count of selected creds
        LogInProgress(winrt::hstring{ L"summary state=selected operation=delete_selected_cached_credentials selected=" + std::to_wstring(credentialIdList.size()) });

        auto weakThis = get_weak();
        co_await winrt::resume_background();
        auto& credentialManager = PluginCredentialManager::getInstance();
        credentialManager.ReloadCredentialManager();

        std::vector<std::vector<UINT8>> cachedCredentialIdList;
        cachedCredentialIdList.reserve(credentialIdList.size());
        for (auto const& credentialId : credentialIdList)
        {
            if (!credentialId.empty() &&
                credentialManager.IsPluginCredentialIdAutofillSupported(
                    static_cast<DWORD>(credentialId.size()),
                    const_cast<PBYTE>(credentialId.data())))
            {
                cachedCredentialIdList.push_back(credentialId);
            }
        }

        HRESULT hr = S_OK;
        if (cachedCredentialIdList.empty())
        {
            hr = HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
        }
        else
        {
            hr = credentialManager.DeletePluginCredentialById(cachedCredentialIdList, false);
        }

        co_await wil::resume_foreground(DispatcherQueue());

        auto self = weakThis.get();
        if (!self)
        {
            co_return;
        }

        self->UpdateCredentialList();
        if (hr == HRESULT_FROM_WIN32(ERROR_NOT_FOUND))
        {
            self->LogInfo(L"summary result=not_found operation=delete_selected_cached_credentials");
            co_return;
        }
        if (FAILED(hr))
        {
            std::wstring detail = DescribeCredentialOperationFailure(hr);
            self->LogFailure(winrt::hstring{ L"summary result=failed operation=delete_selected_cached_credentials detail=" + detail }, hr);
            co_return;
        }
        self->LogSuccess(L"summary result=success operation=delete_selected_cached_credentials");
        co_return;
    }

    winrt::IAsyncAction MainPage::deleteSelectedPluginCredentialsEverywhere_Click(IInspectable const&, Microsoft::UI::Xaml::RoutedEventArgs const&)
    {
        uint64_t requestId = ++m_deleteEverywhereRequestCounter;

        if (m_isDeleteEverywhereInProgress)
        {
            LogWarning(winrt::hstring{
                L"summary result=rejected reason=in_progress request=" +
                std::to_wstring(requestId) +
                L" active_run=" +
                std::to_wstring(m_deleteEverywhereActiveRunId) });
            co_return;
        }

        auto weakThis = get_weak();
        std::vector<std::vector<UINT8>> credentialIdList;
        auto selectedItems = credentialListView().SelectedItems();
        if (selectedItems.Size() == 0)
        {
            LogWarning(winrt::hstring{ L"summary result=rejected reason=no_selection request=" + std::to_wstring(requestId) }, E_NOT_SET);
            co_return;
        }

        uint64_t runId = ++m_deleteEverywhereRunCounter;
        m_deleteEverywhereActiveRunId = runId;
        m_isDeleteEverywhereInProgress = true;
        auto runStartTime = std::chrono::steady_clock::now();
        deleteSelectedLocalButton().IsEnabled(false);
        LogInProgress(winrt::hstring{
            L"summary state=running operation=delete_selected_credentials_everywhere request=" +
            std::to_wstring(requestId) +
            L" run=" +
            std::to_wstring(runId) });

        // find the list of creds with checkbox checked

        for (auto item : selectedItems)
        {
            auto credential = item.as<PasskeyManager::implementation::Credential>();
            auto reader = winrt::Windows::Storage::Streams::DataReader::FromBuffer(credential->CredentialId());
            std::vector<UINT8> credentialIdToDelete(reader.UnconsumedBufferLength());
            reader.ReadBytes(credentialIdToDelete);
            credentialIdList.push_back(credentialIdToDelete);
        }

        // update the status block with count of selected creds
        hstring statusText = winrt::hstring{ L"INFO: summary state=selected operation=delete_selected_credentials_everywhere request=" + std::to_wstring(requestId) + L" run=" + std::to_wstring(runId) + L" selected=" + std::to_wstring(credentialIdList.size()) + L"ℹ" };
        UpdatePasskeyOperationStatusText(statusText);

        co_await winrt::resume_background();
        auto& credentialManager = PluginCredentialManager::getInstance();
        credentialManager.ReloadCredentialManager();

        std::vector<std::vector<UINT8>> cachedCredentialIdList;
        cachedCredentialIdList.reserve(credentialIdList.size());
        for (auto const& credentialId : credentialIdList)
        {
            if (!credentialId.empty() &&
                credentialManager.IsPluginCredentialIdAutofillSupported(
                    static_cast<DWORD>(credentialId.size()),
                    const_cast<PBYTE>(credentialId.data())))
            {
                cachedCredentialIdList.push_back(credentialId);
            }
        }

        HRESULT hr = S_OK;
        if (cachedCredentialIdList.empty())
        {
            hr = HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
        }
        else
        {
            hr = credentialManager.DeletePluginCredentialById(cachedCredentialIdList, true);
        }

        co_await wil::resume_foreground(DispatcherQueue());

        auto self = weakThis.get();
        if (!self)
        {
            co_return;
        }

        self->m_isDeleteEverywhereInProgress = false;
        self->m_deleteEverywhereActiveRunId = 0;
        self->deleteSelectedLocalButton().IsEnabled(true);
        auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - runStartTime).count();

        self->UpdateCredentialList();
        if (hr == HRESULT_FROM_WIN32(ERROR_NOT_FOUND))
        {
            auto missingCount = credentialIdList.size() - cachedCredentialIdList.size();
            self->LogInfo(winrt::hstring{ L"summary result=not_found operation=delete_selected_credentials_everywhere request=" + std::to_wstring(requestId) + L" run=" + std::to_wstring(runId) + L" attempts=1 elapsed_ms=" + std::to_wstring(elapsedMs) + L" hr=" + std::to_wstring(static_cast<int>(hr)) + L" selected=" + std::to_wstring(credentialIdList.size()) + L" cached=" + std::to_wstring(cachedCredentialIdList.size()) + L" missing=" + std::to_wstring(missingCount) });
            co_return;
        }
        if (FAILED(hr))
        {
            auto missingCount = credentialIdList.size() - cachedCredentialIdList.size();
            std::wstring detail = DescribeCredentialOperationFailure(hr);
            self->LogWarning(winrt::hstring{ L"summary result=failed operation=delete_selected_credentials_everywhere request=" + std::to_wstring(requestId) + L" run=" + std::to_wstring(runId) + L" attempts=1 elapsed_ms=" + std::to_wstring(elapsedMs) + L" hr=" + std::to_wstring(static_cast<int>(hr)) + L" selected=" + std::to_wstring(credentialIdList.size()) + L" cached=" + std::to_wstring(cachedCredentialIdList.size()) + L" missing=" + std::to_wstring(missingCount) + L" detail=" + detail }, hr);
            co_return;
        }
        auto missingCount = credentialIdList.size() - cachedCredentialIdList.size();
        self->LogSuccess(winrt::hstring{ L"summary result=success operation=delete_selected_credentials_everywhere request=" + std::to_wstring(requestId) + L" run=" + std::to_wstring(runId) + L" attempts=1 elapsed_ms=" + std::to_wstring(elapsedMs) + L" hr=" + std::to_wstring(static_cast<int>(hr)) + L" selected=" + std::to_wstring(credentialIdList.size()) + L" cached=" + std::to_wstring(cachedCredentialIdList.size()) + L" missing=" + std::to_wstring(missingCount) });
        co_return;
    }

    winrt::IAsyncAction MainPage::clearLogsButton_Click(IInspectable const&, Microsoft::UI::Xaml::RoutedEventArgs const&)
    {
        m_logEntries.clear();
        auto hr = tsupasswd::SyncHistoryStore::Clear();
        if (FAILED(hr))
        {
            OutputDebugStringW((L"DEBUG: summary result=failed operation=clear_logs step=clear_sync_history_file hr=" + std::to_wstring(static_cast<int>(hr)) + L"\n").c_str());
        }
        RebuildLogView();
        syncStatusTextBlock().Text(L"SUCCESS: summary result=success operation=clear_logs step=clear_sync_history_view✅");
        co_return;
    }

    bool MainPage::ShouldShowLogLine(std::wstring const& line)
    {
        auto selected = logsFilterCombo().SelectedItem();
        if (!selected)
        {
            return true;
        }

        std::wstring filter = winrt::unbox_value<winrt::hstring>(selected).c_str();
        if (filter == L"All")
        {
            return true;
        }
        if (filter == L"Info")
        {
            return line.rfind(L"INFO:", 0) == 0;
        }
        if (filter == L"Warning")
        {
            return line.rfind(L"WARNING:", 0) == 0;
        }
        if (filter == L"Failed")
        {
            return line.rfind(L"FAILED:", 0) == 0;
        }
        if (filter == L"Success")
        {
            return line.rfind(L"SUCCESS:", 0) == 0;
        }
        return true;
    }

    void MainPage::RebuildLogView()
    {
        std::wstring visibleLogs;
        bool first = true;

        for (auto it = m_logEntries.rbegin(); it != m_logEntries.rend(); ++it)
        {
            std::wstring line = it->c_str();
            if (!ShouldShowLogLine(line))
            {
                continue;
            }

            std::wstring displayLine = line;
            if (IsSyncRetryDetailLine(line))
            {
                displayLine = L"  -> " + line;
            }

            if (!first)
            {
                visibleLogs += L"\r\n";
            }
            visibleLogs += displayLine;
            first = false;
        }

        syncHistoryTextBox().Text(winrt::hstring{ visibleLogs });

        UpdateLogDetailSummary();
    }

    void MainPage::UpdateLogDetailSummary()
    {
        std::wstring detailTarget;
        std::wstring detailLabel = L"Latest detail:";
        for (auto it = m_logEntries.rbegin(); it != m_logEntries.rend(); ++it)
        {
            std::wstring line = it->c_str();
            if (ShouldShowLogLine(line))
            {
                detailTarget = std::move(line);
                break;
            }
        }

        if (detailTarget.empty())
        {
            logDetailTextBlock().Text(L"Latest detail: Not available");
            return;
        }

        std::wstring detail = detailLabel;
        auto statusCode = ExtractLogTokenValue(detailTarget, L"status=");
        auto code = ExtractLogTokenValue(detailTarget, L"code=");
        auto messageCode = ExtractLogTokenValue(detailTarget, L"message_code=");
        auto message = ExtractLogTokenValue(detailTarget, L"message=");
        auto serverVersion = ExtractLogTokenValue(detailTarget, L"server_version=");

        if (!statusCode.empty())
        {
            detail += L" status=" + statusCode;
        }
        if (!code.empty())
        {
            detail += L" code=" + code;
        }
        if (!messageCode.empty())
        {
            detail += L" message_code=" + messageCode;
        }
        if (!message.empty())
        {
            if (messageCode.empty())
            {
                detail += L" message_code=remote_error_message_present";
            }
            detail += L" message=" + message;
        }
        if (!serverVersion.empty())
        {
            detail += L" server_version=" + serverVersion;
        }

        if (detail == detailLabel)
        {
            if (detailTarget.size() > 180)
            {
                detailTarget = detailTarget.substr(0, 180) + L"...";
            }
            detail += L" " + detailTarget;
        }

        logDetailTextBlock().Text(winrt::hstring{ detail });
    }

    winrt::IAsyncAction MainPage::logsFilterCombo_SelectionChanged(IInspectable const&, Microsoft::UI::Xaml::Controls::SelectionChangedEventArgs const&)
    {
        RebuildLogView();
        co_return;
    }

    winrt::IAsyncAction MainPage::copyLatestLogButton_Click(IInspectable const&, Microsoft::UI::Xaml::RoutedEventArgs const&)
    {
        if (m_logEntries.empty())
        {
            LogInfo(L"summary result=rejected operation=copy_logs reason=no_logs");
            co_return;
        }

        std::wstring clipboardText = syncHistoryTextBox().Text().c_str();
        uint32_t copiedLines = 0;
        if (!clipboardText.empty())
        {
            copiedLines = 1;
            for (wchar_t ch : clipboardText)
            {
                if (ch == L'\n')
                {
                    ++copiedLines;
                }
            }
        }
        else
        {
            clipboardText = m_logEntries.back().c_str();
            copiedLines = 1;
        }

        winrt::Windows::ApplicationModel::DataTransfer::DataPackage package;
        package.SetText(winrt::hstring{ clipboardText });
        winrt::Windows::ApplicationModel::DataTransfer::Clipboard::SetContent(package);

        if (copiedLines > 1)
        {
            LogSuccess(winrt::hstring{ L"summary result=success operation=copy_logs scope=visible lines=" + std::to_wstring(copiedLines) });
        }
        else
        {
            LogSuccess(L"summary result=success operation=copy_logs scope=visible lines=1");
        }
        co_return;
    }

    winrt::IAsyncAction MainPage::deleteAllLocalCredentials_Click(IInspectable const&, Microsoft::UI::Xaml::RoutedEventArgs const&)
    {
        LogInProgress(L"summary state=running operation=delete_all_local_credentials");

        auto weakThis = get_weak();
        co_await winrt::resume_background();

        bool resetResult = PluginCredentialManager::getInstance().ResetLocalCredentialsStore();

        co_await wil::resume_foreground(DispatcherQueue());

        auto self = weakThis.get();
        if (!self)
        {
            co_return;
        }

        self->UpdateCredentialList();
        if (!resetResult)
        {
            self->LogFailure(L"summary result=failed operation=delete_all_local_credentials detail=credential_store_update_failed", HRESULT_FROM_WIN32(ERROR_WRITE_FAULT));
            co_return;
        }
        self->LogSuccess(L"summary result=success operation=delete_all_local_credentials");
        co_return;
    }

    winrt::IAsyncAction MainPage::deleteAllCredentials_Click(IInspectable const&, Microsoft::UI::Xaml::RoutedEventArgs const&)
    {
        LogInProgress(L"summary state=running operation=delete_all_credentials");
        auto weakThis = get_weak();
        co_await winrt::resume_background();
        auto& credManager = PluginCredentialManager::getInstance();
        HRESULT hr = credManager.DeleteAllPluginCredentials();
        bool resetResult = credManager.ResetLocalCredentialsStore();
        co_await wil::resume_foreground(DispatcherQueue());

        auto self = weakThis.get();
        if (!self)
        {
            co_return;
        }

        self->UpdateCredentialList();
        if (hr == HRESULT_FROM_WIN32(ERROR_NOT_FOUND) && resetResult)
        {
            self->LogInfo(L"summary result=success operation=delete_all_credentials outcome=cache_not_found_local_deleted");
            co_return;
        }
        if (FAILED(hr) || !resetResult)
        {
            HRESULT effectiveHr = FAILED(hr) ? hr : HRESULT_FROM_WIN32(ERROR_WRITE_FAULT);
            std::wstring detail = DescribeCredentialOperationFailure(effectiveHr);
            self->LogFailure(winrt::hstring{ L"summary result=failed operation=delete_all_credentials detail=" + detail }, effectiveHr);
            co_return;
        }
        self->LogSuccess(L"summary result=success operation=delete_all_credentials");
    }

    void MainPage::UpdatePluginStateTextBlock(AUTHENTICATOR_STATE state)
    {
        auto resources = Application::Current().Resources();
        auto successBrush = resources.Lookup(winrt::box_value(L"SystemFillColorSuccessBrush")).as<winrt::Microsoft::UI::Xaml::Media::SolidColorBrush>();
        auto criticalBrush = resources.Lookup(winrt::box_value(L"SystemFillColorCriticalBrush")).as<winrt::Microsoft::UI::Xaml::Media::SolidColorBrush>();
        auto cautionBrush = resources.Lookup(winrt::box_value(L"SystemFillColorCautionBrush")).as<winrt::Microsoft::UI::Xaml::Media::SolidColorBrush>();

        switch (state)
        {
        case AuthenticatorState_Enabled:
            pluginStateRun().Text(L"Enabled");
            pluginStateRun().Foreground(successBrush);
            pluginActivationHintText().Text(L"");
            pluginActivationHintText().Visibility(Microsoft::UI::Xaml::Visibility::Collapsed);
            activatePluginButton().Content(box_value(L"Enabled"));
            break;
        case AuthenticatorState_Disabled:
            pluginStateRun().Text(L"Disabled");
            pluginStateRun().Foreground(criticalBrush);
            pluginActivationHintText().Text(L"Plugin is registered but disabled. Click Enable to open Windows Settings and turn the plugin on.");
            pluginActivationHintText().Visibility(Microsoft::UI::Xaml::Visibility::Visible);
            activatePluginButton().Content(box_value(L"Enable in Settings"));
            break;
        default:
            pluginStateRun().Text(L"Unknown");
            pluginStateRun().Foreground(cautionBrush);
            pluginActivationHintText().Text(L"Plugin state is unknown. Open Windows Settings from Enable and verify plugin activation.");
            pluginActivationHintText().Visibility(Microsoft::UI::Xaml::Visibility::Visible);
            activatePluginButton().Content(box_value(L"Enable"));
            break;
        }
    }

    winrt::IAsyncAction MainPage::SelectionChanged(IInspectable const& sender, Microsoft::UI::Xaml::Controls::SelectionChangedEventArgs const&)
    {
        Microsoft::UI::Xaml::Controls::ListView listView = sender.as<Microsoft::UI::Xaml::Controls::ListView>();
        auto selected = listView.SelectedItems().Size() > 0;
        selectedAddButton().IsEnabled(selected);
        deleteSelectedCacheButton().IsEnabled(selected);
        deleteSelectedLocalButton().IsEnabled(selected);
        co_return;
    }

    winrt::IAsyncAction MainPage::activatePluginButton_Click(IInspectable const& sender, Microsoft::UI::Xaml::RoutedEventArgs const& e)
    {
        // URI ms-settings:passkeys-advancedoptions to navigate to the page on Settings app where the users can enable the plugin
        auto weakThis = get_weak();
        LogInProgress(L"summary state=running operation=activate_plugin action=open_settings");
        auto uri = Windows::Foundation::Uri(L"ms-settings:passkeys-advancedoptions");
        bool launched = co_await Windows::System::Launcher::LaunchUriAsync(uri);
        if (!launched)
        {
            LogWarning(L"summary result=failed operation=activate_plugin action=open_settings reason=launch_failed");
            co_return;
        }

        LogSuccess(L"summary result=success operation=activate_plugin action=open_settings");

        for (int attempt = 0; attempt < 5; ++attempt)
        {
            co_await winrt::resume_background();
            std::this_thread::sleep_for(std::chrono::seconds(2));
            HRESULT hrState = PluginRegistrationManager::getInstance().RefreshPluginState();
            AUTHENTICATOR_STATE state = PluginRegistrationManager::getInstance().GetPluginState();

            co_await wil::resume_foreground(DispatcherQueue());
            if (auto self = weakThis.get())
            {
                self->UpdatePluginEnableState();
                if (SUCCEEDED(hrState) && state == AuthenticatorState_Enabled)
                {
                    self->LogSuccess(L"summary result=success operation=activate_plugin outcome=state_enabled");
                    co_return;
                }
            }
            else
            {
                co_return;
            }
        }

        LogWarning(L"summary result=warning operation=activate_plugin outcome=state_not_enabled_after_wait");
        co_return;
    }

    void MainPage::UpdateVaultUnlockControlText(bool isLocked)
    {
        if (isLocked)
        {
            VaultUnlockControl().Content(box_value(L"Vault Locked"));
        }
        else
        {
            VaultUnlockControl().Content(box_value(L"Vault Unlocked"));
        }
    }

    void MainPage::SetVaultLockSwitchState(bool isOn)
    {
        auto resetGuard = wil::scope_exit([this]()
        {
            m_suppressVaultLockSwitchToggled = false;
        });

        m_suppressVaultLockSwitchToggled = true;
        vaultLockSwitch().IsOn(isOn);
    }

    winrt::IAsyncAction MainPage::VaultUnlockControl_IsCheckedChanged(winrt::Microsoft::UI::Xaml::Controls::ToggleSplitButton const& sender, winrt::Microsoft::UI::Xaml::Controls::ToggleSplitButtonIsCheckedChangedEventArgs const& args)
    {
        // Capture the value we need before switching context
        bool toggleSplitState = sender.IsChecked();

        auto hr = PluginCredentialManager::getInstance().SetVaultLock(toggleSplitState);

        if (FAILED(hr))
        {
            LogFailure(L"summary result=failed operation=set_vault_lock_state", hr);
        }

        UpdateVaultUnlockControlText(toggleSplitState);

        co_return;
    }

}
