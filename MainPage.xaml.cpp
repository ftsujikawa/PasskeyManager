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
#include "src/GoogleOAuth.h"
#include <future>
#include <coroutine>
#include <DispatcherQueue.h>
#include <winrt/Microsoft.ui.interop.h>
#include <winrt/Microsoft.UI.Content.h>
#include <winrt/Windows.ApplicationModel.DataTransfer.h>

namespace winrt {
    using namespace winrt::Microsoft::UI::Xaml;
}

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace {
    constexpr wchar_t kGoogleLastConnectedAtRegValueName[] = L"GoogleLastConnectedAt";

    std::wstring FormatLocalTimestamp(SYSTEMTIME const& st)
    {
        wchar_t buffer[32]{};
        swprintf_s(buffer, L"%04u-%02u-%02u %02u:%02u:%02u",
            st.wYear,
            st.wMonth,
            st.wDay,
            st.wHour,
            st.wMinute,
            st.wSecond);
        return buffer;
    }

    std::wstring GetNowLocalTimestamp()
    {
        SYSTEMTIME st{};
        GetLocalTime(&st);
        return FormatLocalTimestamp(st);
    }

    std::wstring GetParentDirectory(std::wstring const& filePath)
    {
        size_t pos = filePath.find_last_of(L"\\/");
        if (pos == std::wstring::npos)
        {
            return L"";
        }
        return filePath.substr(0, pos);
    }

    bool TrySaveGoogleLastConnectedAt(std::wstring const& timestamp)
    {
        if (timestamp.empty())
        {
            return false;
        }

        wil::unique_hkey hKey;
        if (RegCreateKeyExW(HKEY_CURRENT_USER, c_pluginRegistryPath, 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &hKey, nullptr) != ERROR_SUCCESS)
        {
            return false;
        }

        DWORD bytes = static_cast<DWORD>((timestamp.size() + 1) * sizeof(wchar_t));
        return RegSetValueExW(hKey.get(), kGoogleLastConnectedAtRegValueName, 0, REG_SZ, reinterpret_cast<BYTE const*>(timestamp.c_str()), bytes) == ERROR_SUCCESS;
    }

    std::wstring TryLoadGoogleLastConnectedAt()
    {
        wil::unique_hkey hKey;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, c_pluginRegistryPath, 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
        {
            return L"";
        }

        DWORD type = 0;
        DWORD bytes = 0;
        if (RegQueryValueExW(hKey.get(), kGoogleLastConnectedAtRegValueName, nullptr, &type, nullptr, &bytes) != ERROR_SUCCESS || type != REG_SZ || bytes < sizeof(wchar_t))
        {
            return L"";
        }

        std::wstring value(bytes / sizeof(wchar_t), L'\0');
        if (RegQueryValueExW(hKey.get(), kGoogleLastConnectedAtRegValueName, nullptr, nullptr, reinterpret_cast<BYTE*>(value.data()), &bytes) != ERROR_SUCCESS)
        {
            return L"";
        }

        if (!value.empty() && value.back() == L'\0')
        {
            value.pop_back();
        }
        return value;
    }

    void ClearGoogleLastConnectedAt()
    {
        wil::unique_hkey hKey;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, c_pluginRegistryPath, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS)
        {
            RegDeleteValueW(hKey.get(), kGoogleLastConnectedAtRegValueName);
        }
    }

    std::wstring MaskPathForDisplay(std::wstring const& path)
    {
        if (path.empty())
        {
            return L"-";
        }

        size_t pos = path.find_last_of(L"\\/");
        if (pos == std::wstring::npos)
        {
            return path;
        }

        return std::wstring(L"...\\") + path.substr(pos + 1);
    }

    std::wstring TryGetFileLastWriteTimestamp(std::wstring const& path)
    {
        if (path.empty())
        {
            return L"";
        }

        WIN32_FILE_ATTRIBUTE_DATA fileAttr{};
        if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &fileAttr))
        {
            return L"";
        }

        FILETIME localWriteTime{};
        if (!FileTimeToLocalFileTime(&fileAttr.ftLastWriteTime, &localWriteTime))
        {
            return L"";
        }

        SYSTEMTIME st{};
        if (!FileTimeToSystemTime(&localWriteTime, &st))
        {
            return L"";
        }

        return FormatLocalTimestamp(st);
    }

    std::wstring DescribeGoogleOAuthFailure(HRESULT hr)
    {
        if (hr == HRESULT_FROM_WIN32(ERROR_NO_TOKEN))
        {
            return L"No refresh_token was returned. Remove app access in Google Account permissions, then sign in again. Also verify OAuth test user settings.";
        }
        if (hr == HRESULT_FROM_WIN32(ERROR_CANCELLED))
        {
            return L"Google consent/sign-in was cancelled or blocked.";
        }
        if (hr == HRESULT_FROM_WIN32(ERROR_INVALID_DATA))
        {
            return L"OAuth state mismatch detected. Retry the flow from scratch.";
        }
        if (hr == HRESULT_FROM_WIN32(ERROR_NOT_FOUND))
        {
            return L"OAuth callback did not contain authorization code.";
        }
        return L"";
    }

    std::wstring DescribeGoogleConnectionDiagnosis(bool connected, bool tokenFileExists, bool hasLastConnectedRecord)
    {
        if (connected)
        {
            return L"refresh_token loaded successfully.";
        }

        if (tokenFileExists)
        {
            return L"token file exists but could not be loaded. Possible corruption or DPAPI scope mismatch. Action: click Disconnect, then Google Sign-in.";
        }

        if (hasLastConnectedRecord)
        {
            return L"token file is missing but previous connection metadata exists. Action: run Google Sign-in to reconnect.";
        }

        return L"Google is not connected yet. Action: run Google Sign-in.";
    }

    std::wstring ExpandOAuthDebugInfo(std::wstring const& raw)
    {
        if (raw.empty())
        {
            return L"(empty)";
        }

        std::wstring expanded = raw;
        std::wstring const delimiter = L" | ";
        size_t pos = 0;
        while ((pos = expanded.find(delimiter, pos)) != std::wstring::npos)
        {
            expanded.replace(pos, delimiter.size(), L"\r\n");
            pos += 2;
        }
        return expanded;
    }

    std::wstring BuildGoogleOAuthDebugSnapshotText(
        bool connected,
        std::wstring const& connectedAt,
        std::wstring const& tokenPath,
        std::wstring const& diagnosis,
        std::wstring const& oauthDebug)
    {
        std::wstring text = L"[Google OAuth Debug Snapshot]\r\n";
        text += L"captured_at: " + GetNowLocalTimestamp() + L"\r\n";
        text += L"status: " + std::wstring(connected ? L"connected" : L"disconnected") + L"\r\n";
        text += L"last_connected: " + (connectedAt.empty() ? L"unknown" : connectedAt) + L"\r\n";
        text += L"token_path: " + tokenPath + L"\r\n";
        text += L"diagnosis: " + diagnosis + L"\r\n\r\n";
        text += L"[OAuth Raw Debug Info]\r\n";
        text += ExpandOAuthDebugInfo(oauthDebug);
        return text;
    }

    std::wstring DescribeCredentialOperationFailure(HRESULT hr)
    {
        if (hr == HRESULT_FROM_WIN32(ERROR_NOT_FOUND))
        {
            return L"No matching credentials found. Try Refresh and select available items again.";
        }
        if (hr == HRESULT_FROM_WIN32(ERROR_WRITE_FAULT))
        {
            return L"Credential store update failed. Verify local storage access and retry.";
        }
        if (hr == E_INVALIDARG)
        {
            return L"Invalid credential selection was supplied.";
        }
        return L"Unexpected credential operation failure.";
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
    void MainPage::UpdateGoogleConnectionUiState(bool connected)
    {
        std::wstring tokenPath = tsupasswd::GetGoogleRefreshTokenStoragePath();
        googleTokenPathText().Text(winrt::hstring{ L"Token path: " + MaskPathForDisplay(tokenPath) });

        if (connected && m_lastGoogleConnectedAt.empty())
        {
            m_lastGoogleConnectedAt = TryGetFileLastWriteTimestamp(tokenPath);
            if (m_lastGoogleConnectedAt.empty())
            {
                m_lastGoogleConnectedAt = TryLoadGoogleLastConnectedAt();
            }
        }
        if (connected && !m_lastGoogleConnectedAt.empty())
        {
            TrySaveGoogleLastConnectedAt(m_lastGoogleConnectedAt);
        }

        std::wstring connectedAt = connected
            ? (m_lastGoogleConnectedAt.empty() ? L"unknown" : m_lastGoogleConnectedAt)
            : L"-";
        googleConnectedAtText().Text(winrt::hstring{ L"Google last connected: " + connectedAt });

        if (!connected)
        {
            m_lastGoogleConnectedAt.clear();
        }

        googleSignInButton().Content(winrt::box_value(connected ? L"Google Connected" : L"Google Sign-in"));
        googleSignInButton().IsEnabled(!connected && !m_googleOAuthInProgress.load());
        disconnectGoogleButton().IsEnabled(connected && !m_googleOAuthInProgress.load());
    }

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
        vaultLockSwitch().IsOn(vaultUnlockMethod == VaultUnlockMethod::Passkey);
        silentOperationSwitch().IsOn(silentOperation);
        if (FAILED(hr))
        {
            pluginStateRun().Text(L"Not Registered");
            auto resources = Application::Current().Resources();
            auto neutralBrush = resources.Lookup(winrt::box_value(L"SystemFillColorNeutralBrush")).as<winrt::Microsoft::UI::Xaml::Media::SolidColorBrush>();
            pluginStateRun().Foreground(neutralBrush);
            registerPluginButton().IsEnabled(true);
            updatePluginButton().IsEnabled(false);
            unregisterPluginButton().IsEnabled(false);
            activatePluginButton().IsEnabled(false);
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

    winrt::IAsyncAction MainPage::checkGoogleStateButton_Click(IInspectable const&, RoutedEventArgs const&)
    {
        std::wstring refreshToken;
        bool connected = tsupasswd::TryLoadGoogleRefreshToken(refreshToken);
        std::wstring tokenPath = tsupasswd::GetGoogleRefreshTokenStoragePath();
        std::wstring tokenFileTimestamp = TryGetFileLastWriteTimestamp(tokenPath);
        bool tokenFileExists = !tokenFileTimestamp.empty();

        std::wstring lastConnected = m_lastGoogleConnectedAt;
        if (lastConnected.empty())
        {
            lastConnected = tokenFileTimestamp;
        }
        if (lastConnected.empty())
        {
            lastConnected = TryLoadGoogleLastConnectedAt();
        }

        std::wstring diagnosis = DescribeGoogleConnectionDiagnosis(connected, tokenFileExists, !lastConnected.empty());

        std::wstring state = connected ? L"connected" : L"disconnected";
        std::wstring connectedAt = lastConnected.empty() ? L"unknown" : lastConnected;
        std::wstring summary = L"Google state check: status=" + state + L", last_connected=" + connectedAt + L", token_path=" + MaskPathForDisplay(tokenPath) + L", diagnosis=" + diagnosis;
        if (connected)
        {
            LogSuccess(winrt::hstring{ summary });
        }
        else
        {
            LogWarning(winrt::hstring{ summary });
        }

        m_lastGoogleConnectedAt = connected ? lastConnected : L"";
        UpdateGoogleConnectionUiState(connected);
        co_return;
    }

    winrt::IAsyncAction MainPage::copyGoogleDebugInfoButton_Click(IInspectable const&, RoutedEventArgs const&)
    {
        std::wstring oauthDebug = tsupasswd::GetLastGoogleOAuthDebugInfo();
        std::wstring refreshToken;
        bool connected = tsupasswd::TryLoadGoogleRefreshToken(refreshToken);
        std::wstring tokenPath = tsupasswd::GetGoogleRefreshTokenStoragePath();
        std::wstring tokenFileTimestamp = TryGetFileLastWriteTimestamp(tokenPath);

        std::wstring lastConnected = m_lastGoogleConnectedAt;
        if (lastConnected.empty())
        {
            lastConnected = tokenFileTimestamp;
        }
        if (lastConnected.empty())
        {
            lastConnected = TryLoadGoogleLastConnectedAt();
        }

        std::wstring diagnosis = DescribeGoogleConnectionDiagnosis(connected, !tokenFileTimestamp.empty(), !lastConnected.empty());
        std::wstring snapshot = BuildGoogleOAuthDebugSnapshotText(connected, lastConnected, tokenPath, diagnosis, oauthDebug);

        Windows::ApplicationModel::DataTransfer::DataPackage package;
        package.SetText(winrt::hstring{ snapshot });
        Windows::ApplicationModel::DataTransfer::Clipboard::SetContent(package);
        Windows::ApplicationModel::DataTransfer::Clipboard::Flush();
        if (oauthDebug.empty())
        {
            LogWarning(L"OAuth raw debug info is empty. Copied state snapshot only.");
            co_return;
        }
        LogSuccess(L"OAuth debug snapshot copied to clipboard.");
        co_return;
    }

    winrt::IAsyncAction MainPage::runGoogleOAuthSmokeTestButton_Click(IInspectable const&, RoutedEventArgs const&)
    {
        runGoogleOAuthSmokeTestButton().IsEnabled(false);
        LogInProgress(L"Running OAuth smoke test: state check + debug snapshot");

        co_await checkGoogleStateButton_Click(nullptr, RoutedEventArgs{});

        std::wstring debugInfo = tsupasswd::GetLastGoogleOAuthDebugInfo();
        if (debugInfo.empty())
        {
            LogWarning(L"OAuth smoke test: debug snapshot is empty.");
        }
        else
        {
            std::wstring compact = debugInfo;
            if (compact.size() > 600)
            {
                compact.resize(600);
                compact += L"...";
            }
            LogSuccess(winrt::hstring{ L"OAuth smoke test debug snapshot: " + compact });
        }

        runGoogleOAuthSmokeTestButton().IsEnabled(true);
        co_return;
    }

    winrt::IAsyncAction MainPage::runVaultRecoveryButton_Click(IInspectable const&, RoutedEventArgs const&)
    {
        auto weakThis = get_weak();
        runVaultRecoveryButton().IsEnabled(false);
        LogInProgress(L"Running Vault recovery flow");

        com_ptr<App> curApp = winrt::Microsoft::UI::Xaml::Application::Current().as<App>();
        HWND hwnd = curApp->GetNativeWindowHandle();

        co_await winrt::resume_background();
        HRESULT hrSetMethod = PluginCredentialManager::getInstance().SetVaultUnlockMethod(VaultUnlockMethod::Passkey);
        HRESULT hrCreatePasskey = SUCCEEDED(hrSetMethod)
            ? PluginRegistrationManager::getInstance().CreateVaultPasskey(hwnd)
            : hrSetMethod;

        co_await wil::resume_foreground(DispatcherQueue());
        if (auto self{ weakThis.get() })
        {
            self->vaultLockSwitch().IsOn(true);
            self->runVaultRecoveryButton().IsEnabled(true);

            if (FAILED(hrSetMethod))
            {
                self->vaultLockSwitch().IsOn(false);
                self->LogFailure(L"Failed to set Vault Unlock Method to Passkey", hrSetMethod);
                co_return;
            }

            if (SUCCEEDED(hrCreatePasskey))
            {
                self->vaultRecoveryHintText().Text(L"");
                self->vaultRecoveryHintText().Visibility(Microsoft::UI::Xaml::Visibility::Collapsed);
                self->runVaultRecoveryButton().Visibility(Microsoft::UI::Xaml::Visibility::Collapsed);
                self->LogSuccess(L"Vault recovery completed. Passkey was created.");
                co_return;
            }

            if (hrCreatePasskey == NTE_EXISTS)
            {
                self->vaultRecoveryHintText().Text(L"");
                self->vaultRecoveryHintText().Visibility(Microsoft::UI::Xaml::Visibility::Collapsed);
                self->runVaultRecoveryButton().Visibility(Microsoft::UI::Xaml::Visibility::Collapsed);
                self->LogSuccess(L"Vault recovery completed. Vault Unlock passkey already exists.");
                co_return;
            }

            self->vaultLockSwitch().IsOn(false);
            if (hrCreatePasskey == NTE_USER_CANCELLED || hrCreatePasskey == HRESULT_FROM_WIN32(ERROR_CANCELLED))
            {
                self->LogWarning(L"Vault recovery was cancelled", hrCreatePasskey);
            }
            else
            {
                self->LogFailure(L"Vault recovery failed during passkey registration", hrCreatePasskey);
            }
        }
        co_return;
    }

    winrt::IAsyncAction MainPage::disconnectGoogleButton_Click(IInspectable const&, RoutedEventArgs const&)
    {
        if (m_googleOAuthInProgress.load())
        {
            LogWarning(L"Google OAuth is in progress. Wait before disconnecting.");
            co_return;
        }

        if (tsupasswd::TryDeleteGoogleRefreshToken())
        {
            ClearGoogleLastConnectedAt();
            UpdateGoogleConnectionUiState(false);
            LogSuccess(L"Google refresh_token removed. Sign-in required next time.");
        }
        else
        {
            LogWarning(L"Failed to remove Google refresh_token file.");
        }

        co_return;
    }

    winrt::IAsyncAction MainPage::vaultLockSwitch_Toggled(IInspectable const& sender, Microsoft::UI::Xaml::RoutedEventArgs const&)
    {
        auto toggleSwitch = sender.as<Microsoft::UI::Xaml::Controls::ToggleSwitch>();
        bool toggleSwitchState = toggleSwitch.IsOn();

        com_ptr<App> curApp = winrt::Microsoft::UI::Xaml::Application::Current().as<App>();
        HWND hwnd = curApp->GetNativeWindowHandle();

        auto weakThis = get_weak();
        co_await winrt::resume_background();
        auto unlockMethod = toggleSwitchState ? VaultUnlockMethod::Passkey : VaultUnlockMethod::Consent;
        auto hr = PluginCredentialManager::getInstance().SetVaultUnlockMethod(unlockMethod);

        co_await wil::resume_foreground(DispatcherQueue());
        auto self = weakThis.get();
        if (FAILED(hr))
        {
            toggleSwitch.IsOn(!toggleSwitchState);
            if (self)
            {
                self->LogFailure(L"Failed to change 'Vault Unlock Control'", hr);
            }
        }
        else if (self)
        {
            self->LogSuccess(L"Changed 'Vault Unlock Control Method'");
        }

        if (unlockMethod == VaultUnlockMethod::Passkey)
        {
            weakThis = get_weak();
            co_await winrt::resume_background();
            hr = PluginRegistrationManager::getInstance().CreateVaultPasskey(hwnd);

            co_await wil::resume_foreground(DispatcherQueue());
            self = weakThis.get();
            if (SUCCEEDED(hr) || hr == NTE_EXISTS)
            {
                if (self)
                {
                    if (hr == NTE_EXISTS)
                    {
                        self->LogSuccess(L"Vault Unlock passkey already exists");
                    }
                    else
                    {
                        self->LogSuccess(L"Created passkey for Vault Unlock");
                    }
                }
            }
            else
            {
                toggleSwitch.IsOn(false);
                if (self)
                {
                    if (hr == NTE_USER_CANCELLED || hr == HRESULT_FROM_WIN32(ERROR_CANCELLED))
                    {
                        self->LogWarning(L"Passkey registration cancelled", hr);
                    }
                    else
                    {
                        self->LogFailure(L"Failed to register passkey", hr);
                    }

                    if (hr == NTE_NOT_SUPPORTED)
                    {
                        self->LogWarning(L"Likely the authenticator chosen does not suppport PRF. This means the passkey was created in the authenticator, but not registered in Contoso. Delete it to try again.");
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
                self->LogFailure(L"Failed to change 'Silent Operation'", hr);
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
                        self->LogWarning(L"Vault unlock requires UI", E_NOT_VALID_STATE);
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

        std::wstring googleTokenPath = tsupasswd::GetGoogleRefreshTokenStoragePath();
        std::wstring googleTokenFolder = GetParentDirectory(googleTokenPath);
        if (!googleTokenFolder.empty())
        {
            (void)m_googleTokenWatcher.create(googleTokenFolder.c_str(),
                true,
                wil::FolderChangeEvents::All,
                [weakThis](wil::FolderChangeEvent, PCWSTR) -> winrt::fire_and_forget {
                    std::wstring refreshToken;
                    bool connected = tsupasswd::TryLoadGoogleRefreshToken(refreshToken);
                    if (auto self{ weakThis.get() })
                    {
                        co_await wil::resume_foreground(self->DispatcherQueue());
                        if (!connected)
                        {
                            self->m_lastGoogleConnectedAt.clear();
                        }
                        self->UpdateGoogleConnectionUiState(connected);
                    }
                });
        }

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

    winrt::IAsyncAction MainPage::googleSignInButton_Click(IInspectable const&, RoutedEventArgs const&)
    {
        if (m_googleOAuthInProgress.exchange(true))
        {
            LogWarning(L"Google OAuth is already in progress. Wait for the current browser flow to finish.");
            co_return;
        }

        std::wstring existingRefreshToken;
        if (tsupasswd::TryLoadGoogleRefreshToken(existingRefreshToken))
        {
            m_googleOAuthInProgress = false;
            UpdateGoogleConnectionUiState(true);
            LogSuccess(L"Google refresh_token is already saved. Browser sign-in skipped.");
            co_return;
        }

        googleSignInButton().IsEnabled(false);
        disconnectGoogleButton().IsEnabled(false);
        LogInProgress(L"Google OAuth: opening browser...");
        auto weakThis = get_weak();

        co_await winrt::resume_background();
        HRESULT hr = S_OK;
        try
        {
            (void)tsupasswd::PerformGoogleOAuthLoopback();
        }
        catch (...)
        {
            hr = wil::ResultFromCaughtException();
        }

        co_await wil::resume_foreground(DispatcherQueue());
        if (auto self = weakThis.get())
        {
            self->m_googleOAuthInProgress = false;
            if (FAILED(hr))
            {
                self->UpdateGoogleConnectionUiState(false);
                self->LogFailure(L"Google OAuth failed", hr);
                std::wstring hint = DescribeGoogleOAuthFailure(hr);
                if (!hint.empty())
                {
                    self->LogWarning(winrt::hstring{ hint });
                }
                std::wstring oauthDebug = tsupasswd::GetLastGoogleOAuthDebugInfo();
                if (!oauthDebug.empty())
                {
                    self->LogWarning(winrt::hstring{ oauthDebug });
                }
            }
            else
            {
                self->m_lastGoogleConnectedAt = GetNowLocalTimestamp();
                self->UpdateGoogleConnectionUiState(true);
                self->LogSuccess(L"Google OAuth complete (refresh_token saved)");
            }
        }
        else
        {
            m_googleOAuthInProgress = false;
        }
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
        std::wstring existingRefreshToken;
        UpdateGoogleConnectionUiState(tsupasswd::TryLoadGoogleRefreshToken(existingRefreshToken));

        UpdatePluginEnableState();
        UpdateCredentialList();
        co_return;
    }

    winrt::IAsyncAction MainPage::unregisterPluginButton_Click(IInspectable const&, RoutedEventArgs const&)
    {
        LogInProgress(L"Unregistering plugin...");
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
            self->LogFailure(L"Failed to Unregister plugin: ", hr);
            co_return;
        }
        self->LogSuccess(L"Plugin unregistered");
    }

    winrt::IAsyncAction MainPage::registerPluginButton_Click(IInspectable const&, RoutedEventArgs const&)
    {
        LogInProgress(L"Registering plugin...");
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
            self->LogFailure(L"WebAuthNPluginAddAuthenticator", hr);
            co_return;
        }
        self->LogSuccess(L"Plugin registered");

        m_cookie = RegisterWebAuthNStatusChangeCallback(static_cast<void*>(this));
    }

    winrt::IAsyncAction MainPage::updatePluginButton_Click(IInspectable const&, RoutedEventArgs const&)
    {
        LogInProgress(L"Updating plugin...");
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
            self->LogFailure(L"WebAuthNPluginUpdateAuthenticatorDetails", hr);
            co_return;
        }
        self->LogSuccess(L"Plugin updated");
    }

    winrt::IAsyncAction MainPage::addAllPluginCredentials_Click(IInspectable const&, RoutedEventArgs const&)
    {
        LogInProgress(L"Adding All credentials to windows...");

        auto weakThis = get_weak();
        co_await winrt::resume_background();
        HRESULT hr = PluginCredentialManager::getInstance().AddAllPluginCredentials();

        co_await wil::resume_foreground(DispatcherQueue());

        auto self = weakThis.get();
        if (!self)
        {
            co_return;
        }

        self->UpdateCredentialList();
        if (FAILED(hr))
        {
            std::wstring detail = DescribeCredentialOperationFailure(hr);
            self->LogFailure(winrt::hstring{ L"Failed to add credential to system cache. " + detail }, hr);
            co_return;
        }
        self->LogSuccess(L"Credentials synced");
        co_return;
    }

    winrt::IAsyncAction MainPage::addSelectedCredentials_Click(IInspectable const&, Microsoft::UI::Xaml::RoutedEventArgs const&)
    {
        LogInProgress(L"Adding selected passkey metadata to system cache...");

        std::vector<std::vector<UINT8>> credentialIdList;
        auto selectedItems = credentialListView().SelectedItems();
        if (selectedItems.Size() == 0)
        {
            LogWarning(L"No credentials selected", E_NOT_SET);
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

        hstring statusText = L"Adding " + winrt::to_hstring(credentialIdList.size()) + L" selected credentials...";
        UpdatePasskeyOperationStatusText(statusText);

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
        if (FAILED(hr))
        {
            std::wstring detail = DescribeCredentialOperationFailure(hr);
            self->LogFailure(winrt::hstring{ L"Failed to add credentials to system cache. " + detail }, hr);
            co_return;
        }
        self->LogSuccess(L"Selected credentials are added to system cache");
        co_return;
    }

    winrt::IAsyncAction MainPage::deleteAllPluginCredentials_Click(IInspectable const&, Microsoft::UI::Xaml::RoutedEventArgs const&)
    {
        LogInProgress(L"Deleting all credentials stored on this device...");

        auto weakThis = get_weak();
        co_await winrt::resume_background();
        HRESULT hr = PluginCredentialManager::getInstance().DeleteAllPluginCredentials();

        co_await wil::resume_foreground(DispatcherQueue());

        auto self = weakThis.get();
        if (!self)
        {
            co_return;
        }

        self->UpdateCredentialList();
        if (FAILED(hr))
        {
            self->LogFailure(L"Failed to delete credential from system cache", hr);
            co_return;
        }
        self->LogSuccess(L"All credentials deleted from system cache");
        co_return;
    }

    winrt::IAsyncAction MainPage::deleteSelectedPluginCredentials_Click(IInspectable const&, Microsoft::UI::Xaml::RoutedEventArgs const&)
    {
        LogInProgress(L"Deleting selected credentials...");

        // find the list of creds with checkbox checked
        std::vector<std::vector<UINT8>> credentialIdList;
        auto selectedItems = credentialListView().SelectedItems();
        if (selectedItems.Size() == 0)
        {
            LogWarning(L"No credentials selected", E_NOT_SET);
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
        hstring statusText = L"Deleting " + winrt::to_hstring(credentialIdList.size()) + L" selected credentials...";
        UpdatePasskeyOperationStatusText(statusText);

        auto weakThis = get_weak();
        co_await winrt::resume_background();
        HRESULT hr = PluginCredentialManager::getInstance().DeletePluginCredentialById(credentialIdList, false);

        co_await wil::resume_foreground(DispatcherQueue());

        auto self = weakThis.get();
        if (!self)
        {
            co_return;
        }

        self->UpdateCredentialList();
        if (FAILED(hr))
        {
            std::wstring detail = DescribeCredentialOperationFailure(hr);
            self->LogFailure(winrt::hstring{ L"Failed to delete credentials from system cache. " + detail }, hr);
            co_return;
        }
        self->LogSuccess(L"Selected credentials deleted from system cache");
        co_return;
    }

    winrt::IAsyncAction MainPage::deleteSelectedPluginCredentialsEverywhere_Click(IInspectable const&, Microsoft::UI::Xaml::RoutedEventArgs const&)
    {
        LogInProgress(L"Deleting selected credentials everywhere...");

        // find the list of creds with checkbox checked
        std::vector<std::vector<UINT8>> credentialIdList;
        auto selectedItems = credentialListView().SelectedItems();
        if (selectedItems.Size() == 0)
        {
            LogWarning(L"No credentials selected", E_NOT_SET);
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
        hstring statusText = winrt::to_hstring(credentialIdList.size()) + L" credentials selected...";
        UpdatePasskeyOperationStatusText(statusText);

        auto weakThis = get_weak();
        co_await winrt::resume_background();
        HRESULT hr = PluginCredentialManager::getInstance().DeletePluginCredentialById(credentialIdList, true);

        co_await wil::resume_foreground(DispatcherQueue());

        auto self = weakThis.get();
        if (!self)
        {
            co_return;
        }

        self->UpdateCredentialList();
        if (FAILED(hr))
        {
            std::wstring detail = DescribeCredentialOperationFailure(hr);
            self->LogFailure(winrt::hstring{ L"Failed to delete credentials everywhere. " + detail }, hr);
            co_return;
        }
        self->LogSuccess(L"Selected credentials deleted everywhere");
        co_return;
    }

    winrt::IAsyncAction MainPage::clearLogsButton_Click(IInspectable const&, Microsoft::UI::Xaml::RoutedEventArgs const&)
    {
        textContent().Inlines().Clear();
        co_return;
    }

    winrt::IAsyncAction MainPage::deleteAllLocalCredentials_Click(IInspectable const&, Microsoft::UI::Xaml::RoutedEventArgs const&)
    {
        LogInProgress(L"Deleting all local credentials...");

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
            self->LogFailure(L"Failed to delete all local credentials. Credential store update failed. Verify local storage access and retry.", HRESULT_FROM_WIN32(ERROR_WRITE_FAULT));
            co_return;
        }
        self->LogSuccess(L"All local credentials deleted");
        co_return;
    }

    winrt::IAsyncAction MainPage::deleteAllCredentials_Click(IInspectable const&, Microsoft::UI::Xaml::RoutedEventArgs const&)
    {
        LogInProgress(L"Deleting all credentials stored on this device and cache...");
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
        if (FAILED(hr) || !resetResult)
        {
            HRESULT effectiveHr = FAILED(hr) ? hr : HRESULT_FROM_WIN32(ERROR_WRITE_FAULT);
            std::wstring detail = DescribeCredentialOperationFailure(effectiveHr);
            self->LogFailure(winrt::hstring{ L"Failed to delete all credentials. " + detail }, effectiveHr);
            co_return;
        }
        self->LogSuccess(L"All credentials deleted");
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
        LogInProgress(L"Opening Windows Settings for plugin activation...");
        auto uri = Windows::Foundation::Uri(L"ms-settings:passkeys-advancedoptions");
        bool launched = co_await Windows::System::Launcher::LaunchUriAsync(uri);
        if (!launched)
        {
            LogWarning(L"Failed to open Windows Settings. Open Settings > Accounts > Passkeys > Advanced options manually.");
            co_return;
        }
        LogSuccess(L"Windows Settings opened. Enable the plugin, then return and click Refresh.");
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

    winrt::IAsyncAction MainPage::VaultUnlockControl_IsCheckedChanged(winrt::Microsoft::UI::Xaml::Controls::ToggleSplitButton const& sender, winrt::Microsoft::UI::Xaml::Controls::ToggleSplitButtonIsCheckedChangedEventArgs const& args)
    {
        // Capture the value we need before switching context
        bool toggleSplitState = sender.IsChecked();

        auto hr = PluginCredentialManager::getInstance().SetVaultLock(toggleSplitState);

        if (FAILED(hr))
        {
            LogFailure(L"Failed to change 'Simulate Vault Unlock'", hr);
        }

        UpdateVaultUnlockControlText(toggleSplitState);

        co_return;
    }

}
