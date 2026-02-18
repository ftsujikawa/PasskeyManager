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
#include <future>
#include <coroutine>
#include <thread>
#include <DispatcherQueue.h>
#include <winrt/Microsoft.ui.interop.h>
#include <winrt/Microsoft.UI.Content.h>
#include <winrt/Windows.Security.Credentials.UI.h>

namespace winrt {
    using namespace winrt::Microsoft::UI::Xaml;
}

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace {
    std::wstring DescribeCredentialOperationFailure(HRESULT hr)
    {
        if (hr == HRESULT_FROM_WIN32(ERROR_NOT_FOUND))
        {
            return L"No credentials are available to sync. Click Refresh, then retry after credentials appear.";
        }
        if (hr == E_NOT_VALID_STATE)
        {
            return L"Vault is locked or requires interactive unlock. Complete the unlock UI flow, then retry.";
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

    winrt::IAsyncAction MainPage::runVaultRecoveryButton_Click(IInspectable const&, RoutedEventArgs const&)
    {
        auto strongThis = get_strong();
        auto weakThis = get_weak();
        runVaultRecoveryButton().IsEnabled(false);
        quickCreateVaultPasskeyButton().IsEnabled(false);
        LogInProgress(L"Running Vault recovery flow");
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
                self->LogWarning(winrt::hstring{ L"Plugin is not Enabled. Current plugin state=" + stateText + L". Opening Settings now..." });

                auto uri = Windows::Foundation::Uri(L"ms-settings:passkeys-advancedoptions");
                bool launched = co_await Windows::System::Launcher::LaunchUriAsync(uri);
                if (launched)
                {
                    self->LogSuccess(L"Windows Settings opened. Enable the plugin, return to the app, then retry Create Vault Passkey.");
                }
                else
                {
                    self->LogWarning(L"Failed to open Windows Settings. Open Settings > Accounts > Passkeys > Advanced options and enable this plugin.");
                }
            }
            co_return;
        }

        if (auto self{ weakThis.get() })
        {
            self->LogInfo(L"Vault recovery precheck passed. Starting Create Vault Passkey...");
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
                self->LogInfo(L"Create Vault Passkey was cancelled. Skipping immediate retry to avoid plugin busy race.", hrCreatePasskey);
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
                self->LogFailure(L"Failed to set Vault Unlock Method to Passkey", hrSetMethod);
                co_return;
            }

            if (FAILED(hrSetSilent))
            {
                self->LogWarning(L"Failed to force plugin UI visibility (silent mode off). Passkey prompt may be cancelled unexpectedly.", hrSetSilent);
            }

            self->LogInfo(L"Create Vault Passkey returned", hrCreatePasskey);
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
                self->LogInfo(L"Plugin performOperationStatus", pluginPerformStatus);
                self->LogInfo(L"Plugin uvSignatureVerificationStatus", pluginUvStatus);
                self->LogInfo(L"Plugin requestSignatureVerificationStatus", pluginRequestSignStatus);
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

            if (hrCreatePasskey == NTE_NOT_SUPPORTED || hrCreatePasskey == HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED))
            {
                self->SetVaultLockSwitchState(false);
                self->vaultRecoveryHintText().Text(L"Passkey registration is not supported by the selected authenticator. Try selecting tsupasswd_core and retry.");
                self->vaultRecoveryHintText().Visibility(Microsoft::UI::Xaml::Visibility::Visible);
                self->LogWarning(L"Selected authenticator does not support required PRF/HMAC extension. Select tsupasswd_core and retry Create Vault Passkey.");
                co_return;
            }

            self->SetVaultLockSwitchState(false);
            if (hrCreatePasskey == NTE_USER_CANCELLED || hrCreatePasskey == HRESULT_FROM_WIN32(ERROR_CANCELLED))
            {
                self->vaultRecoveryHintText().Text(L"Passkey registration was cancelled (0x800704C7). In storage selection choose tsupasswd_core and complete the prompt.");
                self->vaultRecoveryHintText().Visibility(Microsoft::UI::Xaml::Visibility::Visible);
                self->LogInfo(L"Vault recovery cancelled. If 'Something went wrong' appeared, select tsupasswd_core in storage selection and retry.", hrCreatePasskey);
            }
            else
            {
                self->vaultRecoveryHintText().Text(L"Vault passkey registration failed. Check the latest FAILED/INFO log line for the HRESULT and retry.");
                self->vaultRecoveryHintText().Visibility(Microsoft::UI::Xaml::Visibility::Visible);
                self->LogFailure(L"Vault recovery failed during passkey registration", hrCreatePasskey);
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
                self->LogFailure(L"Failed to change 'Vault Unlock Control'", hr);
            }
        }
        else if (self)
        {
            self->LogSuccess(L"Changed 'Vault Unlock Control Method'");
            if (unlockMethod == VaultUnlockMethod::Passkey && FAILED(hrSetSilent))
            {
                self->LogWarning(L"Failed to force plugin UI visibility (silent mode off). Passkey prompt may be cancelled unexpectedly.", hrSetSilent);
            }
        }

        if (unlockMethod == VaultUnlockMethod::Passkey)
        {
            if (self)
            {
                self->LogInfo(L"Starting Create Vault Passkey from unlock method toggle...");
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
                    self->LogInfo(L"Create Vault Passkey was cancelled. Skipping immediate retry to avoid plugin busy race.", hr);
                }
            }

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
                SetVaultLockSwitchState(false);
                if (self)
                {
                    if (hr == NTE_USER_CANCELLED || hr == HRESULT_FROM_WIN32(ERROR_CANCELLED))
                    {
                        self->LogInfo(L"Passkey registration cancelled. Select tsupasswd_core in storage selection and retry.", hr);
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
            self->LogSuccess(L"Plugin unregistered");
        }
        else
        {
            self->LogWarning(L"Plugin may still be visible in Windows Settings. Close/reopen Settings and click Refresh. If still listed, disable it in Settings and click Remove again.");
        }
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

        auto& credentialManager = PluginCredentialManager::getInstance();
        com_ptr<App> curApp = winrt::Microsoft::UI::Xaml::Application::Current().as<App>();
        HWND hwnd = curApp->GetNativeWindowHandle();
        if (credentialManager.GetVaultLock())
        {
            LogInProgress(L"Vault is locked. Opening unlock UI before credential sync...");
            HRESULT hrUnlock = credentialManager.UnlockCredentialVaultWithPasskey(hwnd);
            if (FAILED(hrUnlock))
            {
                if (hrUnlock == E_NOT_VALID_STATE)
                {
                    LogWarning(L"Vault unlock requires UI. Complete passkey prompt, then retry Add All.", hrUnlock);
                }
                else
                {
                    LogFailure(L"Vault unlock failed before Add All", hrUnlock);
                }
                co_return;
            }
            LogSuccess(L"Vault unlocked. Continuing Add All credential sync.");
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
                self->LogWarning(L"No local credentials to sync yet. Click 'Create Vault Passkey' (or import passkeys), then retry Add All.");
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
        auto weakThis = get_weak();
        LogInProgress(L"Opening Windows Settings for plugin activation...");
        auto uri = Windows::Foundation::Uri(L"ms-settings:passkeys-advancedoptions");
        bool launched = co_await Windows::System::Launcher::LaunchUriAsync(uri);
        if (!launched)
        {
            LogWarning(L"Failed to open Windows Settings. Open Settings > Accounts > Passkeys > Advanced options manually.");
            co_return;
        }

        LogSuccess(L"Windows Settings opened. Waiting for plugin state update...");

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
                    self->LogSuccess(L"Plugin state changed to Enabled.");
                    co_return;
                }
            }
            else
            {
                co_return;
            }
        }

        LogWarning(L"Plugin is still not Enabled. After enabling in Settings, click Refresh.");
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
            LogFailure(L"Failed to change 'Simulate Vault Unlock'", hr);
        }

        UpdateVaultUnlockControlText(toggleSplitState);

        co_return;
    }

}
