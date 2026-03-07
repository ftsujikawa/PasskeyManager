// Copyright (c) Microsoft Corporation and Contributors.
// Licensed under the MIT License.

#include "pch.h"

#include "App.xaml.h"
#include "MainWindow.xaml.h"
#include "MainPage.xaml.h"
#include "MakeCredentialPage.xaml.h"
#include "GetAssertion.xaml.h"
#include "PluginManagement/PluginRegistrationManager.h"
#include "PluginManagement/PluginCredentialManager.h"
#include "PluginAuthenticator/PluginAuthenticatorImpl.h"
#include <winrt/Microsoft.ui.interop.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Microsoft.UI.Xaml.Media.Animation.h>

#include <include/cbor-lite/codec.h>
#include <string>
#include <iostream>
#include <fstream>
namespace winrt
{
    using namespace winrt::Windows::Foundation;
    using namespace winrt::Microsoft::UI::Windowing;
    using namespace winrt::Microsoft::UI::Xaml;
    using namespace winrt::Microsoft::UI::Xaml::Controls;
    using namespace winrt::Microsoft::UI::Xaml::Navigation;
    using namespace CborLite;
}

namespace winrt::PasskeyManager::implementation
{

static void PersistAppComMarker(DWORD value) noexcept
{
    wchar_t tempPath[MAX_PATH]{};
    DWORD tempLen = GetTempPathW(static_cast<DWORD>(std::size(tempPath)), tempPath);
    if (tempLen > 0 && tempLen < std::size(tempPath))
    {
        std::wstring filePath(tempPath);
        filePath += L"tsupasswd_core_app_marker.log";
        HANDLE hFile = CreateFileW(filePath.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile != INVALID_HANDLE_VALUE)
        {
            wchar_t line[64]{};
            const int cch = swprintf_s(line, L"0x%08X\r\n", value);
            if (cch > 0)
            {
                DWORD cb = 0;
                (void)WriteFile(hFile, line, static_cast<DWORD>(cch * sizeof(wchar_t)), &cb, nullptr);
            }
            (void)CloseHandle(hFile);
        }
    }

    wil::unique_hkey hKey;
    if (RegCreateKeyEx(
        HKEY_CURRENT_USER,
        L"Software\\HappyFactory\\PasskeyManager",
        0,
        nullptr,
        REG_OPTION_NON_VOLATILE,
        KEY_WRITE,
        nullptr,
        &hKey,
        nullptr) != ERROR_SUCCESS)
    {
        return;
    }

    (void)RegSetValueEx(
        hKey.get(),
        L"AppComMarker",
        0,
        REG_DWORD,
        reinterpret_cast<const BYTE*>(&value),
        sizeof(value));
}

void App::RegisterPluginClassFactory()
{
    // Ensure COM initialized on the calling thread before registering class objects.
    const HRESULT hrCoInit = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (hrCoInit != RPC_E_CHANGED_MODE)
    {
        winrt::check_hresult(hrCoInit);
    }

    PersistAppComMarker(0xAC0C0001);
    winrt::com_ptr<App> app;
    app.copy_from(this);
    const HRESULT hrReg = ::CoRegisterClassObject(
        happyfactoryplugin_guid,
        make<HappyFactoryPluginFactory>(std::move(app), m_hPluginOpCompletedEvent, m_hAppReadyForPluginOpEvent, m_hPluginCancelOperationEvent).get(),
        CLSCTX_LOCAL_SERVER,
        REGCLS_MULTIPLEUSE,
        &m_registration);
    PersistAppComMarker(SUCCEEDED(hrReg) ? 0xAC0C0002 : 0xAC0C0003);
    winrt::check_hresult(hrReg);
}

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

/// <summary>
/// Initializes the singleton application object.  This is the first line of authored code
/// executed, and as such is the logical equivalent of main() or WinMain().
/// </summary>
App::App() :
    m_hPluginProceedButtonEvent(nullptr),
    m_hPluginCancelOperationEvent(nullptr),
    m_hPluginWindowDisplayInfoReadyEvent(nullptr),
    m_hPluginCredentialSelected(nullptr),
    m_hVaultConsentFailed(nullptr),
    m_hVaultConsentComplete(nullptr),
    m_hWindowReady(nullptr),
    m_pluginOperationStatus({})
{
    s_instance = this;
    InitializeComponent();
#if defined _DEBUG && !defined DISABLE_XAML_GENERATED_BREAK_ON_UNHANDLED_EXCEPTION
    UnhandledException([this](IInspectable const&, UnhandledExceptionEventArgs const& e)
        {
            if (IsDebuggerPresent())
            {
                auto errorMessage = e.Message();
                __debugbreak();
            }
        });
#endif
}

App::App(PWSTR args) : m_args(args)
{
    s_instance = this;
    InitializeComponent();
#if defined _DEBUG && !defined DISABLE_XAML_GENERATED_BREAK_ON_UNHANDLED_EXCEPTION
    UnhandledException([this](IInspectable const&, UnhandledExceptionEventArgs const& e)
        {
            if (IsDebuggerPresent())
            {
                auto errorMessage = e.Message();
                __debugbreak();
            }
        });
#endif
}

void App::InitializeAppWindTitleBar()
{
    AppWindow appWind = m_window.as<MainWindow>()->GetAppWindow();
    AppWindowTitleBar titleBar = appWind.TitleBar();
    titleBar.ButtonBackgroundColor(winrt::Microsoft::UI::Colors::Transparent());
    titleBar.ExtendsContentIntoTitleBar(true);
    titleBar.PreferredHeightOption(winrt::Microsoft::UI::Windowing::TitleBarHeightOption::Tall);
    appWind.Title(L"HappyFactory Passkey Manager");
    appWind.SetIcon(L"Assets\\icon.ico");
    appWind.Title(L"");
}

void App::ResetPluginOperationState()
{
    // Reset all events to their initial state
    ResetEvent(m_hPluginProceedButtonEvent.get());
    ResetEvent(m_hPluginCancelOperationEvent.get());
    ResetEvent(m_hPluginWindowDisplayInfoReadyEvent.get());
    ResetEvent(m_hPluginCredentialSelected.get());
    ResetEvent(m_hVaultConsentFailed.get());
    ResetEvent(m_hVaultConsentComplete.get());
    ResetEvent(m_hWindowReady.get());
    ResetEvent(m_hPluginOpCompletedEvent.get());

    // Reset operation options
    {
        std::lock_guard<std::mutex> lock(m_pluginOperationOptionsMutex);
        m_pluginOperationOptions = PluginOpertaionOptions{};

    }
    // Reset operation status
    m_pluginOperationStatus = PluginOperationStatus{};
    m_isOperationInProgress = false;

    CloseOrHideWindow();
}

void App::CloseOrHideWindow()
{
    if (m_window)
    {
        // get native window handle
        HWND windowNative = m_window.as<MainWindow>()->GetNativeWindowHandle();
        // reset the owner window
        SetWindowLongPtr(windowNative, GWLP_HWNDPARENT, 0);
        // Hide the window instead of closing it to keep the process alive
        auto appWindow = m_window.as<MainWindow>()->GetAppWindow();
        if (appWindow)
        {
            appWindow.Hide();
        }
    }
}

void App::OnLaunched(LaunchActivatedEventArgs const&)
{
    PersistAppComMarker(0xAC0C1000);
    std::wstring argsString{ m_args };
    if (argsString.find(L"-PluginActivated") != std::wstring::npos)
    {
        PersistAppComMarker(0xAC0C1100);
        // Ensure registration details are up-to-date even when the app is launched only by WebAuthN plugin activation.
        // Without this, supported RP ID changes (e.g., passkeys.guru) may not be reflected until interactive launch.
        auto& registrationManager = PluginRegistrationManager::getInstance();
        HRESULT hrEnsurePlugin = registrationManager.RefreshPluginState();
        if (hrEnsurePlugin == NTE_NOT_FOUND)
        {
            (void)registrationManager.RegisterPlugin();
        }
        else if (SUCCEEDED(hrEnsurePlugin))
        {
            (void)registrationManager.UpdatePlugin();
        }

        // Background Mode: The app is being activated by the OS to handle a passkey operation. It runs in the background.
        RegisterPluginClassFactory();
        // Start the plugin operation handling loop
        HandlePluginOperations();
    }
    else
    {
        PersistAppComMarker(0xAC0C1200);
        // Interactive Mode: The user is launching the app directly.
        PluginCredentialManager::getInstance();
        m_window = make<MainWindow>();
        InitializeAppWindTitleBar();
        Frame rootFrame = CreateRootFrame();
        rootFrame.Navigate(xaml_typename<PasskeyManager::MainPage>(), box_value(m_args));
        m_window.Activate();

        // Ensure the COM local server is also registered in interactive mode so browsers can activate
        // the plugin without relying on a -PluginActivated relaunch.
        RegisterPluginClassFactory();
        static std::once_flag s_pluginLoopStarted;
        std::call_once(s_pluginLoopStarted, [this]
        {
            std::thread([this]
            {
                // WebAuthn can call into the COM server on arbitrary threads; ensure COM is initialized.
                const HRESULT hrCoInit = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
                if (hrCoInit != RPC_E_CHANGED_MODE)
                {
                    (void)hrCoInit;
                }
                HandlePluginOperations();
            }).detach();
        });
    }
}

void App::SetupPluginWindow()
{
    bool windowCreated = false;
    if (m_pluginOperationOptions.silentMode)
    {
        SetEvent(m_hWindowReady.get());
        SetEvent(m_hPluginCredentialSelected.get());
        SetEvent(m_hPluginProceedButtonEvent.get());
        return;
    }
    if (!m_window)
    {
        m_window = make<MainWindow>();
        InitializeAppWindTitleBar();
        windowCreated = true;
    }

    if (m_window.Visible())
    {
        return;
    }

    winrt::Microsoft::UI::Xaml::Controls::Frame rootFrame = CreateRootFrame();
    if (!windowCreated)
    {   rootFrame.Navigated([this](IInspectable const&, NavigationEventArgs const&)
        {
            this->m_window.Content().as<Frame>().Content().as<Page>().Loaded([this](IInspectable const&, RoutedEventArgs const&)
                {
                    this->m_window.AppWindow().Show();
                });
        });
    }
    if (m_pluginOperationOptions.operationType == PluginOperationType::MakeCredential)
    {
        rootFrame.Navigate(xaml_typename<PasskeyManager::MakeCredentialPage>(), box_value(m_args), Media::Animation::SuppressNavigationTransitionInfo{});
    }
    else
    {
        rootFrame.Navigate(xaml_typename<PasskeyManager::GetAssertion>(), box_value(m_args), Media::Animation::SuppressNavigationTransitionInfo{});
    }

    HWND windowNative = m_window.as<MainWindow>()->GetNativeWindowHandle();
    HWND& clientWindowHandle = m_pluginOperationOptions.hWnd;

    SetWindowLongPtr(windowNative, GWLP_HWNDPARENT, reinterpret_cast<LONG_PTR>(clientWindowHandle));

    RECT rc, rcClient, rcWindow;
    GetWindowRect(clientWindowHandle, &rcClient);
    GetWindowRect(windowNative, &rcWindow);
    CopyRect(&rc, &rcClient);

    // Fix the size of the window
    int width = 550;
    int height = 450;

    // Align the center of the window.
    int clientCenterX = (rcClient.right + rcClient.left) / 2;
    int clientCenterY = (rcClient.bottom + rcClient.top) / 2;
    int newX = max(clientCenterX - width / 2, 0);
    int newY = max(clientCenterY - height / 2, 0);

    SetWindowPos(windowNative,
        HWND_TOP,
        newX,
        newY,
        width,
        height,
        SWP_ASYNCWINDOWPOS);

    if (windowCreated)
    {
        m_window.Activate();
    }
    SetEvent(m_hWindowReady.get());
}

void App::HandlePluginOperations()
{
    // This method handles plugin operations in a loop as long as the app is running in background.
    while (true)
    {
        SetEvent(m_hAppReadyForPluginOpEvent.get());
        HANDLE rghWait[] = {
            m_hPluginWindowDisplayInfoReadyEvent.get(),
            m_hPluginOpCompletedEvent.get(),
            m_hPluginCancelOperationEvent.get()
        };

        DWORD dwSleepMilliseconds = INFINITE;
        DWORD hIndex = 0;
        if (FAILED(CoWaitForMultipleHandles(COWAIT_DISPATCH_WINDOW_MESSAGES | COWAIT_DISPATCH_CALLS, dwSleepMilliseconds, ARRAYSIZE(rghWait), rghWait, &hIndex)))
        {
            break; // Exit the loop on error
        }

        if (hIndex == 2) // user canceled before window could be setup
        {
            PluginCancelAction();
            continue; // keep handling subsequent operations
        }
        else if (hIndex == 1) // Plugin operation completed before display info was parsed. No UI to be displayed.
        {
            ResetPluginOperationState();
            continue; // Continue to next operation
        }
        else if (m_pluginOperationOptions.silentMode)
        {
            SetEvent(m_hWindowReady.get());
            SetEvent(m_hPluginProceedButtonEvent.get());
            LOG_IF_FAILED(CoWaitForMultipleHandles(COWAIT_DISPATCH_WINDOW_MESSAGES | COWAIT_DISPATCH_CALLS, dwSleepMilliseconds, 1, m_hPluginOpCompletedEvent.addressof(), &hIndex));
            ResetPluginOperationState();
            continue; // Continue to next operation
        }
        else
        {
            LOG_IF_FAILED(CoWaitForMultipleHandles(COWAIT_DISPATCH_WINDOW_MESSAGES | COWAIT_DISPATCH_CALLS, dwSleepMilliseconds, 1, m_hWindowReady.addressof(), &hIndex));
            LOG_IF_FAILED(CoWaitForMultipleHandles(COWAIT_DISPATCH_WINDOW_MESSAGES | COWAIT_DISPATCH_CALLS, dwSleepMilliseconds, 1, m_hPluginOpCompletedEvent.addressof(), &hIndex));
            ResetPluginOperationState();
            continue; // keep handling subsequent operations
        }
    }
}

Frame App::CreateRootFrame()
{
    Frame rootFrame{ nullptr };
    auto content = m_window.Content();
    if (content)
    {
        rootFrame = content.try_as<Frame>();
    }

    if (!rootFrame)
    {
        rootFrame = Frame();
        rootFrame.NavigationFailed({ this, &App::OnNavigationFailed });
        m_window.Content(rootFrame);
    }

    return rootFrame;
}

void App::OnNavigationFailed(IInspectable const&, NavigationFailedEventArgs const& e)
{
    throw hresult_error(E_FAIL, hstring(L"Failed to load Page ") + e.SourcePageType().Name);
}

HWND App::GetNativeWindowHandle()
{
    return this->m_window.try_as<MainWindow>()->GetNativeWindowHandle();
}

bool App::SetPluginPerformOperationOptions(HWND hWnd,
    PluginOperationType operationType,
    std::wstring rpName,
    std::wstring userName)
{
    auto& credMgr = PluginCredentialManager::getInstance();
    credMgr.ReloadRegistryValues();
    bool vaultLocked = credMgr.GetVaultLock();
    {
        std::lock_guard<std::mutex> lock(m_pluginOperationOptionsMutex);
        m_pluginOperationOptions.hWnd = hWnd;
        m_pluginOperationOptions.operationType = operationType;
        m_pluginOperationOptions.rpName = rpName;
        m_pluginOperationOptions.userName = userName;
        m_pluginOperationOptions.matchingCredentials.clear();
        m_pluginOperationOptions.selectedCredential = nullptr;
        m_pluginOperationOptions.silentMode = credMgr.GetSilentOperation();

        // Local ceremonies should not show plugin-owned UI when the vault is already unlocked.
        // Keep the operation in silent mode and let the WebAuthN platform prompt drive UX.
        if ((operationType == PluginOperationType::MakeCredential || operationType == PluginOperationType::GetAssertion) && !vaultLocked)
        {
            m_pluginOperationOptions.silentMode = true;
        }

        if (m_pluginOperationOptions.matchingCredentials.size() > 1 || credMgr.GetVaultLock())
        {
            m_pluginOperationOptions.silentMode = false;
        }
    }

    m_pluginOperationStatus.performOperationStatus = S_OK;

    SetEvent(this->m_hPluginWindowDisplayInfoReadyEvent.get());

    SetupPluginWindow();
    return true;
}

bool App::SetSelectedCredentialId(Windows::Storage::Streams::IBuffer credentialId)
{
    std::lock_guard<std::mutex> lock(m_pluginOperationOptionsMutex);
    for (auto& cred : m_pluginOperationOptions.matchingCredentials)
    {
        const std::vector<UINT8> credId(cred->pbCredentialID, cred->pbCredentialID + cred->cbCredentialID);
        auto reader = winrt::Windows::Storage::Streams::DataReader::FromBuffer(credentialId);
        std::vector<UINT8> selectedCredentialIdVec(reader.UnconsumedBufferLength());
        reader.ReadBytes(selectedCredentialIdVec);
        if (credId.size() == selectedCredentialIdVec.size() && memcmp(credId.data(), selectedCredentialIdVec.data(), credId.size()) == 0)
        {
            m_pluginOperationOptions.selectedCredential = cred;
            SetEvent(m_hPluginCredentialSelected.get());
            return true;
        }
    }
    return false;
}

bool App::SetMatchingCredentials(
    std::wstring_view rpName,
    const std::vector<const WEBAUTHN_CREDENTIAL_DETAILS *>& matchedCreds,
    HWND clientHwnd)
{
    auto& credMgr = PluginCredentialManager::getInstance();
    credMgr.ReloadRegistryValues();
    {
        std::lock_guard<std::mutex> lock(m_pluginOperationOptionsMutex);
        m_pluginOperationOptions.rpName = rpName;
        m_pluginOperationOptions.operationType = PluginOperationType::GetAssertion;
        m_pluginOperationOptions.matchingCredentials = matchedCreds;
        m_pluginOperationOptions.hWnd = clientHwnd;
        m_pluginOperationOptions.silentMode = credMgr.GetSilentOperation();
        if (m_pluginOperationOptions.matchingCredentials.size() > 1 || credMgr.GetVaultLock())
        {
            m_pluginOperationOptions.silentMode = false;
        }
        else // if there is only one matching credential, select it by default
        {
            m_pluginOperationOptions.selectedCredential = m_pluginOperationOptions.matchingCredentials[0];
        }
    }

    SetEvent(this->m_hPluginWindowDisplayInfoReadyEvent.get());
    SetupPluginWindow();
    return true;
}

winrt::fire_and_forget App::SimulateUnLockVault()
{
    auto mainWindow = m_window.as<MainWindow>();
    auto reenableUI = wil::scope_exit([&]() { mainWindow->EnableUI(); });
    if (GetSilentMode())
    {
        reenableUI.release();
    }
    else
    {
        mainWindow->DisableUI();
    }

    winrt::hresult consentResult;
    auto vaultUnlockMethod = PluginCredentialManager::getInstance().GetVaultUnlockMethod();
    if (vaultUnlockMethod == VaultUnlockMethod::Consent)
    {
        consentResult = co_await mainWindow->RequestConsent(L"Unlock HappyFactory Passkey Manager Vault");
    }
    else if (vaultUnlockMethod == VaultUnlockMethod::Passkey)
    {
        winrt::apartment_context ui_thread;
        co_await winrt::resume_background();
        consentResult = PluginCredentialManager::getInstance().UnlockCredentialVaultWithPasskey(mainWindow->GetNativeWindowHandle());
        co_await ui_thread;
    }
    if (SUCCEEDED(consentResult))
    {
        SetEvent(m_hVaultConsentComplete.get());
    }
    else
    {
        SetEvent(m_hVaultConsentFailed.get());
    }
}

bool App::PluginCompleteAction()
{
    SetEvent(m_hPluginProceedButtonEvent.get());
    DWORD hIndex = 0;
    LOG_IF_FAILED(CoWaitForMultipleHandles(COWAIT_DISPATCH_WINDOW_MESSAGES | COWAIT_DISPATCH_CALLS, INFINITE, 1, m_hPluginOpCompletedEvent.addressof(), &hIndex));

    if (m_window)
    {
        m_window.as<MainWindow>()->UpdatePasskeyOperationStatus(m_pluginOperationStatus.performOperationStatus);
    }

    // Operation completed, continue to next operation
    ResetPluginOperationState();
    
    return true;
}

bool App::PluginCancelAction()
{
    SetEvent(m_hPluginCredentialSelected.get());

    if (m_window)
    {
        m_window.as<MainWindow>()->UpdatePasskeyOperationStatus(NTE_USER_CANCELLED);
    }

    // Operation completed, continue to next operation
    ResetPluginOperationState();

    return true;
}
}


int WINAPI wWinMain(_In_ HINSTANCE, _In_opt_ HINSTANCE, _In_ PWSTR args, _In_ int)
{
    winrt::init_apartment(winrt::apartment_type::single_threaded);

    winrt::check_hresult(CoInitializeSecurity(
        nullptr,
        -1,
        nullptr,
        nullptr,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr,
        EOAC_NONE,
        nullptr));

    ::winrt::Microsoft::UI::Xaml::Application::Start(
        [args](auto&&)
        {
            if (args[0] != '\0')
            {
                ::winrt::make<::winrt::PasskeyManager::implementation::App>(args);
            }
            else
            {
                ::winrt::make<::winrt::PasskeyManager::implementation::App>();
            }
        });

    return 0;
}
