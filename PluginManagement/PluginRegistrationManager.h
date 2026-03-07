#pragma once
#include "pch.h"
#include <App.xaml.h>
#include <MainWindow.xaml.h>
#include <MainPage.xaml.h>
#include <PluginAuthenticator/PluginAuthenticatorImpl.h>

constexpr wchar_t c_pluginName[] = L"HappyFactory";
constexpr wchar_t c_pluginRpId[] = L"happyfactory.dev";
constexpr wchar_t c_pluginRpIdWebAuthnIo[] = L"webauthn.io";
constexpr wchar_t c_pluginRpIdWebAuthnIoWww[] = L"www.webauthn.io";
constexpr wchar_t c_pluginRpIdPasskeyOrg[] = L"passkey.org";
constexpr wchar_t c_pluginRpIdPasskeyOrgWww[] = L"www.passkey.org";
constexpr wchar_t c_pluginRpIdPasskeysIo[] = L"passkeys.io";
constexpr wchar_t c_pluginRpIdPasskeysIoWww[] = L"www.passkeys.io";
constexpr wchar_t c_pluginRpIdPasskeysGuru[] = L"passkeys.guru";
constexpr wchar_t c_pluginRpIdPasskeysGuruWww[] = L"www.passkeys.guru";
constexpr wchar_t c_pluginRpIdWebAuthnPasswordlessId[] = L"webauthn.passwordless.id";
constexpr wchar_t c_pluginRpIdWebAuthnPasswordlessIdWww[] = L"www.webauthn.passwordless.id";
constexpr wchar_t c_rpName[] = L"HappyFactory";
constexpr wchar_t c_userName[] = L"HappyFactoryUser";
constexpr wchar_t c_userDisplayName[] = L"HappyFactory User";
constexpr wchar_t c_userId[] = L"HappyFactoryUserId";
constexpr wchar_t c_dummySecretVault[] = L"DummySecretVault";

/* The AAGUID is a unique identifier for the FIDO authenticator model.
*'AAGUID' maybe used to fetch information about the authenticator from the FIDO Metadata Service and other sources.
* Refer: https://fidoalliance.org/metadata/
*/
constexpr char c_pluginAaguidString[] = "12345678-1234-5678-90ab-cdef12345678";
static_assert(c_pluginAaguidString[1] != '#', "Please replace the AAGUID value c_pluginAaguid above with your AAGUID");
constexpr BYTE c_pluginAaguidBytes[] = { 0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78 }; // big endian
static_assert(c_pluginAaguidBytes[0] != '#', "Please replace the AAGUID values c_pluginAaguid and c_pluginAaguidBytes above with your AAGUID");

constexpr wchar_t c_pluginSigningKeyName[] = L"TestAppPluginIdKey";
constexpr wchar_t c_pluginRegistryPath[] = L"Software\\HappyFactory\\PasskeyManager";
constexpr wchar_t c_windowsPluginRequestSigningKeyRegKeyName[] = L"RequestSigningKeyBlob";
constexpr wchar_t c_windowsPluginVaultLockedRegKeyName[] = L"VaultLocked";
constexpr wchar_t c_windowsPluginSilentOperationRegKeyName[] = L"SilentOperation";
constexpr wchar_t c_windowsPluginDBUpdateInd[] = L"PluginDBUpdate";
constexpr wchar_t c_pluginHMACSecretInput[] = L"HMACSecretInput";
constexpr wchar_t c_pluginProtectedHMACSecretInput[] = L"HMACSecretInputProtected";
constexpr wchar_t c_pluginEncryptedVaultData[] = L"EncryptedVaultData";
constexpr wchar_t c_windowsPluginVaultUnlockMethodRegKeyName[] = L"VaultUnlockMethod";
constexpr wchar_t c_windowsPluginLastMakeCredentialStatusRegKeyName[] = L"LastMakeCredentialStatus";
constexpr wchar_t c_windowsPluginLastMakeCredentialSequenceRegKeyName[] = L"LastMakeCredentialSequence";

namespace winrt::PasskeyManager::implementation
{
    class PluginRegistrationManager
    {
    public:
        static PluginRegistrationManager& getInstance()
        {
            static PluginRegistrationManager instance;
            return instance;
        }

        HRESULT Initialize(); // calls GetPluginState to check if the plugin is already registered

        HRESULT RegisterPlugin();
        HRESULT UnregisterPlugin();
        HRESULT UpdatePlugin();

        HRESULT RefreshPluginState();

        bool IsPluginRegistered() const
        {
            return m_pluginRegistered;
        }

        AUTHENTICATOR_STATE GetPluginState() const
        {
            return m_pluginState;
        }

        HRESULT CreateVaultPasskey(HWND hwnd, std::wstring const& requestId = L"");
        HRESULT SetHMACSecret(std::vector<BYTE> hmacSecret, std::wstring const& requestId = L"");
        std::vector<BYTE> GetHMACSecret() const
        {
            return m_hmacSecret;
        }

        HRESULT WriteEncryptedVaultData(std::vector<BYTE> cipherText);
        HRESULT ReadEncryptedVaultData(std::vector<BYTE>& cipherText, std::wstring const& requestId = L"");
        HRESULT ClearLocalEncryptedVaultData(std::wstring const& requestId = L"");
        HRESULT ManualResyncSelfHostedVault(std::wstring const& requestId = L"");
        HRESULT RestoreSelfHostedVaultSnapshot(std::wstring const& requestId = L"");
        void ReloadRegistryValues(std::wstring const& requestId = L"");

    private:
        AUTHENTICATOR_STATE m_pluginState;
        bool m_initialized = false;
        bool m_pluginRegistered = false;

        std::mutex m_pluginOperationConfigMutex;
        _Guarded_by_(m_pluginOperationConfigMutex) std::vector<BYTE> m_hmacSecret = {};

        PluginRegistrationManager();
        ~PluginRegistrationManager();
        PluginRegistrationManager(const PluginRegistrationManager&) = delete;
        PluginRegistrationManager& operator=(const PluginRegistrationManager&) = delete;

        void UpdatePasskeyOperationStatusText(hstring const& statusText)
        {
            com_ptr<App> curApp = winrt::Microsoft::UI::Xaml::Application::Current().as<App>();
            curApp->GetDispatcherQueue().TryEnqueue([curApp, statusText]()
            {
                curApp->m_window.Content().try_as<Microsoft::UI::Xaml::Controls::Frame>().Content().try_as<MainPage>()->UpdatePasskeyOperationStatusText(statusText);
            });
        }
    };
};
